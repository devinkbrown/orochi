// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mooring handshake session: drives the PQ-hybrid AKE to `Established` and
//! bridges its authenticated 20-byte node id to the `u64` mesh routing handle a
//! Undertow `s2s_peer` keys on.
//!
//! `mooring_handshake` provides the raw `Initiator`/`Responder` state machines;
//! this wraps them in one role-agnostic driver so the S2S transport can run the
//! handshake without branching on role, and — crucially — hands back exactly
//! what it needs to stand up the inner CRDT peer:
//!
//!   * `peerNodeId()`  — the canonical, authenticated 20-byte identity.
//!   * `peerShortId()` — `node_short_id.shortId(peer)`, the value to pass as
//!                       `S2sPeer.Options.remote_node_id` so the secured channel
//!                       and the CRDT/gossip layer agree on who the peer is.
//!   * `established()` — the derived directional AEAD keys for the post-handshake
//!                       secure channel.
//!
//! The keypairs/prekeys are borrowed (the handshake structs hold pointers);
//! keep them alive for the session's lifetime, as with the raw API.
const std = @import("std");

const hs = @import("mooring_handshake.zig");
const sign = @import("sign.zig");
const xwing = @import("xwing.zig");
const node_short_id = @import("node_short_id.zig");

pub const Error = hs.Error;
pub const NodeId = hs.NodeId;
pub const Established = hs.Established;
pub const SignedPrekey = hs.SignedPrekey;
pub const Config = hs.Config;

pub const Role = enum { initiator, responder };

pub const Session = struct {
    allocator: std.mem.Allocator,
    inner: union(Role) {
        initiator: hs.Initiator,
        responder: hs.Responder,
    },
    /// Initiator-side Established is returned by `Initiator.recv` and owned here.
    /// (Responder keeps its Established inside `inner.responder`; we never copy it
    /// so there is exactly one owner and no double-wipe.)
    init_est: ?hs.Established = null,
    peer_short: u64 = 0,
    done: bool = false,

    pub fn initInitiator(
        allocator: std.mem.Allocator,
        local_node: *const sign.KeyPair,
        local_prekey: SignedPrekey,
        local_prekey_secret: *const xwing.SecretKey,
        responder_prekey: SignedPrekey,
        cfg: Config,
    ) Session {
        return .{
            .allocator = allocator,
            .inner = .{ .initiator = hs.Initiator.init(allocator, local_node, local_prekey, local_prekey_secret, responder_prekey, cfg) },
        };
    }

    pub fn initResponder(
        allocator: std.mem.Allocator,
        local_node: *const sign.KeyPair,
        local_prekey: SignedPrekey,
        local_prekey_secret: *const xwing.SecretKey,
        cfg: Config,
    ) Session {
        return .{
            .allocator = allocator,
            .inner = .{ .responder = hs.Responder.init(allocator, local_node, local_prekey, local_prekey_secret, cfg) },
        };
    }

    pub fn deinit(self: *Session) void {
        if (self.init_est) |*e| e.deinit();
        switch (self.inner) {
            .initiator => |*i| i.deinit(),
            .responder => |*r| r.deinit(),
        }
        self.* = undefined;
    }

    /// Initiator only: produce the first handshake message (M1). Caller frees.
    pub fn open(self: *Session, rng: std.Io) Error![]u8 {
        return switch (self.inner) {
            .initiator => |*i| i.start(rng),
            .responder => error.InvalidState,
        };
    }

    /// Feed an inbound handshake message.
    ///   * responder: receives M1, returns M2 (caller frees) and establishes.
    ///   * initiator: receives M2, returns null and establishes.
    /// On establishment the canonical peer id is captured and bridged.
    pub fn feed(self: *Session, bytes: []const u8, rng: std.Io) Error!?[]u8 {
        switch (self.inner) {
            .responder => |*r| {
                const m2 = try r.recv(bytes, rng);
                if (r.established) |est| self.markDone(est.peer_node_id);
                return m2;
            },
            .initiator => |*i| {
                const est = try i.recv(bytes);
                self.init_est = est;
                self.markDone(est.peer_node_id);
                return null;
            },
        }
    }

    fn markDone(self: *Session, peer: NodeId) void {
        self.peer_short = node_short_id.shortId(peer);
        self.done = true;
    }

    pub fn isEstablished(self: *const Session) bool {
        return self.done;
    }

    /// The authenticated 20-byte canonical peer identity (null before establish).
    pub fn peerNodeId(self: *const Session) ?NodeId {
        if (!self.done) return null;
        return switch (self.inner) {
            .initiator => if (self.init_est) |e| e.peer_node_id else null,
            .responder => |r| if (r.established) |e| e.peer_node_id else null,
        };
    }

    /// The peer's authenticated raw Ed25519 signing public key (null before
    /// establish). Verifies peer-signed artifacts such as cross-mesh oper grants.
    pub fn peerNodeKey(self: *const Session) ?[32]u8 {
        if (!self.done) return null;
        const est = switch (self.inner) {
            .initiator => if (self.init_est) |*e| e else null,
            .responder => |*r| if (r.established) |*e| e else null,
        } orelse return null;
        return est.peer_node_key;
    }

    /// The u64 mesh routing handle for the peer — pass as `S2sPeer.remote_node_id`.
    pub fn peerShortId(self: *const Session) ?u64 {
        if (!self.done) return null;
        return self.peer_short;
    }

    /// The established directional keys for the post-handshake secure channel.
    pub fn established(self: *const Session) ?*const Established {
        return switch (self.inner) {
            .initiator => if (self.init_est) |*e| e else null,
            .responder => |*r| if (r.established) |*e| e else null,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Deterministic randomness for handshake KEM (mirrors mooring_handshake tests).
const DeterministicIo = struct {
    s: u64,
    fn io(self: *DeterministicIo) std.Io {
        return .{ .userdata = self, .vtable = &vtable };
    }
    fn random(userdata: ?*anyopaque, buffer: []u8) void {
        var self: *DeterministicIo = @ptrCast(@alignCast(userdata.?));
        for (buffer) |*b| {
            self.s = self.s *% 6364136223846793005 +% 1442695040888963407;
            b.* = @truncate(self.s >> 56);
        }
    }
    const vtable: std.Io.VTable = blk: {
        var vt = std.Io.failing.vtable.*;
        vt.random = random;
        break :blk vt;
    };
};

const Fixture = struct {
    i_node: sign.KeyPair,
    r_node: sign.KeyPair,
    i_kem: xwing.KeyPair,
    r_kem: xwing.KeyPair,
    i_pre: SignedPrekey,
    r_pre: SignedPrekey,
    cfg: Config,

    cfg_r: Config,

    fn make(_: std.mem.Allocator) !Fixture {
        const realm: hs.RealmId = @splat(0xA1);
        const bands: u128 = 0b1111;
        const features: u128 = 0b101;
        const i_node = try sign.KeyPair.fromSeed(@as([32]u8, @splat(0x11)));
        const r_node = try sign.KeyPair.fromSeed(@as([32]u8, @splat(0x22)));
        const i_kem = try xwing.KeyPair.generateDeterministic(@as([32]u8, @splat(0x33)));
        const r_kem = try xwing.KeyPair.generateDeterministic(@as([32]u8, @splat(0x44)));
        const i_pre = try SignedPrekey.create(&i_node, &i_kem, realm, 1, 10, 1000, 1, bands, features);
        const r_pre = try SignedPrekey.create(&r_node, &r_kem, realm, 2, 10, 1000, 1, bands, features);
        return .{
            .i_node = i_node,
            .r_node = r_node,
            .i_kem = i_kem,
            .r_kem = r_kem,
            .i_pre = i_pre,
            .r_pre = r_pre,
            .cfg = .{ .realm = realm, .supported_bands = bands, .supported_features = features, .mesh_pass = "meshpass secret", .now_ms = 20 },
            .cfg_r = .{ .realm = realm, .supported_bands = bands, .supported_features = features, .now_ms = 20 },
        };
    }

    fn deinit(self: *Fixture) void {
        self.i_node.deinit();
        self.r_node.deinit();
        self.i_kem.wipe();
        self.r_kem.wipe();
    }
};

test "session drives the AKE and both sides bridge to matching short ids" {
    const allocator = testing.allocator;
    var fx = try Fixture.make(allocator);
    defer fx.deinit();

    var rng = DeterministicIo{ .s = 0x1234 };
    var initiator = Session.initInitiator(allocator, &fx.i_node, fx.i_pre, &fx.i_kem.secret_key, fx.r_pre, fx.cfg);
    defer initiator.deinit();
    var responder = Session.initResponder(allocator, &fx.r_node, fx.r_pre, &fx.r_kem.secret_key, fx.cfg_r);
    defer responder.deinit();

    try testing.expect(!initiator.isEstablished());

    const m1 = try initiator.open(rng.io());
    defer allocator.free(m1);
    const m2 = (try responder.feed(m1, rng.io())).?;
    defer allocator.free(m2);
    const none = try initiator.feed(m2, rng.io());
    try testing.expect(none == null);

    try testing.expect(initiator.isEstablished());
    try testing.expect(responder.isEstablished());

    // Each side learned the OTHER's canonical id, and the bridged u64 matches the
    // direct derivation from the prekey id — the value S2sPeer will key on.
    try testing.expectEqualSlices(u8, &fx.r_pre.node_id, &initiator.peerNodeId().?);
    try testing.expectEqualSlices(u8, &fx.i_pre.node_id, &responder.peerNodeId().?);
    try testing.expectEqual(node_short_id.shortId(fx.r_pre.node_id), initiator.peerShortId().?);
    try testing.expectEqual(node_short_id.shortId(fx.i_pre.node_id), responder.peerShortId().?);
}

test "established keys are crossed (initiator send == responder recv)" {
    const allocator = testing.allocator;
    var fx = try Fixture.make(allocator);
    defer fx.deinit();

    var rng = DeterministicIo{ .s = 0xABCD };
    var initiator = Session.initInitiator(allocator, &fx.i_node, fx.i_pre, &fx.i_kem.secret_key, fx.r_pre, fx.cfg);
    defer initiator.deinit();
    var responder = Session.initResponder(allocator, &fx.r_node, fx.r_pre, &fx.r_kem.secret_key, fx.cfg_r);
    defer responder.deinit();

    const m1 = try initiator.open(rng.io());
    defer allocator.free(m1);
    const m2 = (try responder.feed(m1, rng.io())).?;
    defer allocator.free(m2);
    _ = try initiator.feed(m2, rng.io());

    const ei = initiator.established().?;
    const er = responder.established().?;
    try testing.expectEqualSlices(u8, &ei.send_key.declassify(), &er.recv_key.declassify());
    try testing.expectEqualSlices(u8, &ei.recv_key.declassify(), &er.send_key.declassify());
}

test "calling open on a responder is rejected" {
    const allocator = testing.allocator;
    var fx = try Fixture.make(allocator);
    defer fx.deinit();
    var rng = DeterministicIo{ .s = 0x1 };
    var responder = Session.initResponder(allocator, &fx.r_node, fx.r_pre, &fx.r_kem.secret_key, fx.cfg_r);
    defer responder.deinit();
    try testing.expectError(error.InvalidState, responder.open(rng.io()));
}

test "a tampered M2 fails the initiator and leaves it unestablished" {
    const allocator = testing.allocator;
    var fx = try Fixture.make(allocator);
    defer fx.deinit();

    var rng = DeterministicIo{ .s = 0x9 };
    var initiator = Session.initInitiator(allocator, &fx.i_node, fx.i_pre, &fx.i_kem.secret_key, fx.r_pre, fx.cfg);
    defer initiator.deinit();
    var responder = Session.initResponder(allocator, &fx.r_node, fx.r_pre, &fx.r_kem.secret_key, fx.cfg_r);
    defer responder.deinit();

    const m1 = try initiator.open(rng.io());
    defer allocator.free(m1);
    const m2 = (try responder.feed(m1, rng.io())).?;
    defer allocator.free(m2);
    m2[m2.len - 1] ^= 1;
    try testing.expectError(error.AuthFailed, initiator.feed(m2, rng.io()));
    try testing.expect(!initiator.isEstablished());
    try testing.expect(initiator.peerShortId() == null);
}
