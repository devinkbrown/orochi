//! Secure S2S link: Tsumugi PQ-hybrid handshake wrapping the Suimyaku CRDT peer.
//!
//! This is the composition the live server-to-server path uses, assembled from
//! three tested primitives:
//!
//!   1. `tsumugi_session` — the PQ-hybrid (X-Wing) authenticated key exchange.
//!      Both peers prove their Ed25519 identity and derive crossed AEAD keys.
//!   2. `node_short_id`    — bridges the authenticated 20-byte node id to the
//!      `u64` routing handle the CRDT/gossip layer keys on.
//!   3. `s2s_link`         — the reactor-independent CRDT convergence driver.
//!
//! It runs as a two-phase byte stream: AKE messages first, then — once both
//! sides are authenticated — the CRDT handshake/burst/gossip. The phase pivot is
//! clean because each AKE message is sent and answered in its own step (M1 then
//! M2), so AKE bytes never share a buffer with CRDT bytes. The identity bridge
//! guarantees both ends construct their inner `S2sLink` with consistent local /
//! remote short ids, so the inner plaintext node-id check matches.
//!
//! Keypairs/prekeys are borrowed (held by the AKE structs); keep them alive for
//! the link's lifetime.
const std = @import("std");

const tsumugi_session = @import("../crypto/tsumugi_session.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const sign = @import("../crypto/sign.zig");
const xwing = @import("../crypto/xwing.zig");
const s2s_link = @import("s2s_link.zig");

pub const Role = tsumugi_session.Role;
pub const SignedPrekey = tsumugi_session.SignedPrekey;
pub const Config = tsumugi_session.Config;
pub const Phase = enum { handshake, established };

pub const Options = struct {
    allocator: std.mem.Allocator,
    role: Role,
    // AKE inputs (passed through to tsumugi_session).
    local_node: *const sign.KeyPair,
    local_prekey: SignedPrekey,
    local_prekey_secret: *const xwing.SecretKey,
    responder_prekey: SignedPrekey = undefined, // initiator only
    cfg: Config,
    // Inner CRDT link identity (used after the AKE establishes).
    server_name: []const u8,
    local_epoch_ms: u64 = 1000,
    channel_name: []const u8 = "#suimyaku",
};

pub const SecureLink = struct {
    allocator: std.mem.Allocator,
    role: Role,
    session: tsumugi_session.Session,
    phase: Phase = .handshake,
    /// Inner CRDT link, constructed once the AKE establishes (heap-pinned: its
    /// clock captures its own address).
    link: ?*s2s_link.S2sLink = null,
    out: std.ArrayList(u8) = .empty,
    feed_seq: u64 = 0,
    // Held for deferred inner-link construction.
    local_short: u64,
    server_name: []const u8,
    local_epoch_ms: u64,
    channel_name: []const u8,

    pub fn init(opts: Options) SecureLink {
        const session = switch (opts.role) {
            .initiator => tsumugi_session.Session.initInitiator(
                opts.allocator,
                opts.local_node,
                opts.local_prekey,
                opts.local_prekey_secret,
                opts.responder_prekey,
                opts.cfg,
            ),
            .responder => tsumugi_session.Session.initResponder(
                opts.allocator,
                opts.local_node,
                opts.local_prekey,
                opts.local_prekey_secret,
                opts.cfg,
            ),
        };
        return .{
            .allocator = opts.allocator,
            .role = opts.role,
            .session = session,
            .local_short = node_short_id.shortId(opts.local_prekey.node_id),
            .server_name = opts.server_name,
            .local_epoch_ms = opts.local_epoch_ms,
            .channel_name = opts.channel_name,
        };
    }

    pub fn deinit(self: *SecureLink) void {
        self.session.deinit();
        if (self.link) |l| {
            l.deinit();
            self.allocator.destroy(l);
        }
        self.out.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isEstablished(self: *const SecureLink) bool {
        if (self.link) |l| return l.established();
        return false;
    }

    /// The authenticated peer's u64 routing handle (null before the AKE completes).
    pub fn peerShortId(self: *const SecureLink) ?u64 {
        return self.session.peerShortId();
    }

    /// Pending outbound bytes; copy to the wire then `clearOutbound`.
    pub fn outbound(self: *const SecureLink) []const u8 {
        return self.out.items;
    }

    pub fn clearOutbound(self: *SecureLink) void {
        self.out.clearRetainingCapacity();
    }

    fn knownServers(self: *const SecureLink) usize {
        return if (self.link) |l| l.knownServers() else 0;
    }

    /// Initiator only: produce the first AKE message (M1).
    pub fn open(self: *SecureLink, rng: std.Io) !void {
        const m1 = try self.session.open(rng);
        defer self.allocator.free(m1);
        try self.out.appendSlice(self.allocator, m1);
    }

    /// Feed inbound bytes. While in the handshake phase they drive the AKE; once
    /// the AKE establishes, the inner CRDT link is stood up and subsequent bytes
    /// are CRDT frames. `now_ms` is the caller's clock (the reactor's).
    pub fn feed(self: *SecureLink, bytes: []const u8, now_ms: u64, rng: std.Io) !void {
        switch (self.phase) {
            .handshake => {
                if (try self.session.feed(bytes, rng)) |reply| {
                    defer self.allocator.free(reply);
                    try self.out.appendSlice(self.allocator, reply);
                }
                if (self.session.isEstablished()) try self.beginCrdt(now_ms);
            },
            .established => {
                const link = self.link.?;
                self.feed_seq +%= 1;
                try link.feed(bytes, now_ms, self.feed_seq);
                try self.drainLink();
            },
        }
    }

    /// Construct the inner CRDT link with the bridged identities and, for the
    /// initiator, open its CRDT handshake. The responder waits for the inbound one.
    fn beginCrdt(self: *SecureLink, now_ms: u64) !void {
        const peer_short = self.session.peerShortId().?;
        const link = try self.allocator.create(s2s_link.S2sLink);
        errdefer self.allocator.destroy(link);
        try link.init(.{
            .allocator = self.allocator,
            .local_node_id = self.local_short,
            .remote_node_id = peer_short,
            .local_epoch_ms = self.local_epoch_ms,
            .server_name = self.server_name,
            .channel_name = self.channel_name,
            .now_ms = now_ms,
        });
        self.link = link;
        self.phase = .established;
        if (self.role == .initiator) {
            try link.start(now_ms);
            try self.drainLink();
        }
    }

    fn drainLink(self: *SecureLink) !void {
        const link = self.link.?;
        const out = link.outbound();
        if (out.len != 0) {
            try self.out.appendSlice(self.allocator, out);
            link.clearOutbound();
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

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
    cfg_i: Config,
    cfg_r: Config,

    fn make() !Fixture {
        const r: [32]u8 = [_]u8{0xA1} ** 32;
        const bands: u128 = 0b1111;
        const features: u128 = 0b101;
        const i_node = try sign.KeyPair.fromSeed([_]u8{0x11} ** 32);
        const r_node = try sign.KeyPair.fromSeed([_]u8{0x22} ** 32);
        const i_kem = try xwing.KeyPair.generateDeterministic([_]u8{0x33} ** 32);
        const r_kem = try xwing.KeyPair.generateDeterministic([_]u8{0x44} ** 32);
        const i_pre = try SignedPrekey.create(&i_node, &i_kem, r, 1, 10, 1000, 1, bands, features);
        const r_pre = try SignedPrekey.create(&r_node, &r_kem, r, 2, 10, 1000, 1, bands, features);
        return .{
            .i_node = i_node,
            .r_node = r_node,
            .i_kem = i_kem,
            .r_kem = r_kem,
            .i_pre = i_pre,
            .r_pre = r_pre,
            .cfg_i = .{ .realm = r, .supported_bands = bands, .supported_features = features, .mesh_pass = "mp", .now_ms = 20 },
            .cfg_r = .{ .realm = r, .supported_bands = bands, .supported_features = features, .now_ms = 20 },
        };
    }

    fn deinit(self: *Fixture) void {
        self.i_node.deinit();
        self.r_node.deinit();
        self.i_kem.wipe();
        self.r_kem.wipe();
    }
};

/// Pump two secure links back and forth (loopback) until both quiesce.
fn pump(a: *SecureLink, b: *SecureLink, rng: std.Io) !void {
    var now: u64 = 1;
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try testing.allocator.dupe(u8, a_out);
        defer testing.allocator.free(a_copy);
        const b_copy = try testing.allocator.dupe(u8, b_out);
        defer testing.allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, rng);
        if (b_copy.len != 0) try a.feed(b_copy, now, rng);
        now += 1;
    }
}

test "secure link: AKE authenticates, bridges identity, then CRDT converges" {
    var fx = try Fixture.make();
    defer fx.deinit();
    var rng = DeterministicIo{ .s = 0x5ECC };

    var a = SecureLink.init(.{
        .allocator = testing.allocator,
        .role = .initiator,
        .local_node = &fx.i_node,
        .local_prekey = fx.i_pre,
        .local_prekey_secret = &fx.i_kem.secret_key,
        .responder_prekey = fx.r_pre,
        .cfg = fx.cfg_i,
        .server_name = "a.mizuchi",
    });
    defer a.deinit();
    var b = SecureLink.init(.{
        .allocator = testing.allocator,
        .role = .responder,
        .local_node = &fx.r_node,
        .local_prekey = fx.r_pre,
        .local_prekey_secret = &fx.r_kem.secret_key,
        .cfg = fx.cfg_r,
        .server_name = "b.mizuchi",
    });
    defer b.deinit();

    try a.open(rng.io());
    try pump(&a, &b, rng.io());

    // The AKE bridged each side to the other's u64 handle...
    try testing.expectEqual(node_short_id.shortId(fx.r_pre.node_id), a.peerShortId().?);
    try testing.expectEqual(node_short_id.shortId(fx.i_pre.node_id), b.peerShortId().?);
    // ...and the inner CRDT link then handshook + converged over the secured link.
    try testing.expect(a.isEstablished());
    try testing.expect(b.isEstablished());
    try testing.expect(a.knownServers() >= 2);
    try testing.expect(b.knownServers() >= 2);
}

test "secure link stays unestablished if the AKE never starts" {
    var fx = try Fixture.make();
    defer fx.deinit();
    var b = SecureLink.init(.{
        .allocator = testing.allocator,
        .role = .responder,
        .local_node = &fx.r_node,
        .local_prekey = fx.r_pre,
        .local_prekey_secret = &fx.r_kem.secret_key,
        .cfg = fx.cfg_r,
        .server_name = "b.mizuchi",
    });
    defer b.deinit();
    try testing.expect(!b.isEstablished());
    try testing.expect(b.peerShortId() == null);
}
