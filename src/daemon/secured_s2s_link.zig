//! Framed secured S2S link: the live-path Tsumugi handshake over a byte stream.
//!
//! `tsumugi_session` drives the AKE message-at-a-time; on a real TCP stream the
//! TOFU preamble, M1, and M2 must be delimited so they survive coalescing and
//! splitting. This adapter length-prefixes ONLY those three handshake messages
//! (u32 LE length + payload, reassembled through an inbound buffer); once the AKE
//! establishes it hands off to the inner `S2sLink`, whose own `s2s_frame` decoder
//! already frames the CRDT stream — so post-handshake bytes pass through raw, with
//! no double-framing.
//!
//! TOFU bootstrap (decision: trust-on-first-use): the responder announces its
//! signed prekey as the preamble; the initiator verifies the signature + validity
//! window and adopts the node id (optionally pinned via `expected_remote`), then
//! runs Noise-IK. Identity keypairs/prekeys are borrowed — keep them alive.
const std = @import("std");

const node_identity = @import("node_identity.zig");
const tsumugi_session = @import("../crypto/tsumugi_session.zig");
const hs = @import("../crypto/tsumugi_handshake.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const s2s_link = @import("s2s_link.zig");
const s2s_peer = @import("../substrate/suimyaku/s2s_peer.zig");
const partition_detector = @import("../substrate/suimyaku/partition_detector.zig");

pub const Role = tsumugi_session.Role;

/// Bound on a single buffered handshake message (prekey ~1.3KB, M1/M2 a few KB).
const max_handshake_msg: u32 = 64 * 1024;

/// Named errors this adapter raises (it also surfaces handshake, allocation, and
/// inner-link errors; the methods use `anyerror` to carry the union).
pub const HandshakeError = error{ HandshakeTooLarge, PrekeyRejected, UnexpectedRemote };

pub const Options = struct {
    allocator: std.mem.Allocator,
    role: Role,
    /// Borrowed local identity (provides the static + KEM keys and realm).
    identity: *const node_identity.NodeIdentity,
    /// This node's signed prekey (build via `identity.signedPrekey(...)`).
    local_prekey: hs.SignedPrekey,
    cfg: hs.Config,
    rng: std.Io,
    server_name: []const u8,
    /// Human description of THIS node, gossiped to the peer in the CRDT handshake
    /// so remote WHOIS (312) names the right per-server description. Empty = none.
    description: []const u8 = "",
    local_epoch_ms: u64 = 1000,
    channel_name: []const u8 = "#suimyaku",
    /// Optional trust pin: require the peer's node id to equal this. Null = TOFU.
    expected_remote: ?[20]u8 = null,
};

const Phase = enum { await_prekey, ake, established };

pub const SecuredLink = struct {
    allocator: std.mem.Allocator,
    role: Role,
    identity: *const node_identity.NodeIdentity,
    local_prekey: hs.SignedPrekey,
    cfg: hs.Config,
    rng: std.Io,
    expected_remote: ?[20]u8,
    server_name: []const u8,
    description: []const u8,
    local_epoch_ms: u64,
    channel_name: []const u8,

    phase: Phase,
    session: ?tsumugi_session.Session = null,
    inner: ?*s2s_link.S2sLink = null,
    inbuf: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,
    feed_seq: u64 = 0,

    /// Initialize. The responder immediately queues its prekey preamble and stands
    /// up its session; the initiator waits for the responder's preamble.
    pub fn init(opts: Options) anyerror!SecuredLink {
        var self = SecuredLink{
            .allocator = opts.allocator,
            .role = opts.role,
            .identity = opts.identity,
            .local_prekey = opts.local_prekey,
            .cfg = opts.cfg,
            .rng = opts.rng,
            .expected_remote = opts.expected_remote,
            .server_name = opts.server_name,
            .description = opts.description,
            .local_epoch_ms = opts.local_epoch_ms,
            .channel_name = opts.channel_name,
            .phase = if (opts.role == .responder) .ake else .await_prekey,
        };
        if (opts.role == .responder) {
            self.session = tsumugi_session.Session.initResponder(
                opts.allocator,
                &opts.identity.sign_kp,
                opts.local_prekey,
                &opts.identity.kem_kp.secret_key,
                opts.cfg,
            );
            // Preamble: announce our signed prekey so the initiator can run IK.
            const wire = try hs.encodeSignedPrekey(opts.allocator, &opts.local_prekey);
            defer opts.allocator.free(wire);
            try self.writeFramed(wire);
        }
        return self;
    }

    pub fn deinit(self: *SecuredLink) void {
        if (self.session) |*s| s.deinit();
        if (self.inner) |l| {
            l.deinit();
            self.allocator.destroy(l);
        }
        self.inbuf.deinit(self.allocator);
        self.out.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn outbound(self: *const SecuredLink) []const u8 {
        return self.out.items;
    }
    pub fn clearOutbound(self: *SecuredLink) void {
        self.out.clearRetainingCapacity();
    }
    pub fn established(self: *const SecuredLink) bool {
        return if (self.inner) |l| l.established() else false;
    }
    pub fn peerShortId(self: *const SecuredLink) ?u64 {
        return if (self.session) |s| s.peerShortId() else null;
    }

    /// The peer's authenticated raw Ed25519 signing public key (null before the
    /// AKE establishes). Verifies peer-signed cross-mesh operator grants.
    pub fn peerNodeKey(self: *const SecuredLink) ?[32]u8 {
        return if (self.session) |s| s.peerNodeKey() else null;
    }
    pub fn channelMembers(self: *const SecuredLink, channel: []const u8) []const s2s_peer.MemberInfo {
        return if (self.inner) |l| l.channelMembers(channel) else &.{};
    }

    pub fn remoteName(self: *const SecuredLink) []const u8 {
        return if (self.inner) |l| l.remoteName() else "";
    }

    /// Which node (if known) owns `nick`, per this peer's route table.
    pub fn routeNickNode(self: *const SecuredLink, nick: []const u8) ?u64 {
        return if (self.inner) |l| l.routeNickNode(nick) else null;
    }

    /// Find `nick` in this peer's converged remote channel rosters (ASCII
    /// case-insensitive). Borrowed; valid until the next membership mutation.
    pub fn findRemoteMember(self: *const SecuredLink, nick: []const u8) ?s2s_peer.MemberInfo {
        return if (self.inner) |l| l.findRemoteMember(nick) else null;
    }

    /// Server name registered for `node` (handshake or gossiped registry).
    pub fn nodeName(self: *const SecuredLink, node: u64) ?[]const u8 {
        return if (self.inner) |l| l.nodeName(node) else null;
    }

    /// Server description registered for `node`, or null when unknown/empty.
    pub fn nodeDescription(self: *const SecuredLink, node: u64) ?[]const u8 {
        return if (self.inner) |l| l.nodeDescription(node) else null;
    }

    /// Announce a local member to the peer over the secured CRDT link (no-op until
    /// established), carrying the member's real username/realname/visible-host.
    /// Outbound bytes accumulate in `out`.
    pub fn sendMembership(self: *SecuredLink, channel: []const u8, nick: []const u8, status: u4, hlc: u64, present: bool, ident: s2s_peer.MemberIdentity) anyerror!void {
        const link = self.inner orelse return;
        try link.sendMembership(channel, nick, status, hlc, present, ident);
        try self.drainInner();
    }

    /// Announce aggregate local boolean MODE flags for `channel` over the
    /// secured CRDT link (no-op until established). Outbound bytes accumulate in
    /// `out`.
    pub fn sendChannelModeFlags(self: *SecuredLink, channel: []const u8, flags: u16, hlc: u64) anyerror!void {
        const link = self.inner orelse return;
        try link.sendChannelModeFlags(channel, flags, hlc);
        try self.drainInner();
    }

    /// Announce a local IRCX channel PROP set/delete over the secured CRDT link.
    /// Outbound bytes accumulate in `out`.
    pub fn sendChannelProp(
        self: *SecuredLink,
        channel: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
    ) anyerror!void {
        const link = self.inner orelse return;
        try link.sendChannelProp(channel, key, value, owner, hlc, present);
        try self.drainInner();
    }

    /// Forward a cross-node user message over the secured CRDT link.
    pub fn sendMessage(self: *SecuredLink, msg: s2s_link.RelayMessage) anyerror!void {
        const link = self.inner orelse return;
        try link.sendMessage(msg);
        try self.drainInner();
    }

    /// Drain inbound cross-node messages decoded by the inner link. Caller owns
    /// the slice + each Owned (deinit each, free the slice).
    pub fn takeInbound(self: *SecuredLink) anyerror![]s2s_peer.InboundMessage {
        const link = self.inner orelse return &.{};
        return link.takeInbound();
    }

    /// Drain remote channel membership changes (JOIN/PART) for the daemon to
    /// surface to local members. Caller owns the slice + each delta's strings.
    pub fn takeMembershipChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.MembershipDelta {
        const link = self.inner orelse return &.{};
        return link.takeMembershipChanges();
    }

    /// Drain remote channel MODE flag changes for the daemon to apply and
    /// surface to local members. Caller owns the slice + each delta's string.
    pub fn takeChannelModeFlagChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.ChannelModeFlagsDelta {
        const link = self.inner orelse return &.{};
        return link.takeChannelModeFlagChanges();
    }

    /// Announce a local channel list-mode (+b/+e/+I) change over the secured
    /// link. Outbound bytes accumulate in `out`.
    pub fn sendChannelList(
        self: *SecuredLink,
        channel: []const u8,
        kind: s2s_peer.S2sPeer.ChannelListDelta.Kind,
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) anyerror!void {
        const link = self.inner orelse return;
        try link.sendChannelList(channel, kind, mask, setter, set_at, hlc, present);
        try self.drainInner();
    }

    /// Drain remote channel list-mode changes decoded by the inner link.
    pub fn takeChannelListChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.ChannelListDelta {
        const link = self.inner orelse return &.{};
        return link.takeChannelListChanges();
    }

    /// Drain remote channel PROP changes for daemon-side LWW apply.
    pub fn takeChannelPropChanges(self: *SecuredLink) anyerror![]s2s_peer.S2sPeer.ChannelPropDelta {
        const link = self.inner orelse return &.{};
        return link.takeChannelPropChanges();
    }

    /// Forward a signed cross-mesh operator grant to the peer over the secured
    /// CRDT link (no-op until established). Outbound bytes accumulate in `out`.
    pub fn sendOperGrant(self: *SecuredLink, signed: []const u8) anyerror!void {
        const link = self.inner orelse return;
        try link.sendOperGrant(signed);
        try self.drainInner();
    }

    /// Drain queued inbound oper-grant payloads decoded by the inner link. Caller
    /// owns + frees each slice and the outer slice. Verify each against
    /// `peerNodeKey()` before trusting it.
    pub fn takeOperGrants(self: *SecuredLink) anyerror![][]u8 {
        const link = self.inner orelse return &.{};
        return link.takeOperGrants();
    }

    /// Copy this peer's known-server topology into `out` for partition analysis
    /// (empty until the inner CRDT link is established).
    pub fn collectTopology(self: *const SecuredLink, out: []partition_detector.TopoNode) usize {
        const link = self.inner orelse return 0;
        return link.collectTopology(out);
    }

    fn writeFramed(self: *SecuredLink, payload: []const u8) anyerror!void {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, @intCast(payload.len), .little);
        try self.out.appendSlice(self.allocator, &hdr);
        try self.out.appendSlice(self.allocator, payload);
    }

    /// Feed inbound stream bytes. Handshake messages are length-deframed; once
    /// established, bytes flow straight to the inner CRDT link.
    pub fn feed(self: *SecuredLink, bytes: []const u8, now_ms: u64) anyerror!void {
        if (self.phase == .established) {
            try self.feedInner(bytes, now_ms);
            return;
        }
        try self.inbuf.appendSlice(self.allocator, bytes);
        try self.drainHandshake(now_ms);
    }

    fn drainHandshake(self: *SecuredLink, now_ms: u64) anyerror!void {
        while (self.phase != .established) {
            if (self.inbuf.items.len < 4) return;
            const len = std.mem.readInt(u32, self.inbuf.items[0..4], .little);
            if (len > max_handshake_msg) return error.HandshakeTooLarge;
            if (self.inbuf.items.len < 4 + len) return; // wait for the rest
            const msg = self.inbuf.items[4 .. 4 + len];
            try self.processHandshake(msg, now_ms);
            // Consume the framed message.
            const consumed = 4 + len;
            const rest = self.inbuf.items.len - consumed;
            std.mem.copyForwards(u8, self.inbuf.items[0..rest], self.inbuf.items[consumed..]);
            self.inbuf.shrinkRetainingCapacity(rest);
        }
        // Established: any trailing bytes are the start of the raw CRDT stream.
        if (self.inbuf.items.len != 0) {
            const tail = try self.allocator.dupe(u8, self.inbuf.items);
            defer self.allocator.free(tail);
            self.inbuf.clearRetainingCapacity();
            try self.feedInner(tail, now_ms);
        }
    }

    fn processHandshake(self: *SecuredLink, msg: []const u8, now_ms: u64) anyerror!void {
        switch (self.phase) {
            .await_prekey => {
                // Initiator: verify + adopt the responder's announced prekey (TOFU).
                const remote_prekey = hs.decodeSignedPrekey(msg) catch return error.PrekeyRejected;
                remote_prekey.verify(self.cfg.now_ms) catch return error.PrekeyRejected;
                if (self.expected_remote) |want| {
                    if (!std.mem.eql(u8, &want, &remote_prekey.node_id)) return error.UnexpectedRemote;
                }
                self.session = tsumugi_session.Session.initInitiator(
                    self.allocator,
                    &self.identity.sign_kp,
                    self.local_prekey,
                    &self.identity.kem_kp.secret_key,
                    remote_prekey,
                    self.cfg,
                );
                const m1 = try self.session.?.open(self.rng);
                defer self.allocator.free(m1);
                try self.writeFramed(m1);
                self.phase = .ake;
            },
            .ake => {
                if (try self.session.?.feed(msg, self.rng)) |reply| {
                    defer self.allocator.free(reply);
                    try self.writeFramed(reply);
                }
                if (self.session.?.isEstablished()) try self.beginCrdt(now_ms);
            },
            .established => unreachable,
        }
    }

    fn beginCrdt(self: *SecuredLink, now_ms: u64) anyerror!void {
        const peer_short = self.session.?.peerShortId().?;
        const link = try self.allocator.create(s2s_link.S2sLink);
        errdefer self.allocator.destroy(link);
        try link.init(.{
            .allocator = self.allocator,
            .local_node_id = node_short_id.shortId(self.identity.node_id),
            .remote_node_id = peer_short,
            .local_epoch_ms = self.local_epoch_ms,
            .server_name = self.server_name,
            .description = self.description,
            .channel_name = self.channel_name,
            .now_ms = now_ms,
        });
        self.inner = link;
        self.phase = .established;
        if (self.role == .initiator) {
            try link.start(now_ms);
            try self.drainInner();
        }
    }

    fn feedInner(self: *SecuredLink, bytes: []const u8, now_ms: u64) anyerror!void {
        const link = self.inner.?;
        self.feed_seq +%= 1;
        try link.feed(bytes, now_ms, self.feed_seq);
        try self.drainInner();
    }

    fn drainInner(self: *SecuredLink) anyerror!void {
        const link = self.inner.?;
        const o = link.outbound();
        if (o.len != 0) {
            try self.out.appendSlice(self.allocator, o);
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

fn cfgFor(realm: [32]u8, mesh_pass: []const u8) hs.Config {
    return .{ .realm = realm, .supported_bands = 0b1111, .supported_features = 0b1, .mesh_pass = mesh_pass, .now_ms = 20 };
}

/// Pump two links, optionally splitting each transfer into 1-byte feeds to prove
/// the handshake framing survives arbitrary TCP fragmentation.
fn pump(a: *SecuredLink, b: *SecuredLink, split: bool) !void {
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
        if (a_copy.len != 0) try feedMaybeSplit(b, a_copy, now, split);
        if (b_copy.len != 0) try feedMaybeSplit(a, b_copy, now, split);
        now += 1;
    }
}

fn feedMaybeSplit(link: *SecuredLink, bytes: []const u8, now: u64, split: bool) !void {
    if (!split) {
        try link.feed(bytes, now);
        return;
    }
    for (bytes) |byte| try link.feed(&[_]u8{byte}, now);
}

fn runScenario(split: bool) !void {
    var ida = try node_identity.fromSeed([_]u8{0x11} ** 32, "local");
    defer ida.deinit();
    var idb = try node_identity.fromSeed([_]u8{0x22} ** 32, "local");
    defer idb.deinit();
    const pre_a = try ida.signedPrekey(1, 10, 1000, 0b1111, 0b1);
    const pre_b = try idb.signedPrekey(2, 10, 1000, 0b1111, 0b1);

    var rng = DeterministicIo{ .s = 0xABCDEF };

    var a = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .initiator,
        .identity = &ida,
        .local_prekey = pre_a,
        .cfg = cfgFor(ida.realm, "mp"),
        .rng = rng.io(),
        .server_name = "a.orochi",
    });
    defer a.deinit();
    var b = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .responder,
        .identity = &idb,
        .local_prekey = pre_b,
        .cfg = cfgFor(idb.realm, ""),
        .rng = rng.io(),
        .server_name = "b.orochi",
    });
    defer b.deinit();

    try pump(&a, &b, split);

    try testing.expect(a.established());
    try testing.expect(b.established());
    // TOFU: each side adopted the other's bridged identity.
    try testing.expectEqual(idb.shortId(), a.peerShortId().?);
    try testing.expectEqual(ida.shortId(), b.peerShortId().?);
    // Each side recovered the peer's authenticated raw Ed25519 sign key — the
    // key cross-mesh oper grants are verified against.
    try testing.expectEqualSlices(u8, &idb.sign_kp.public_key, &a.peerNodeKey().?);
    try testing.expectEqualSlices(u8, &ida.sign_kp.public_key, &b.peerNodeKey().?);
}

test "secured link: TOFU preamble + IK handshake + CRDT over a whole-buffer stream" {
    try runScenario(false);
}

test "secured link survives 1-byte fragmentation of every handshake message" {
    try runScenario(true);
}

test "a trust-pin mismatch rejects the peer prekey" {
    var ida = try node_identity.fromSeed([_]u8{0x11} ** 32, "local");
    defer ida.deinit();
    var idb = try node_identity.fromSeed([_]u8{0x22} ** 32, "local");
    defer idb.deinit();
    const pre_a = try ida.signedPrekey(1, 10, 1000, 0b1111, 0b1);
    const pre_b = try idb.signedPrekey(2, 10, 1000, 0b1111, 0b1);
    var rng = DeterministicIo{ .s = 1 };

    // Initiator pins a WRONG expected remote id.
    var a = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .initiator,
        .identity = &ida,
        .local_prekey = pre_a,
        .cfg = cfgFor(ida.realm, "mp"),
        .rng = rng.io(),
        .server_name = "a.orochi",
        .expected_remote = [_]u8{0xFF} ** 20,
    });
    defer a.deinit();
    var b = try SecuredLink.init(.{
        .allocator = testing.allocator,
        .role = .responder,
        .identity = &idb,
        .local_prekey = pre_b,
        .cfg = cfgFor(idb.realm, ""),
        .rng = rng.io(),
        .server_name = "b.orochi",
    });
    defer b.deinit();

    // Feed B's preamble to A -> A rejects on the pin mismatch.
    const preamble = try testing.allocator.dupe(u8, b.outbound());
    defer testing.allocator.free(preamble);
    try testing.expectError(error.UnexpectedRemote, a.feed(preamble, 1));
}
