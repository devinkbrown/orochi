//! Reactor-independent buffering adapter around `s2s_peer.S2sPeer`.
//!
//! `s2s_peer` is a pure server-to-server connection driver that emits outbound
//! bytes through a `ByteSink` callback and consumes a caller-supplied clock/rng.
//! The io_uring reactor, however, speaks in *buffers*: a recv completion hands
//! us inbound bytes, and a send completion drains an outbound buffer. `S2sLink`
//! bridges the two — it owns the per-peer CRDT state, a monotonic `now_ms` cell
//! the driver's clock reads, and a growable outbound buffer the sink appends to.
//!
//! Lifecycle (in-place, because the driver's clock holds a pointer to this
//! struct's `now_ms` field, which must stay at a stable address):
//!   var link: S2sLink = undefined;
//!   try link.init(allocator, opts);
//!   defer link.deinit();
//!   try link.start(now_ms);          // local side opens the handshake
//!   try link.feed(inbound, now, rng) // drive on each recv
//!   const out = link.outbound();     // send these bytes, then link.clearOutbound()
const std = @import("std");

const s2s_peer = @import("../substrate/suimyaku/s2s_peer.zig");
const partition_detector = @import("../substrate/suimyaku/partition_detector.zig");

/// Cross-node relay message types (re-exported at module scope for the daemon).
pub const RelayMessage = s2s_peer.RelayMessage;
pub const RelayVerb = s2s_peer.RelayVerb;
const channel_crdt = @import("../substrate/suimyaku/channel_crdt.zig");
const peer_link = @import("../substrate/suimyaku/peer_link.zig");

pub const NodeId = s2s_peer.NodeId;
pub const ChannelCrdt = s2s_peer.ChannelCrdt;

/// Caller-supplied identity/config for one S2S link. The sovereign node_id is the
/// single mesh identity (no legacy server-id): it keys the registry and is the
/// CRDT replica lane.
pub const Options = struct {
    allocator: std.mem.Allocator,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    local_epoch_ms: u64,
    server_name: []const u8,
    description: []const u8 = "",
    channel_name: []const u8 = "#suimyaku",
    now_ms: u64 = 0,
};

pub const S2sLink = struct {
    allocator: std.mem.Allocator,
    /// Monotonic clock cell read by the driver's `peer_link.Clock`. Stable
    /// address required: the clock captures `&self`.
    now_ms: u64,
    /// Per-peer convergent channel state (heap-owned; the driver borrows it).
    state: *ChannelCrdt,
    peer: s2s_peer.S2sPeer,
    /// Bytes the driver wants written to the wire, awaiting the send path.
    out: std.ArrayList(u8) = .empty,

    fn clockNow(ptr: *anyopaque) u64 {
        const self: *S2sLink = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn sinkWrite(ptr: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *S2sLink = @ptrCast(@alignCast(ptr));
        try self.out.appendSlice(self.allocator, bytes);
    }

    fn sink(self: *S2sLink) s2s_peer.ByteSink {
        return .{ .ptr = self, .write_fn = sinkWrite };
    }

    /// Initialize in place. `self` must already live at its final address.
    pub fn init(self: *S2sLink, opts: Options) !void {
        self.* = .{
            .allocator = opts.allocator,
            .now_ms = opts.now_ms,
            .state = undefined,
            .peer = undefined,
            .out = .empty,
        };
        const state = try opts.allocator.create(ChannelCrdt);
        errdefer opts.allocator.destroy(state);
        // The CRDT replica lane is the sovereign node id (ReplicaId is u64).
        state.* = ChannelCrdt.init(opts.allocator, opts.local_node_id);
        errdefer state.deinit();
        self.state = state;

        self.peer = try s2s_peer.S2sPeer.init(.{
            .allocator = opts.allocator,
            .state = state,
            .clock = .{ .ptr = self, .now_fn = clockNow },
            .local_node_id = opts.local_node_id,
            .remote_node_id = opts.remote_node_id,
            .local_epoch_ms = opts.local_epoch_ms,
            .server_name = opts.server_name,
            .description = opts.description,
            .channel_name = opts.channel_name,
        });
    }

    pub fn deinit(self: *S2sLink) void {
        self.peer.deinit();
        self.state.deinit();
        self.allocator.destroy(self.state);
        self.out.deinit(self.allocator);
        self.* = undefined;
    }

    /// Open the handshake from the local side (the connecting peer calls this).
    pub fn start(self: *S2sLink, now_ms: u64) !void {
        self.now_ms = now_ms;
        try self.peer.startHandshake(self.sink());
    }

    /// Drive the link with inbound bytes; outbound frames accumulate in `out`.
    pub fn feed(self: *S2sLink, bytes: []const u8, now_ms: u64, rng_seed: u64) !void {
        self.now_ms = now_ms;
        try self.peer.feed(bytes, self.sink(), now_ms, rng_seed);
    }

    /// Emit a PING with `payload` (heartbeat / liveness probe).
    pub fn ping(self: *S2sLink, payload: []const u8, now_ms: u64) !void {
        self.now_ms = now_ms;
        try self.peer.sendPing(payload, self.sink());
    }

    /// Pending outbound bytes; copy to the wire, then call `clearOutbound`.
    pub fn outbound(self: *const S2sLink) []const u8 {
        return self.out.items;
    }

    /// Drop the first `n` outbound bytes (a partial send) or all of them.
    pub fn consumeOutbound(self: *S2sLink, n: usize) void {
        const take = @min(n, self.out.items.len);
        const rest = self.out.items.len - take;
        std.mem.copyForwards(u8, self.out.items[0..rest], self.out.items[take..]);
        self.out.shrinkRetainingCapacity(rest);
    }

    pub fn clearOutbound(self: *S2sLink) void {
        self.out.clearRetainingCapacity();
    }

    pub fn established(self: *const S2sLink) bool {
        return self.peer.linkState() == .established;
    }

    /// Which remote node currently owns `nick`, per the route table.
    pub fn routeNickNode(self: *const S2sLink, nick: []const u8) ?NodeId {
        return self.peer.routeNickNode(nick);
    }

    /// Find `nick` in this peer's converged remote channel rosters (ASCII
    /// case-insensitive). Borrowed; valid until the next membership mutation.
    pub fn findRemoteMember(self: *const S2sLink, nick: []const u8) ?s2s_peer.MemberInfo {
        return self.peer.findRemoteMember(nick);
    }

    /// Server name registered for `node` (handshake or gossiped registry).
    pub fn nodeName(self: *const S2sLink, node: NodeId) ?[]const u8 {
        return self.peer.nodeName(node);
    }

    /// Server description registered for `node`, or null when unknown/empty.
    pub fn nodeDescription(self: *const S2sLink, node: NodeId) ?[]const u8 {
        return self.peer.nodeDescription(node);
    }

    /// The remote server's name once the handshake has been processed (empty
    /// before establishment).
    pub fn remoteName(self: *const S2sLink) []const u8 {
        return self.peer.remoteName();
    }

    /// The remote node id once learned from the handshake (null before).
    pub fn remoteNodeId(self: *const S2sLink) ?NodeId {
        return self.peer.remoteNodeId();
    }

    pub fn knownServers(self: *const S2sLink) usize {
        return self.peer.registryCount();
    }

    /// Announce a local member's presence/departure in `channel` to the peer.
    /// Outbound frames accumulate in `out`. Best-effort: only meaningful once the
    /// link is established.
    pub fn sendMembership(
        self: *S2sLink,
        channel: []const u8,
        nick: []const u8,
        status: u4,
        hlc: u64,
        present: bool,
    ) !void {
        try self.peer.sendMembership(self.sink(), channel, nick, status, hlc, present);
    }

    /// Announce a local IRCX channel PROP set/delete to the peer.
    /// Outbound frames accumulate in `out`.
    pub fn sendChannelProp(
        self: *S2sLink,
        channel: []const u8,
        key: []const u8,
        value: []const u8,
        owner: []const u8,
        hlc: u64,
        present: bool,
    ) !void {
        try self.peer.sendChannelProp(self.sink(), channel, key, value, owner, hlc, present);
    }

    /// Remote members the peer has announced for `channel` (borrowed roster).
    pub fn channelMembers(self: *const S2sLink, channel: []const u8) []const s2s_peer.MemberInfo {
        return self.peer.channelMembers(channel);
    }

    pub const RelayMessage = s2s_peer.RelayMessage;
    pub const RelayVerb = s2s_peer.RelayVerb;

    /// Forward a cross-node user message (PRIVMSG/NOTICE/TAGMSG) to the peer.
    pub fn sendMessage(self: *S2sLink, msg: s2s_peer.RelayMessage) !void {
        try self.peer.sendMessage(self.sink(), msg);
    }

    /// Drain inbound cross-node messages decoded from this peer. Caller owns the
    /// returned slice + each Owned (deinit each, free the slice).
    pub fn takeInbound(self: *S2sLink) ![]s2s_peer.InboundMessage {
        return self.peer.takeInbound();
    }

    /// Drain remote channel membership changes (JOIN/PART) the daemon should
    /// surface to local members. Caller owns the slice + each delta's strings.
    pub fn takeMembershipChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.MembershipDelta {
        return self.peer.takeMembershipChanges();
    }

    /// Announce aggregate local boolean MODE flags for `channel` to the peer.
    /// Outbound frames accumulate in `out`.
    pub fn sendChannelModeFlags(self: *S2sLink, channel: []const u8, flags: u16, hlc: u64) !void {
        try self.peer.sendChannelModeFlags(self.sink(), channel, flags, hlc);
    }

    /// Drain remote channel MODE flag changes the daemon should apply and
    /// surface to local members.
    pub fn takeChannelModeFlagChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.ChannelModeFlagsDelta {
        return self.peer.takeChannelModeFlagChanges();
    }

    /// Announce a local channel list-mode (+b/+e/+I) change to the peer.
    pub fn sendChannelList(
        self: *S2sLink,
        channel: []const u8,
        kind: s2s_peer.S2sPeer.ChannelListDelta.Kind,
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
        hlc: u64,
        present: bool,
    ) !void {
        try self.peer.sendChannelList(self.sink(), channel, kind, mask, setter, set_at, hlc, present);
    }

    /// Drain remote channel list-mode changes (+b/+e/+I) the daemon should apply
    /// to local world state and surface as MODE lines.
    pub fn takeChannelListChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.ChannelListDelta {
        return self.peer.takeChannelListChanges();
    }

    /// Drain remote channel PROP changes for daemon-side LWW apply. Caller owns
    /// the slice + each delta's strings.
    pub fn takeChannelPropChanges(self: *S2sLink) ![]s2s_peer.S2sPeer.ChannelPropDelta {
        return self.peer.takeChannelPropChanges();
    }

    /// Forward a signed cross-mesh operator grant to the peer (best-effort; only
    /// meaningful once established). `signed` is opaque `oper_cred_share` bytes.
    pub fn sendOperGrant(self: *S2sLink, signed: []const u8) !void {
        try self.peer.sendOperGrant(self.sink(), signed);
    }

    /// Drain queued inbound oper-grant payloads decoded from this peer. Caller
    /// owns + frees each slice and the outer slice.
    pub fn takeOperGrants(self: *S2sLink) ![][]u8 {
        return self.peer.takeOperGrants();
    }

    /// Copy this peer's known-server topology into `out` for partition analysis.
    pub fn collectTopology(self: *const S2sLink, out: []partition_detector.TopoNode) usize {
        return self.peer.collectTopology(out);
    }
};

test "two links handshake and converge over a byte loopback" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{
        .allocator = allocator,
        .local_node_id = 1,
        .remote_node_id = 2,
        .local_epoch_ms = 1000,
        .server_name = "a.orochi",
    });
    defer a.deinit();

    var b: S2sLink = undefined;
    try b.init(.{
        .allocator = allocator,
        .local_node_id = 2,
        .remote_node_id = 1,
        .local_epoch_ms = 1001,
        .server_name = "b.orochi",
    });
    defer b.deinit();

    // A opens the handshake; pump bytes back and forth until both quiesce.
    try a.start(10);
    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;

        // Snapshot each side's output, clear, then feed to the other.
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();

        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    try std.testing.expect(a.established());
    try std.testing.expect(b.established());
    // Each side learned the other server through the registry burst.
    try std.testing.expect(a.knownServers() >= 2);
    try std.testing.expect(b.knownServers() >= 2);
}

test "MEMBERSHIP propagates a member across the link into channelMembers" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.orochi" });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.orochi" });
    defer b.deinit();

    // Establish, then A announces alice (op) on #chat; pump to B.
    try a.start(10);
    var now: u64 = 11;
    try a.sendMembership("#chat", "alice", 0b0010, 100, true); // op bit
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    // B now sees alice on #chat as a remote member homed on node 1, with op status.
    const members = b.channelMembers("#chat");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("alice", members[0].nick);
    try std.testing.expectEqual(@as(u64, 1), members[0].node);
    try std.testing.expectEqual(@as(u4, 0b0010), members[0].status);

    // A part removes her on B too.
    try a.sendMembership("#chat", "alice", 0, 101, false);
    rounds = 0;
    while (rounds < 16) : (rounds += 1) {
        const a_out = a.outbound();
        if (a_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        a.clearOutbound();
        try b.feed(a_copy, now, 7);
        now += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), b.channelMembers("#chat").len);
}

test "CHANNEL_MODE_FLAGS propagates aggregate flag state across the link" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.orochi" });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.orochi" });
    defer b.deinit();

    try a.start(10);
    var now: u64 = 11;
    try a.sendChannelModeFlags("#chat", 0b1011, 100);
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeChannelModeFlagChanges();
    defer {
        for (changes) |*ch| ch.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 1), changes.len);
    try std.testing.expectEqualStrings("#chat", changes[0].channel);
    try std.testing.expectEqual(@as(u16, 0b1011), changes[0].flags);

    try a.sendChannelModeFlags("#chat", 0b0101, 99); // stale
    rounds = 0;
    while (rounds < 16) : (rounds += 1) {
        const a_out = a.outbound();
        if (a_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        a.clearOutbound();
        try b.feed(a_copy, now, 7);
        now += 1;
    }
    const stale = try b.takeChannelModeFlagChanges();
    defer allocator.free(stale);
    try std.testing.expectEqual(@as(usize, 0), stale.len);
}

test "CHANNEL_PROP payload round-trips across the link into takeChannelPropChanges" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.orochi" });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.orochi" });
    defer b.deinit();

    try a.start(10);
    try a.sendChannelProp("#chat", "TOPIC", "hello mesh", "alice", 100, true);
    try a.sendChannelProp("#chat", "SUBJECT", "", "alice", 101, false);

    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const changes = try b.takeChannelPropChanges();
    defer {
        for (changes) |*ch| ch.deinit(allocator);
        allocator.free(changes);
    }
    try std.testing.expectEqual(@as(usize, 2), changes.len);
    try std.testing.expect(changes[0].present);
    try std.testing.expectEqual(@as(u64, 100), changes[0].hlc);
    try std.testing.expectEqualStrings("#chat", changes[0].channel);
    try std.testing.expectEqualStrings("TOPIC", changes[0].key);
    try std.testing.expectEqualStrings("hello mesh", changes[0].value);
    try std.testing.expectEqualStrings("alice", changes[0].owner);
    try std.testing.expect(!changes[1].present);
    try std.testing.expectEqualStrings("SUBJECT", changes[1].key);
}

test "OPER_GRANT payload round-trips across the link into takeOperGrants" {
    const allocator = std.testing.allocator;

    var a: S2sLink = undefined;
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.orochi" });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.orochi" });
    defer b.deinit();

    // Establish, then A sends an opaque signed grant blob; pump to B.
    try a.start(10);
    const grant = "signed-oper-grant-bytes-opaque-to-the-link";
    try a.sendOperGrant(grant);
    var now: u64 = 11;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        const a_out = a.outbound();
        const b_out = b.outbound();
        if (a_out.len == 0 and b_out.len == 0) break;
        const a_copy = try allocator.dupe(u8, a_out);
        defer allocator.free(a_copy);
        const b_copy = try allocator.dupe(u8, b_out);
        defer allocator.free(b_copy);
        a.clearOutbound();
        b.clearOutbound();
        if (a_copy.len != 0) try b.feed(a_copy, now, 7);
        if (b_copy.len != 0) try a.feed(b_copy, now, 9);
        now += 1;
    }

    const grants = try b.takeOperGrants();
    defer {
        for (grants) |g| allocator.free(g);
        allocator.free(grants);
    }
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqualSlices(u8, grant, grants[0]);
    // Drained: a second take yields nothing.
    const empty = try b.takeOperGrants();
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "consumeOutbound drops a partial-send prefix" {
    const allocator = std.testing.allocator;
    var link: S2sLink = undefined;
    try link.init(.{
        .allocator = allocator,
        .local_node_id = 1,
        .remote_node_id = 2,
        .local_epoch_ms = 1000,
        .server_name = "a.orochi",
    });
    defer link.deinit();

    try link.start(10);
    const total = link.outbound().len;
    try std.testing.expect(total > 0);
    link.consumeOutbound(1);
    try std.testing.expectEqual(total - 1, link.outbound().len);
    link.clearOutbound();
    try std.testing.expectEqual(@as(usize, 0), link.outbound().len);
}
