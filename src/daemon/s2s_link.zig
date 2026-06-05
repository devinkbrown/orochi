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

    /// Remote members the peer has announced for `channel` (borrowed roster).
    pub fn channelMembers(self: *const S2sLink, channel: []const u8) []const s2s_peer.MemberInfo {
        return self.peer.channelMembers(channel);
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
        .server_name = "a.mizuchi",
    });
    defer a.deinit();

    var b: S2sLink = undefined;
    try b.init(.{
        .allocator = allocator,
        .local_node_id = 2,
        .remote_node_id = 1,
        .local_epoch_ms = 1001,
        .server_name = "b.mizuchi",
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
    try a.init(.{ .allocator = allocator, .local_node_id = 1, .remote_node_id = 2, .local_epoch_ms = 1000, .server_name = "a.mizuchi" });
    defer a.deinit();
    var b: S2sLink = undefined;
    try b.init(.{ .allocator = allocator, .local_node_id = 2, .remote_node_id = 1, .local_epoch_ms = 1001, .server_name = "b.mizuchi" });
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

test "consumeOutbound drops a partial-send prefix" {
    const allocator = std.testing.allocator;
    var link: S2sLink = undefined;
    try link.init(.{
        .allocator = allocator,
        .local_node_id = 1,
        .remote_node_id = 2,
        .local_epoch_ms = 1000,
        .server_name = "a.mizuchi",
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
