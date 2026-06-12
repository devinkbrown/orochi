//! Bounded cross-node route table for SUIMYAKU message fan-out.
//!
//! The table is pure state: callers own all I/O decisions and pass allocator
//! ownership in at init. String keys are copied into managed StringHashMaps and
//! released on removal/deinit.
const std = @import("std");
const toml = @import("../../proto/toml.zig");

pub const NodeId = u64;

pub const Error = std.mem.Allocator.Error || error{
    BufferTooSmall,
    ChannelFanoutFull,
    InvalidConfig,
    InvalidName,
    InvalidNode,
    MemberCountOverflow,
    RouteTableFull,
};

pub const Config = struct {
    max_nicks: usize = 4096,
    max_channels: usize = 1024,
    max_nodes_per_channel: usize = 64,
    max_name_len: usize = 64,

    pub fn validate(self: Config) Error!void {
        if (self.max_nicks == 0) return error.InvalidConfig;
        if (self.max_channels == 0) return error.InvalidConfig;
        if (self.max_nodes_per_channel == 0) return error.InvalidConfig;
        if (self.max_name_len == 0) return error.InvalidConfig;
    }

    /// Overlay `[mesh.routing]` route-table keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.routing.max_nicks")) |v| cfg.max_nicks = @intCast(v);
        if (doc.getUint("mesh.routing.max_channels")) |v| cfg.max_channels = @intCast(v);
        if (doc.getUint("mesh.routing.max_nodes_per_channel")) |v| cfg.max_nodes_per_channel = @intCast(v);
        if (doc.getUint("mesh.routing.max_name_len")) |v| cfg.max_name_len = @intCast(v);
    }
};

pub const MembershipChange = enum {
    join,
    part,
};

const NodeRef = struct {
    id: NodeId,
    members: u32 = 1,
};

const ChannelState = struct {
    nodes: []NodeRef,
    len: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) Error!ChannelState {
        return .{ .nodes = try allocator.alloc(NodeRef, capacity) };
    }

    fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
        allocator.free(self.nodes);
        self.* = undefined;
    }

    fn addMember(self: *ChannelState, node: NodeId) Error!void {
        if (self.find(node)) |idx| {
            if (self.nodes[idx].members == std.math.maxInt(u32)) {
                return error.MemberCountOverflow;
            }
            self.nodes[idx].members += 1;
            return;
        }

        if (self.len == self.nodes.len) return error.ChannelFanoutFull;
        self.nodes[self.len] = .{ .id = node };
        self.len += 1;
    }

    fn removeMember(self: *ChannelState, node: NodeId) void {
        const idx = self.find(node) orelse return;
        if (self.nodes[idx].members > 1) {
            self.nodes[idx].members -= 1;
            return;
        }
        self.swapRemove(idx);
    }

    fn removeNode(self: *ChannelState, node: NodeId) void {
        const idx = self.find(node) orelse return;
        self.swapRemove(idx);
    }

    fn copyNodes(self: *const ChannelState, out: []NodeId) Error!usize {
        if (out.len < self.len) return error.BufferTooSmall;
        for (self.nodes[0..self.len], 0..) |entry, idx| out[idx] = entry.id;
        return self.len;
    }

    fn find(self: *const ChannelState, node: NodeId) ?usize {
        for (self.nodes[0..self.len], 0..) |entry, idx| {
            if (entry.id == node) return idx;
        }
        return null;
    }

    fn swapRemove(self: *ChannelState, idx: usize) void {
        self.len -= 1;
        if (idx != self.len) self.nodes[idx] = self.nodes[self.len];
    }
};

/// One remote channel member's identity, for projecting NAMES/WHO. `nick`,
/// `username`, `realname`, and `host` are owned by the route table; `status`
/// reuses the MemberStatus bit layout (founder/owner/op/voice) so prefixes
/// render; `hlc` drives last-writer-wins. Identity strings may be empty when
/// the origin did not propagate them (consumers substitute placeholders).
pub const Member = struct {
    nick: []u8,
    /// The member's username (USER ident) on its home node ("" = unknown).
    username: []u8,
    /// The member's realname/GECOS ("" = unknown).
    realname: []u8,
    /// The member's VISIBLE (cloaked) host ("" = unknown).
    host: []u8,
    node: NodeId,
    status: u4,
    hlc: u64,

    fn freeStrings(self: *const Member, allocator: std.mem.Allocator) void {
        allocator.free(self.nick);
        allocator.free(self.username);
        allocator.free(self.realname);
        allocator.free(self.host);
    }
};

/// A remote member's propagated identity, as `applyMembership` accepts it
/// (borrowed; duped into owned `Member` strings on store).
pub const MemberIdentity = struct {
    username: []const u8 = "",
    realname: []const u8 = "",
    host: []const u8 = "",
};

/// Per-channel member roster (flat list — channels are bounded, and a flat list
/// keeps ownership trivial: owned nick + identity strings per entry).
const MemberList = struct {
    entries: std.ArrayListUnmanaged(Member) = .empty,

    fn deinit(self: *MemberList, allocator: std.mem.Allocator) void {
        for (self.entries.items) |m| m.freeStrings(allocator);
        self.entries.deinit(allocator);
    }

    fn find(self: *const MemberList, nick: []const u8) ?usize {
        for (self.entries.items, 0..) |m, i| {
            if (std.mem.eql(u8, m.nick, nick)) return i;
        }
        return null;
    }
};

pub const RouteTable = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    cfg: Config,
    nick_to_node: std.StringHashMap(NodeId),
    channels: std.StringHashMap(ChannelState),
    /// channel name -> roster of remote members (nick + status), populated by
    /// MEMBERSHIP propagation (see docs/planning/16). Independent of `channels`
    /// (which is node-level routing) so identity churn never disturbs routing.
    channel_members: std.StringHashMap(MemberList),
    nick_count: usize = 0,
    channel_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Error!Self {
        try cfg.validate();
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .nick_to_node = std.StringHashMap(NodeId).init(allocator),
            .channels = std.StringHashMap(ChannelState).init(allocator),
            .channel_members = std.StringHashMap(MemberList).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.clear();
        self.nick_to_node.deinit();
        self.channels.deinit();
        self.channel_members.deinit();
        self.* = undefined;
    }

    pub fn clear(self: *Self) void {
        var nicks = self.nick_to_node.iterator();
        while (nicks.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.nick_to_node.clearRetainingCapacity();

        var channels = self.channels.iterator();
        while (channels.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.clearRetainingCapacity();

        var members = self.channel_members.iterator();
        while (members.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channel_members.clearRetainingCapacity();

        self.nick_count = 0;
        self.channel_count = 0;
    }

    pub fn setNickLocation(self: *Self, nick: []const u8, node: NodeId) Error!void {
        try self.validateName(nick);
        try validateNode(node);

        if (self.nick_to_node.getPtr(nick)) |slot| {
            slot.* = node;
            return;
        }

        if (self.nick_count == self.cfg.max_nicks) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned);
        try self.nick_to_node.putNoClobber(owned, node);
        self.nick_count += 1;
    }

    pub fn removeNick(self: *Self, nick: []const u8) bool {
        const removed = self.nick_to_node.fetchRemove(nick) orelse return false;
        self.allocator.free(removed.key);
        self.nick_count -= 1;
        return true;
    }

    pub fn nickNode(self: *const Self, nick: []const u8) ?NodeId {
        return self.nick_to_node.get(nick);
    }

    pub fn channelNodes(self: *const Self, chan: []const u8, out: []NodeId) Error!usize {
        try self.validateName(chan);
        const state = self.channels.getPtr(chan) orelse return 0;
        return state.copyNodes(out);
    }

    pub fn updateOnMembershipChange(
        self: *Self,
        chan: []const u8,
        node: NodeId,
        change: MembershipChange,
    ) Error!void {
        switch (change) {
            .join => try self.addChannelMember(chan, node),
            .part => self.removeChannelMember(chan, node),
        }
    }

    pub fn addChannelMember(self: *Self, chan: []const u8, node: NodeId) Error!void {
        try self.validateName(chan);
        try validateNode(node);

        if (self.channels.getPtr(chan)) |state| {
            try state.addMember(node);
            return;
        }

        if (self.channel_count == self.cfg.max_channels) return error.RouteTableFull;

        var state = try ChannelState.init(self.allocator, self.cfg.max_nodes_per_channel);
        errdefer state.deinit(self.allocator);
        try state.addMember(node);

        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, state);
        self.channel_count += 1;
    }

    pub fn removeChannelMember(self: *Self, chan: []const u8, node: NodeId) void {
        const entry = self.channels.getEntry(chan) orelse return;
        entry.value_ptr.removeMember(node);
        if (entry.value_ptr.len != 0) return;

        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
        self.channel_count -= 1;
    }

    /// Outcome of `applyMembership`, so the caller can emit the matching live IRC
    /// surface (a remote `JOIN`/`PART` to local channel members). `unchanged`
    /// covers stale events and re-affirmations of an existing member (so the
    /// periodic anti-entropy re-burst never produces a duplicate JOIN).
    pub const ApplyOutcome = enum { joined, parted, status_changed, unchanged };

    /// Outcome plus the member's previous status bits, so the caller can emit a
    /// precise MODE diff (which prefixes were added/removed) for a status change.
    pub const ApplyResult = struct {
        outcome: ApplyOutcome,
        prev_status: u4 = 0,
    };

    /// Apply a MEMBERSHIP event for a remote member, last-writer-wins by `hlc`.
    /// `present` true = join/status upsert; false = part. Stale events (hlc <= the
    /// stored one for this nick) are ignored, so out-of-order gossip converges.
    /// `ident` carries the member's propagated username/realname/visible-host;
    /// on a newer event the stored identity is replaced (LWW, like the status).
    pub fn applyMembership(
        self: *Self,
        chan: []const u8,
        nick: []const u8,
        node: NodeId,
        status: u4,
        hlc: u64,
        present: bool,
        ident: MemberIdentity,
    ) Error!ApplyResult {
        try self.validateName(chan);
        try self.validateName(nick);
        try validateNode(node);

        const list = try self.ensureMemberList(chan);
        if (list.find(nick)) |idx| {
            const cur = &list.entries.items[idx];
            const prev = cur.status;
            if (hlc <= cur.hlc) return .{ .outcome = .unchanged, .prev_status = prev }; // stale
            if (present) {
                const changed = cur.status != status or cur.node != node;
                try replaceOwned(self.allocator, &cur.username, ident.username);
                try replaceOwned(self.allocator, &cur.realname, ident.realname);
                try replaceOwned(self.allocator, &cur.host, ident.host);
                cur.node = node;
                cur.status = status;
                cur.hlc = hlc;
                return .{ .outcome = if (changed) .status_changed else .unchanged, .prev_status = prev };
            } else {
                cur.freeStrings(self.allocator);
                _ = list.entries.swapRemove(idx);
                self.pruneIfEmpty(chan);
                return .{ .outcome = .parted, .prev_status = prev };
            }
        }
        if (!present) return .{ .outcome = .unchanged }; // part for an unknown member
        if (list.entries.items.len >= self.cfg.max_nicks) return error.RouteTableFull;
        const owned = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned);
        const owned_user = try self.allocator.dupe(u8, ident.username);
        errdefer self.allocator.free(owned_user);
        const owned_real = try self.allocator.dupe(u8, ident.realname);
        errdefer self.allocator.free(owned_real);
        const owned_host = try self.allocator.dupe(u8, ident.host);
        errdefer self.allocator.free(owned_host);
        try list.entries.append(self.allocator, .{
            .nick = owned,
            .username = owned_user,
            .realname = owned_real,
            .host = owned_host,
            .node = node,
            .status = status,
            .hlc = hlc,
        });
        return .{ .outcome = .joined };
    }

    /// Borrowed roster of remote members for `chan` (empty if none). Valid until
    /// the next `applyMembership`/eviction touching this channel.
    pub fn channelMembers(self: *const Self, chan: []const u8) []const Member {
        const list = self.channel_members.getPtr(chan) orelse return &.{};
        return list.entries.items;
    }

    /// Scan every channel roster for `nick` (ASCII case-insensitive, matching
    /// the daemon's nick comparison) and return the first match by value. The
    /// returned `nick` slice is borrowed from the table — valid until the next
    /// `applyMembership`/eviction. Channel membership is the only mesh-wide
    /// nick replication, so a remote user in no channels is not findable here.
    pub fn findMember(self: *const Self, nick: []const u8) ?Member {
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.entries.items) |m| {
                if (std.ascii.eqlIgnoreCase(m.nick, nick)) return m;
            }
        }
        return null;
    }

    fn ensureMemberList(self: *Self, chan: []const u8) Error!*MemberList {
        if (self.channel_members.getPtr(chan)) |list| return list;
        const owned = try self.allocator.dupe(u8, chan);
        errdefer self.allocator.free(owned);
        try self.channel_members.putNoClobber(owned, .{});
        return self.channel_members.getPtr(chan).?;
    }

    fn pruneIfEmpty(self: *Self, chan: []const u8) void {
        const entry = self.channel_members.getEntry(chan) orelse return;
        if (entry.value_ptr.entries.items.len != 0) return;
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channel_members.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    pub fn removeNode(self: *Self, node: NodeId) void {
        self.removeNodeNicks(node);
        self.removeNodeChannels(node);
        self.removeNodeMembers(node);
    }

    /// Drop every remote member homed on a departed node (netsplit hygiene), and
    /// remove any channel left with no remaining members.
    fn removeNodeMembers(self: *Self, node: NodeId) void {
        var empties: std.ArrayListUnmanaged([]const u8) = .empty;
        defer empties.deinit(self.allocator);
        var it = self.channel_members.iterator();
        while (it.next()) |entry| {
            const list = entry.value_ptr;
            var i: usize = 0;
            while (i < list.entries.items.len) {
                if (list.entries.items[i].node == node) {
                    list.entries.items[i].freeStrings(self.allocator);
                    _ = list.entries.swapRemove(i);
                } else i += 1;
            }
            if (list.entries.items.len == 0) empties.append(self.allocator, entry.key_ptr.*) catch {};
        }
        for (empties.items) |chan| self.pruneIfEmpty(chan);
    }

    pub fn nickCount(self: *const Self) usize {
        return self.nick_count;
    }

    pub fn channelCount(self: *const Self) usize {
        return self.channel_count;
    }

    fn removeNodeNicks(self: *Self, node: NodeId) void {
        while (true) {
            var it = self.nick_to_node.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* != node) continue;
                const owned_key = entry.key_ptr.*;
                self.nick_to_node.removeByPtr(entry.key_ptr);
                self.allocator.free(owned_key);
                self.nick_count -= 1;
                break;
            } else {
                return;
            }
        }
    }

    fn removeNodeChannels(self: *Self, node: NodeId) void {
        while (true) {
            var it = self.channels.iterator();
            var removed_empty = false;
            while (it.next()) |entry| {
                entry.value_ptr.removeNode(node);
                if (entry.value_ptr.len != 0) continue;

                const owned_key = entry.key_ptr.*;
                entry.value_ptr.deinit(self.allocator);
                self.channels.removeByPtr(entry.key_ptr);
                self.allocator.free(owned_key);
                self.channel_count -= 1;
                removed_empty = true;
                break;
            }
            if (!removed_empty) return;
        }
    }

    fn validateName(self: *const Self, name: []const u8) Error!void {
        if (name.len == 0 or name.len > self.cfg.max_name_len) return error.InvalidName;
    }
};

fn validateNode(node: NodeId) Error!void {
    if (node == 0) return error.InvalidNode;
}

/// Replace an owned string with a copy of `incoming` (no-op when equal). The
/// new copy is allocated BEFORE the old one is freed, so an allocation failure
/// leaves the previous owned value intact (never a dangling slot).
fn replaceOwned(allocator: std.mem.Allocator, slot: *[]u8, incoming: []const u8) std.mem.Allocator.Error!void {
    if (std.mem.eql(u8, slot.*, incoming)) return;
    const fresh = try allocator.dupe(u8, incoming);
    allocator.free(slot.*);
    slot.* = fresh;
}

fn containsNode(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |candidate| {
        if (candidate == node) return true;
    }
    return false;
}

test "nick routing" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();

    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
    try table.setNickLocation("alice", 10);
    try std.testing.expectEqual(@as(?NodeId, 10), table.nickNode("alice"));

    try table.setNickLocation("alice", 20);
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode("alice"));
    try std.testing.expectEqual(@as(usize, 1), table.nickCount());

    try std.testing.expect(table.removeNick("alice"));
    try std.testing.expect(!table.removeNick("alice"));
    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
}

test "channel fan-out node set" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nodes_per_channel = 3 });
    defer table.deinit();

    try table.updateOnMembershipChange("#zig", 10, .join);
    try table.updateOnMembershipChange("#zig", 20, .join);
    try table.updateOnMembershipChange("#zig", 10, .join);

    var out: [3]NodeId = undefined;
    var len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expect(containsNode(out[0..len], 10));
    try std.testing.expect(containsNode(out[0..len], 20));

    try table.updateOnMembershipChange("#zig", 10, .part);
    len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expect(containsNode(out[0..len], 10));

    try table.updateOnMembershipChange("#zig", 10, .part);
    len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expect(!containsNode(out[0..len], 10));
    try std.testing.expect(containsNode(out[0..len], 20));
}

test "node removal purges its nicks" {
    var table = try RouteTable.init(std.testing.allocator, .{});
    defer table.deinit();

    try table.setNickLocation("alice", 10);
    try table.setNickLocation("bob", 20);
    try table.updateOnMembershipChange("#zig", 10, .join);
    try table.updateOnMembershipChange("#zig", 20, .join);
    try table.updateOnMembershipChange("#empty-after-purge", 10, .join);

    table.removeNode(10);

    try std.testing.expectEqual(@as(?NodeId, null), table.nickNode("alice"));
    try std.testing.expectEqual(@as(?NodeId, 20), table.nickNode("bob"));

    var out: [2]NodeId = undefined;
    const len = try table.channelNodes("#zig", &out);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expect(containsNode(out[0..len], 20));
    try std.testing.expectEqual(@as(usize, 0), try table.channelNodes("#empty-after-purge", &out));
}

test "no leak across clear, remove, and deinit paths" {
    var table = try RouteTable.init(std.testing.allocator, .{
        .max_nicks = 4,
        .max_channels = 4,
        .max_nodes_per_channel = 4,
    });
    defer table.deinit();

    try table.setNickLocation("alice", 1);
    try table.setNickLocation("bob", 2);
    try table.updateOnMembershipChange("#a", 1, .join);
    try table.updateOnMembershipChange("#a", 2, .join);
    try table.updateOnMembershipChange("#b", 2, .join);

    try std.testing.expect(table.removeNick("alice"));
    table.removeNode(2);
    table.clear();

    try std.testing.expectEqual(@as(usize, 0), table.nickCount());
    try std.testing.expectEqual(@as(usize, 0), table.channelCount());
}

test "applyMembership tracks remote channel members with last-writer-wins" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "alice", 10, 0b0100, 1, true, .{}); // op
    _ = try table.applyMembership("#chat", "bob", 20, 0b0000, 1, true, .{});
    try std.testing.expectEqual(@as(usize, 2), table.channelMembers("#chat").len);

    // A stale event (lower hlc) is ignored; a newer one updates status.
    _ = try table.applyMembership("#chat", "alice", 10, 0b0000, 0, true, .{});
    _ = try table.applyMembership("#chat", "alice", 10, 0b0010, 5, true, .{}); // now voice
    var alice_status: ?u4 = null;
    for (table.channelMembers("#chat")) |m| {
        if (std.mem.eql(u8, m.nick, "alice")) alice_status = m.status;
    }
    try std.testing.expectEqual(@as(u4, 0b0010), alice_status.?);
}

test "applyMembership stores and LWW-updates the propagated identity" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{
        .username = "alice",
        .realname = "Alice Liddell",
        .host = "cloak-1a2b.users",
    });
    var alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("alice", alice.username);
    try std.testing.expectEqualStrings("Alice Liddell", alice.realname);
    try std.testing.expectEqualStrings("cloak-1a2b.users", alice.host);

    // A stale event must NOT clobber the stored identity.
    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{ .username = "stale" });
    alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("alice", alice.username);

    // A newer event replaces it (e.g. a vhost change re-announced).
    _ = try table.applyMembership("#chat", "alice", 10, 0, 9, true, .{
        .username = "alice",
        .realname = "Alice Liddell",
        .host = "vanity.example",
    });
    alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("vanity.example", alice.host);

    // Part frees the identity strings (leak-checked by testing.allocator).
    _ = try table.applyMembership("#chat", "alice", 10, 0, 10, false, .{});
    try std.testing.expect(table.findMember("alice") == null);
}

test "findMember locates a roster member case-insensitively with its node" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "Alice", 10, 0b0100, 1, true, .{});
    _ = try table.applyMembership("#ops", "bob", 20, 0, 1, true, .{});

    const alice = table.findMember("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Alice", alice.nick);
    try std.testing.expectEqual(@as(NodeId, 10), alice.node);

    const bob = table.findMember("BOB") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(NodeId, 20), bob.node);

    try std.testing.expect(table.findMember("carol") == null);
}

test "applyMembership part removes a member and prunes an empty channel" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#x", "alice", 10, 0, 1, true, .{});
    // Stale part (hlc <= current) does not remove.
    _ = try table.applyMembership("#x", "alice", 10, 0, 1, false, .{});
    try std.testing.expectEqual(@as(usize, 1), table.channelMembers("#x").len);
    // Newer part removes; the now-empty channel is pruned.
    _ = try table.applyMembership("#x", "alice", 10, 0, 2, false, .{});
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#x").len);
}

test "removeNode evicts that node's remote members (netsplit hygiene)" {
    var table = try RouteTable.init(std.testing.allocator, .{ .max_nicks = 8, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    _ = try table.applyMembership("#chat", "alice", 10, 0, 1, true, .{});
    _ = try table.applyMembership("#chat", "bob", 20, 0, 1, true, .{});
    table.removeNode(10);
    const members = table.channelMembers("#chat");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("bob", members[0].nick);

    table.removeNode(20); // last member gone -> channel pruned
    try std.testing.expectEqual(@as(usize, 0), table.channelMembers("#chat").len);
}

test "Config.applyToml overlays mesh.routing route-table keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.routing]
        \\max_nicks = 8192
        \\max_nodes_per_channel = 128
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 8192), cfg.max_nicks);
    try std.testing.expectEqual(@as(usize, 128), cfg.max_nodes_per_channel);
    try std.testing.expectEqual(@as(usize, 1024), cfg.max_channels); // default
}
