//! Bounded cross-node route table for SUIMYAKU message fan-out.
//!
//! The table is pure state: callers own all I/O decisions and pass allocator
//! ownership in at init. String keys are copied into managed StringHashMaps and
//! released on removal/deinit.
const std = @import("std");

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

pub const RouteTable = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    cfg: Config,
    nick_to_node: std.StringHashMap(NodeId),
    channels: std.StringHashMap(ChannelState),
    nick_count: usize = 0,
    channel_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Error!Self {
        try cfg.validate();
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .nick_to_node = std.StringHashMap(NodeId).init(allocator),
            .channels = std.StringHashMap(ChannelState).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.clear();
        self.nick_to_node.deinit();
        self.channels.deinit();
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

    pub fn removeNode(self: *Self, node: NodeId) void {
        self.removeNodeNicks(node);
        self.removeNodeChannels(node);
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
