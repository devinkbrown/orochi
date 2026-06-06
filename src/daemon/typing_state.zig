//! Per-channel typing state with expiry pruning.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_typing_per_channel: usize = 128;
pub const max_channel_bytes: usize = 128;
pub const max_user_bytes: usize = 64;
pub const max_ttl_ms: i64 = 300_000;

pub const Error = std.mem.Allocator.Error || error{
    InvalidChannel,
    InvalidUser,
    InvalidTtl,
    TooManyChannels,
    TooManyUsers,
};

const ChannelState = struct {
    users: std.ArrayListUnmanaged([]const u8) = .empty,
    expires_at_ms: std.ArrayListUnmanaged(i64) = .empty,

    fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
        for (self.users.items) |user| allocator.free(user);
        self.users.deinit(allocator);
        self.expires_at_ms.deinit(allocator);
    }

    fn find(self: *const ChannelState, user: []const u8) ?usize {
        for (self.users.items, 0..) |stored, i| {
            if (std.mem.eql(u8, stored, user)) return i;
        }
        return null;
    }

    fn pruneExpired(self: *ChannelState, allocator: std.mem.Allocator, now_ms: i64) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.users.items.len) {
            if (self.expires_at_ms.items[i] <= now_ms) {
                allocator.free(self.users.items[i]);
                _ = self.users.orderedRemove(i);
                _ = self.expires_at_ms.orderedRemove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }
};

pub const TypingState = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(ChannelState),

    pub fn init(allocator: std.mem.Allocator) TypingState {
        return .{ .allocator = allocator, .channels = std.StringHashMap(ChannelState).init(allocator) };
    }

    pub fn deinit(self: *TypingState) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn mark(self: *TypingState, channel: []const u8, user: []const u8, now_ms: i64, ttl_ms: i64) Error!void {
        try validateChannel(channel);
        try validateUser(user);
        if (ttl_ms <= 0 or ttl_ms > max_ttl_ms) return error.InvalidTtl;
        const expires_at = std.math.add(i64, now_ms, ttl_ms) catch return error.InvalidTtl;

        const state = try self.ensureChannel(channel);
        _ = state.pruneExpired(self.allocator, now_ms);
        if (state.find(user)) |idx| {
            state.expires_at_ms.items[idx] = expires_at;
            return;
        }

        if (state.users.items.len >= max_typing_per_channel) return error.TooManyUsers;
        const owned_user = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(owned_user);
        try state.users.append(self.allocator, owned_user);
        errdefer _ = state.users.pop();
        try state.expires_at_ms.append(self.allocator, expires_at);
    }

    /// Prunes expired entries and returns borrowed active users for `channel`.
    /// The returned slice is valid until the next mutation touching this state.
    pub fn active(self: *TypingState, channel: []const u8, now_ms: i64) []const []const u8 {
        const entry = self.channels.getEntry(channel) orelse return &.{};
        _ = entry.value_ptr.pruneExpired(self.allocator, now_ms);
        if (entry.value_ptr.users.items.len == 0) {
            const key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.channels.removeByPtr(entry.key_ptr);
            self.allocator.free(key);
            return &.{};
        }
        return entry.value_ptr.users.items;
    }

    pub fn clearChannel(self: *TypingState, channel: []const u8) usize {
        const entry = self.channels.getEntry(channel) orelse return 0;
        const count = entry.value_ptr.users.items.len;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return count;
    }

    fn ensureChannel(self: *TypingState, channel: []const u8) Error!*ChannelState {
        if (self.channels.getPtr(channel)) |state| return state;
        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        try self.channels.putNoClobber(owned_channel, .{});
        return self.channels.getPtr(channel).?;
    }

    fn validateChannel(channel: []const u8) Error!void {
        if (channel.len == 0 or channel.len > max_channel_bytes) return error.InvalidChannel;
    }

    fn validateUser(user: []const u8) Error!void {
        if (user.len == 0 or user.len > max_user_bytes) return error.InvalidUser;
    }
};

const testing = std.testing;

test "mark and active track users per channel" {
    var state = TypingState.init(testing.allocator);
    defer state.deinit();

    try state.mark("#chat", "alice", 100, 50);
    try state.mark("#chat", "bob", 100, 50);
    const users = state.active("#chat", 120);
    try testing.expectEqual(@as(usize, 2), users.len);
    try testing.expectEqualStrings("alice", users[0]);
    try testing.expectEqualStrings("bob", users[1]);
}

test "active prunes expired users before returning" {
    var state = TypingState.init(testing.allocator);
    defer state.deinit();

    try state.mark("#chat", "alice", 100, 10);
    try state.mark("#chat", "bob", 100, 30);
    const users = state.active("#chat", 115);
    try testing.expectEqual(@as(usize, 1), users.len);
    try testing.expectEqualStrings("bob", users[0]);
    try testing.expectEqual(@as(usize, 0), state.active("#chat", 131).len);
}

test "mark refreshes an existing user's expiry" {
    var state = TypingState.init(testing.allocator);
    defer state.deinit();

    try state.mark("#chat", "alice", 100, 10);
    try state.mark("#chat", "alice", 105, 50);
    const users = state.active("#chat", 120);
    try testing.expectEqual(@as(usize, 1), users.len);
    try testing.expectEqualStrings("alice", users[0]);
}

test "clearChannel removes all users and invalid inputs are rejected" {
    var state = TypingState.init(testing.allocator);
    defer state.deinit();

    try state.mark("#chat", "alice", 100, 10);
    try state.mark("#chat", "bob", 100, 10);
    try testing.expectEqual(@as(usize, 2), state.clearChannel("#chat"));
    try testing.expectEqual(@as(usize, 0), state.clearChannel("#chat"));
    try testing.expectError(error.InvalidChannel, state.mark("", "alice", 0, 1));
    try testing.expectError(error.InvalidUser, state.mark("#chat", "", 0, 1));
    try testing.expectError(error.InvalidTtl, state.mark("#chat", "alice", 0, 0));
}
