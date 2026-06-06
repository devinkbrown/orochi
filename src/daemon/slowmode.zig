//! Per-channel slow message pacing.
//!
//! Slowmode tracks configured channel intervals plus per-user last-send times
//! for channels where pacing is enabled.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_channel_bytes: usize = 128;
pub const max_user_bytes: usize = 128;
pub const max_users_per_channel: usize = 8192;

pub const Error = std.mem.Allocator.Error || error{
    InvalidChannel,
    InvalidUser,
    TooManyChannels,
    TooManyUsers,
};

const ChannelState = struct {
    interval_ms: u32,
    users: std.StringHashMap(i64),

    fn init(allocator: std.mem.Allocator, interval_ms: u32) ChannelState {
        return .{
            .interval_ms = interval_ms,
            .users = std.StringHashMap(i64).init(allocator),
        };
    }

    fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
        var it = self.users.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.users.deinit();
        self.* = undefined;
    }
};

pub const Slowmode = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(ChannelState),

    pub fn init(allocator: std.mem.Allocator) Slowmode {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(ChannelState).init(allocator),
        };
    }

    pub fn deinit(self: *Slowmode) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn setInterval(self: *Slowmode, channel: []const u8, ms: u32) Error!void {
        try validateChannel(channel);
        if (ms == 0) {
            if (self.channels.getEntry(channel)) |entry| self.removeEntry(entry);
            return;
        }

        if (self.channels.getPtr(channel)) |state| {
            state.interval_ms = ms;
            return;
        }

        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        try self.channels.putNoClobber(owned_channel, ChannelState.init(self.allocator, ms));
    }

    /// Returns true when `user` may send now. Allowed sends record `now_ms`.
    pub fn allow(self: *Slowmode, channel: []const u8, user: []const u8, now_ms: i64) Error!bool {
        try validateChannel(channel);
        try validateUser(user);

        const state = self.channels.getPtr(channel) orelse return true;
        if (state.interval_ms == 0) return true;

        if (state.users.getPtr(user)) |last_ms| {
            if (!elapsed(last_ms.*, now_ms, state.interval_ms)) return false;
            last_ms.* = now_ms;
            return true;
        }

        if (state.users.count() >= max_users_per_channel) return error.TooManyUsers;
        const owned_user = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(owned_user);
        try state.users.putNoClobber(owned_user, now_ms);
        return true;
    }

    pub fn intervalOf(self: *const Slowmode, channel: []const u8) u32 {
        const state = self.channels.getPtr(channel) orelse return 0;
        return state.interval_ms;
    }

    fn removeEntry(self: *Slowmode, entry: std.StringHashMap(ChannelState).Entry) void {
        const key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
    }
};

fn validateChannel(channel: []const u8) Error!void {
    if (channel.len == 0 or channel.len > max_channel_bytes) return error.InvalidChannel;
}

fn validateUser(user: []const u8) Error!void {
    if (user.len == 0 or user.len > max_user_bytes) return error.InvalidUser;
}

fn elapsed(last_ms: i64, now_ms: i64, interval_ms: u32) bool {
    const delta = @as(i128, now_ms) - @as(i128, last_ms);
    if (delta < 0) return false;
    return @as(u128, @intCast(delta)) >= @as(u128, interval_ms);
}

const testing = std.testing;

test "setInterval and intervalOf round-trip" {
    var slow = Slowmode.init(testing.allocator);
    defer slow.deinit();

    try testing.expectEqual(@as(u32, 0), slow.intervalOf("#main"));
    try slow.setInterval("#main", 1500);
    try testing.expectEqual(@as(u32, 1500), slow.intervalOf("#main"));
    try slow.setInterval("#main", 2000);
    try testing.expectEqual(@as(u32, 2000), slow.intervalOf("#main"));
}

test "allow records successful sends and denies early repeats" {
    var slow = Slowmode.init(testing.allocator);
    defer slow.deinit();

    try slow.setInterval("#main", 1000);
    try testing.expect(try slow.allow("#main", "alice", 100));
    try testing.expect(!try slow.allow("#main", "alice", 999));
    try testing.expect(try slow.allow("#main", "alice", 1100));
    try testing.expect(!try slow.allow("#main", "alice", 1500));
}

test "users and channels are tracked independently" {
    var slow = Slowmode.init(testing.allocator);
    defer slow.deinit();

    try slow.setInterval("#a", 1000);
    try slow.setInterval("#b", 2000);

    try testing.expect(try slow.allow("#a", "alice", 0));
    try testing.expect(try slow.allow("#a", "bob", 100));
    try testing.expect(try slow.allow("#b", "alice", 100));
    try testing.expect(!try slow.allow("#a", "alice", 500));
    try testing.expect(!try slow.allow("#b", "alice", 1500));
    try testing.expect(try slow.allow("#a", "alice", 1000));
}

test "zero interval disables pacing and clears sender state" {
    var slow = Slowmode.init(testing.allocator);
    defer slow.deinit();

    try slow.setInterval("#main", 1000);
    try testing.expect(try slow.allow("#main", "alice", 0));
    try slow.setInterval("#main", 0);

    try testing.expectEqual(@as(u32, 0), slow.intervalOf("#main"));
    try testing.expect(try slow.allow("#main", "alice", 1));
    try testing.expect(try slow.allow("#main", "alice", 2));
}

test "validation rejects empty channel or user" {
    var slow = Slowmode.init(testing.allocator);
    defer slow.deinit();

    try testing.expectError(error.InvalidChannel, slow.setInterval("", 100));
    try slow.setInterval("#main", 100);
    try testing.expectError(error.InvalidUser, slow.allow("#main", "", 1));
}
