//! Per-channel admission lobby for calls. Accounts are owned by the room while
//! pending and are removed on admit or deny.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_pending_per_channel: usize = 256;
pub const max_channel_bytes: usize = 128;
pub const max_account_bytes: usize = 64;

pub const Error = std.mem.Allocator.Error || error{ TooManyChannels, TooManyPending, InvalidAccount };

const PendingList = struct {
    accounts: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *PendingList, allocator: std.mem.Allocator) void {
        for (self.accounts.items) |account| allocator.free(account);
        self.accounts.deinit(allocator);
    }

    fn find(self: *const PendingList, account: []const u8) ?usize {
        for (self.accounts.items, 0..) |item, i| {
            if (std.mem.eql(u8, item, account)) return i;
        }
        return null;
    }
};

pub const WaitingRoom = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(PendingList),

    pub fn init(allocator: std.mem.Allocator) WaitingRoom {
        return .{ .allocator = allocator, .channels = std.StringHashMap(PendingList).init(allocator) };
    }

    pub fn deinit(self: *WaitingRoom) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn knock(self: *WaitingRoom, channel: []const u8, account: []const u8) Error!void {
        if (!validName(channel, max_channel_bytes) or !validName(account, max_account_bytes)) return error.InvalidAccount;
        const list = try self.ensureChannel(channel);
        if (list.find(account) != null) return;
        if (list.accounts.items.len >= max_pending_per_channel) return error.TooManyPending;
        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try list.accounts.append(self.allocator, owned);
    }

    pub fn pending(self: *const WaitingRoom, channel: []const u8) []const []const u8 {
        const list = self.channels.getPtr(channel) orelse return &.{};
        return list.accounts.items;
    }

    pub fn admit(self: *WaitingRoom, channel: []const u8, account: []const u8) bool {
        return self.remove(channel, account);
    }

    pub fn deny(self: *WaitingRoom, channel: []const u8, account: []const u8) bool {
        return self.remove(channel, account);
    }

    fn remove(self: *WaitingRoom, channel: []const u8, account: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const idx = entry.value_ptr.find(account) orelse return false;
        const owned = entry.value_ptr.accounts.orderedRemove(idx);
        self.allocator.free(owned);
        if (entry.value_ptr.accounts.items.len == 0) {
            const key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.channels.removeByPtr(entry.key_ptr);
            self.allocator.free(key);
        }
        return true;
    }

    fn ensureChannel(self: *WaitingRoom, channel: []const u8) Error!*PendingList {
        if (self.channels.getPtr(channel)) |list| return list;
        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }
};

fn validName(value: []const u8, cap: usize) bool {
    return value.len > 0 and value.len <= cap and std.mem.indexOfScalar(u8, value, 0) == null;
}

const testing = std.testing;

test "knock stores pending accounts in order" {
    var room = WaitingRoom.init(testing.allocator);
    defer room.deinit();

    try room.knock("#call", "alice");
    try room.knock("#call", "bob");

    const list = room.pending("#call");
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqualStrings("alice", list[0]);
    try testing.expectEqualStrings("bob", list[1]);
}

test "knock is idempotent per channel" {
    var room = WaitingRoom.init(testing.allocator);
    defer room.deinit();

    try room.knock("#call", "alice");
    try room.knock("#call", "alice");

    try testing.expectEqual(@as(usize, 1), room.pending("#call").len);
}

test "admit and deny remove pending accounts" {
    var room = WaitingRoom.init(testing.allocator);
    defer room.deinit();

    try room.knock("#call", "alice");
    try room.knock("#call", "bob");

    try testing.expect(room.admit("#call", "alice"));
    try testing.expect(!room.admit("#call", "alice"));
    try testing.expect(room.deny("#call", "bob"));
    try testing.expectEqual(@as(usize, 0), room.pending("#call").len);
}

test "pending cap is enforced" {
    var room = WaitingRoom.init(testing.allocator);
    defer room.deinit();

    var i: usize = 0;
    while (i < max_pending_per_channel) : (i += 1) {
        var buf: [32]u8 = undefined;
        const account = try std.fmt.bufPrint(&buf, "u{}", .{i});
        try room.knock("#call", account);
    }
    try testing.expectError(error.TooManyPending, room.knock("#call", "extra"));
}
