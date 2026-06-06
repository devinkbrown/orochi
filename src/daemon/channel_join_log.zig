const std = @import("std");

pub const ChannelJoinLog = struct {
    const max_channel_len = 128;
    const max_account_len = 128;
    const max_channels = 4096;
    pub const max_recent = 100;

    pub const Join = struct {
        account: []u8,
        at_ms: i64,
    };

    allocator: std.mem.Allocator,
    channels: std.ArrayList(Channel) = .empty,

    const Channel = struct {
        name: []u8,
        events: std.ArrayList(Join) = .empty,
    };

    pub fn init(allocator: std.mem.Allocator) ChannelJoinLog {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChannelJoinLog) void {
        for (self.channels.items) |*channel| {
            self.freeChannel(channel);
        }
        self.channels.deinit(self.allocator);
        self.* = ChannelJoinLog.init(self.allocator);
    }

    pub fn record(self: *ChannelJoinLog, channel: []const u8, account: []const u8, at_ms: i64) !void {
        try validate(channel, max_channel_len, error.EmptyChannel, error.ChannelTooLong);
        try validate(account, max_account_len, error.EmptyAccount, error.AccountTooLong);

        if (self.find(channel)) |index| {
            try self.recordExisting(index, account, at_ms);
            return;
        }

        if (self.channels.items.len >= max_channels) return error.TooManyChannels;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const account_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(account_copy);

        var new_channel = Channel{ .name = channel_copy };
        errdefer {
            for (new_channel.events.items) |event| self.allocator.free(event.account);
            new_channel.events.deinit(self.allocator);
        }
        try new_channel.events.append(self.allocator, .{
            .account = account_copy,
            .at_ms = at_ms,
        });

        try self.channels.append(self.allocator, new_channel);
    }

    pub fn recent(self: *const ChannelJoinLog, channel: []const u8) []const Join {
        const index = self.find(channel) orelse return &[_]Join{};
        return self.channels.items[index].events.items;
    }

    pub fn clearChannel(self: *ChannelJoinLog, channel: []const u8) usize {
        const index = self.find(channel) orelse return 0;
        const removed = self.channels.orderedRemove(index);
        const count = removed.events.items.len;
        var copy = removed;
        self.freeChannel(&copy);
        return count;
    }

    fn recordExisting(self: *ChannelJoinLog, index: usize, account: []const u8, at_ms: i64) !void {
        const account_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(account_copy);

        var channel = &self.channels.items[index];
        if (channel.events.items.len == max_recent) {
            const removed = channel.events.orderedRemove(0);
            self.allocator.free(removed.account);
        }

        try channel.events.append(self.allocator, .{
            .account = account_copy,
            .at_ms = at_ms,
        });
    }

    fn freeChannel(self: *ChannelJoinLog, channel: *Channel) void {
        self.allocator.free(channel.name);
        for (channel.events.items) |event| {
            self.allocator.free(event.account);
        }
        channel.events.deinit(self.allocator);
    }

    fn find(self: *const ChannelJoinLog, channel: []const u8) ?usize {
        for (self.channels.items, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.name, channel)) return index;
        }
        return null;
    }

    fn validate(value: []const u8, max_len: usize, empty_error: anyerror, long_error: anyerror) !void {
        if (value.len == 0) return empty_error;
        if (value.len > max_len) return long_error;
    }
};

test "record stores recent joins in order" {
    var log = ChannelJoinLog.init(std.testing.allocator);
    defer log.deinit();

    try log.record("#dev", "alice", 10);
    try log.record("#dev", "bob", 20);

    const recent = log.recent("#dev");
    try std.testing.expectEqual(@as(usize, 2), recent.len);
    try std.testing.expectEqualStrings("alice", recent[0].account);
    try std.testing.expectEqual(@as(i64, 20), recent[1].at_ms);
}

test "ring keeps the newest one hundred joins" {
    var log = ChannelJoinLog.init(std.testing.allocator);
    defer log.deinit();

    var i: usize = 0;
    while (i < 105) : (i += 1) {
        const account = try std.fmt.allocPrint(std.testing.allocator, "acct{d}", .{i});
        defer std.testing.allocator.free(account);
        try log.record("#ring", account, @intCast(i));
    }

    const recent = log.recent("#ring");
    try std.testing.expectEqual(ChannelJoinLog.max_recent, recent.len);
    try std.testing.expectEqualStrings("acct5", recent[0].account);
    try std.testing.expectEqualStrings("acct104", recent[99].account);
}

test "clearChannel removes only the requested channel" {
    var log = ChannelJoinLog.init(std.testing.allocator);
    defer log.deinit();

    try log.record("#a", "one", 1);
    try log.record("#a", "two", 2);
    try log.record("#b", "three", 3);

    try std.testing.expectEqual(@as(usize, 2), log.clearChannel("#a"));
    try std.testing.expectEqual(@as(usize, 0), log.recent("#a").len);
    try std.testing.expectEqual(@as(usize, 1), log.recent("#b").len);
    try std.testing.expectEqual(@as(usize, 0), log.clearChannel("#missing"));
}

test "record rejects empty names" {
    var log = ChannelJoinLog.init(std.testing.allocator);
    defer log.deinit();

    try std.testing.expectError(error.EmptyChannel, log.record("", "alice", 1));
    try std.testing.expectError(error.EmptyAccount, log.record("#dev", "", 1));
}
