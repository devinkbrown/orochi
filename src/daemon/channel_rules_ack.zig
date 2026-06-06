const std = @import("std");

pub const ChannelRulesAck = struct {
    const max_name_len = 128;
    const max_acks = 8192;

    allocator: std.mem.Allocator,
    acks: std.ArrayList(Ack) = .empty,

    const Ack = struct {
        channel: []u8,
        account: []u8,
    };

    pub fn init(allocator: std.mem.Allocator) ChannelRulesAck {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChannelRulesAck) void {
        for (self.acks.items) |ack_item| {
            self.allocator.free(ack_item.channel);
            self.allocator.free(ack_item.account);
        }
        self.acks.deinit(self.allocator);
        self.* = ChannelRulesAck.init(self.allocator);
    }

    pub fn ack(self: *ChannelRulesAck, channel: []const u8, account: []const u8) !void {
        try validateName(channel);
        try validateName(account);
        if (self.hasAcked(channel, account)) return;
        if (self.acks.items.len >= max_acks) return error.TooManyAcks;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const account_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(account_copy);

        try self.acks.append(self.allocator, .{
            .channel = channel_copy,
            .account = account_copy,
        });
    }

    pub fn hasAcked(self: *const ChannelRulesAck, channel: []const u8, account: []const u8) bool {
        for (self.acks.items) |ack_item| {
            if (std.mem.eql(u8, ack_item.channel, channel) and std.mem.eql(u8, ack_item.account, account)) {
                return true;
            }
        }
        return false;
    }

    pub fn clearChannel(self: *ChannelRulesAck, channel: []const u8) usize {
        var removed_count: usize = 0;
        var index: usize = 0;
        while (index < self.acks.items.len) {
            if (!std.mem.eql(u8, self.acks.items[index].channel, channel)) {
                index += 1;
                continue;
            }

            const removed = self.acks.orderedRemove(index);
            self.allocator.free(removed.channel);
            self.allocator.free(removed.account);
            removed_count += 1;
        }
        return removed_count;
    }

    fn validateName(value: []const u8) !void {
        if (value.len == 0) return error.EmptyName;
        if (value.len > max_name_len) return error.NameTooLong;
    }
};

test "ack records account acceptance per channel" {
    var rules = ChannelRulesAck.init(std.testing.allocator);
    defer rules.deinit();

    try rules.ack("#dev", "alice");
    try std.testing.expect(rules.hasAcked("#dev", "alice"));
    try std.testing.expect(!rules.hasAcked("#dev", "bob"));
    try std.testing.expect(!rules.hasAcked("#other", "alice"));
}

test "duplicate ack is idempotent" {
    var rules = ChannelRulesAck.init(std.testing.allocator);
    defer rules.deinit();

    try rules.ack("#dev", "alice");
    try rules.ack("#dev", "alice");
    try std.testing.expectEqual(@as(usize, 1), rules.clearChannel("#dev"));
}

test "clearChannel removes all accounts for one channel" {
    var rules = ChannelRulesAck.init(std.testing.allocator);
    defer rules.deinit();

    try rules.ack("#a", "one");
    try rules.ack("#a", "two");
    try rules.ack("#b", "one");

    try std.testing.expectEqual(@as(usize, 2), rules.clearChannel("#a"));
    try std.testing.expect(!rules.hasAcked("#a", "one"));
    try std.testing.expect(rules.hasAcked("#b", "one"));
    try std.testing.expectEqual(@as(usize, 0), rules.clearChannel("#missing"));
}

test "empty names are rejected" {
    var rules = ChannelRulesAck.init(std.testing.allocator);
    defer rules.deinit();

    try std.testing.expectError(error.EmptyName, rules.ack("", "alice"));
    try std.testing.expectError(error.EmptyName, rules.ack("#dev", ""));
}

