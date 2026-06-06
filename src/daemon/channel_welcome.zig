const std = @import("std");

pub const ChannelWelcome = struct {
    const max_channel_len = 128;
    const max_message_len = 400;
    const max_channels = 4096;

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    const Entry = struct {
        channel: []u8,
        message: []u8,
    };

    pub fn init(allocator: std.mem.Allocator) ChannelWelcome {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChannelWelcome) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.channel);
            self.allocator.free(entry.message);
        }
        self.entries.deinit(self.allocator);
        self.* = ChannelWelcome.init(self.allocator);
    }

    pub fn set(self: *ChannelWelcome, channel: []const u8, message: []const u8) !void {
        try validateChannel(channel);
        if (message.len > max_message_len) return error.MessageTooLong;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const message_copy = try self.allocator.dupe(u8, message);
        errdefer self.allocator.free(message_copy);

        if (self.find(channel)) |index| {
            const old = self.entries.items[index];
            self.allocator.free(old.channel);
            self.allocator.free(old.message);
            self.entries.items[index] = .{
                .channel = channel_copy,
                .message = message_copy,
            };
            return;
        }

        if (self.entries.items.len >= max_channels) return error.TooManyChannels;
        try self.entries.append(self.allocator, .{
            .channel = channel_copy,
            .message = message_copy,
        });
    }

    pub fn get(self: *const ChannelWelcome, channel: []const u8) ?[]const u8 {
        const index = self.find(channel) orelse return null;
        return self.entries.items[index].message;
    }

    pub fn clear(self: *ChannelWelcome, channel: []const u8) bool {
        const index = self.find(channel) orelse return false;
        const removed = self.entries.orderedRemove(index);
        self.allocator.free(removed.channel);
        self.allocator.free(removed.message);
        return true;
    }

    fn find(self: *const ChannelWelcome, channel: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.channel, channel)) return index;
        }
        return null;
    }

    fn validateChannel(channel: []const u8) !void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > max_channel_len) return error.ChannelTooLong;
    }
};

test "set and get welcome message" {
    var welcome = ChannelWelcome.init(std.testing.allocator);
    defer welcome.deinit();

    try welcome.set("#dev", "Read the topic before posting.");
    try std.testing.expectEqualStrings("Read the topic before posting.", welcome.get("#dev").?);
    try std.testing.expect(welcome.get("#missing") == null);
}

test "set replaces existing channel message" {
    var welcome = ChannelWelcome.init(std.testing.allocator);
    defer welcome.deinit();

    try welcome.set("#dev", "first");
    try welcome.set("#dev", "second");
    try std.testing.expectEqualStrings("second", welcome.get("#dev").?);
}

test "clear removes one channel only" {
    var welcome = ChannelWelcome.init(std.testing.allocator);
    defer welcome.deinit();

    try welcome.set("#a", "alpha");
    try welcome.set("#b", "beta");
    try std.testing.expect(welcome.clear("#a"));
    try std.testing.expect(!welcome.clear("#a"));
    try std.testing.expect(welcome.get("#a") == null);
    try std.testing.expectEqualStrings("beta", welcome.get("#b").?);
}

test "message cap is enforced" {
    var welcome = ChannelWelcome.init(std.testing.allocator);
    defer welcome.deinit();

    const long = "x" ** 401;
    try std.testing.expectError(error.MessageTooLong, welcome.set("#dev", long));
}
