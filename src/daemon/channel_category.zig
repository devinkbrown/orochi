//! Channel category labels for room grouping and discovery.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    ChannelTooLong,
    EmptyLabel,
    LabelTooLong,
    TooManyChannels,
};

pub const Config = struct {
    max_channels: usize = 4096,
    max_channel_len: usize = 128,
    max_label_len: usize = 48,
};

pub const ChannelCategory = struct {
    allocator: std.mem.Allocator,
    config: Config,
    labels: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) ChannelCategory {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) ChannelCategory {
        return .{
            .allocator = allocator,
            .config = config,
            .labels = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *ChannelCategory) void {
        var it = self.labels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.labels.deinit();
        self.* = undefined;
    }

    pub fn set(self: *ChannelCategory, channel: []const u8, label: []const u8) Error!void {
        try self.validateChannel(channel);
        try self.validateLabel(label);

        if (self.labels.getEntry(channel)) |entry| {
            const owned_label = try self.allocator.dupe(u8, label);
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = owned_label;
            return;
        }

        if (self.labels.count() >= self.config.max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        const owned_label = try self.allocator.dupe(u8, label);
        errdefer self.allocator.free(owned_label);
        try self.labels.putNoClobber(owned_channel, owned_label);
    }

    pub fn get(self: *const ChannelCategory, channel: []const u8) ?[]const u8 {
        return self.labels.get(channel);
    }

    pub fn clear(self: *ChannelCategory, channel: []const u8) bool {
        const entry = self.labels.getEntry(channel) orelse return false;
        const owned_channel = entry.key_ptr.*;
        const owned_label = entry.value_ptr.*;
        self.labels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_channel);
        self.allocator.free(owned_label);
        return true;
    }

    fn validateChannel(self: *const ChannelCategory, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.config.max_channel_len) return error.ChannelTooLong;
    }

    fn validateLabel(self: *const ChannelCategory, label: []const u8) Error!void {
        if (label.len == 0) return error.EmptyLabel;
        if (label.len > self.config.max_label_len) return error.LabelTooLong;
    }
};

const testing = std.testing;

test "set and get category label" {
    var categories = ChannelCategory.init(testing.allocator);
    defer categories.deinit();

    try categories.set("#main", "general");
    try testing.expectEqualStrings("general", categories.get("#main").?);
    try testing.expect(categories.get("#missing") == null);
}

test "set replaces existing label without changing other channels" {
    var categories = ChannelCategory.init(testing.allocator);
    defer categories.deinit();

    try categories.set("#main", "general");
    try categories.set("#ops", "staff");
    try categories.set("#main", "support");
    try testing.expectEqualStrings("support", categories.get("#main").?);
    try testing.expectEqualStrings("staff", categories.get("#ops").?);
}

test "clear removes owned label and reports presence" {
    var categories = ChannelCategory.init(testing.allocator);
    defer categories.deinit();

    try categories.set("#main", "general");
    try testing.expect(categories.clear("#main"));
    try testing.expect(!categories.clear("#main"));
    try testing.expect(categories.get("#main") == null);
}

test "label and channel caps are enforced" {
    var categories = ChannelCategory.initWithConfig(testing.allocator, .{ .max_channels = 1, .max_channel_len = 4, .max_label_len = 3 });
    defer categories.deinit();

    try testing.expectError(error.EmptyChannel, categories.set("", "ops"));
    try testing.expectError(error.ChannelTooLong, categories.set("#toolong", "ops"));
    try testing.expectError(error.EmptyLabel, categories.set("#ok", ""));
    try testing.expectError(error.LabelTooLong, categories.set("#ok", "long"));
    try categories.set("#one", "ops");
    try testing.expectError(error.TooManyChannels, categories.set("#two", "net"));
}
