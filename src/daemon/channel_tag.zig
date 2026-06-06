//! Per-channel tag sets for lightweight room metadata.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    ChannelTooLong,
    EmptyTag,
    TagTooLong,
    TooManyChannels,
    TooManyTags,
};

pub const Config = struct {
    max_channels: usize = 4096,
    max_channel_len: usize = 128,
    max_tag_len: usize = 48,
    max_tags_per_channel: usize = 32,
};

const TagList = struct {
    tags: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *TagList, allocator: std.mem.Allocator) void {
        for (self.tags.items) |tag| allocator.free(tag);
        self.tags.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const TagList, tag: []const u8) ?usize {
        for (self.tags.items, 0..) |item, idx| {
            if (std.mem.eql(u8, item, tag)) return idx;
        }
        return null;
    }
};

pub const ChannelTag = struct {
    allocator: std.mem.Allocator,
    config: Config,
    channels: std.StringHashMap(TagList),

    pub fn init(allocator: std.mem.Allocator) ChannelTag {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) ChannelTag {
        return .{
            .allocator = allocator,
            .config = config,
            .channels = std.StringHashMap(TagList).init(allocator),
        };
    }

    pub fn deinit(self: *ChannelTag) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn add(self: *ChannelTag, channel: []const u8, tag: []const u8) Error!bool {
        try self.validateChannel(channel);
        try self.validateTag(tag);

        const tag_list = try self.ensureChannel(channel);
        if (tag_list.indexOf(tag) != null) return false;
        if (tag_list.tags.items.len >= self.config.max_tags_per_channel) return error.TooManyTags;

        const owned = try self.allocator.dupe(u8, tag);
        errdefer self.allocator.free(owned);
        try tag_list.tags.append(self.allocator, owned);
        return true;
    }

    pub fn remove(self: *ChannelTag, channel: []const u8, tag: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const idx = entry.value_ptr.indexOf(tag) orelse return false;
        self.allocator.free(entry.value_ptr.tags.items[idx]);
        _ = entry.value_ptr.tags.orderedRemove(idx);
        if (entry.value_ptr.tags.items.len == 0) self.dropChannel(entry);
        return true;
    }

    pub fn has(self: *const ChannelTag, channel: []const u8, tag: []const u8) bool {
        const list_ref = self.channels.getPtr(channel) orelse return false;
        return list_ref.indexOf(tag) != null;
    }

    pub fn list(self: *const ChannelTag, channel: []const u8) []const []const u8 {
        const list_ref = self.channels.getPtr(channel) orelse return &.{};
        return list_ref.tags.items;
    }

    fn ensureChannel(self: *ChannelTag, channel: []const u8) Error!*TagList {
        if (self.channels.getPtr(channel)) |list_ref| return list_ref;
        if (self.channels.count() >= self.config.max_channels) return error.TooManyChannels;

        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }

    fn dropChannel(self: *ChannelTag, entry: std.StringHashMap(TagList).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn validateChannel(self: *const ChannelTag, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.config.max_channel_len) return error.ChannelTooLong;
    }

    fn validateTag(self: *const ChannelTag, tag: []const u8) Error!void {
        if (tag.len == 0) return error.EmptyTag;
        if (tag.len > self.config.max_tag_len) return error.TagTooLong;
    }
};

const testing = std.testing;

test "add stores tags and deduplicates by channel" {
    var tags = ChannelTag.init(testing.allocator);
    defer tags.deinit();

    try testing.expect(try tags.add("#main", "help"));
    try testing.expect(!try tags.add("#main", "help"));
    try testing.expect(try tags.add("#main", "chat"));
    try testing.expect(tags.has("#main", "help"));
    try testing.expectEqual(@as(usize, 2), tags.list("#main").len);
}

test "remove prunes empty channel state" {
    var tags = ChannelTag.init(testing.allocator);
    defer tags.deinit();

    _ = try tags.add("#main", "ops");
    try testing.expect(tags.remove("#main", "ops"));
    try testing.expect(!tags.remove("#main", "ops"));
    try testing.expect(!tags.has("#main", "ops"));
    try testing.expectEqual(@as(usize, 0), tags.list("#main").len);
}

test "per-channel tag cap is enforced" {
    var tags = ChannelTag.initWithConfig(testing.allocator, .{ .max_tags_per_channel = 2 });
    defer tags.deinit();

    _ = try tags.add("#main", "a");
    _ = try tags.add("#main", "b");
    try testing.expectError(error.TooManyTags, tags.add("#main", "c"));
}

test "input caps reject empty and oversized values" {
    var tags = ChannelTag.initWithConfig(testing.allocator, .{ .max_channel_len = 4, .max_tag_len = 3 });
    defer tags.deinit();

    try testing.expectError(error.EmptyChannel, tags.add("", "ok"));
    try testing.expectError(error.ChannelTooLong, tags.add("#toolong", "ok"));
    try testing.expectError(error.EmptyTag, tags.add("#ok", ""));
    try testing.expectError(error.TagTooLong, tags.add("#ok", "long"));
}
