//! Per-channel topic history.
//!
//! TopicHistory keeps a small owned FIFO ring for each channel. Callers provide
//! timestamps; this module performs no I/O and reads no clock.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_channel_bytes: usize = 128;
pub const max_setter_bytes: usize = 128;
pub const max_topic_bytes: usize = 400;
pub const max_per_channel: usize = 64;

pub const Error = std.mem.Allocator.Error || error{
    InvalidChannel,
    InvalidSetter,
    InvalidTopic,
    TooManyChannels,
};

pub const TopicEntry = struct {
    setter: []u8,
    topic: []u8,
    at_ms: i64,

    fn deinit(self: *TopicEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.setter);
        allocator.free(self.topic);
        self.* = undefined;
    }
};

const Ring = struct {
    items: std.ArrayListUnmanaged(TopicEntry) = .empty,

    fn deinit(self: *Ring, allocator: std.mem.Allocator) void {
        for (self.items.items) |*entry| entry.deinit(allocator);
        self.items.deinit(allocator);
        self.* = undefined;
    }
};

pub const TopicHistory = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(Ring),

    pub fn init(allocator: std.mem.Allocator) TopicHistory {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(Ring).init(allocator),
        };
    }

    pub fn deinit(self: *TopicHistory) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    /// Append a topic change and return the channel history depth.
    pub fn push(self: *TopicHistory, channel: []const u8, setter: []const u8, topic: []const u8, at_ms: i64) Error!usize {
        try validateChannel(channel);
        try validateSetter(setter);
        try validateTopic(topic);

        var owned_entry = TopicEntry{
            .setter = try self.allocator.dupe(u8, setter),
            .topic = undefined,
            .at_ms = at_ms,
        };
        errdefer self.allocator.free(owned_entry.setter);
        owned_entry.topic = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(owned_entry.topic);

        const ring = try self.ensureChannel(channel);
        try ring.items.append(self.allocator, owned_entry);
        if (ring.items.items.len > max_per_channel) {
            var evicted = ring.items.orderedRemove(0);
            evicted.deinit(self.allocator);
        }
        return ring.items.items.len;
    }

    /// Borrowed entries for `channel`, oldest first. Valid until the next
    /// mutation touching this store.
    pub fn recent(self: *const TopicHistory, channel: []const u8) []const TopicEntry {
        const ring = self.channels.getPtr(channel) orelse return &.{};
        return ring.items.items;
    }

    /// Remove one channel's history and return the number of dropped entries.
    pub fn clearChannel(self: *TopicHistory, channel: []const u8) usize {
        const entry = self.channels.getEntry(channel) orelse return 0;
        const count = entry.value_ptr.items.items.len;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return count;
    }

    fn ensureChannel(self: *TopicHistory, channel: []const u8) Error!*Ring {
        if (self.channels.getPtr(channel)) |ring| return ring;
        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }
};

fn validateChannel(channel: []const u8) Error!void {
    if (channel.len == 0 or channel.len > max_channel_bytes) return error.InvalidChannel;
}

fn validateSetter(setter: []const u8) Error!void {
    if (setter.len == 0 or setter.len > max_setter_bytes) return error.InvalidSetter;
}

fn validateTopic(topic: []const u8) Error!void {
    if (topic.len > max_topic_bytes) return error.InvalidTopic;
}

const testing = std.testing;

test "push and recent keep owned topic entries" {
    var history = TopicHistory.init(testing.allocator);
    defer history.deinit();

    try testing.expectEqual(@as(usize, 1), try history.push("#main", "alice", "first", 10));
    try testing.expectEqual(@as(usize, 2), try history.push("#main", "bob", "second", 20));

    const entries = history.recent("#main");
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("alice", entries[0].setter);
    try testing.expectEqualStrings("second", entries[1].topic);
    try testing.expectEqual(@as(i64, 20), entries[1].at_ms);
}

test "ring evicts oldest entries after the per-channel cap" {
    var history = TopicHistory.init(testing.allocator);
    defer history.deinit();

    var i: usize = 0;
    while (i < max_per_channel + 5) : (i += 1) {
        try testing.expectEqual(@min(i + 1, max_per_channel), try history.push("#main", "setter", "topic", @intCast(i)));
    }

    const entries = history.recent("#main");
    try testing.expectEqual(max_per_channel, entries.len);
    try testing.expectEqual(@as(i64, 5), entries[0].at_ms);
}

test "clearChannel drops one channel without touching others" {
    var history = TopicHistory.init(testing.allocator);
    defer history.deinit();

    _ = try history.push("#a", "alice", "one", 1);
    _ = try history.push("#a", "alice", "two", 2);
    _ = try history.push("#b", "bob", "other", 3);

    try testing.expectEqual(@as(usize, 2), history.clearChannel("#a"));
    try testing.expectEqual(@as(usize, 0), history.recent("#a").len);
    try testing.expectEqual(@as(usize, 1), history.recent("#b").len);
    try testing.expectEqual(@as(usize, 0), history.clearChannel("#missing"));
}

test "validation rejects oversized fields" {
    var history = TopicHistory.init(testing.allocator);
    defer history.deinit();

    var long_topic: [max_topic_bytes + 1]u8 = undefined;
    @memset(&long_topic, 'x');

    try testing.expectError(error.InvalidChannel, history.push("", "setter", "topic", 1));
    try testing.expectError(error.InvalidSetter, history.push("#main", "", "topic", 1));
    try testing.expectError(error.InvalidTopic, history.push("#main", "setter", &long_topic, 1));
    try testing.expectEqual(@as(usize, 0), history.recent("#main").len);
}
