//! Per-channel pinned message store.
//!
//! Each channel owns a bounded FIFO ring of pinned messages. Pinning an
//! existing message id refreshes its stored text and actor without increasing
//! the ring depth.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_channel_bytes: usize = 128;
pub const max_msgid_bytes: usize = 128;
pub const max_text_bytes: usize = 400;
pub const max_by_bytes: usize = 128;
pub const max_per_channel: usize = 50;

pub const Error = std.mem.Allocator.Error || error{
    InvalidChannel,
    InvalidMsgid,
    InvalidText,
    InvalidActor,
    TooManyChannels,
};

pub const PinnedMessage = struct {
    msgid: []u8,
    text: []u8,
    by: []u8,

    fn deinit(self: *PinnedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.msgid);
        allocator.free(self.text);
        allocator.free(self.by);
        self.* = undefined;
    }
};

const Ring = struct {
    items: std.ArrayListUnmanaged(PinnedMessage) = .empty,

    fn deinit(self: *Ring, allocator: std.mem.Allocator) void {
        for (self.items.items) |*item| item.deinit(allocator);
        self.items.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const Ring, msgid: []const u8) ?usize {
        for (self.items.items, 0..) |item, index| {
            if (std.mem.eql(u8, item.msgid, msgid)) return index;
        }
        return null;
    }
};

pub const PinnedMessages = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(Ring),

    pub fn init(allocator: std.mem.Allocator) PinnedMessages {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(Ring).init(allocator),
        };
    }

    pub fn deinit(self: *PinnedMessages) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    /// Pin or update a message, returning the channel pin count.
    pub fn pin(self: *PinnedMessages, channel: []const u8, msgid: []const u8, text: []const u8, by: []const u8) Error!usize {
        try validateChannel(channel);
        try validateMsgid(msgid);
        try validateText(text);
        try validateActor(by);

        var owned = PinnedMessage{
            .msgid = try self.allocator.dupe(u8, msgid),
            .text = undefined,
            .by = undefined,
        };
        errdefer self.allocator.free(owned.msgid);
        owned.text = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned.text);
        owned.by = try self.allocator.dupe(u8, by);
        errdefer self.allocator.free(owned.by);

        const ring = try self.ensureChannel(channel);
        if (ring.indexOf(msgid)) |index| {
            ring.items.items[index].deinit(self.allocator);
            ring.items.items[index] = owned;
            return ring.items.items.len;
        }

        try ring.items.append(self.allocator, owned);
        if (ring.items.items.len > max_per_channel) {
            var evicted = ring.items.orderedRemove(0);
            evicted.deinit(self.allocator);
        }
        return ring.items.items.len;
    }

    pub fn unpin(self: *PinnedMessages, channel: []const u8, msgid: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const index = entry.value_ptr.indexOf(msgid) orelse return false;
        var removed = entry.value_ptr.items.orderedRemove(index);
        removed.deinit(self.allocator);
        if (entry.value_ptr.items.items.len == 0) {
            const key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.channels.removeByPtr(entry.key_ptr);
            self.allocator.free(key);
        }
        return true;
    }

    /// Borrowed pinned messages for `channel`, oldest first.
    pub fn list(self: *const PinnedMessages, channel: []const u8) []const PinnedMessage {
        const ring = self.channels.getPtr(channel) orelse return &.{};
        return ring.items.items;
    }

    fn ensureChannel(self: *PinnedMessages, channel: []const u8) Error!*Ring {
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

fn validateMsgid(msgid: []const u8) Error!void {
    if (msgid.len == 0 or msgid.len > max_msgid_bytes) return error.InvalidMsgid;
}

fn validateText(text: []const u8) Error!void {
    if (text.len == 0 or text.len > max_text_bytes) return error.InvalidText;
}

fn validateActor(by: []const u8) Error!void {
    if (by.len == 0 or by.len > max_by_bytes) return error.InvalidActor;
}

const testing = std.testing;

test "pin lists messages in insertion order" {
    var pins = PinnedMessages.init(testing.allocator);
    defer pins.deinit();

    try testing.expectEqual(@as(usize, 1), try pins.pin("#main", "m1", "hello", "alice"));
    try testing.expectEqual(@as(usize, 2), try pins.pin("#main", "m2", "world", "bob"));

    const listed = pins.list("#main");
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("m1", listed[0].msgid);
    try testing.expectEqualStrings("world", listed[1].text);
}

test "pin updates existing message id without adding another entry" {
    var pins = PinnedMessages.init(testing.allocator);
    defer pins.deinit();

    try testing.expectEqual(@as(usize, 1), try pins.pin("#main", "m1", "old", "alice"));
    try testing.expectEqual(@as(usize, 1), try pins.pin("#main", "m1", "new", "carol"));

    const listed = pins.list("#main");
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings("new", listed[0].text);
    try testing.expectEqualStrings("carol", listed[0].by);
}

test "unpin removes entries and prunes empty channels" {
    var pins = PinnedMessages.init(testing.allocator);
    defer pins.deinit();

    _ = try pins.pin("#main", "m1", "one", "alice");
    _ = try pins.pin("#main", "m2", "two", "bob");

    try testing.expect(pins.unpin("#main", "m1"));
    try testing.expect(!pins.unpin("#main", "m1"));
    try testing.expectEqual(@as(usize, 1), pins.list("#main").len);
    try testing.expect(pins.unpin("#main", "m2"));
    try testing.expectEqual(@as(usize, 0), pins.list("#main").len);
}

test "ring cap evicts oldest pin" {
    var pins = PinnedMessages.init(testing.allocator);
    defer pins.deinit();

    var i: usize = 0;
    while (i < max_per_channel + 3) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const msgid = try std.fmt.bufPrint(&id_buf, "m{}", .{i});
        _ = try pins.pin("#main", msgid, "text", "actor");
    }

    const listed = pins.list("#main");
    try testing.expectEqual(max_per_channel, listed.len);
    try testing.expectEqualStrings("m3", listed[0].msgid);
}
