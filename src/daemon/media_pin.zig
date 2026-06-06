//! Bounded per-channel pinned media references.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_pins_per_channel: usize = 50;
pub const max_channel_len: usize = 128;
pub const max_url_len: usize = 2048;
pub const max_actor_len: usize = 128;

pub const Error = std.mem.Allocator.Error || error{
    InvalidChannel,
    FieldTooLong,
    TooManyChannels,
    TooManyPins,
};

pub const Pin = struct {
    url: []u8,
    by: []u8,
};

const PinList = struct {
    pins: std.ArrayListUnmanaged(Pin) = .empty,

    fn deinit(self: *PinList, allocator: std.mem.Allocator) void {
        for (self.pins.items) |pin| {
            allocator.free(pin.url);
            allocator.free(pin.by);
        }
        self.pins.deinit(allocator);
    }

    fn findUrl(self: *const PinList, url: []const u8) ?usize {
        for (self.pins.items, 0..) |pin, i| {
            if (std.mem.eql(u8, pin.url, url)) return i;
        }
        return null;
    }
};

pub const MediaPin = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(PinList),
    channel_limit: usize,

    pub fn init(allocator: std.mem.Allocator) MediaPin {
        return initWithLimit(allocator, max_channels);
    }

    pub fn initWithLimit(allocator: std.mem.Allocator, channel_limit: usize) MediaPin {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(PinList).init(allocator),
            .channel_limit = channel_limit,
        };
    }

    pub fn deinit(self: *MediaPin) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn pin(self: *MediaPin, channel: []const u8, url: []const u8, by: []const u8) Error!usize {
        try validate(channel, url, by);
        const pin_list = try self.ensureChannel(channel);

        if (pin_list.findUrl(url)) |idx| {
            const next_by = try self.allocator.dupe(u8, by);
            errdefer self.allocator.free(next_by);
            self.allocator.free(pin_list.pins.items[idx].by);
            pin_list.pins.items[idx].by = next_by;
            return idx;
        }

        if (pin_list.pins.items.len >= max_pins_per_channel) return error.TooManyPins;
        const owned_url = try self.allocator.dupe(u8, url);
        errdefer self.allocator.free(owned_url);
        const owned_by = try self.allocator.dupe(u8, by);
        errdefer self.allocator.free(owned_by);
        try pin_list.pins.append(self.allocator, .{ .url = owned_url, .by = owned_by });
        return pin_list.pins.items.len - 1;
    }

    pub fn unpin(self: *MediaPin, channel: []const u8, url: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const idx = entry.value_ptr.findUrl(url) orelse return false;
        const old = entry.value_ptr.pins.orderedRemove(idx);
        self.allocator.free(old.url);
        self.allocator.free(old.by);
        if (entry.value_ptr.pins.items.len == 0) self.dropChannel(entry);
        return true;
    }

    pub fn list(self: *const MediaPin, channel: []const u8) []const Pin {
        const pins = self.channels.getPtr(channel) orelse return &.{};
        return pins.pins.items;
    }

    pub fn channelCount(self: *const MediaPin) usize {
        return self.channels.count();
    }

    fn ensureChannel(self: *MediaPin, channel: []const u8) Error!*PinList {
        if (self.channels.getPtr(channel)) |pins| return pins;
        if (self.channels.count() >= self.channel_limit) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }

    fn dropChannel(self: *MediaPin, entry: std.StringHashMap(PinList).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn validate(channel: []const u8, url: []const u8, by: []const u8) Error!void {
        if (channel.len == 0) return error.InvalidChannel;
        if (channel.len > max_channel_len or url.len == 0 or url.len > max_url_len or by.len > max_actor_len) {
            return error.FieldTooLong;
        }
    }
};

const testing = std.testing;

test "pin appends and list returns channel pins" {
    var pins = MediaPin.init(testing.allocator);
    defer pins.deinit();

    try testing.expectEqual(@as(usize, 0), try pins.pin("#room", "https://m.example/a", "alice"));
    try testing.expectEqual(@as(usize, 1), try pins.pin("#room", "https://m.example/b", "bob"));
    const listed = pins.list("#room");
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("https://m.example/a", listed[0].url);
    try testing.expectEqualStrings("alice", listed[0].by);
}

test "pinning an existing url updates the actor" {
    var pins = MediaPin.init(testing.allocator);
    defer pins.deinit();

    try testing.expectEqual(@as(usize, 0), try pins.pin("#room", "https://m.example/a", "alice"));
    try testing.expectEqual(@as(usize, 0), try pins.pin("#room", "https://m.example/a", "carol"));
    const listed = pins.list("#room");
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings("carol", listed[0].by);
}

test "unpin removes and prunes empty channels" {
    var pins = MediaPin.init(testing.allocator);
    defer pins.deinit();

    _ = try pins.pin("#room", "https://m.example/a", "alice");
    try testing.expect(pins.unpin("#room", "https://m.example/a"));
    try testing.expect(!pins.unpin("#room", "https://m.example/a"));
    try testing.expectEqual(@as(usize, 0), pins.list("#room").len);
    try testing.expectEqual(@as(usize, 0), pins.channelCount());
}

test "pin cap is enforced per channel" {
    var pins = MediaPin.init(testing.allocator);
    defer pins.deinit();

    var i: usize = 0;
    while (i < max_pins_per_channel) : (i += 1) {
        var buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&buf, "https://m.example/{d}", .{i});
        _ = try pins.pin("#room", url, "alice");
    }
    try testing.expectError(error.TooManyPins, pins.pin("#room", "https://m.example/full", "alice"));
}
