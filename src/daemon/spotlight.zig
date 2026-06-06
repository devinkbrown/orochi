//! Per-channel participant spotlight sets. The set is intentionally small and
//! ordered by insertion so clients can render a stable spotlight strip.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_spotlights_per_channel: usize = 256;
pub const max_channel_bytes: usize = 128;
pub const max_participant_bytes: usize = 64;

pub const Error = std.mem.Allocator.Error || error{ TooManyChannels, TooManySpotlights, InvalidParticipant };

const SpotlightList = struct {
    ids: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *SpotlightList, allocator: std.mem.Allocator) void {
        for (self.ids.items) |id| allocator.free(id);
        self.ids.deinit(allocator);
    }

    fn find(self: *const SpotlightList, pid: []const u8) ?usize {
        for (self.ids.items, 0..) |id, i| {
            if (std.mem.eql(u8, id, pid)) return i;
        }
        return null;
    }
};

pub const Spotlight = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(SpotlightList),

    pub fn init(allocator: std.mem.Allocator) Spotlight {
        return .{ .allocator = allocator, .channels = std.StringHashMap(SpotlightList).init(allocator) };
    }

    pub fn deinit(self: *Spotlight) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn set(self: *Spotlight, channel: []const u8, pid: []const u8) Error!void {
        if (!validName(channel, max_channel_bytes) or !validName(pid, max_participant_bytes)) return error.InvalidParticipant;
        const ids = try self.ensureChannel(channel);
        if (ids.find(pid) != null) return;
        if (ids.ids.items.len >= max_spotlights_per_channel) return error.TooManySpotlights;
        const owned = try self.allocator.dupe(u8, pid);
        errdefer self.allocator.free(owned);
        try ids.ids.append(self.allocator, owned);
    }

    pub fn clear(self: *Spotlight, channel: []const u8, pid: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const idx = entry.value_ptr.find(pid) orelse return false;
        const owned = entry.value_ptr.ids.orderedRemove(idx);
        self.allocator.free(owned);
        if (entry.value_ptr.ids.items.len == 0) {
            const key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.channels.removeByPtr(entry.key_ptr);
            self.allocator.free(key);
        }
        return true;
    }

    pub fn isSpotlighted(self: *const Spotlight, channel: []const u8, pid: []const u8) bool {
        const ids = self.channels.getPtr(channel) orelse return false;
        return ids.find(pid) != null;
    }

    pub fn list(self: *const Spotlight, channel: []const u8) []const []const u8 {
        const ids = self.channels.getPtr(channel) orelse return &.{};
        return ids.ids.items;
    }

    fn ensureChannel(self: *Spotlight, channel: []const u8) Error!*SpotlightList {
        if (self.channels.getPtr(channel)) |ids| return ids;
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

test "set and query spotlight state" {
    var spot = Spotlight.init(testing.allocator);
    defer spot.deinit();

    try spot.set("#call", "alice");
    try testing.expect(spot.isSpotlighted("#call", "alice"));
    try testing.expect(!spot.isSpotlighted("#call", "bob"));
}

test "set is idempotent and list is stable" {
    var spot = Spotlight.init(testing.allocator);
    defer spot.deinit();

    try spot.set("#call", "alice");
    try spot.set("#call", "bob");
    try spot.set("#call", "alice");

    const ids = spot.list("#call");
    try testing.expectEqual(@as(usize, 2), ids.len);
    try testing.expectEqualStrings("alice", ids[0]);
    try testing.expectEqualStrings("bob", ids[1]);
}

test "clear removes and prunes empty channel" {
    var spot = Spotlight.init(testing.allocator);
    defer spot.deinit();

    try spot.set("#call", "alice");
    try testing.expect(spot.clear("#call", "alice"));
    try testing.expect(!spot.clear("#call", "alice"));
    try testing.expectEqual(@as(usize, 0), spot.list("#call").len);
}

test "spotlight cap is enforced" {
    var spot = Spotlight.init(testing.allocator);
    defer spot.deinit();

    var i: usize = 0;
    while (i < max_spotlights_per_channel) : (i += 1) {
        var buf: [32]u8 = undefined;
        const pid = try std.fmt.bufPrint(&buf, "p{}", .{i});
        try spot.set("#call", pid);
    }
    try testing.expectError(error.TooManySpotlights, spot.set("#call", "extra"));
}
