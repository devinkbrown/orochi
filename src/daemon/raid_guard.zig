const std = @import("std");

pub const RaidGuard = struct {
    pub const default_window_ms: i64 = 10_000;
    pub const max_channels: usize = 256;
    pub const max_channel_len: usize = 128;
    pub const max_events_per_channel: usize = 1024;

    pub const Error = std.mem.Allocator.Error || error{
        EmptyChannel,
        ChannelTooLong,
        ChannelLimit,
    };

    const ChannelState = struct {
        name: []u8,
        joins: std.ArrayList(i64) = .empty,

        fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            self.joins.deinit(allocator);
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    channels: std.ArrayList(ChannelState) = .empty,
    window_ms: i64 = default_window_ms,

    pub fn init(allocator: std.mem.Allocator) RaidGuard {
        return .{ .allocator = allocator };
    }

    pub fn initWithWindow(allocator: std.mem.Allocator, window_ms: i64) RaidGuard {
        return .{
            .allocator = allocator,
            .window_ms = if (window_ms > 0) window_ms else default_window_ms,
        };
    }

    pub fn deinit(self: *RaidGuard) void {
        for (self.channels.items) |*state| {
            state.deinit(self.allocator);
        }
        self.channels.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn record(self: *RaidGuard, channel: []const u8, now_ms: i64) Error!u32 {
        try validateChannel(channel);

        if (self.indexOf(channel)) |idx| {
            return self.recordAt(idx, now_ms);
        }

        self.pruneAll(now_ms);
        self.removeEmptyChannels();
        if (self.channels.items.len >= max_channels) return error.ChannelLimit;

        var state = ChannelState{
            .name = try self.allocator.dupe(u8, channel),
        };
        errdefer state.deinit(self.allocator);

        try self.channels.append(self.allocator, state);
        errdefer {
            var removed = self.channels.orderedRemove(self.channels.items.len - 1);
            removed.deinit(self.allocator);
        }
        return self.recordAt(self.channels.items.len - 1, now_ms);
    }

    pub fn tripped(self: *RaidGuard, channel: []const u8, now_ms: i64, threshold: u32) bool {
        if (threshold == 0) return false;
        const idx = self.indexOf(channel) orelse return false;
        self.pruneState(&self.channels.items[idx], now_ms);
        return self.channels.items[idx].joins.items.len >= threshold;
    }

    pub fn channelCount(self: *const RaidGuard) usize {
        return self.channels.items.len;
    }

    fn recordAt(self: *RaidGuard, idx: usize, now_ms: i64) Error!u32 {
        const state = &self.channels.items[idx];
        self.pruneState(state, now_ms);
        if (state.joins.items.len == max_events_per_channel) {
            _ = state.joins.orderedRemove(0);
        }
        try state.joins.append(self.allocator, now_ms);
        return @intCast(state.joins.items.len);
    }

    fn indexOf(self: *const RaidGuard, channel: []const u8) ?usize {
        for (self.channels.items, 0..) |state, idx| {
            if (std.mem.eql(u8, state.name, channel)) return idx;
        }
        return null;
    }

    fn pruneAll(self: *RaidGuard, now_ms: i64) void {
        for (self.channels.items) |*state| {
            self.pruneState(state, now_ms);
        }
    }

    fn pruneState(self: *const RaidGuard, state: *ChannelState, now_ms: i64) void {
        var idx: usize = 0;
        while (idx < state.joins.items.len) {
            if (insideWindow(state.joins.items[idx], now_ms, self.window_ms)) {
                idx += 1;
            } else {
                _ = state.joins.orderedRemove(idx);
            }
        }
    }

    fn removeEmptyChannels(self: *RaidGuard) void {
        var idx: usize = 0;
        while (idx < self.channels.items.len) {
            if (self.channels.items[idx].joins.items.len == 0) {
                var removed = self.channels.orderedRemove(idx);
                removed.deinit(self.allocator);
            } else {
                idx += 1;
            }
        }
    }

    fn validateChannel(channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > max_channel_len) return error.ChannelTooLong;
    }

    fn insideWindow(at_ms: i64, now_ms: i64, window_ms: i64) bool {
        if (at_ms > now_ms) return true;
        const delta: i128 = @as(i128, now_ms) - @as(i128, at_ms);
        return delta <= @as(i128, window_ms);
    }
};

const testing = std.testing;

test "record returns per-channel count inside default window" {
    var guard = RaidGuard.init(testing.allocator);
    defer guard.deinit();

    try testing.expectEqual(@as(u32, 1), try guard.record("#a", 0));
    try testing.expectEqual(@as(u32, 2), try guard.record("#a", 5_000));
    try testing.expectEqual(@as(u32, 1), try guard.record("#b", 5_000));
    try testing.expectEqual(@as(u32, 2), try guard.record("#a", 10_001));
}

test "tripped observes threshold after pruning" {
    var guard = RaidGuard.initWithWindow(testing.allocator, 100);
    defer guard.deinit();

    _ = try guard.record("#a", 0);
    _ = try guard.record("#a", 50);

    try testing.expect(guard.tripped("#a", 50, 2));
    try testing.expect(!guard.tripped("#a", 101, 2));
    try testing.expect(!guard.tripped("#missing", 101, 1));
}

test "event storage per channel is capped" {
    var guard = RaidGuard.init(testing.allocator);
    defer guard.deinit();

    var i: usize = 0;
    while (i < RaidGuard.max_events_per_channel + 5) : (i += 1) {
        _ = try guard.record("#a", 1);
    }

    try testing.expectEqual(@as(u32, RaidGuard.max_events_per_channel), try guard.record("#a", 1));
    try testing.expect(guard.tripped("#a", 1, RaidGuard.max_events_per_channel));
}

test "channel table is bounded and old empty channels are pruned" {
    var guard = RaidGuard.initWithWindow(testing.allocator, 10);
    defer guard.deinit();

    var i: usize = 0;
    while (i < RaidGuard.max_channels) : (i += 1) {
        var buf: [32]u8 = undefined;
        const channel = try std.fmt.bufPrint(&buf, "#c-{d}", .{i});
        _ = try guard.record(channel, 0);
    }

    try testing.expectError(error.ChannelLimit, guard.record("#overflow", 0));
    try testing.expectEqual(@as(u32, 1), try guard.record("#fresh", 11));
    try testing.expectEqual(@as(usize, 1), guard.channelCount());
}
