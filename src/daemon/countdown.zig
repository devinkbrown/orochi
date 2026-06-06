//! Named timestamp countdowns.
const std = @import("std");

pub const CountdownEntry = struct {
    target_ms: i64,
};

pub const Error = std.mem.Allocator.Error;

pub const Countdown = struct {
    allocator: std.mem.Allocator,
    targets: std.StringHashMap(CountdownEntry),

    pub fn init(allocator: std.mem.Allocator) Countdown {
        return .{
            .allocator = allocator,
            .targets = std.StringHashMap(CountdownEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Countdown) void {
        var iterator = self.targets.iterator();
        while (iterator.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.targets.deinit();
        self.* = undefined;
    }

    pub fn set(self: *Countdown, name: []const u8, target_ms: i64) Error!void {
        if (self.targets.getPtr(name)) |entry| {
            entry.target_ms = target_ms;
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.targets.putNoClobber(owned_name, .{ .target_ms = target_ms });
    }

    pub fn remaining(self: *const Countdown, name: []const u8, now_ms: i64) ?i64 {
        const entry = self.targets.get(name) orelse return null;
        return entry.target_ms - now_ms;
    }

    pub fn clear(self: *Countdown, name: []const u8) bool {
        const entry = self.targets.getEntry(name) orelse return false;
        const owned_name = entry.key_ptr.*;
        self.targets.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_name);
        return true;
    }
};

const testing = std.testing;

test "set creates a countdown target" {
    var countdown = Countdown.init(testing.allocator);
    defer countdown.deinit();

    try countdown.set("launch", 10_000);
    try testing.expectEqual(@as(?i64, 2500), countdown.remaining("launch", 7500));
}

test "set replaces a countdown target" {
    var countdown = Countdown.init(testing.allocator);
    defer countdown.deinit();

    try countdown.set("launch", 10_000);
    try countdown.set("launch", 20_000);
    try testing.expectEqual(@as(?i64, 12_500), countdown.remaining("launch", 7500));
}

test "remaining returns null for unknown names" {
    var countdown = Countdown.init(testing.allocator);
    defer countdown.deinit();

    try testing.expectEqual(@as(?i64, null), countdown.remaining("missing", 0));
}

test "clear removes a countdown once" {
    var countdown = Countdown.init(testing.allocator);
    defer countdown.deinit();

    try countdown.set("topic", 100);
    try testing.expect(countdown.clear("topic"));
    try testing.expect(!countdown.clear("topic"));
    try testing.expectEqual(@as(?i64, null), countdown.remaining("topic", 100));
}
