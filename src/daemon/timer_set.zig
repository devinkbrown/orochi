//! Named countdown timers.
const std = @import("std");

pub const Timer = struct {
    fire_ms: i64,
};

pub const Error = std.mem.Allocator.Error;

pub const TimerSet = struct {
    allocator: std.mem.Allocator,
    timers: std.StringHashMap(Timer),

    pub fn init(allocator: std.mem.Allocator) TimerSet {
        return .{
            .allocator = allocator,
            .timers = std.StringHashMap(Timer).init(allocator),
        };
    }

    pub fn deinit(self: *TimerSet) void {
        var iterator = self.timers.iterator();
        while (iterator.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.timers.deinit();
        self.* = undefined;
    }

    pub fn start(self: *TimerSet, name: []const u8, fire_ms: i64) Error!void {
        if (self.timers.getPtr(name)) |timer| {
            timer.fire_ms = fire_ms;
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.timers.putNoClobber(owned_name, .{ .fire_ms = fire_ms });
    }

    pub fn fired(self: *const TimerSet, name: []const u8, now_ms: i64) bool {
        const timer = self.timers.get(name) orelse return false;
        return now_ms >= timer.fire_ms;
    }

    pub fn cancel(self: *TimerSet, name: []const u8) bool {
        const entry = self.timers.getEntry(name) orelse return false;
        const owned_name = entry.key_ptr.*;
        self.timers.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_name);
        return true;
    }

    pub fn remaining(self: *const TimerSet, name: []const u8, now_ms: i64) i64 {
        const timer = self.timers.get(name) orelse return 0;
        return timer.fire_ms - now_ms;
    }
};

const testing = std.testing;

test "start creates timers and fired observes time" {
    var timers = TimerSet.init(testing.allocator);
    defer timers.deinit();

    try timers.start("quiet", 5000);
    try testing.expect(!timers.fired("quiet", 4999));
    try testing.expect(timers.fired("quiet", 5000));
}

test "start replaces an existing timer" {
    var timers = TimerSet.init(testing.allocator);
    defer timers.deinit();

    try timers.start("quiet", 5000);
    try timers.start("quiet", 9000);
    try testing.expect(!timers.fired("quiet", 8000));
    try testing.expectEqual(@as(i64, 1000), timers.remaining("quiet", 8000));
}

test "cancel removes a timer once" {
    var timers = TimerSet.init(testing.allocator);
    defer timers.deinit();

    try timers.start("topic", 100);
    try testing.expect(timers.cancel("topic"));
    try testing.expect(!timers.cancel("topic"));
    try testing.expect(!timers.fired("topic", 200));
}

test "remaining can be negative after fire time" {
    var timers = TimerSet.init(testing.allocator);
    defer timers.deinit();

    try timers.start("burst", 100);
    try testing.expectEqual(@as(i64, -50), timers.remaining("burst", 150));
    try testing.expectEqual(@as(i64, 0), timers.remaining("missing", 150));
}
