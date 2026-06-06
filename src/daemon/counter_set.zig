const std = @import("std");

const max_counters = 4096;
const max_name_len = 64;

pub const CounterSetError = error{
    NameTooLong,
    TooManyCounters,
    CounterOverflow,
};

pub const CounterSet = struct {
    allocator: std.mem.Allocator,
    counters: std.StringHashMap(u64),

    pub fn init(allocator: std.mem.Allocator) CounterSet {
        return .{
            .allocator = allocator,
            .counters = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *CounterSet) void {
        var it = self.counters.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.counters.deinit();
        self.* = undefined;
    }

    pub fn incr(self: *CounterSet, name: []const u8, by: u64) !u64 {
        try checkName(name);
        if (!self.counters.contains(name) and self.counters.count() >= max_counters) {
            return CounterSetError.TooManyCounters;
        }

        if (self.counters.getPtr(name)) |value| {
            if (std.math.maxInt(u64) - value.* < by) return CounterSetError.CounterOverflow;
            value.* += by;
            return value.*;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.counters.put(owned_name, by);
        return by;
    }

    pub fn get(self: *const CounterSet, name: []const u8) u64 {
        if (!validName(name)) return 0;
        return self.counters.get(name) orelse 0;
    }

    pub fn reset(self: *CounterSet, name: []const u8) bool {
        if (!validName(name)) return false;
        const value = self.counters.getPtr(name) orelse return false;
        value.* = 0;
        return true;
    }
};

fn checkName(name: []const u8) CounterSetError!void {
    if (!validName(name)) return CounterSetError.NameTooLong;
}

fn validName(name: []const u8) bool {
    return name.len <= max_name_len;
}

const testing = std.testing;

test "increment creates and accumulates counters" {
    var set = CounterSet.init(testing.allocator);
    defer set.deinit();

    try testing.expectEqual(@as(u64, 1), try set.incr("lines", 1));
    try testing.expectEqual(@as(u64, 6), try set.incr("lines", 5));
    try testing.expectEqual(@as(u64, 6), set.get("lines"));
}

test "missing counters read as zero and reset reports absence" {
    var set = CounterSet.init(testing.allocator);
    defer set.deinit();

    try testing.expectEqual(@as(u64, 0), set.get("missing"));
    try testing.expect(!set.reset("missing"));
}

test "reset keeps the counter name and clears the value" {
    var set = CounterSet.init(testing.allocator);
    defer set.deinit();

    _ = try set.incr("bytes", 100);
    try testing.expect(set.reset("bytes"));
    try testing.expectEqual(@as(u64, 0), set.get("bytes"));
    try testing.expectEqual(@as(u64, 7), try set.incr("bytes", 7));
}

test "caps and overflow are rejected" {
    var set = CounterSet.init(testing.allocator);
    defer set.deinit();

    var long_name: [max_name_len + 1]u8 = undefined;
    @memset(&long_name, 'n');
    try testing.expectError(CounterSetError.NameTooLong, set.incr(&long_name, 1));

    _ = try set.incr("max", std.math.maxInt(u64));
    try testing.expectError(CounterSetError.CounterOverflow, set.incr("max", 1));
}
