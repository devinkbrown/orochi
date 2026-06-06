const std = @import("std");

const max_entries = 4096;
const max_key_len = 64;

pub const CooldownError = error{
    KeyTooLong,
    NegativeInterval,
    TimeOverflow,
    TooManyEntries,
};

pub const Cooldown = struct {
    allocator: std.mem.Allocator,
    next_allowed: std.StringHashMap(i64),

    pub fn init(allocator: std.mem.Allocator) Cooldown {
        return .{
            .allocator = allocator,
            .next_allowed = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn deinit(self: *Cooldown) void {
        var it = self.next_allowed.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.next_allowed.deinit();
        self.* = undefined;
    }

    pub fn allow(self: *Cooldown, key: []const u8, now: i64, interval_ms: i64) !bool {
        try checkKey(key);
        if (interval_ms < 0) return CooldownError.NegativeInterval;

        if (self.next_allowed.get(key)) |next| {
            if (now < next) return false;
            const entry = self.next_allowed.getPtr(key).?;
            entry.* = try nextTime(now, interval_ms);
            return true;
        }

        if (self.next_allowed.count() >= max_entries) return CooldownError.TooManyEntries;
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.next_allowed.put(owned_key, try nextTime(now, interval_ms));
        return true;
    }

    pub fn remaining(self: *const Cooldown, key: []const u8, now: i64) i64 {
        if (!validKey(key)) return 0;
        const next = self.next_allowed.get(key) orelse return 0;
        if (now >= next) return 0;
        return next - now;
    }
};

fn nextTime(now: i64, interval_ms: i64) CooldownError!i64 {
    return std.math.add(i64, now, interval_ms) catch CooldownError.TimeOverflow;
}

fn checkKey(key: []const u8) CooldownError!void {
    if (!validKey(key)) return CooldownError.KeyTooLong;
}

fn validKey(key: []const u8) bool {
    return key.len <= max_key_len;
}

const testing = std.testing;

test "new key is allowed and armed" {
    var cd = Cooldown.init(testing.allocator);
    defer cd.deinit();

    try testing.expect(try cd.allow("nick", 1000, 250));
    try testing.expectEqual(@as(i64, 250), cd.remaining("nick", 1000));
    try testing.expectEqual(@as(i64, 0), cd.remaining("other", 1000));
}

test "key is denied until the interval elapses" {
    var cd = Cooldown.init(testing.allocator);
    defer cd.deinit();

    try testing.expect(try cd.allow("nick", 1000, 500));
    try testing.expect(!(try cd.allow("nick", 1200, 500)));
    try testing.expectEqual(@as(i64, 300), cd.remaining("nick", 1200));
    try testing.expect(try cd.allow("nick", 1500, 500));
}

test "elapsed key is rearmed from the current time" {
    var cd = Cooldown.init(testing.allocator);
    defer cd.deinit();

    try testing.expect(try cd.allow("topic", 10, 5));
    try testing.expect(try cd.allow("topic", 20, 7));
    try testing.expectEqual(@as(i64, 7), cd.remaining("topic", 20));
}

test "caps and invalid intervals are rejected" {
    var cd = Cooldown.init(testing.allocator);
    defer cd.deinit();

    var long_key: [max_key_len + 1]u8 = undefined;
    @memset(&long_key, 'k');
    try testing.expectError(CooldownError.KeyTooLong, cd.allow(&long_key, 0, 1));
    try testing.expectError(CooldownError.NegativeInterval, cd.allow("nick", 0, -1));
    try testing.expectError(CooldownError.TimeOverflow, cd.allow("edge", std.math.maxInt(i64), 1));
}
