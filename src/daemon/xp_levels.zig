//! Per-account experience totals and integer level curve.
const std = @import("std");

pub const XpLevels = struct {
    allocator: std.mem.Allocator,
    totals: std.StringHashMap(u64),

    pub const Error = std.mem.Allocator.Error || error{Overflow};

    pub fn init(allocator: std.mem.Allocator) XpLevels {
        return .{
            .allocator = allocator,
            .totals = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *XpLevels) void {
        var it = self.totals.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.totals.deinit();
        self.* = undefined;
    }

    /// Adds XP and returns the new total.
    pub fn add(self: *XpLevels, account: []const u8, xp: u64) Error!u64 {
        if (self.totals.getEntry(account)) |entry| {
            const next = std.math.add(u64, entry.value_ptr.*, xp) catch return error.Overflow;
            entry.value_ptr.* = next;
            return next;
        }

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.totals.putNoClobber(owned, xp);
        return xp;
    }

    pub fn level(self: *const XpLevels, account: []const u8) u32 {
        return levelFor(self.total(account));
    }

    pub fn total(self: *const XpLevels, account: []const u8) u64 {
        return self.totals.get(account) orelse 0;
    }

    fn levelFor(xp: u64) u32 {
        if (xp == 0) return 0;
        const raw = isqrt(xp / 100) + 1;
        return @intCast(@min(raw, std.math.maxInt(u32)));
    }

    fn isqrt(n: u64) u64 {
        var lo: u64 = 0;
        var hi: u64 = @min(n, std.math.maxInt(u32));
        var ans: u64 = 0;
        while (lo <= hi) {
            const mid = lo + (hi - lo) / 2;
            if (mid == 0 or mid <= n / mid) {
                ans = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return ans;
    }
};

const testing = std.testing;

test "add stores per-account totals" {
    var xp = XpLevels.init(testing.allocator);
    defer xp.deinit();

    try testing.expectEqual(@as(u64, 75), try xp.add("alice", 75));
    try testing.expectEqual(@as(u64, 125), try xp.add("alice", 50));
    try testing.expectEqual(@as(u64, 9), try xp.add("bob", 9));
    try testing.expectEqual(@as(u64, 125), xp.total("alice"));
    try testing.expectEqual(@as(u64, 9), xp.total("bob"));
}

test "level follows the integer root curve" {
    var xp = XpLevels.init(testing.allocator);
    defer xp.deinit();

    try testing.expectEqual(@as(u32, 0), xp.level("none"));
    _ = try xp.add("a", 1);
    _ = try xp.add("b", 100);
    _ = try xp.add("c", 400);
    try testing.expectEqual(@as(u32, 1), xp.level("a"));
    try testing.expectEqual(@as(u32, 2), xp.level("b"));
    try testing.expectEqual(@as(u32, 3), xp.level("c"));
}

test "overflow is reported without changing the total" {
    var xp = XpLevels.init(testing.allocator);
    defer xp.deinit();

    _ = try xp.add("alice", std.math.maxInt(u64));
    try testing.expectError(error.Overflow, xp.add("alice", 1));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), xp.total("alice"));
}
