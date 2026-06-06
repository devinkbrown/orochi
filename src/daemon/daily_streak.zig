//! Per-account consecutive-day check-in streaks.
const std = @import("std");

const Record = struct {
    last_day: i64,
    count: u32,
};

pub const DailyStreak = struct {
    allocator: std.mem.Allocator,
    records: std.StringHashMap(Record),

    pub fn init(allocator: std.mem.Allocator) DailyStreak {
        return .{
            .allocator = allocator,
            .records = std.StringHashMap(Record).init(allocator),
        };
    }

    pub fn deinit(self: *DailyStreak) void {
        var it = self.records.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.records.deinit();
        self.* = undefined;
    }

    pub fn checkin(self: *DailyStreak, account: []const u8, day_index: i64) std.mem.Allocator.Error!u32 {
        if (self.records.getEntry(account)) |entry| {
            const current = entry.value_ptr;
            if (day_index == current.last_day) return current.count;

            if (day_index == current.last_day + 1) {
                current.count = std.math.add(u32, current.count, 1) catch std.math.maxInt(u32);
            } else {
                current.count = 1;
            }
            current.last_day = day_index;
            return current.count;
        }

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.records.putNoClobber(owned, .{ .last_day = day_index, .count = 1 });
        return 1;
    }

    pub fn streak(self: *const DailyStreak, account: []const u8) u32 {
        const record = self.records.get(account) orelse return 0;
        return record.count;
    }
};

const testing = std.testing;

test "first checkin starts a streak" {
    var daily = DailyStreak.init(testing.allocator);
    defer daily.deinit();

    try testing.expectEqual(@as(u32, 1), try daily.checkin("alice", 10));
    try testing.expectEqual(@as(u32, 1), daily.streak("alice"));
    try testing.expectEqual(@as(u32, 0), daily.streak("missing"));
}

test "same day is idempotent and next day increments" {
    var daily = DailyStreak.init(testing.allocator);
    defer daily.deinit();

    try testing.expectEqual(@as(u32, 1), try daily.checkin("alice", 10));
    try testing.expectEqual(@as(u32, 1), try daily.checkin("alice", 10));
    try testing.expectEqual(@as(u32, 2), try daily.checkin("alice", 11));
    try testing.expectEqual(@as(u32, 2), daily.streak("alice"));
}

test "gaps and earlier days reset" {
    var daily = DailyStreak.init(testing.allocator);
    defer daily.deinit();

    _ = try daily.checkin("alice", 10);
    _ = try daily.checkin("alice", 11);
    try testing.expectEqual(@as(u32, 1), try daily.checkin("alice", 13));
    try testing.expectEqual(@as(u32, 1), try daily.checkin("alice", 12));
}
