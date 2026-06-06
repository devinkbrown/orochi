const std = @import("std");

pub const RateQuota = struct {
    const Entry = struct {
        window_start_ms: i64,
        used_units: u64,
    };

    allocator: std.mem.Allocator,
    quotas: std.StringHashMap(Entry),

    pub fn init(allocator: std.mem.Allocator) RateQuota {
        return .{
            .allocator = allocator,
            .quotas = std.StringHashMap(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *RateQuota) void {
        var it = self.quotas.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.quotas.deinit();
    }

    pub fn consume(
        self: *RateQuota,
        account: []const u8,
        units: u64,
        now_ms: i64,
        limit: u64,
        window_ms: i64,
    ) !bool {
        if (window_ms <= 0) return false;

        if (self.quotas.getPtr(account)) |entry| {
            if (isExpired(entry.window_start_ms, now_ms, window_ms)) {
                entry.* = .{
                    .window_start_ms = now_ms,
                    .used_units = 0,
                };
            }

            return consumeEntry(entry, units, limit);
        }

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);

        try self.quotas.putNoClobber(owned_account, .{
            .window_start_ms = now_ms,
            .used_units = 0,
        });

        return consumeEntry(self.quotas.getPtr(account).?, units, limit);
    }

    pub fn used(self: *RateQuota, account: []const u8, now_ms: i64, window_ms: i64) u64 {
        if (window_ms <= 0) return 0;
        const entry = self.quotas.get(account) orelse return 0;
        if (isExpired(entry.window_start_ms, now_ms, window_ms)) return 0;
        return entry.used_units;
    }

    fn consumeEntry(entry: *Entry, units: u64, limit: u64) bool {
        const next = std.math.add(u64, entry.used_units, units) catch return false;
        if (next > limit) return false;

        entry.used_units = next;
        return true;
    }

    fn isExpired(start_ms: i64, now_ms: i64, window_ms: i64) bool {
        return now_ms < start_ms or now_ms - start_ms >= window_ms;
    }
};

test "RateQuota consumes units under limit" {
    var quota = RateQuota.init(std.testing.allocator);
    defer quota.deinit();

    try std.testing.expect(try quota.consume("alice", 3, 1_000, 10, 86_400_000));
    try std.testing.expect(try quota.consume("alice", 7, 1_100, 10, 86_400_000));
    try std.testing.expectEqual(@as(u64, 10), quota.used("alice", 1_200, 86_400_000));
}

test "RateQuota rejects over limit without incrementing" {
    var quota = RateQuota.init(std.testing.allocator);
    defer quota.deinit();

    try std.testing.expect(try quota.consume("bob", 8, 0, 10, 1_000));
    try std.testing.expect(!try quota.consume("bob", 3, 1, 10, 1_000));
    try std.testing.expectEqual(@as(u64, 8), quota.used("bob", 1, 1_000));
}

test "RateQuota resets after window" {
    var quota = RateQuota.init(std.testing.allocator);
    defer quota.deinit();

    try std.testing.expect(try quota.consume("carol", 5, 100, 5, 50));
    try std.testing.expectEqual(@as(u64, 0), quota.used("carol", 150, 50));
    try std.testing.expect(try quota.consume("carol", 2, 150, 5, 50));
    try std.testing.expectEqual(@as(u64, 2), quota.used("carol", 151, 50));
}
