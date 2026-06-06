const std = @import("std");

pub const FloodScore = struct {
    pub const max_accounts: usize = 65536;
    pub const max_account_len: usize = 128;
    pub const decay_interval_ms: i64 = 1000;
    pub const max_score: u32 = std.math.maxInt(u32);

    allocator: std.mem.Allocator,
    entries: std.StringHashMap(Entry),

    pub fn init(allocator: std.mem.Allocator) FloodScore {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *FloodScore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn bump(self: *FloodScore, account: []const u8, points: u32, now_ms: i64) u32 {
        const entry = self.entryFor(account, now_ms) catch return max_score;
        decay(entry, now_ms);
        entry.score = saturatingAdd(entry.score, points);
        return entry.score;
    }

    pub fn tripped(self: *FloodScore, account: []const u8, now_ms: i64, threshold: u32) bool {
        if (threshold == 0) return true;
        if (!validAccount(account)) return true;
        const entry = self.entries.getPtr(account) orelse return false;
        decay(entry, now_ms);
        return entry.score >= threshold;
    }

    pub fn scoreOf(self: *FloodScore, account: []const u8, now_ms: i64) ?u32 {
        if (!validAccount(account)) return null;
        const entry = self.entries.getPtr(account) orelse return null;
        decay(entry, now_ms);
        return entry.score;
    }

    pub fn accountCount(self: *const FloodScore) usize {
        return self.entries.count();
    }

    fn entryFor(self: *FloodScore, account: []const u8, now_ms: i64) !*Entry {
        if (!validAccount(account)) return error.InvalidAccount;
        if (self.entries.getPtr(account)) |entry| return entry;
        if (self.entries.count() >= max_accounts) return error.TooManyAccounts;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);

        try self.entries.put(owned, .{
            .score = 0,
            .last_decay_ms = now_ms,
        });
        return self.entries.getPtr(owned).?;
    }

    fn validAccount(account: []const u8) bool {
        return account.len > 0 and account.len <= max_account_len;
    }
};

const Entry = struct {
    score: u32,
    last_decay_ms: i64,
};

fn decay(entry: *Entry, now_ms: i64) void {
    if (now_ms <= entry.last_decay_ms) return;

    const elapsed = now_ms - entry.last_decay_ms;
    const elapsed_steps = @divTrunc(elapsed, FloodScore.decay_interval_ms);
    const steps: u32 = @intCast(@min(@as(i64, std.math.maxInt(u32)), elapsed_steps));
    if (steps == 0) return;

    if (steps >= entry.score) {
        entry.score = 0;
        entry.last_decay_ms = now_ms;
        return;
    }

    entry.score -= steps;
    entry.last_decay_ms += @as(i64, @intCast(steps)) * FloodScore.decay_interval_ms;
}

fn saturatingAdd(a: u32, b: u32) u32 {
    const sum = @as(u64, a) + @as(u64, b);
    return if (sum > FloodScore.max_score) FloodScore.max_score else @intCast(sum);
}

test "bump records and accumulates score" {
    var scores = FloodScore.init(std.testing.allocator);
    defer scores.deinit();

    try std.testing.expectEqual(@as(u32, 3), scores.bump("alice", 3, 100));
    try std.testing.expectEqual(@as(u32, 7), scores.bump("alice", 4, 100));
    try std.testing.expectEqual(@as(usize, 1), scores.accountCount());
}

test "elapsed time decays before adding points" {
    var scores = FloodScore.init(std.testing.allocator);
    defer scores.deinit();

    try std.testing.expectEqual(@as(u32, 10), scores.bump("bob", 10, 0));
    try std.testing.expectEqual(@as(u32, 8), scores.bump("bob", 0, 2500));
    try std.testing.expectEqual(@as(u32, 7), scores.bump("bob", 0, 3000));
    try std.testing.expectEqual(@as(u32, 0), scores.bump("bob", 0, 10000));
}

test "tripped uses decayed score and handles unknown accounts" {
    var scores = FloodScore.init(std.testing.allocator);
    defer scores.deinit();

    try std.testing.expect(!scores.tripped("carol", 0, 1));
    _ = scores.bump("carol", 5, 0);
    try std.testing.expect(scores.tripped("carol", 0, 5));
    try std.testing.expect(!scores.tripped("carol", 3000, 5));
    try std.testing.expect(scores.tripped("carol", 3000, 2));
}

test "score clamps at u32 maximum" {
    var scores = FloodScore.init(std.testing.allocator);
    defer scores.deinit();

    try std.testing.expectEqual(FloodScore.max_score, scores.bump("delta", FloodScore.max_score, 0));
    try std.testing.expectEqual(FloodScore.max_score, scores.bump("delta", 1, 0));
}
