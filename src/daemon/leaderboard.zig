const std = @import("std");

const max_entries = 4096;
const max_name_len = 64;

pub const LeaderboardError = error{
    NameTooLong,
    TooManyEntries,
};

pub const Leaderboard = struct {
    allocator: std.mem.Allocator,
    scores: std.StringHashMap(i64),

    pub const Entry = struct {
        name: []const u8,
        score: i64,
    };

    pub fn init(allocator: std.mem.Allocator) Leaderboard {
        return .{
            .allocator = allocator,
            .scores = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn deinit(self: *Leaderboard) void {
        var it = self.scores.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.scores.deinit();
        self.* = undefined;
    }

    pub fn set(self: *Leaderboard, name: []const u8, score: i64) !void {
        try checkName(name);
        if (!self.scores.contains(name) and self.scores.count() >= max_entries) {
            return LeaderboardError.TooManyEntries;
        }

        if (self.scores.getPtr(name)) |stored_score| {
            stored_score.* = score;
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.scores.put(owned_name, score);
    }

    pub fn top(self: *const Leaderboard, n: usize, out: []Entry) usize {
        const limit = @min(n, out.len);
        var written: usize = 0;

        while (written < limit) : (written += 1) {
            var best: ?Entry = null;
            var it = self.scores.iterator();
            while (it.next()) |entry| {
                const candidate: Entry = .{
                    .name = entry.key_ptr.*,
                    .score = entry.value_ptr.*,
                };
                if (alreadySelected(out[0..written], candidate.name)) continue;
                if (best == null or entryBeats(candidate, best.?)) best = candidate;
            }
            out[written] = best orelse return written;
        }

        return written;
    }

    pub fn scoreOf(self: *const Leaderboard, name: []const u8) ?i64 {
        if (!validName(name)) return null;
        return self.scores.get(name);
    }
};

fn entryBeats(a: Leaderboard.Entry, b: Leaderboard.Entry) bool {
    if (a.score != b.score) return a.score > b.score;
    return std.mem.lessThan(u8, a.name, b.name);
}

fn alreadySelected(entries: []const Leaderboard.Entry, name: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return true;
    }
    return false;
}

fn checkName(name: []const u8) LeaderboardError!void {
    if (!validName(name)) return LeaderboardError.NameTooLong;
}

fn validName(name: []const u8) bool {
    return name.len <= max_name_len;
}

const testing = std.testing;

test "set and score lookup" {
    var board = Leaderboard.init(testing.allocator);
    defer board.deinit();

    try board.set("alice", 10);
    try board.set("bob", -3);

    try testing.expectEqual(@as(?i64, 10), board.scoreOf("alice"));
    try testing.expectEqual(@as(?i64, -3), board.scoreOf("bob"));
    try testing.expect(board.scoreOf("carol") == null);
}

test "top returns scores in descending order" {
    var board = Leaderboard.init(testing.allocator);
    defer board.deinit();

    try board.set("alice", 10);
    try board.set("bob", 30);
    try board.set("carol", 20);

    var out: [2]Leaderboard.Entry = undefined;
    const count = board.top(2, &out);

    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("bob", out[0].name);
    try testing.expectEqual(@as(i64, 30), out[0].score);
    try testing.expectEqualStrings("carol", out[1].name);
}

test "top uses name ordering for equal scores" {
    var board = Leaderboard.init(testing.allocator);
    defer board.deinit();

    try board.set("zoe", 5);
    try board.set("amy", 5);

    var out: [2]Leaderboard.Entry = undefined;
    try testing.expectEqual(@as(usize, 2), board.top(10, &out));
    try testing.expectEqualStrings("amy", out[0].name);
    try testing.expectEqualStrings("zoe", out[1].name);
}

test "set replaces scores and enforces name caps" {
    var board = Leaderboard.init(testing.allocator);
    defer board.deinit();

    try board.set("alice", 1);
    try board.set("alice", 42);
    try testing.expectEqual(@as(?i64, 42), board.scoreOf("alice"));

    var long_name: [max_name_len + 1]u8 = undefined;
    @memset(&long_name, 'n');
    try testing.expectError(LeaderboardError.NameTooLong, board.set(&long_name, 1));
}
