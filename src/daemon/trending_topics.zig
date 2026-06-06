const std = @import("std");

pub const Topic = struct {
    word: []const u8,
    score: u64,
    last_seen: u64,
};

pub const TrendingTopics = struct {
    pub const Config = struct {
        max_topics: usize = 8192,
        max_word_bytes: usize = 64,
        decay_interval: u64 = 60,
    };

    pub const Error = std.mem.Allocator.Error || error{ EmptyWord, TokenTooLong, InvalidWord, TooManyTopics };

    const State = struct {
        score: u64,
        last_seen: u64,
    };

    allocator: std.mem.Allocator,
    cfg: Config,
    topics: std.StringHashMap(State),

    pub fn init(allocator: std.mem.Allocator) TrendingTopics {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) TrendingTopics {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .topics = std.StringHashMap(State).init(allocator),
        };
    }

    pub fn deinit(self: *TrendingTopics) void {
        var it = self.topics.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.topics.deinit();
        self.* = undefined;
    }

    pub fn bump(self: *TrendingTopics, word: []const u8, now: u64) Error!void {
        var buf: [256]u8 = undefined;
        const normalized = try normalizeWord(&buf, word, self.cfg.max_word_bytes);
        const entry = try self.ensureTopic(normalized, now);
        decayState(entry.value_ptr, now, self.cfg.decay_interval);
        entry.value_ptr.score +%= 1;
        if (now > entry.value_ptr.last_seen) entry.value_ptr.last_seen = now;
    }

    pub fn top(self: *TrendingTopics, n: usize, out: []Topic, now: u64) usize {
        const limit = @min(n, out.len);
        if (limit == 0) return 0;

        var used: usize = 0;
        var it = self.topics.iterator();
        while (it.next()) |entry| {
            decayState(entry.value_ptr, now, self.cfg.decay_interval);
            if (entry.value_ptr.score == 0) continue;
            insertTop(out[0..limit], &used, .{
                .word = entry.key_ptr.*,
                .score = entry.value_ptr.score,
                .last_seen = entry.value_ptr.last_seen,
            });
        }
        return used;
    }

    fn ensureTopic(self: *TrendingTopics, word: []const u8, now: u64) Error!std.StringHashMap(State).Entry {
        if (self.topics.getEntry(word)) |entry| return entry;
        if (self.topics.count() >= self.cfg.max_topics) return error.TooManyTopics;

        const owned = try self.allocator.dupe(u8, word);
        errdefer self.allocator.free(owned);
        try self.topics.putNoClobber(owned, .{ .score = 0, .last_seen = now });
        return self.topics.getEntry(owned).?;
    }

    fn normalizeWord(buf: []u8, word: []const u8, max_word_bytes: usize) Error![]const u8 {
        if (word.len == 0) return error.EmptyWord;
        if (word.len > max_word_bytes or word.len > buf.len) return error.TokenTooLong;
        for (word, 0..) |byte, i| {
            if (!(std.ascii.isAlphanumeric(byte) or byte == '_')) return error.InvalidWord;
            buf[i] = std.ascii.toLower(byte);
        }
        return buf[0..word.len];
    }

    fn decayState(state: *State, now: u64, interval: u64) void {
        if (interval == 0 or now <= state.last_seen or state.score == 0) return;
        const steps = (now - state.last_seen) / interval;
        if (steps == 0) return;
        if (steps >= 64) {
            state.score = 0;
        } else {
            state.score >>= @as(u6, @intCast(steps));
        }
        state.last_seen += steps * interval;
    }

    fn insertTop(out: []Topic, used: *usize, item: Topic) void {
        var pos: usize = 0;
        while (pos < used.* and better(out[pos], item)) pos += 1;
        if (pos >= out.len) return;

        if (used.* < out.len) used.* += 1;
        var i = used.* - 1;
        while (i > pos) : (i -= 1) out[i] = out[i - 1];
        out[pos] = item;
    }

    fn better(a: Topic, b: Topic) bool {
        if (a.score != b.score) return a.score > b.score;
        if (a.last_seen != b.last_seen) return a.last_seen > b.last_seen;
        return std.mem.lessThan(u8, a.word, b.word);
    }
};

const testing = std.testing;

test "bump lowercases and ranks topics" {
    var trends = TrendingTopics.init(testing.allocator);
    defer trends.deinit();

    try trends.bump("Zig", 10);
    try trends.bump("zig", 11);
    try trends.bump("chat", 12);

    var out: [3]Topic = undefined;
    const n = trends.top(3, &out, 12);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("zig", out[0].word);
    try testing.expectEqual(@as(u64, 2), out[0].score);
}

test "scores decay by interval while ranking" {
    var trends = TrendingTopics.initWithConfig(testing.allocator, .{
        .max_topics = 8,
        .max_word_bytes = 16,
        .decay_interval = 10,
    });
    defer trends.deinit();

    try trends.bump("alpha", 0);
    try trends.bump("alpha", 0);
    try trends.bump("alpha", 0);
    try trends.bump("alpha", 0);

    var out: [1]Topic = undefined;
    const n = trends.top(1, &out, 20);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u64, 1), out[0].score);
}

test "top respects requested limit" {
    var trends = TrendingTopics.init(testing.allocator);
    defer trends.deinit();

    try trends.bump("one", 1);
    try trends.bump("two", 2);
    try trends.bump("three", 3);

    var out: [3]Topic = undefined;
    const n = trends.top(2, &out, 3);
    try testing.expectEqual(@as(usize, 2), n);
}

test "invalid and oversized words are rejected" {
    var trends = TrendingTopics.initWithConfig(testing.allocator, .{
        .max_topics = 1,
        .max_word_bytes = 8,
        .decay_interval = 60,
    });
    defer trends.deinit();

    try testing.expectError(error.EmptyWord, trends.bump("", 0));
    try testing.expectError(error.InvalidWord, trends.bump("bad-word", 0));
    try testing.expectError(error.TokenTooLong, trends.bump("verylarge", 0));
    try trends.bump("ok", 0);
    try testing.expectError(error.TooManyTopics, trends.bump("next", 0));
}
