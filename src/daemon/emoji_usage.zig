const std = @import("std");

pub const EmojiCount = struct {
    emoji: []const u8,
    count: u64,
};

pub const EmojiUsage = struct {
    pub const Config = struct {
        max_emojis: usize = 4096,
        max_emoji_bytes: usize = 32,
    };

    pub const Error = std.mem.Allocator.Error || error{ EmptyEmoji, EmojiTooLong, TooManyEmojis };

    allocator: std.mem.Allocator,
    cfg: Config,
    counts: std.StringHashMap(u64),

    pub fn init(allocator: std.mem.Allocator) EmojiUsage {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) EmojiUsage {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .counts = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *EmojiUsage) void {
        var it = self.counts.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.counts.deinit();
        self.* = undefined;
    }

    pub fn bump(self: *EmojiUsage, emoji: []const u8) Error!u64 {
        const entry = try self.ensureEmoji(emoji);
        entry.value_ptr.* +%= 1;
        return entry.value_ptr.*;
    }

    pub fn count(self: *const EmojiUsage, emoji: []const u8) u64 {
        return self.counts.get(emoji) orelse 0;
    }

    pub fn top(self: *const EmojiUsage, n: usize, out: []EmojiCount) usize {
        const limit = @min(n, out.len);
        if (limit == 0) return 0;

        var used: usize = 0;
        var it = self.counts.iterator();
        while (it.next()) |entry| {
            insertTop(out[0..limit], &used, .{
                .emoji = entry.key_ptr.*,
                .count = entry.value_ptr.*,
            });
        }
        return used;
    }

    fn ensureEmoji(self: *EmojiUsage, emoji: []const u8) Error!std.StringHashMap(u64).Entry {
        if (emoji.len == 0) return error.EmptyEmoji;
        if (emoji.len > self.cfg.max_emoji_bytes) return error.EmojiTooLong;
        if (self.counts.getEntry(emoji)) |entry| return entry;
        if (self.counts.count() >= self.cfg.max_emojis) return error.TooManyEmojis;

        const owned = try self.allocator.dupe(u8, emoji);
        errdefer self.allocator.free(owned);
        try self.counts.putNoClobber(owned, 0);
        return self.counts.getEntry(owned).?;
    }

    fn insertTop(out: []EmojiCount, used: *usize, item: EmojiCount) void {
        var pos: usize = 0;
        while (pos < used.* and better(out[pos], item)) pos += 1;
        if (pos >= out.len) return;

        if (used.* < out.len) used.* += 1;
        var i = used.* - 1;
        while (i > pos) : (i -= 1) out[i] = out[i - 1];
        out[pos] = item;
    }

    fn better(a: EmojiCount, b: EmojiCount) bool {
        if (a.count != b.count) return a.count > b.count;
        return std.mem.lessThan(u8, a.emoji, b.emoji);
    }
};

const testing = std.testing;

test "bump returns updated emoji count" {
    var usage = EmojiUsage.init(testing.allocator);
    defer usage.deinit();

    try testing.expectEqual(@as(u64, 1), try usage.bump("\xF0\x9F\x99\x82"));
    try testing.expectEqual(@as(u64, 2), try usage.bump("\xF0\x9F\x99\x82"));
    try testing.expectEqual(@as(u64, 2), usage.count("\xF0\x9F\x99\x82"));
    try testing.expectEqual(@as(u64, 0), usage.count("\xF0\x9F\x94\xA5"));
}

test "top ranks by count" {
    var usage = EmojiUsage.init(testing.allocator);
    defer usage.deinit();

    _ = try usage.bump("\xF0\x9F\x99\x82");
    _ = try usage.bump("\xF0\x9F\x94\xA5");
    _ = try usage.bump("\xF0\x9F\x94\xA5");

    var out: [2]EmojiCount = undefined;
    const n = usage.top(2, &out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("\xF0\x9F\x94\xA5", out[0].emoji);
    try testing.expectEqual(@as(u64, 2), out[0].count);
}

test "top applies lexical ordering for ties" {
    var usage = EmojiUsage.init(testing.allocator);
    defer usage.deinit();

    _ = try usage.bump("b");
    _ = try usage.bump("a");

    var out: [4]EmojiCount = undefined;
    const n = usage.top(4, &out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("a", out[0].emoji);
    try testing.expectEqualStrings("b", out[1].emoji);
}

test "configured bounds reject invalid emoji keys" {
    var usage = EmojiUsage.initWithConfig(testing.allocator, .{
        .max_emojis = 1,
        .max_emoji_bytes = 4,
    });
    defer usage.deinit();

    try testing.expectError(error.EmptyEmoji, usage.bump(""));
    try testing.expectError(error.EmojiTooLong, usage.bump("longer"));
    _ = try usage.bump("ok");
    try testing.expectError(error.TooManyEmojis, usage.bump("no"));
}
