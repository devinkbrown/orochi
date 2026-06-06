const std = @import("std");

pub const SearchHit = []const u8;

pub const SearchIndex = struct {
    pub const Config = struct {
        max_words: usize = 8192,
        max_ids_per_word: usize = 1024,
        max_token_bytes: usize = 64,
    };

    pub const Error = std.mem.Allocator.Error || error{ TooManyWords, TooManyIds, TokenTooLong };

    const IdList = struct {
        ids: std.ArrayListUnmanaged([]u8) = .empty,

        fn deinit(self: *IdList, allocator: std.mem.Allocator) void {
            for (self.ids.items) |id| allocator.free(id);
            self.ids.deinit(allocator);
        }

        fn find(self: *const IdList, msgid: []const u8) ?usize {
            for (self.ids.items, 0..) |id, i| {
                if (std.mem.eql(u8, id, msgid)) return i;
            }
            return null;
        }
    };

    allocator: std.mem.Allocator,
    cfg: Config,
    words: std.StringHashMap(IdList),

    pub fn init(allocator: std.mem.Allocator) SearchIndex {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) SearchIndex {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .words = std.StringHashMap(IdList).init(allocator),
        };
    }

    pub fn deinit(self: *SearchIndex) void {
        var it = self.words.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.words.deinit();
        self.* = undefined;
    }

    pub fn index(self: *SearchIndex, msgid: []const u8, text: []const u8) Error!void {
        _ = self.remove(msgid);

        var start: ?usize = null;
        for (text, 0..) |byte, i| {
            if (isWordByte(byte)) {
                if (start == null) start = i;
            } else if (start) |s| {
                try self.addToken(msgid, text[s..i]);
                start = null;
            }
        }
        if (start) |s| try self.addToken(msgid, text[s..]);
    }

    pub fn find(self: *SearchIndex, word: []const u8) []const SearchHit {
        var token_buf: [256]u8 = undefined;
        const token = normalizeToken(&token_buf, word) orelse return &.{};
        const list = self.words.getPtr(token) orelse return &.{};
        return list.ids.items;
    }

    pub fn remove(self: *SearchIndex, msgid: []const u8) bool {
        var removed = false;

        while (true) {
            var pruned = false;
            var it = self.words.iterator();
            while (it.next()) |entry| {
                while (entry.value_ptr.find(msgid)) |idx| {
                    const owned_id = entry.value_ptr.ids.swapRemove(idx);
                    self.allocator.free(owned_id);
                    removed = true;
                }
                if (entry.value_ptr.ids.items.len == 0) {
                    const owned_word = entry.key_ptr.*;
                    entry.value_ptr.deinit(self.allocator);
                    self.words.removeByPtr(entry.key_ptr);
                    self.allocator.free(owned_word);
                    pruned = true;
                    break;
                }
            }
            if (!pruned) break;
        }

        return removed;
    }

    fn addToken(self: *SearchIndex, msgid: []const u8, raw: []const u8) Error!void {
        if (raw.len > self.cfg.max_token_bytes) return error.TokenTooLong;

        var stack: [256]u8 = undefined;
        const token = normalizeToken(&stack, raw) orelse return;
        if (token.len > self.cfg.max_token_bytes) return error.TokenTooLong;

        const list = try self.ensureWord(token);
        if (list.find(msgid) != null) return;
        if (list.ids.items.len >= self.cfg.max_ids_per_word) return error.TooManyIds;

        const owned_id = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_id);
        try list.ids.append(self.allocator, owned_id);
    }

    fn ensureWord(self: *SearchIndex, word: []const u8) Error!*IdList {
        if (self.words.getPtr(word)) |list| return list;
        if (self.words.count() >= self.cfg.max_words) return error.TooManyWords;

        const owned = try self.allocator.dupe(u8, word);
        errdefer self.allocator.free(owned);
        try self.words.putNoClobber(owned, .{});
        return self.words.getPtr(owned).?;
    }

    fn isWordByte(byte: u8) bool {
        return std.ascii.isAlphanumeric(byte) or byte == '_';
    }

    fn normalizeToken(buf: []u8, raw: []const u8) ?[]const u8 {
        if (raw.len == 0 or raw.len > buf.len) return null;
        for (raw, 0..) |byte, i| {
            if (!isWordByte(byte)) return null;
            buf[i] = std.ascii.toLower(byte);
        }
        return buf[0..raw.len];
    }
};

const testing = std.testing;

test "index lowercases words and returns matching ids" {
    var indexer = SearchIndex.init(testing.allocator);
    defer indexer.deinit();

    try indexer.index("m1", "Hello search SEARCH");
    try indexer.index("m2", "search path");

    const hits = indexer.find("SEARCH");
    try testing.expectEqual(@as(usize, 2), hits.len);
    try testing.expectEqualStrings("m1", hits[0]);
    try testing.expectEqualStrings("m2", hits[1]);
}

test "remove deletes an id from every word" {
    var indexer = SearchIndex.init(testing.allocator);
    defer indexer.deinit();

    try indexer.index("a", "alpha beta");
    try indexer.index("b", "alpha");

    try testing.expect(indexer.remove("a"));
    try testing.expectEqual(@as(usize, 1), indexer.find("alpha").len);
    try testing.expectEqualStrings("b", indexer.find("alpha")[0]);
    try testing.expectEqual(@as(usize, 0), indexer.find("beta").len);
    try testing.expect(!indexer.remove("a"));
}

test "reindex replaces old words for the same id" {
    var indexer = SearchIndex.init(testing.allocator);
    defer indexer.deinit();

    try indexer.index("same", "old topic");
    try indexer.index("same", "new topic");

    try testing.expectEqual(@as(usize, 0), indexer.find("old").len);
    try testing.expectEqual(@as(usize, 1), indexer.find("new").len);
    try testing.expectEqual(@as(usize, 1), indexer.find("topic").len);
}

test "configured bounds reject oversize indexes" {
    var indexer = SearchIndex.initWithConfig(testing.allocator, .{
        .max_words = 1,
        .max_ids_per_word = 1,
        .max_token_bytes = 4,
    });
    defer indexer.deinit();

    try indexer.index("a", "tiny");
    try testing.expectError(error.TooManyWords, indexer.index("b", "next"));
    try testing.expectError(error.TooManyIds, indexer.index("b", "tiny"));
    try testing.expectError(error.TokenTooLong, indexer.index("c", "large"));
}
