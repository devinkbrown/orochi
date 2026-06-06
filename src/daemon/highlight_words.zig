//! Per-account highlight keyword lists for the Mizuchi daemon.
//!
//! Each account owns a small list of keywords (max `max_words`, each at most
//! `max_word_len` bytes). Clients use these words to decide when to raise a
//! local notification: when an incoming message body contains any of the
//! account's keywords (case-insensitive), `matches` returns true.

const std = @import("std");

/// Maximum number of keywords retained per account.
pub const max_words: usize = 64;

/// Maximum byte length of a single keyword.
pub const max_word_len: usize = 64;

const WordList = std.ArrayListUnmanaged([]u8);

/// Owns the mapping of account name -> keyword list. All keys and stored
/// keyword strings are heap-owned and freed on `deinit`.
pub const HighlightWords = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMapUnmanaged(WordList),

    pub fn init(allocator: std.mem.Allocator) HighlightWords {
        return .{
            .allocator = allocator,
            .map = .{},
        };
    }

    pub fn deinit(self: *HighlightWords) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |word| {
                self.allocator.free(word);
            }
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit(self.allocator);
        self.* = undefined;
    }

    /// ASCII case-insensitive byte equality.
    fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |ca, cb| {
            if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
        }
        return true;
    }

    /// Add `word` to `account`'s keyword list.
    ///
    /// Returns true if the word was added, false if it duplicates an existing
    /// keyword (case-insensitive) or the account is already at `max_words`.
    /// Only allocation failures produce an error. Words longer than
    /// `max_word_len` are rejected (returns false).
    pub fn add(self: *HighlightWords, account: []const u8, word: []const u8) !bool {
        if (word.len == 0 or word.len > max_word_len) return false;

        const gop = try self.map.getOrPut(self.allocator, account);
        if (!gop.found_existing) {
            const key_copy = self.allocator.dupe(u8, account) catch |err| {
                self.map.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .empty;
        }

        const wl = gop.value_ptr;

        for (wl.items) |existing| {
            if (eqlIgnoreCase(existing, word)) return false;
        }
        if (wl.items.len >= max_words) return false;

        const word_copy = try self.allocator.dupe(u8, word);
        errdefer self.allocator.free(word_copy);
        try wl.append(self.allocator, word_copy);
        return true;
    }

    /// Remove `word` (case-insensitive) from `account`'s list.
    /// Returns true if a keyword was removed.
    pub fn remove(self: *HighlightWords, account: []const u8, word: []const u8) bool {
        const wl = self.map.getPtr(account) orelse return false;
        for (wl.items, 0..) |existing, idx| {
            if (eqlIgnoreCase(existing, word)) {
                const removed = wl.orderedRemove(idx);
                self.allocator.free(removed);
                return true;
            }
        }
        return false;
    }

    /// Return the account's keyword list, or an empty slice if none exist.
    /// The returned slice is owned by `self`; do not free or retain past
    /// the next mutation.
    pub fn list(self: *HighlightWords, account: []const u8) []const []const u8 {
        const lp = self.map.getPtr(account) orelse return &.{};
        return lp.items;
    }

    /// True if `text` contains any of `account`'s keywords (case-insensitive).
    pub fn matches(self: *HighlightWords, account: []const u8, text: []const u8) bool {
        const lp = self.map.getPtr(account) orelse return false;
        for (lp.items) |word| {
            if (word.len == 0 or word.len > text.len) continue;
            if (containsIgnoreCase(text, word)) return true;
        }
        return false;
    }

    /// True if `haystack` contains `needle` (ASCII case-insensitive).
    fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
        if (needle.len == 0) return true;
        if (needle.len > haystack.len) return false;
        const last = haystack.len - needle.len;
        var i: usize = 0;
        while (i <= last) : (i += 1) {
            if (eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
        }
        return false;
    }
};

test "add, list, and dedup" {
    var hw = HighlightWords.init(std.testing.allocator);
    defer hw.deinit();

    try std.testing.expect(try hw.add("alice", "ping"));
    try std.testing.expect(try hw.add("alice", "urgent"));

    // case-insensitive duplicate is rejected
    try std.testing.expect(!try hw.add("alice", "PING"));
    // empty and oversized words rejected
    try std.testing.expect(!try hw.add("alice", ""));
    const too_long = "x" ** (max_word_len + 1);
    try std.testing.expect(!try hw.add("alice", too_long));

    const words = hw.list("alice");
    try std.testing.expectEqual(@as(usize, 2), words.len);
    try std.testing.expectEqualStrings("ping", words[0]);
    try std.testing.expectEqualStrings("urgent", words[1]);

    // unknown account yields empty list
    try std.testing.expectEqual(@as(usize, 0), hw.list("nobody").len);
}

test "remove keyword case-insensitive" {
    var hw = HighlightWords.init(std.testing.allocator);
    defer hw.deinit();

    try std.testing.expect(try hw.add("bob", "Alert"));
    try std.testing.expect(try hw.add("bob", "review"));

    // removing a missing word returns false
    try std.testing.expect(!hw.remove("bob", "missing"));
    try std.testing.expect(!hw.remove("ghost", "anything"));

    // case-insensitive removal succeeds
    try std.testing.expect(hw.remove("bob", "ALERT"));
    try std.testing.expectEqual(@as(usize, 1), hw.list("bob").len);
    try std.testing.expectEqualStrings("review", hw.list("bob")[0]);

    // a re-add is now allowed since the word is gone
    try std.testing.expect(try hw.add("bob", "alert"));
    try std.testing.expectEqual(@as(usize, 2), hw.list("bob").len);
}

test "matches is case-insensitive and substring-aware" {
    var hw = HighlightWords.init(std.testing.allocator);
    defer hw.deinit();

    try std.testing.expect(try hw.add("carol", "deploy"));
    try std.testing.expect(try hw.add("carol", "p0"));

    try std.testing.expect(hw.matches("carol", "Time to DEPLOY now"));
    try std.testing.expect(hw.matches("carol", "this is a P0 incident"));
    // substring within a larger word still matches
    try std.testing.expect(hw.matches("carol", "redeploying soon"));

    try std.testing.expect(!hw.matches("carol", "nothing relevant here"));
    // unknown account never matches
    try std.testing.expect(!hw.matches("stranger", "deploy deploy deploy"));
}

test "per-account cap enforced at max_words" {
    var hw = HighlightWords.init(std.testing.allocator);
    defer hw.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < max_words) : (i += 1) {
        const w = try std.fmt.bufPrint(&buf, "w{d}", .{i});
        try std.testing.expect(try hw.add("dave", w));
    }
    try std.testing.expectEqual(max_words, hw.list("dave").len);

    // one past the cap is rejected
    try std.testing.expect(!try hw.add("dave", "overflow"));
    try std.testing.expectEqual(max_words, hw.list("dave").len);
}
