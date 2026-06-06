//! Mizuchi content filter (Koshi) — operator-curated message screening.
//!
//! A Mizuchi-native moderation primitive (not a clone of any other daemon's
//! "spamfilter"): a small set of oper-curated patterns is matched against
//! outgoing PRIVMSG / NOTICE bodies and a hit blocks the message. Patterns are
//! owned here and the Aho-Corasick automaton is rebuilt on every mutation — the
//! set is operator-curated and small, so rebuild cost is irrelevant and keeps
//! matching O(text) regardless of pattern count. Matching is case-insensitive.
const std = @import("std");
const aho = @import("../substrate/aho_corasick.zig");

pub const Error = std.mem.Allocator.Error;

pub const max_patterns: usize = 256;
pub const max_pattern_len: usize = 256;

pub const ContentFilter = struct {
    allocator: std.mem.Allocator,
    patterns: std.ArrayListUnmanaged([]u8) = .empty,
    automaton: ?aho.AhoCorasick = null,

    pub fn init(allocator: std.mem.Allocator) ContentFilter {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ContentFilter) void {
        for (self.patterns.items) |p| self.allocator.free(p);
        self.patterns.deinit(self.allocator);
        if (self.automaton) |*a| a.deinit();
        self.* = undefined;
    }

    /// Add a pattern (deduplicated, case-insensitive). Returns false if the
    /// pattern is empty, too long, the table is full, or it already exists.
    pub fn add(self: *ContentFilter, pattern: []const u8) Error!bool {
        if (pattern.len == 0 or pattern.len > max_pattern_len) return false;
        if (self.patterns.items.len >= max_patterns) return false;
        if (self.indexOf(pattern) != null) return false;
        const owned = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned);
        try self.patterns.append(self.allocator, owned);
        try self.rebuild();
        return true;
    }

    /// Remove a pattern (case-insensitive). Returns true if it was present.
    pub fn remove(self: *ContentFilter, pattern: []const u8) Error!bool {
        const idx = self.indexOf(pattern) orelse return false;
        self.allocator.free(self.patterns.items[idx]);
        _ = self.patterns.orderedRemove(idx);
        try self.rebuild();
        return true;
    }

    /// Borrowed view of the current patterns (valid until the next mutation).
    pub fn list(self: *const ContentFilter) []const []u8 {
        return self.patterns.items;
    }

    /// Whether `text` contains any filtered pattern.
    pub fn matches(self: *const ContentFilter, text: []const u8) bool {
        const a = self.automaton orelse return false;
        return a.containsAny(text);
    }

    fn indexOf(self: *const ContentFilter, pattern: []const u8) ?usize {
        for (self.patterns.items, 0..) |p, i| {
            if (std.ascii.eqlIgnoreCase(p, pattern)) return i;
        }
        return null;
    }

    fn rebuild(self: *ContentFilter) Error!void {
        if (self.automaton) |*a| a.deinit();
        self.automaton = null;
        if (self.patterns.items.len == 0) return;
        self.automaton = try aho.AhoCorasick.build(self.allocator, self.patterns.items, .{ .case_insensitive = true });
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "add/match/remove round-trip (case-insensitive)" {
    var f = ContentFilter.init(testing.allocator);
    defer f.deinit();
    try testing.expect(!f.matches("anything")); // empty filter never matches
    try testing.expect(try f.add("spamword"));
    try testing.expect(f.matches("this is SPAMWORD here"));
    try testing.expect(!f.matches("clean message"));
    try testing.expect(try f.remove("SPAMWORD"));
    try testing.expect(!f.matches("this is spamword here"));
}

test "dedup and empty/oversize rejected" {
    var f = ContentFilter.init(testing.allocator);
    defer f.deinit();
    try testing.expect(try f.add("foo"));
    try testing.expect(!try f.add("FOO")); // duplicate (case-insensitive)
    try testing.expect(!try f.add("")); // empty rejected
    try testing.expectEqual(@as(usize, 1), f.list().len);
}

test "multiple patterns match independently" {
    var f = ContentFilter.init(testing.allocator);
    defer f.deinit();
    _ = try f.add("buy now");
    _ = try f.add("free money");
    try testing.expect(f.matches("get FREE MONEY today"));
    try testing.expect(f.matches("please buy now!"));
    try testing.expect(!f.matches("a normal sentence"));
    try testing.expect(try f.remove("buy now"));
    try testing.expect(!f.matches("please buy now!"));
    try testing.expect(f.matches("free money still here"));
}
