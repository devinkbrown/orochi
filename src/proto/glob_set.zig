//! Ordered, bounded sets of ASCII case-insensitive `*`/`?` glob patterns.
//!
//! Patterns are owned by the set. Matching uses a pre-folded pattern form with
//! consecutive `*` bytes collapsed so repeated queries avoid re-normalizing the
//! stored patterns.

const std = @import("std");

/// Default maximum number of stored glob patterns.
pub const DEFAULT_MAX_PATTERNS: usize = 256;

/// Default maximum byte length of a single glob pattern.
pub const DEFAULT_MAX_PATTERN_BYTES: usize = 256;

/// Compile-time limits for a glob pattern set.
pub const Params = struct {
    max_patterns: usize = DEFAULT_MAX_PATTERNS,
    max_pattern_bytes: usize = DEFAULT_MAX_PATTERN_BYTES,
};

/// Errors returned while mutating a glob pattern set.
pub const GlobSetError = std.mem.Allocator.Error || error{
    EmptyPattern,
    PatternTooLong,
    TooManyPatterns,
    PatternExists,
};

/// Borrowed view of one stored glob pattern.
pub const PatternView = struct {
    index: usize,
    pattern: []const u8,
};

const StoredPattern = struct {
    pattern: []u8,
    matcher: []u8,
};

/// Return a bounded, owning glob pattern set type.
pub fn GlobSet(comptime params: Params) type {
    comptime {
        if (params.max_patterns == 0) @compileError("glob set needs at least one pattern slot");
        if (params.max_pattern_bytes == 0) @compileError("glob patterns need byte storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        patterns: std.ArrayListUnmanaged(StoredPattern) = .empty,

        /// Create an empty glob set backed by `allocator`.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        /// Free all owned patterns and release list capacity.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.patterns.deinit(self.allocator);
            self.* = undefined;
        }

        /// Remove every pattern while retaining list capacity.
        pub fn clear(self: *Self) void {
            for (self.patterns.items) |*entry| freeEntry(self.allocator, entry);
            self.patterns.clearRetainingCapacity();
        }

        /// Add a glob pattern and return its stable insertion index.
        pub fn add(self: *Self, pattern: []const u8) GlobSetError!usize {
            try validatePattern(pattern);

            var matcher_buf: [params.max_pattern_bytes]u8 = undefined;
            const matcher = foldedPattern(pattern, &matcher_buf);
            if (self.indexOfMatcher(matcher) != null) return error.PatternExists;
            if (self.patterns.items.len >= params.max_patterns) return error.TooManyPatterns;

            const owned_pattern = try self.allocator.dupe(u8, pattern);
            errdefer self.allocator.free(owned_pattern);
            const owned_matcher = try self.allocator.dupe(u8, matcher);
            errdefer self.allocator.free(owned_matcher);

            try self.patterns.append(self.allocator, .{
                .pattern = owned_pattern,
                .matcher = owned_matcher,
            });
            return self.patterns.items.len - 1;
        }

        /// Return the number of stored patterns.
        pub fn count(self: *const Self) usize {
            return self.patterns.items.len;
        }

        /// Return a borrowed view of the pattern at `index`, if present.
        pub fn patternAt(self: *const Self, index: usize) ?PatternView {
            if (index >= self.patterns.items.len) return null;
            return .{ .index = index, .pattern = self.patterns.items[index].pattern };
        }

        /// Return the first stored pattern index matching `text`, or null.
        pub fn anyMatch(self: *const Self, text: []const u8) ?usize {
            for (self.patterns.items, 0..) |entry, index| {
                if (matchFolded(entry.matcher, text)) return index;
            }
            return null;
        }

        /// Count every stored pattern matching `text`.
        pub fn matchCount(self: *const Self, text: []const u8) usize {
            var matched: usize = 0;
            for (self.patterns.items) |entry| {
                if (matchFolded(entry.matcher, text)) matched += 1;
            }
            return matched;
        }

        fn validatePattern(pattern: []const u8) GlobSetError!void {
            if (pattern.len == 0) return error.EmptyPattern;
            if (pattern.len > params.max_pattern_bytes) return error.PatternTooLong;
        }

        fn indexOfMatcher(self: *const Self, matcher: []const u8) ?usize {
            for (self.patterns.items, 0..) |entry, index| {
                if (std.mem.eql(u8, entry.matcher, matcher)) return index;
            }
            return null;
        }
    };
}

/// Default glob pattern set using the module defaults.
pub const DefaultSet = GlobSet(.{});

fn freeEntry(allocator: std.mem.Allocator, entry: *StoredPattern) void {
    allocator.free(entry.pattern);
    allocator.free(entry.matcher);
    entry.* = undefined;
}

fn foldedPattern(pattern: []const u8, out: []u8) []const u8 {
    var len: usize = 0;
    var prev_star = false;
    for (pattern) |byte| {
        if (byte == '*') {
            if (prev_star) continue;
            prev_star = true;
        } else {
            prev_star = false;
        }
        out[len] = std.ascii.toLower(byte);
        len += 1;
    }
    return out[0..len];
}

fn matchFolded(pattern: []const u8, text: []const u8) bool {
    var pattern_i: usize = 0;
    var text_i: usize = 0;
    var star_i: ?usize = null;
    var retry_text_i: usize = 0;

    while (text_i < text.len) {
        if (pattern_i < pattern.len and (pattern[pattern_i] == '?' or pattern[pattern_i] == std.ascii.toLower(text[text_i]))) {
            pattern_i += 1;
            text_i += 1;
        } else if (pattern_i < pattern.len and pattern[pattern_i] == '*') {
            star_i = pattern_i;
            pattern_i += 1;
            retry_text_i = text_i;
        } else if (star_i) |star| {
            pattern_i = star + 1;
            retry_text_i += 1;
            text_i = retry_text_i;
        } else {
            return false;
        }
    }

    while (pattern_i < pattern.len and pattern[pattern_i] == '*') {
        pattern_i += 1;
    }
    return pattern_i == pattern.len;
}

const testing = std.testing;

test "glob set matches multiple patterns and counts all matching entries" {
    // Arrange.
    var set = DefaultSet.init(testing.allocator);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 0), try set.add("alice!*"));
    try testing.expectEqual(@as(usize, 1), try set.add("*@example.net"));
    try testing.expectEqual(@as(usize, 2), try set.add("a?ice!*@example.*"));

    // Act.
    const first = set.anyMatch("Alice!user@example.net");
    const matches = set.matchCount("Alice!user@example.net");

    // Assert.
    try testing.expectEqual(@as(?usize, 0), first);
    try testing.expectEqual(@as(usize, 3), matches);
}

test "glob set returns the first matching insertion index" {
    // Arrange.
    var set = DefaultSet.init(testing.allocator);
    defer set.deinit();
    _ = try set.add("*@example.net");
    _ = try set.add("alice!*");
    _ = try set.add("*");

    // Act.
    const first = set.anyMatch("alice!user@example.net");
    const matches = set.matchCount("alice!user@example.net");

    // Assert.
    try testing.expectEqual(@as(?usize, 0), first);
    try testing.expectEqual(@as(usize, 3), matches);
}

test "glob set reports no match for unmatched text" {
    // Arrange.
    var set = DefaultSet.init(testing.allocator);
    defer set.deinit();
    _ = try set.add("#zig-*");
    _ = try set.add("staff?user");

    // Act.
    const first = set.anyMatch("#general");
    const matches = set.matchCount("#general");

    // Assert.
    try testing.expectEqual(@as(?usize, null), first);
    try testing.expectEqual(@as(usize, 0), matches);
}

test "glob set matching is ASCII case-insensitive" {
    // Arrange.
    var set = DefaultSet.init(testing.allocator);
    defer set.deinit();
    const index = try set.add("#Zig-HELP");

    // Act.
    const first = set.anyMatch("#zig-help");
    const view = set.patternAt(index).?;

    // Assert.
    try testing.expectEqual(@as(?usize, index), first);
    try testing.expectEqualStrings("#Zig-HELP", view.pattern);
    try testing.expectEqual(@as(usize, 1), set.matchCount("#ZIG-HELP"));
}

test "glob set owns patterns independently from caller storage" {
    // Arrange.
    var set = DefaultSet.init(testing.allocator);
    defer set.deinit();
    var mutable = [_]u8{ 't', 'e', 'm', 'p', '*' };
    _ = try set.add(mutable[0..]);
    mutable[0] = 'x';

    // Act.
    const first = set.anyMatch("temporary");
    const view = set.patternAt(0).?;

    // Assert.
    try testing.expectEqual(@as(?usize, 0), first);
    try testing.expectEqualStrings("temp*", view.pattern);
}

test "glob set enforces bounds and rejects duplicate folded patterns" {
    // Arrange.
    const SmallSet = GlobSet(.{ .max_patterns = 2, .max_pattern_bytes = 4 });
    var set = SmallSet.init(testing.allocator);
    defer set.deinit();

    // Act.
    _ = try set.add("A**");
    const duplicate = set.add("a*");
    _ = try set.add("b?");
    const full = set.add("c?");
    const too_long = set.add("longer");
    const empty = set.add("");

    // Assert.
    try testing.expectError(error.PatternExists, duplicate);
    try testing.expectError(error.TooManyPatterns, full);
    try testing.expectError(error.PatternTooLong, too_long);
    try testing.expectError(error.EmptyPattern, empty);
    try testing.expectEqual(@as(usize, 2), set.count());
}

test "glob set handles empty text and star-only patterns" {
    // Arrange.
    var set = DefaultSet.init(testing.allocator);
    defer set.deinit();
    _ = try set.add("*");
    _ = try set.add("?");

    // Act.
    const first_empty = set.anyMatch("");
    const count_empty = set.matchCount("");
    const first_one = set.anyMatch("x");
    const count_one = set.matchCount("x");

    // Assert.
    try testing.expectEqual(@as(?usize, 0), first_empty);
    try testing.expectEqual(@as(usize, 1), count_empty);
    try testing.expectEqual(@as(?usize, 0), first_one);
    try testing.expectEqual(@as(usize, 2), count_one);
}
