//! Aho-Corasick multi-pattern byte-string matcher.
//!
//! The matcher is intended for filter-style scans over UTF-8 or raw byte
//! strings. Case-insensitive mode folds ASCII letters only and leaves all other
//! bytes unchanged.

const std = @import("std");
const Allocator = std.mem.Allocator;

const no_link = std.math.maxInt(usize);

pub const Options = struct {
    case_insensitive: bool = false,
};

pub const Match = struct {
    pattern_index: usize,
    start: usize,
    end: usize,
};

const Edge = struct {
    byte: u8,
    next: usize,
};

const Node = struct {
    edges: std.ArrayList(Edge) = .empty,
    fail: usize = 0,
    output_link: usize = no_link,
    outputs: std.ArrayList(usize) = .empty,

    fn deinit(self: *Node, allocator: Allocator) void {
        self.edges.deinit(allocator);
        self.outputs.deinit(allocator);
        self.* = undefined;
    }
};

pub fn build(allocator: Allocator, patterns: []const []const u8, options: Options) !AhoCorasick {
    return AhoCorasick.build(allocator, patterns, options);
}

pub const AhoCorasick = struct {
    const Self = @This();

    allocator: Allocator,
    case_insensitive: bool,
    nodes: std.ArrayList(Node) = .empty,
    pattern_lengths: std.ArrayList(usize) = .empty,

    pub fn build(allocator: Allocator, patterns: []const []const u8, options: Options) !Self {
        var automaton = Self{
            .allocator = allocator,
            .case_insensitive = options.case_insensitive,
        };
        errdefer automaton.deinit();

        try automaton.nodes.append(allocator, .{});

        for (patterns, 0..) |pattern, pattern_index| {
            try automaton.pattern_lengths.append(allocator, pattern.len);
            if (pattern.len == 0) continue;
            try automaton.insert(pattern, pattern_index);
        }

        try automaton.buildFailures();
        return automaton;
    }

    pub fn deinit(self: *Self) void {
        for (self.nodes.items) |*node| {
            node.deinit(self.allocator);
        }
        self.nodes.deinit(self.allocator);
        self.pattern_lengths.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn patternCount(self: *const Self) usize {
        return self.pattern_lengths.items.len;
    }

    pub fn findAll(self: *const Self, text: []const u8) ![]Match {
        var matches: std.ArrayList(Match) = .empty;
        errdefer matches.deinit(self.allocator);

        var state: usize = 0;
        for (text, 0..) |raw_byte, i| {
            state = self.step(state, self.normalize(raw_byte));
            try self.appendMatches(&matches, state, i + 1);
        }

        return matches.toOwnedSlice(self.allocator);
    }

    pub fn containsAny(self: *const Self, text: []const u8) bool {
        var state: usize = 0;
        for (text) |raw_byte| {
            state = self.step(state, self.normalize(raw_byte));
            const node = &self.nodes.items[state];
            if (node.outputs.items.len != 0 or node.output_link != no_link) return true;
        }
        return false;
    }

    fn insert(self: *Self, pattern: []const u8, pattern_index: usize) !void {
        var state: usize = 0;
        for (pattern) |raw_byte| {
            const byte = self.normalize(raw_byte);
            state = self.child(state, byte) orelse try self.addChild(state, byte);
        }
        try self.nodes.items[state].outputs.append(self.allocator, pattern_index);
    }

    fn addChild(self: *Self, state: usize, byte: u8) !usize {
        const next = self.nodes.items.len;
        try self.nodes.items[state].edges.append(self.allocator, .{
            .byte = byte,
            .next = next,
        });
        errdefer _ = self.nodes.items[state].edges.pop();

        try self.nodes.append(self.allocator, .{});
        return next;
    }

    fn buildFailures(self: *Self) !void {
        var queue: std.ArrayList(usize) = .empty;
        defer queue.deinit(self.allocator);

        for (self.nodes.items[0].edges.items) |edge| {
            self.nodes.items[edge.next].fail = 0;
            self.nodes.items[edge.next].output_link = no_link;
            try queue.append(self.allocator, edge.next);
        }

        var head: usize = 0;
        while (head < queue.items.len) : (head += 1) {
            const state = queue.items[head];
            const edges = self.nodes.items[state].edges.items;

            for (edges) |edge| {
                var fallback = self.nodes.items[state].fail;
                while (fallback != 0 and self.child(fallback, edge.byte) == null) {
                    fallback = self.nodes.items[fallback].fail;
                }

                const fail_state = self.child(fallback, edge.byte) orelse 0;
                self.nodes.items[edge.next].fail = fail_state;
                self.nodes.items[edge.next].output_link = if (self.nodes.items[fail_state].outputs.items.len != 0)
                    fail_state
                else
                    self.nodes.items[fail_state].output_link;

                try queue.append(self.allocator, edge.next);
            }
        }
    }

    fn step(self: *const Self, start_state: usize, byte: u8) usize {
        var state = start_state;
        while (state != 0 and self.child(state, byte) == null) {
            state = self.nodes.items[state].fail;
        }
        return self.child(state, byte) orelse 0;
    }

    fn child(self: *const Self, state: usize, byte: u8) ?usize {
        for (self.nodes.items[state].edges.items) |edge| {
            if (edge.byte == byte) return edge.next;
        }
        return null;
    }

    fn appendMatches(self: *const Self, matches: *std.ArrayList(Match), state: usize, end: usize) !void {
        try self.appendNodeMatches(matches, state, end);

        var link = self.nodes.items[state].output_link;
        while (link != no_link) {
            try self.appendNodeMatches(matches, link, end);
            link = self.nodes.items[link].output_link;
        }
    }

    fn appendNodeMatches(self: *const Self, matches: *std.ArrayList(Match), state: usize, end: usize) !void {
        for (self.nodes.items[state].outputs.items) |pattern_index| {
            const len = self.pattern_lengths.items[pattern_index];
            try matches.append(self.allocator, .{
                .pattern_index = pattern_index,
                .start = end - len,
                .end = end,
            });
        }
    }

    fn normalize(self: *const Self, byte: u8) u8 {
        if (!self.case_insensitive) return byte;
        return asciiLower(byte);
    }
};

fn asciiLower(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

fn expectMatches(actual: []const Match, expected: []const Match) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| {
        try std.testing.expectEqual(e.pattern_index, a.pattern_index);
        try std.testing.expectEqual(e.start, a.start);
        try std.testing.expectEqual(e.end, a.end);
    }
}

test "multiple overlapping patterns found at correct positions" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{ "a", "aa", "aaa" };
    var ac = try build(allocator, &patterns, .{});
    defer ac.deinit();

    const matches = try ac.findAll("aaaa");
    defer allocator.free(matches);

    const expected = [_]Match{
        .{ .pattern_index = 0, .start = 0, .end = 1 },
        .{ .pattern_index = 1, .start = 0, .end = 2 },
        .{ .pattern_index = 0, .start = 1, .end = 2 },
        .{ .pattern_index = 2, .start = 0, .end = 3 },
        .{ .pattern_index = 1, .start = 1, .end = 3 },
        .{ .pattern_index = 0, .start = 2, .end = 3 },
        .{ .pattern_index = 2, .start = 1, .end = 4 },
        .{ .pattern_index = 1, .start = 2, .end = 4 },
        .{ .pattern_index = 0, .start = 3, .end = 4 },
    };
    try expectMatches(matches, &expected);
}

test "classic suffix and overlap matches" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{ "he", "she", "his", "hers" };
    var ac = try build(allocator, &patterns, .{});
    defer ac.deinit();

    const matches = try ac.findAll("ushers");
    defer allocator.free(matches);

    const expected = [_]Match{
        .{ .pattern_index = 1, .start = 1, .end = 4 },
        .{ .pattern_index = 0, .start = 2, .end = 4 },
        .{ .pattern_index = 3, .start = 2, .end = 6 },
    };
    try expectMatches(matches, &expected);
}

test "contains any reports matches without allocating result storage" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{ "spam", "eggs", "ham" };
    var ac = try build(allocator, &patterns, .{});
    defer ac.deinit();

    try std.testing.expect(ac.containsAny("green eggs and ham"));
    try std.testing.expect(ac.containsAny("spammer"));
    try std.testing.expect(!ac.containsAny("toast"));
}

test "case insensitive option folds ASCII pattern and text bytes" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{ "Bad", "WORD" };
    var ac = try build(allocator, &patterns, .{ .case_insensitive = true });
    defer ac.deinit();

    const matches = try ac.findAll("a bad WoRd BADGE");
    defer allocator.free(matches);

    const expected = [_]Match{
        .{ .pattern_index = 0, .start = 2, .end = 5 },
        .{ .pattern_index = 1, .start = 6, .end = 10 },
        .{ .pattern_index = 0, .start = 11, .end = 14 },
    };
    try expectMatches(matches, &expected);
}

test "case sensitive mode keeps distinct byte values" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{"Bad"};
    var ac = try build(allocator, &patterns, .{});
    defer ac.deinit();

    try std.testing.expect(!ac.containsAny("bad"));
    try std.testing.expect(ac.containsAny("Bad"));
}

test "empty text and empty patterns produce no matches" {
    const allocator = std.testing.allocator;

    const no_patterns = [_][]const u8{};
    var empty_ac = try build(allocator, &no_patterns, .{});
    defer empty_ac.deinit();

    try std.testing.expectEqual(@as(usize, 0), empty_ac.patternCount());
    try std.testing.expect(!empty_ac.containsAny(""));
    try std.testing.expect(!empty_ac.containsAny("anything"));

    const empty_matches = try empty_ac.findAll("");
    defer allocator.free(empty_matches);
    try expectMatches(empty_matches, &.{});

    const patterns = [_][]const u8{ "a", "bc" };
    var ac = try build(allocator, &patterns, .{});
    defer ac.deinit();

    const matches = try ac.findAll("");
    defer allocator.free(matches);
    try expectMatches(matches, &.{});
}

test "empty patterns are ignored but preserve later pattern indexes" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{ "", "x", "" };
    var ac = try build(allocator, &patterns, .{});
    defer ac.deinit();

    try std.testing.expectEqual(@as(usize, 3), ac.patternCount());
    try std.testing.expect(!ac.containsAny(""));
    try std.testing.expect(ac.containsAny("x"));

    const matches = try ac.findAll("xx");
    defer allocator.free(matches);

    const expected = [_]Match{
        .{ .pattern_index = 1, .start = 0, .end = 1 },
        .{ .pattern_index = 1, .start = 1, .end = 2 },
    };
    try expectMatches(matches, &expected);
}

test "deterministic result order for repeated builds" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{ "ab", "bab", "bc", "bca", "c", "caa" };

    var left = try build(allocator, &patterns, .{});
    defer left.deinit();
    var right = try build(allocator, &patterns, .{});
    defer right.deinit();

    const text = "abccab";
    const left_matches = try left.findAll(text);
    defer allocator.free(left_matches);
    const right_matches = try right.findAll(text);
    defer allocator.free(right_matches);

    try expectMatches(left_matches, right_matches);
}

test "no match returns an empty slice and false contains any" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{ "needle", "pin" };
    var ac = try build(allocator, &patterns, .{});
    defer ac.deinit();

    try std.testing.expect(!ac.containsAny("haystack"));
    const matches = try ac.findAll("haystack");
    defer allocator.free(matches);
    try expectMatches(matches, &.{});
}
