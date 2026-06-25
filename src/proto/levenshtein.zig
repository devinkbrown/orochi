// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded Levenshtein edit distance helpers for nick typo suggestions.
//!
//! Distances are computed over bytes and use pure Levenshtein operations:
//! insert, delete, and substitute. Adjacent transpositions count as two edits.
//! The implementation is allocation-free and uses two fixed rolling rows on
//! the stack, so accepted input length is capped.

const std = @import("std");

/// Maximum byte length supported by the fixed stack buffers.
pub const MAX_INPUT_BYTES: usize = 64;

/// Tunable bounds for a `Levenshtein` calculator.
pub const Params = struct {
    /// Maximum byte length accepted for either input.
    max_input_bytes: usize = MAX_INPUT_BYTES,
};

/// Errors surfaced by exact distance calculations.
pub const LevenshteinError = error{
    /// A configured maximum cannot be represented by the fixed stack buffers.
    InvalidMaxInputBytes,
    /// At least one input exceeded the configured byte cap.
    InputTooLong,
};

/// Allocation-free bounded Levenshtein calculator.
pub const Levenshtein = struct {
    /// Bounds applied by this calculator.
    params: Params,

    /// Create a calculator using `params`.
    pub fn init(params: Params) Levenshtein {
        return .{ .params = params };
    }

    /// Release calculator state. No heap memory is owned.
    pub fn deinit(self: *Levenshtein) void {
        self.* = undefined;
    }

    /// Return the exact byte-level Levenshtein edit distance between `a` and `b`.
    pub fn distance(self: *const Levenshtein, a: []const u8, b: []const u8) LevenshteinError!usize {
        try self.validateInputs(a, b);
        return computeDistance(a, b);
    }

    /// Return true when `a` and `b` are within edit distance `k`.
    ///
    /// Invalid bounds or over-cap inputs are treated as not within range. The
    /// computation exits early when the length delta or a rolling row proves the
    /// final distance must exceed `k`.
    pub fn withinK(self: *const Levenshtein, a: []const u8, b: []const u8, k: usize) bool {
        self.validateInputs(a, b) catch return false;
        return computeWithinK(a, b, k);
    }

    fn validateInputs(self: *const Levenshtein, a: []const u8, b: []const u8) LevenshteinError!void {
        if (self.params.max_input_bytes > MAX_INPUT_BYTES) return error.InvalidMaxInputBytes;
        if (a.len > self.params.max_input_bytes or b.len > self.params.max_input_bytes) {
            return error.InputTooLong;
        }
    }
};

/// Return the exact byte-level Levenshtein edit distance using default bounds.
pub fn distance(a: []const u8, b: []const u8) LevenshteinError!usize {
    var metric = Levenshtein.init(.{});
    defer metric.deinit();
    return metric.distance(a, b);
}

/// Return true when `a` and `b` are within edit distance `k` using default bounds.
pub fn withinK(a: []const u8, b: []const u8, k: usize) bool {
    var metric = Levenshtein.init(.{});
    defer metric.deinit();
    return metric.withinK(a, b, k);
}

fn computeDistance(a: []const u8, b: []const u8) usize {
    const columns = if (a.len <= b.len) a else b;
    const rows = if (a.len <= b.len) b else a;

    var prev_buf: [MAX_INPUT_BYTES + 1]usize = undefined;
    var curr_buf: [MAX_INPUT_BYTES + 1]usize = undefined;
    var prev = prev_buf[0 .. columns.len + 1];
    var curr = curr_buf[0 .. columns.len + 1];

    var j: usize = 0;
    while (j <= columns.len) : (j += 1) {
        prev[j] = j;
    }

    var i: usize = 1;
    while (i <= rows.len) : (i += 1) {
        curr[0] = i;

        j = 1;
        while (j <= columns.len) : (j += 1) {
            const cost: usize = if (rows[i - 1] == columns[j - 1]) 0 else 1;
            curr[j] = min3(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
        }

        const tmp = prev;
        prev = curr;
        curr = tmp;
    }

    return prev[columns.len];
}

fn computeWithinK(a: []const u8, b: []const u8, k: usize) bool {
    if (lengthDelta(a.len, b.len) > k) return false;

    const columns = if (a.len <= b.len) a else b;
    const rows = if (a.len <= b.len) b else a;

    var prev_buf: [MAX_INPUT_BYTES + 1]usize = undefined;
    var curr_buf: [MAX_INPUT_BYTES + 1]usize = undefined;
    var prev = prev_buf[0 .. columns.len + 1];
    var curr = curr_buf[0 .. columns.len + 1];

    var j: usize = 0;
    while (j <= columns.len) : (j += 1) {
        prev[j] = j;
    }

    if (columns.len > k and rows.len == 0) return false;

    var i: usize = 1;
    while (i <= rows.len) : (i += 1) {
        curr[0] = i;
        var row_min = curr[0];

        j = 1;
        while (j <= columns.len) : (j += 1) {
            const cost: usize = if (rows[i - 1] == columns[j - 1]) 0 else 1;
            const value = min3(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
            curr[j] = value;
            if (value < row_min) row_min = value;
        }

        if (row_min > k) return false;

        const tmp = prev;
        prev = curr;
        curr = tmp;
    }

    return prev[columns.len] <= k;
}

fn lengthDelta(a_len: usize, b_len: usize) usize {
    return if (a_len >= b_len) a_len - b_len else b_len - a_len;
}

fn min3(a: usize, b: usize, c: usize) usize {
    return @min(@min(a, b), c);
}

test "distance returns known Levenshtein examples" {
    // Arrange.
    const allocator = std.testing.allocator;
    const kitten = try allocator.dupe(u8, "kitten");
    defer allocator.free(kitten);
    const sitting = try allocator.dupe(u8, "sitting");
    defer allocator.free(sitting);
    const empty = try allocator.dupe(u8, "");
    defer allocator.free(empty);
    const saturday = try allocator.dupe(u8, "saturday");
    defer allocator.free(saturday);
    const sunday = try allocator.dupe(u8, "sunday");
    defer allocator.free(sunday);

    // Act.
    const kitten_distance = try distance(kitten, sitting);
    const empty_distance = try distance(empty, "abc");
    const same_distance = try distance("nick", "nick");
    const saturday_distance = try distance(saturday, sunday);

    // Assert.
    try std.testing.expectEqual(@as(usize, 3), kitten_distance);
    try std.testing.expectEqual(@as(usize, 3), empty_distance);
    try std.testing.expectEqual(@as(usize, 0), same_distance);
    try std.testing.expectEqual(@as(usize, 3), saturday_distance);
}

test "transposition is not a single edit" {
    // Arrange.
    const allocator = std.testing.allocator;
    const left = try allocator.dupe(u8, "ab");
    defer allocator.free(left);
    const right = try allocator.dupe(u8, "ba");
    defer allocator.free(right);

    // Act.
    const edit_distance = try distance(left, right);
    const within_one = withinK(left, right, 1);
    const within_two = withinK(left, right, 2);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), edit_distance);
    try std.testing.expect(!within_one);
    try std.testing.expect(within_two);
}

test "withinK accepts close values and rejects rows that exceed the threshold" {
    // Arrange.
    const allocator = std.testing.allocator;
    const close_left = try allocator.dupe(u8, "example");
    defer allocator.free(close_left);
    const close_right = try allocator.dupe(u8, "exempla");
    defer allocator.free(close_right);
    const far_left = try allocator.dupe(u8, "aaaaaaaaaa");
    defer allocator.free(far_left);
    const far_right = try allocator.dupe(u8, "zzzzzzzzzz");
    defer allocator.free(far_right);

    // Act.
    const close_within = withinK(close_left, close_right, 2);
    const close_too_small = withinK(close_left, close_right, 1);
    const far_within = withinK(far_left, far_right, 2);
    const length_delta_reject = withinK("nick", "nickname", 3);

    // Assert.
    try std.testing.expect(close_within);
    try std.testing.expect(!close_too_small);
    try std.testing.expect(!far_within);
    try std.testing.expect(!length_delta_reject);
}

test "custom length cap rejects overlong inputs without allocating" {
    // Arrange.
    const allocator = std.testing.allocator;
    const short = try allocator.dupe(u8, "nick");
    defer allocator.free(short);
    const long = try allocator.dupe(u8, "nicker");
    defer allocator.free(long);
    var metric = Levenshtein.init(.{ .max_input_bytes = 4 });
    defer metric.deinit();

    // Act and assert.
    try std.testing.expectError(error.InputTooLong, metric.distance(short, long));
    try std.testing.expect(!metric.withinK(short, long, 2));
}

test "invalid cap is reported for exact distance and rejected for threshold checks" {
    // Arrange.
    var metric = Levenshtein.init(.{ .max_input_bytes = MAX_INPUT_BYTES + 1 });
    defer metric.deinit();

    // Act and assert.
    try std.testing.expectError(error.InvalidMaxInputBytes, metric.distance("a", "b"));
    try std.testing.expect(!metric.withinK("a", "b", 1));
}
