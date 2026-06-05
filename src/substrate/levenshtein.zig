const std = @import("std");

pub const Error = std.mem.Allocator.Error;

/// Computes the byte-wise Levenshtein edit distance using two rows of dynamic
/// programming state. The memory cost is O(min(a.len, b.len)).
pub fn levenshtein(allocator: std.mem.Allocator, a: []const u8, b: []const u8) Error!usize {
    if (std.mem.eql(u8, a, b)) return 0;
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    const rows = if (a.len >= b.len) a else b;
    const cols = if (a.len >= b.len) b else a;

    var previous = try allocator.alloc(usize, cols.len + 1);
    defer allocator.free(previous);
    var current = try allocator.alloc(usize, cols.len + 1);
    defer allocator.free(current);

    for (previous, 0..) |*cell, j| {
        cell.* = j;
    }

    for (rows, 1..) |row_byte, i| {
        current[0] = i;

        for (cols, 1..) |col_byte, j| {
            const substitution_cost: usize = if (row_byte == col_byte) 0 else 1;
            current[j] = min3(
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + substitution_cost,
            );
        }

        const tmp = previous;
        previous = current;
        current = tmp;
    }

    return previous[cols.len];
}

/// Computes the byte-wise optimal-string-alignment Damerau-Levenshtein
/// distance. Adjacent transpositions count as one edit.
pub fn damerauLevenshtein(allocator: std.mem.Allocator, a: []const u8, b: []const u8) Error!usize {
    if (std.mem.eql(u8, a, b)) return 0;
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    const rows = if (a.len >= b.len) a else b;
    const cols = if (a.len >= b.len) b else a;

    var two_back = try allocator.alloc(usize, cols.len + 1);
    defer allocator.free(two_back);
    var previous = try allocator.alloc(usize, cols.len + 1);
    defer allocator.free(previous);
    var current = try allocator.alloc(usize, cols.len + 1);
    defer allocator.free(current);

    for (previous, 0..) |*cell, j| {
        cell.* = j;
    }

    for (rows, 1..) |row_byte, i| {
        current[0] = i;

        for (cols, 1..) |col_byte, j| {
            const substitution_cost: usize = if (row_byte == col_byte) 0 else 1;
            var distance = min3(
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + substitution_cost,
            );

            if (i > 1 and j > 1 and row_byte == cols[j - 2] and rows[i - 2] == col_byte) {
                distance = @min(distance, two_back[j - 2] + 1);
            }

            current[j] = distance;
        }

        const tmp = two_back;
        two_back = previous;
        previous = current;
        current = tmp;
    }

    return previous[cols.len];
}

/// Returns the Levenshtein distance when it is at most max. If the distance
/// exceeds max, returns max + 1 as a sentinel.
pub fn boundedDistance(
    allocator: std.mem.Allocator,
    a: []const u8,
    b: []const u8,
    max: usize,
) Error!usize {
    const exceeded = max +| 1;

    if (std.mem.eql(u8, a, b)) return 0;
    if (lengthGap(a.len, b.len) > max) return exceeded;
    if (a.len == 0) return if (b.len <= max) b.len else exceeded;
    if (b.len == 0) return if (a.len <= max) a.len else exceeded;

    const rows = if (a.len >= b.len) a else b;
    const cols = if (a.len >= b.len) b else a;

    var previous = try allocator.alloc(usize, cols.len + 1);
    defer allocator.free(previous);
    var current = try allocator.alloc(usize, cols.len + 1);
    defer allocator.free(current);

    for (previous, 0..) |*cell, j| {
        cell.* = if (j <= max) j else exceeded;
    }
    @memset(current, exceeded);

    for (rows, 1..) |row_byte, i| {
        const start = if (i > max) i - max else 1;
        const end = @min(cols.len, i + max);
        var row_min = exceeded;

        current[0] = if (i <= max) i else exceeded;
        if (current[0] < row_min) row_min = current[0];

        if (start > 1) {
            current[start - 1] = exceeded;
        }

        if (start <= end) {
            for (start..end + 1) |j| {
                const substitution_cost: usize = if (row_byte == cols[j - 1]) 0 else 1;
                const distance = min3(
                    addOne(previous[j], exceeded),
                    addOne(current[j - 1], exceeded),
                    addCost(previous[j - 1], substitution_cost, exceeded),
                );
                current[j] = distance;
                if (distance < row_min) row_min = distance;
            }
        }

        if (end < cols.len) {
            current[end + 1] = exceeded;
        }

        if (row_min > max) return exceeded;

        const tmp = previous;
        previous = current;
        current = tmp;
    }

    const distance = previous[cols.len];
    return if (distance <= max) distance else exceeded;
}

/// Returns a normalized Levenshtein similarity ratio in [0, 1].
/// Identical strings, including two empty strings, return 1.
pub fn similarityRatio(allocator: std.mem.Allocator, a: []const u8, b: []const u8) Error!f64 {
    const max_len = @max(a.len, b.len);
    if (max_len == 0) return 1.0;

    const distance = try levenshtein(allocator, a, b);
    const distance_f: f64 = @floatFromInt(distance);
    const max_len_f: f64 = @floatFromInt(max_len);
    const ratio = 1.0 - (distance_f / max_len_f);

    if (ratio < 0.0) return 0.0;
    if (ratio > 1.0) return 1.0;
    return ratio;
}

fn min3(a: usize, b: usize, c: usize) usize {
    return @min(@min(a, b), c);
}

fn lengthGap(a_len: usize, b_len: usize) usize {
    return if (a_len >= b_len) a_len - b_len else b_len - a_len;
}

fn addOne(value: usize, limit: usize) usize {
    return if (value >= limit) limit else value + 1;
}

fn addCost(value: usize, cost: usize, limit: usize) usize {
    if (cost == 0) return value;
    return addOne(value, limit);
}

test "levenshtein known distances" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(@as(usize, 3), try levenshtein(allocator, "kitten", "sitting"));
    try std.testing.expectEqual(@as(usize, 1), try levenshtein(allocator, "flaw", "flaws"));
    try std.testing.expectEqual(@as(usize, 2), try levenshtein(allocator, "gumbo", "gambol"));
    try std.testing.expectEqual(@as(usize, 3), try levenshtein(allocator, "saturday", "sunday"));
}

test "levenshtein handles identical and empty strings" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(@as(usize, 0), try levenshtein(allocator, "same", "same"));
    try std.testing.expectEqual(@as(usize, 0), try levenshtein(allocator, "", ""));
    try std.testing.expectEqual(@as(usize, 3), try levenshtein(allocator, "", "abc"));
    try std.testing.expectEqual(@as(usize, 3), try levenshtein(allocator, "abc", ""));
}

test "damerau levenshtein counts adjacent transposition as one edit" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(@as(usize, 2), try levenshtein(allocator, "ab", "ba"));
    try std.testing.expectEqual(@as(usize, 1), try damerauLevenshtein(allocator, "ab", "ba"));
    try std.testing.expectEqual(@as(usize, 1), try damerauLevenshtein(allocator, "ca", "ac"));
    try std.testing.expectEqual(@as(usize, 2), try damerauLevenshtein(allocator, "abcdef", "abcfde"));
}

test "bounded distance returns exact values within threshold" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(@as(usize, 3), try boundedDistance(allocator, "kitten", "sitting", 3));
    try std.testing.expectEqual(@as(usize, 0), try boundedDistance(allocator, "nick", "nick", 0));
    try std.testing.expectEqual(@as(usize, 1), try boundedDistance(allocator, "nick", "nick1", 1));
    try std.testing.expectEqual(@as(usize, 3), try boundedDistance(allocator, "", "abc", 3));
}

test "bounded distance returns max plus one sentinel when exceeded" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(@as(usize, 3), try boundedDistance(allocator, "kitten", "sitting", 2));
    try std.testing.expectEqual(@as(usize, 1), try boundedDistance(allocator, "a", "b", 0));
    try std.testing.expectEqual(@as(usize, 2), try boundedDistance(allocator, "abc", "", 1));
    try std.testing.expectEqual(@as(usize, 2), try boundedDistance(allocator, "abcdef", "uvwxyz", 1));
}

test "similarity ratio is normalized" {
    const allocator = std.testing.allocator;

    try std.testing.expectApproxEqAbs(@as(f64, 1.0), try similarityRatio(allocator, "same", "same"), 0.000000000001);
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), try similarityRatio(allocator, "", ""), 0.000000000001);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), try similarityRatio(allocator, "", "abc"), 0.000000000001);
    try std.testing.expectApproxEqAbs(@as(f64, 4.0 / 7.0), try similarityRatio(allocator, "kitten", "sitting"), 0.000000000001);
}
