//! Compact numeric range-list parser.
//!
//! This module parses a compact, comma-separated list of numeric values and
//! inclusive ranges (for example `"1-5,7,10-12"`) into a bounded, sorted,
//! de-duplicated set of `u32` values. It is intentionally allocation-free:
//! `parse` expands directly into a caller-provided buffer and never touches an
//! allocator, while `contains` answers membership questions without expanding
//! anything at all.
//!
//! Grammar (informal):
//!
//!   list  := item ("," item)*
//!   item  := number | number "-" number
//!   number := DIGIT+        (decimal, no sign, no whitespace)
//!
//! Semantics:
//!
//!   * A bare `number` contributes a single value.
//!   * A `lo-hi` range contributes every value in `[lo, hi]` inclusive and
//!     must be ascending (`lo <= hi`); reversed ranges are rejected.
//!   * The expanded result from `parse` is sorted ascending with duplicates
//!     removed, so overlapping items (`"1-5,3-7"`) collapse cleanly.
//!
//! Hardening guarantees:
//!
//!   * Every number is parsed with explicit overflow checking; values beyond
//!     `u32` range yield `error.Overflow`.
//!   * `parse` refuses to write past the caller buffer and caps the total
//!     expanded count at `max_values` (whichever is smaller), returning
//!     `error.Overflow` rather than truncating silently.
//!   * Empty input, empty items (`"1,,2"`), stray separators, and any
//!     non-digit garbage are rejected with `error.InvalidCharacter` or
//!     `error.EmptyItem`.
//!
//! The parser performs no allocation, so the caller owns all memory: there is
//! nothing to free here. Buffers handed to `parse` remain owned by the caller.

const std = @import("std");

/// Errors that range-list parsing can produce.
pub const ParseError = error{
    /// The overall input or an individual item was empty (e.g. `""`, `"1,,2"`,
    /// `","`, or a range missing one side like `"-5"` / `"5-"`).
    EmptyItem,
    /// A character outside the accepted grammar was encountered.
    InvalidCharacter,
    /// A range was descending (`"5-1"`).
    ReversedRange,
    /// A number exceeded `u32`, or the expanded set exceeded the buffer or the
    /// configured cap.
    Overflow,
};

/// Hard upper bound on the number of expanded values produced by `parse`,
/// independent of the caller buffer length. The effective cap is the minimum of
/// this constant and the supplied buffer length.
pub const max_values: usize = 4096;

const item_separator: u8 = ',';
const range_separator: u8 = '-';

/// One inclusive `[start, end]` range or single value (`start == end`) as it
/// appears in the source text, before expansion or de-duplication.
pub const Range = struct {
    start: u32,
    end: u32,

    /// Number of distinct values this range covers (always >= 1). Computed with
    /// overflow safety; the result fits in `u64` because `end - start` is at
    /// most `u32` max.
    pub fn count(self: Range) u64 {
        return @as(u64, self.end - self.start) + 1;
    }

    /// Whether `n` falls within this inclusive range.
    pub fn contains(self: Range, n: u32) bool {
        return n >= self.start and n <= self.end;
    }
};

/// Lazy iterator over the `{start, end}` pairs in a range-list, in source
/// order, without expanding or de-duplicating. Each `next()` validates exactly
/// one item, so malformed input surfaces as an error mid-iteration.
///
/// The iterator borrows `text`; the caller must keep it alive for the lifetime
/// of the iterator. No allocation occurs.
pub const RangeIter = struct {
    text: []const u8,
    pos: usize = 0,
    /// Set once the final item has been yielded, so a trailing separator is
    /// still surfaced as one last (empty) item rather than silently dropped.
    done: bool = false,
    /// True when the most recently consumed item was followed by a separator,
    /// meaning at least one more item is expected even at end of input.
    pending: bool = false,

    /// Create an iterator over `text`. Validation happens lazily in `next()`.
    pub fn init(text: []const u8) RangeIter {
        return .{ .text = text };
    }

    /// Yield the next `Range`, or `null` once the input is exhausted. Returns a
    /// `ParseError` if the upcoming item is malformed.
    ///
    /// A trailing separator (e.g. `"1,2,"`) is reported as a final empty item,
    /// which `parseItem` rejects with `error.EmptyItem`.
    pub fn next(self: *RangeIter) ParseError!?Range {
        if (self.done) return null;

        if (self.pos >= self.text.len) {
            // End of input. If the previous item ended with a separator there is
            // one more (empty) item to surface; otherwise we are finished.
            self.done = true;
            if (self.pending) {
                self.pending = false;
                return try parseItem(self.text[self.pos..self.pos]);
            }
            return null;
        }

        const start = self.pos;
        // Scan to the next item separator (or end of input).
        var end = start;
        while (end < self.text.len and self.text[end] != item_separator) : (end += 1) {}

        const item = self.text[start..end];

        // Advance past the separator (if any) so the next call resumes cleanly.
        if (end < self.text.len) {
            self.pos = end + 1;
            self.pending = true;
        } else {
            self.pos = end;
            self.pending = false;
        }

        return try parseItem(item);
    }
};

/// Parse a single item ("N" or "LO-HI") into a `Range`.
fn parseItem(item: []const u8) ParseError!Range {
    if (item.len == 0) return ParseError.EmptyItem;

    // Find the range separator, if present. Because numbers are unsigned and
    // contain no '-', the first '-' unambiguously splits low from high.
    var dash: ?usize = null;
    for (item, 0..) |c, i| {
        if (c == range_separator) {
            dash = i;
            break;
        }
    }

    if (dash) |d| {
        const lo_text = item[0..d];
        const hi_text = item[d + 1 ..];
        if (lo_text.len == 0 or hi_text.len == 0) return ParseError.EmptyItem;
        // A second dash inside either half is rejected by parseNumber as an
        // invalid character.
        const lo = try parseNumber(lo_text);
        const hi = try parseNumber(hi_text);
        if (lo > hi) return ParseError.ReversedRange;
        return Range{ .start = lo, .end = hi };
    }

    const value = try parseNumber(item);
    return Range{ .start = value, .end = value };
}

/// Parse a bare decimal number with explicit overflow checking. Only ASCII
/// digits are accepted; any other byte (including whitespace, signs, or a
/// second range separator) is rejected.
fn parseNumber(text: []const u8) ParseError!u32 {
    if (text.len == 0) return ParseError.EmptyItem;

    var acc: u32 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return ParseError.InvalidCharacter;
        const digit: u32 = c - '0';
        acc = std.math.mul(u32, acc, 10) catch return ParseError.Overflow;
        acc = std.math.add(u32, acc, digit) catch return ParseError.Overflow;
    }
    return acc;
}

/// Insert `value` into the sorted, de-duplicated `buf[0..len]` prefix, keeping
/// it sorted. Returns the new length, or `error.Overflow` if the buffer/cap is
/// exhausted. Uses binary search for the insertion point so repeated inserts
/// stay efficient on large ranges.
fn insertSorted(buf: []u32, len: usize, cap: usize, value: u32) ParseError!usize {
    // Binary search for the first index whose element is >= value.
    var lo: usize = 0;
    var hi: usize = len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (buf[mid] < value) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    // Duplicate: already present, nothing to do.
    if (lo < len and buf[lo] == value) return len;

    if (len >= cap) return ParseError.Overflow;

    // Shift the tail right by one to open a slot at `lo`.
    var i = len;
    while (i > lo) : (i -= 1) {
        buf[i] = buf[i - 1];
    }
    buf[lo] = value;
    return len + 1;
}

/// Parse `text` and expand it into `out_buf`, returning the sorted,
/// de-duplicated slice of values (`out_buf[0..n]`).
///
/// The effective capacity is `@min(out_buf.len, max_values)`. If the expansion
/// would exceed that capacity, `error.Overflow` is returned and `out_buf` may
/// have been partially written (its contents are then unspecified). On success
/// the returned slice aliases `out_buf` and remains owned by the caller.
///
/// No allocation is performed.
pub fn parse(text: []const u8, out_buf: []u32) ParseError![]u32 {
    if (text.len == 0) return ParseError.EmptyItem;

    const cap = @min(out_buf.len, max_values);
    var len: usize = 0;

    var iter = RangeIter.init(text);
    while (try iter.next()) |range| {
        var v = range.start;
        while (true) {
            len = try insertSorted(out_buf, len, cap, v);
            if (v == range.end) break;
            v += 1;
        }
    }

    return out_buf[0..len];
}

/// Test whether `n` is a member of the set described by `text`, without
/// expanding into any buffer. Returns a `ParseError` if `text` is malformed.
///
/// This is allocation-free and runs in O(items) time, making it suitable for
/// membership checks against large ranges (e.g. `"1-1000000"`) where expansion
/// would be wasteful or impossible within the configured cap.
pub fn contains(text: []const u8, n: u32) ParseError!bool {
    if (text.len == 0) return ParseError.EmptyItem;

    var iter = RangeIter.init(text);
    while (try iter.next()) |range| {
        if (range.contains(n)) return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

test "parse single value" {
    var buf: [16]u32 = undefined;
    const out = try parse("42", &buf);
    try testing.expectEqualSlices(u32, &.{42}, out);
}

test "parse comma list" {
    var buf: [16]u32 = undefined;
    const out = try parse("3,1,2", &buf);
    // Sorted on output.
    try testing.expectEqualSlices(u32, &.{ 1, 2, 3 }, out);
}

test "parse inclusive range" {
    var buf: [16]u32 = undefined;
    const out = try parse("10-12", &buf);
    try testing.expectEqualSlices(u32, &.{ 10, 11, 12 }, out);
}

test "parse mixed list and ranges" {
    var buf: [16]u32 = undefined;
    const out = try parse("1-5,7,10-12", &buf);
    try testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4, 5, 7, 10, 11, 12 }, out);
}

test "parse overlap is de-duplicated" {
    var buf: [16]u32 = undefined;
    const out = try parse("1-5,3-7", &buf);
    try testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4, 5, 6, 7 }, out);
}

test "parse duplicate singles collapse" {
    var buf: [16]u32 = undefined;
    const out = try parse("5,5,5,5", &buf);
    try testing.expectEqualSlices(u32, &.{5}, out);
}

test "parse single-element range" {
    var buf: [16]u32 = undefined;
    const out = try parse("8-8", &buf);
    try testing.expectEqualSlices(u32, &.{8}, out);
}

test "parse rejects reversed range" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.ReversedRange, parse("5-1", &buf));
}

test "parse rejects empty input" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.EmptyItem, parse("", &buf));
}

test "parse rejects empty item in list" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.EmptyItem, parse("1,,2", &buf));
}

test "parse rejects trailing comma" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.EmptyItem, parse("1,2,", &buf));
}

test "parse rejects leading comma" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.EmptyItem, parse(",1", &buf));
}

test "parse rejects missing range sides" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.EmptyItem, parse("-5", &buf));
    try testing.expectError(ParseError.EmptyItem, parse("5-", &buf));
}

test "parse rejects garbage characters" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.InvalidCharacter, parse("1,a,2", &buf));
    try testing.expectError(ParseError.InvalidCharacter, parse("1 2", &buf));
    try testing.expectError(ParseError.InvalidCharacter, parse("+5", &buf));
    // A double dash leaves a stray '-' inside a half -> invalid character.
    try testing.expectError(ParseError.InvalidCharacter, parse("1--5", &buf));
}

test "parse rejects u32 overflow" {
    var buf: [16]u32 = undefined;
    try testing.expectError(ParseError.Overflow, parse("4294967296", &buf));
}

test "parse accepts u32 max" {
    var buf: [4]u32 = undefined;
    const out = try parse("4294967295", &buf);
    try testing.expectEqualSlices(u32, &.{4294967295}, out);
}

test "parse caps at buffer length" {
    var buf: [4]u32 = undefined;
    // 1-4 fits exactly into a 4-slot buffer.
    const out = try parse("1-4", &buf);
    try testing.expectEqual(@as(usize, 4), out.len);
    // 1-5 overflows the 4-slot buffer.
    try testing.expectError(ParseError.Overflow, parse("1-5", &buf));
}

test "parse cap does not count duplicates" {
    var buf: [3]u32 = undefined;
    // Heavy overlap collapses to {1,2,3}, fitting a 3-slot buffer.
    const out = try parse("1-3,1-3,2-2", &buf);
    try testing.expectEqualSlices(u32, &.{ 1, 2, 3 }, out);
}

test "parse with std.testing.allocator-backed buffer" {
    // Exercise the allocation-free API against an allocator-owned buffer to
    // confirm there are no internal leaks (allocator only owns `buf`).
    const buf = try testing.allocator.alloc(u32, 64);
    defer testing.allocator.free(buf);

    const out = try parse("100-110,5,5,200", buf);
    try testing.expectEqualSlices(
        u32,
        &.{ 5, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 200 },
        out,
    );
}

test "contains membership without expansion" {
    try testing.expect(try contains("1-5,7,10-12", 3));
    try testing.expect(try contains("1-5,7,10-12", 7));
    try testing.expect(try contains("1-5,7,10-12", 11));
    try testing.expect(!try contains("1-5,7,10-12", 6));
    try testing.expect(!try contains("1-5,7,10-12", 0));
    try testing.expect(!try contains("1-5,7,10-12", 13));
}

test "contains handles huge ranges without buffer" {
    // Far larger than max_values; would be impossible to expand.
    try testing.expect(try contains("0-4294967295", 123456789));
    try testing.expect(try contains("1-1000000", 999999));
    try testing.expect(!try contains("1-1000000", 1000001));
}

test "contains propagates parse errors" {
    try testing.expectError(ParseError.EmptyItem, contains("", 1));
    try testing.expectError(ParseError.ReversedRange, contains("9-2", 5));
    try testing.expectError(ParseError.InvalidCharacter, contains("x", 5));
}

test "RangeIter yields source-order pairs" {
    var iter = RangeIter.init("1-5,7,10-12");

    const a = (try iter.next()).?;
    try testing.expectEqual(@as(u32, 1), a.start);
    try testing.expectEqual(@as(u32, 5), a.end);

    const b = (try iter.next()).?;
    try testing.expectEqual(@as(u32, 7), b.start);
    try testing.expectEqual(@as(u32, 7), b.end);

    const c = (try iter.next()).?;
    try testing.expectEqual(@as(u32, 10), c.start);
    try testing.expectEqual(@as(u32, 12), c.end);

    try testing.expectEqual(@as(?Range, null), try iter.next());
}

test "RangeIter does not sort or dedupe" {
    var iter = RangeIter.init("5,1,5");
    const a = (try iter.next()).?;
    const b = (try iter.next()).?;
    const c = (try iter.next()).?;
    try testing.expectEqual(@as(u32, 5), a.start);
    try testing.expectEqual(@as(u32, 1), b.start);
    try testing.expectEqual(@as(u32, 5), c.start);
}

test "Range count and contains helpers" {
    const r = Range{ .start = 10, .end = 12 };
    try testing.expectEqual(@as(u64, 3), r.count());
    try testing.expect(r.contains(10));
    try testing.expect(r.contains(12));
    try testing.expect(!r.contains(13));

    const full = Range{ .start = 0, .end = 4294967295 };
    try testing.expectEqual(@as(u64, 4294967296), full.count());
}
