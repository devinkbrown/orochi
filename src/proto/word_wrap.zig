//! Greedy, allocation-free word wrapping for human-readable IRC bodies.
//!
//! This module folds free-form text into a sequence of display lines whose
//! width does not exceed a caller-chosen column budget. It is intended for
//! presentation text such as MOTD bodies, the WELCOME burst, and long
//! `NOTICE`/`PRIVMSG` paragraphs that should be reflowed for readability
//! rather than truncated.
//!
//! It is deliberately distinct from the protocol-level folding in `motd.zig`:
//! that code splits raw bytes at a fixed IRC line-length budget without regard
//! for word boundaries, whereas this module performs *greedy word wrapping* —
//! it prefers to break on spaces and only ever splits a single word when that
//! word is, on its own, wider than the column budget.
//!
//! Design guarantees:
//!
//!   * Zero allocation. `Wrapper.next` returns borrowed sub-slices of the
//!     original `text`; the iterator owns no heap memory and frees nothing
//!     because it allocates nothing. Returned slices are valid for exactly as
//!     long as the backing `text` is valid.
//!   * Greedy packing. Each emitted line is the longest run of whole words
//!     that fits within `max_cols`, measured in bytes.
//!   * Hard splitting. A word longer than `max_cols` is split at the column
//!     boundary so that progress is always made and no emitted line exceeds
//!     `max_cols` (except the degenerate `max_cols == 0` case, normalized to
//!     1 below).
//!   * Space handling. Runs of spaces between words are treated as separators
//!     and collapsed: emitted lines never carry leading or trailing spaces and
//!     never contain a run of spaces that was used purely as a break point.
//!
//! Width is measured in bytes, not grapheme clusters or display columns. For
//! ASCII MOTD and notice text this matches visual width; multi-byte UTF-8 is
//! never split mid-codepoint by the space-breaking path, but the hard-split
//! fallback for an over-long unbroken run may split on a byte boundary. Hard
//! splits are an edge case reserved for pathological input (e.g. a single
//! enormous token), so this trade-off is acceptable for presentation text.

const std = @import("std");

/// A single ASCII space; the only character treated as an inter-word break.
const space: u8 = ' ';

/// Greedy word-wrap iterator over a borrowed text buffer.
///
/// Construct with `init` and pull lines with `next` until it returns `null`.
/// The iterator never allocates and never mutates `text`; every slice it
/// yields aliases into `text`.
pub const Wrapper = struct {
    /// The backing text. Never modified.
    text: []const u8,
    /// Maximum line width in bytes. Always >= 1 after normalization.
    max_cols: usize,
    /// Index of the next unconsumed byte in `text`.
    cursor: usize,

    /// Initialize a wrapper over `text` with a column budget of `max_cols`.
    ///
    /// A `max_cols` of `0` is normalized to `1` so that hard splitting always
    /// makes forward progress and cannot loop forever on long words.
    pub fn init(text: []const u8, max_cols: usize) Wrapper {
        return .{
            .text = text,
            .max_cols = if (max_cols == 0) 1 else max_cols,
            .cursor = 0,
        };
    }

    /// Return the next wrapped line, or `null` once the text is exhausted.
    ///
    /// The returned slice borrows from `text` and never includes leading or
    /// trailing break spaces. Lines fit within `max_cols` bytes wherever the
    /// input allows; a single word wider than `max_cols` is hard-split.
    ///
    /// An empty input yields no lines (the first call returns `null`).
    pub fn next(self: *Wrapper) ?[]const u8 {
        // Skip any run of separator spaces preceding the next word so that
        // emitted lines never begin with break whitespace.
        self.skipSpaces();
        if (self.cursor >= self.text.len) return null;

        const line_start = self.cursor;
        // `line_end` is the exclusive end of the content committed to the
        // current line so far (trailing break spaces excluded).
        var line_end = self.cursor;

        while (self.cursor < self.text.len) {
            // Consume the run of spaces that separates the previous word from
            // the next one. A line break may legitimately fall inside this run.
            const word_start = self.skipSpacesFrom(self.cursor);
            if (word_start >= self.text.len) {
                // Trailing spaces only; nothing more to pack onto this line.
                self.cursor = word_start;
                break;
            }

            const word_end = self.wordEndFrom(word_start);
            const word_len = word_end - word_start;
            const candidate_len = word_end - line_start;

            if (candidate_len <= self.max_cols) {
                // The whole word (plus its leading spaces) fits: commit it.
                line_end = word_end;
                self.cursor = word_end;
                continue;
            }

            // The word does not fit on the current line as-is.
            if (line_end > line_start) {
                // We already placed at least one word; flush this line and
                // leave the non-fitting word for the next call. Rewind the
                // cursor to the start of the separating spaces so they are
                // re-skipped (and discarded) next time around.
                self.cursor = line_end;
                break;
            }

            // The line is empty and a single word is too wide for the budget:
            // hard-split it at the column boundary to guarantee progress.
            if (word_len > self.max_cols) {
                const hard_end = line_start + self.max_cols;
                self.cursor = hard_end;
                return self.text[line_start..hard_end];
            }

            // The word fits within `max_cols` on its own but the leading
            // spaces pushed it over; start the line at the word instead.
            line_end = word_end;
            self.cursor = word_end;
        }

        return self.text[line_start..line_end];
    }

    /// Advance `cursor` past any run of spaces at the current position.
    fn skipSpaces(self: *Wrapper) void {
        self.cursor = self.skipSpacesFrom(self.cursor);
    }

    /// Return the first index at or after `from` that is not a space.
    fn skipSpacesFrom(self: *const Wrapper, from: usize) usize {
        var i = from;
        while (i < self.text.len and self.text[i] == space) : (i += 1) {}
        return i;
    }

    /// Return the exclusive end index of the word beginning at `from`.
    ///
    /// `from` must reference a non-space byte. The word extends to the next
    /// space or to the end of the text.
    fn wordEndFrom(self: *const Wrapper, from: usize) usize {
        var i = from;
        while (i < self.text.len and self.text[i] != space) : (i += 1) {}
        return i;
    }
};

/// Count how many lines `Wrapper.init(text, max_cols)` would yield.
///
/// This is a convenience that drives a transient `Wrapper` to exhaustion. It
/// allocates nothing and leaves no observable state; the result equals the
/// number of non-null values `next` would return.
pub fn countLines(text: []const u8, max_cols: usize) usize {
    var wrapper = Wrapper.init(text, max_cols);
    var count: usize = 0;
    while (wrapper.next()) |_| count += 1;
    return count;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Collect all wrapped lines into a heap-owned list for assertion.
///
/// Each entry borrows from `text`; only the outer list is heap-allocated and
/// it is returned to the caller, who must free it with the same allocator.
fn collect(
    allocator: std.mem.Allocator,
    text: []const u8,
    max_cols: usize,
) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);
    var wrapper = Wrapper.init(text, max_cols);
    while (wrapper.next()) |line| try list.append(allocator, line);
    return list.toOwnedSlice(allocator);
}

test "empty input yields no lines" {
    var wrapper = Wrapper.init("", 10);
    try testing.expectEqual(@as(?[]const u8, null), wrapper.next());
    try testing.expectEqual(@as(usize, 0), countLines("", 10));
}

test "whitespace-only input yields no lines" {
    var wrapper = Wrapper.init("     ", 10);
    try testing.expectEqual(@as(?[]const u8, null), wrapper.next());
    try testing.expectEqual(@as(usize, 0), countLines("     ", 10));
}

test "short text fits on a single line" {
    const lines = try collect(testing.allocator, "hello world", 20);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings("hello world", lines[0]);
    try testing.expectEqual(@as(usize, 1), countLines("hello world", 20));
}

test "text exactly at the column budget stays on one line" {
    // "hello" is 5 bytes; budget is 5.
    const lines = try collect(testing.allocator, "hello", 5);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings("hello", lines[0]);
}

test "greedy wrap across multiple lines" {
    // Budget 11 packs "the quick" (9) but not "the quick brown" (15).
    const text = "the quick brown fox jumps";
    const lines = try collect(testing.allocator, text, 11);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 3), lines.len);
    try testing.expectEqualStrings("the quick", lines[0]);
    try testing.expectEqualStrings("brown fox", lines[1]);
    try testing.expectEqualStrings("jumps", lines[2]);
    try testing.expectEqual(@as(usize, 3), countLines(text, 11));
}

test "no emitted line exceeds the column budget" {
    const text = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
    const max_cols: usize = 12;
    var wrapper = Wrapper.init(text, max_cols);
    while (wrapper.next()) |line| {
        try testing.expect(line.len <= max_cols);
        // No emitted line carries break whitespace at its edges.
        try testing.expect(line.len == 0 or line[0] != space);
        try testing.expect(line.len == 0 or line[line.len - 1] != space);
    }
}

test "long unbreakable word is hard-split at the budget" {
    // 20-byte token, budget 6 -> ceil(20/6) = 4 chunks (6,6,6,2).
    const text = "abcdefghijklmnopqrst";
    const lines = try collect(testing.allocator, text, 6);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 4), lines.len);
    try testing.expectEqualStrings("abcdef", lines[0]);
    try testing.expectEqualStrings("ghijkl", lines[1]);
    try testing.expectEqualStrings("mnopqr", lines[2]);
    try testing.expectEqualStrings("st", lines[3]);
}

test "hard-split word interleaves with normal words" {
    // "hi" fits, then the 8-byte word exceeds budget 4 and is hard-split.
    const text = "hi enormousword bye";
    const lines = try collect(testing.allocator, text, 4);
    defer testing.allocator.free(lines);

    try testing.expectEqualStrings("hi", lines[0]);
    try testing.expectEqualStrings("enor", lines[1]);
    try testing.expectEqualStrings("mous", lines[2]);
    try testing.expectEqualStrings("word", lines[3]);
    try testing.expectEqualStrings("bye", lines[4]);
}

test "leading and trailing spaces are trimmed" {
    const lines = try collect(testing.allocator, "   padded text   ", 20);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings("padded text", lines[0]);
}

test "multiple internal spaces are collapsed at break points" {
    // The wide gap between words is consumed as a separator, not preserved.
    const text = "one     two     three";
    const lines = try collect(testing.allocator, text, 5);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 3), lines.len);
    try testing.expectEqualStrings("one", lines[0]);
    try testing.expectEqualStrings("two", lines[1]);
    try testing.expectEqualStrings("three", lines[2]);
}

test "internal spaces preserved when words share a line" {
    // Two short words with multiple spaces still fit; the spaces remain
    // because no break falls between them.
    const lines = try collect(testing.allocator, "a  b", 10);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings("a  b", lines[0]);
}

test "zero column budget is normalized to one" {
    const lines = try collect(testing.allocator, "ab", 0);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 2), lines.len);
    try testing.expectEqualStrings("a", lines[0]);
    try testing.expectEqualStrings("b", lines[1]);
}

test "countLines matches collected line count for mixed input" {
    const text = "Welcome to the network! Please read the rules carefully before chatting.";
    const max_cols: usize = 16;
    const lines = try collect(testing.allocator, text, max_cols);
    defer testing.allocator.free(lines);

    try testing.expectEqual(lines.len, countLines(text, max_cols));
}

test "single word equal to budget is not split" {
    const lines = try collect(testing.allocator, "exactly", 7);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings("exactly", lines[0]);
}

test "single word one over budget is hard-split into two" {
    const lines = try collect(testing.allocator, "overflow", 7);
    defer testing.allocator.free(lines);

    try testing.expectEqual(@as(usize, 2), lines.len);
    try testing.expectEqualStrings("overflo", lines[0]);
    try testing.expectEqualStrings("w", lines[1]);
}
