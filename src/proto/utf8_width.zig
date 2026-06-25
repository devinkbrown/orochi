// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UTF-8 terminal display-width helpers.
//!
//! This module measures how many terminal columns a UTF-8 string occupies and
//! truncates strings on codepoint boundaries to fit a column budget. It is the
//! display-width counterpart to `utf8_guard.zig` (which only *validates* UTF-8);
//! the two concerns are intentionally kept separate.
//!
//! Width rules approximate the common `wcwidth` model:
//!   * Combining marks and zero-width codepoints occupy 0 columns.
//!   * Wide East-Asian and emoji-class codepoints occupy 2 columns.
//!   * Everything else occupies 1 column.
//!
//! All helpers are allocation-free and operate on caller-owned slices. Malformed
//! UTF-8 is treated leniently for measurement purposes: each undecodable byte is
//! consumed as a single column-1 unit so the daemon never crashes on hostile or
//! truncated input.
const std = @import("std");

/// A half-open codepoint range, inclusive of both endpoints.
const Range = struct {
    lo: u21,
    hi: u21,
};

/// Codepoints that contribute zero display columns: combining marks, joiners,
/// and other zero-width control/format characters. Ordered ascending for binary
/// search. This is a pragmatic subset, not the full Unicode property database.
const ZERO_WIDTH_RANGES = [_]Range{
    .{ .lo = 0x0300, .hi = 0x036F }, // Combining Diacritical Marks
    .{ .lo = 0x0483, .hi = 0x0489 }, // Cyrillic combining marks
    .{ .lo = 0x0591, .hi = 0x05BD }, // Hebrew points
    .{ .lo = 0x05BF, .hi = 0x05BF },
    .{ .lo = 0x05C1, .hi = 0x05C2 },
    .{ .lo = 0x05C4, .hi = 0x05C5 },
    .{ .lo = 0x05C7, .hi = 0x05C7 },
    .{ .lo = 0x0610, .hi = 0x061A }, // Arabic marks
    .{ .lo = 0x064B, .hi = 0x065F },
    .{ .lo = 0x0670, .hi = 0x0670 },
    .{ .lo = 0x06D6, .hi = 0x06DC },
    .{ .lo = 0x06DF, .hi = 0x06E4 },
    .{ .lo = 0x06E7, .hi = 0x06E8 },
    .{ .lo = 0x06EA, .hi = 0x06ED },
    .{ .lo = 0x0711, .hi = 0x0711 }, // Syriac
    .{ .lo = 0x0730, .hi = 0x074A },
    .{ .lo = 0x07A6, .hi = 0x07B0 }, // Thaana
    .{ .lo = 0x07EB, .hi = 0x07F3 }, // NKo
    .{ .lo = 0x0816, .hi = 0x0819 }, // Samaritan
    .{ .lo = 0x081B, .hi = 0x0823 },
    .{ .lo = 0x0825, .hi = 0x0827 },
    .{ .lo = 0x0829, .hi = 0x082D },
    .{ .lo = 0x0859, .hi = 0x085B }, // Mandaic
    .{ .lo = 0x0900, .hi = 0x0902 }, // Devanagari signs
    .{ .lo = 0x093A, .hi = 0x093A },
    .{ .lo = 0x093C, .hi = 0x093C },
    .{ .lo = 0x0941, .hi = 0x0948 },
    .{ .lo = 0x094D, .hi = 0x094D },
    .{ .lo = 0x0951, .hi = 0x0957 },
    .{ .lo = 0x0962, .hi = 0x0963 },
    .{ .lo = 0x0E31, .hi = 0x0E31 }, // Thai
    .{ .lo = 0x0E34, .hi = 0x0E3A },
    .{ .lo = 0x0E47, .hi = 0x0E4E },
    .{ .lo = 0x1AB0, .hi = 0x1AFF }, // Combining Diacritical Marks Extended
    .{ .lo = 0x1DC0, .hi = 0x1DFF }, // Combining Diacritical Marks Supplement
    .{ .lo = 0x200B, .hi = 0x200F }, // ZWSP, ZWNJ, ZWJ, LRM, RLM
    .{ .lo = 0x2028, .hi = 0x202E }, // line/paragraph sep, bidi controls
    .{ .lo = 0x2060, .hi = 0x2064 }, // word joiner, invisible operators
    .{ .lo = 0x20D0, .hi = 0x20FF }, // Combining Diacritical Marks for Symbols
    .{ .lo = 0xFE00, .hi = 0xFE0F }, // Variation Selectors
    .{ .lo = 0xFE20, .hi = 0xFE2F }, // Combining Half Marks
    .{ .lo = 0xFEFF, .hi = 0xFEFF }, // Zero Width No-Break Space (BOM)
    .{ .lo = 0xFFF9, .hi = 0xFFFB }, // interlinear annotation
    .{ .lo = 0xE0100, .hi = 0xE01EF }, // Variation Selectors Supplement
};

/// Codepoints that occupy two display columns: East-Asian wide/fullwidth ranges
/// and common wide emoji blocks. Ordered ascending for binary search.
const WIDE_RANGES = [_]Range{
    .{ .lo = 0x1100, .hi = 0x115F }, // Hangul Jamo
    .{ .lo = 0x2329, .hi = 0x232A }, // angle brackets
    .{ .lo = 0x2E80, .hi = 0x303E }, // CJK Radicals .. Kangxi .. CJK symbols
    .{ .lo = 0x3041, .hi = 0x33FF }, // Hiragana .. Katakana .. CJK compat
    .{ .lo = 0x3400, .hi = 0x4DBF }, // CJK Ext A
    .{ .lo = 0x4E00, .hi = 0x9FFF }, // CJK Unified Ideographs
    .{ .lo = 0xA000, .hi = 0xA4CF }, // Yi
    .{ .lo = 0xA960, .hi = 0xA97F }, // Hangul Jamo Extended-A
    .{ .lo = 0xAC00, .hi = 0xD7A3 }, // Hangul Syllables
    .{ .lo = 0xF900, .hi = 0xFAFF }, // CJK Compatibility Ideographs
    .{ .lo = 0xFE10, .hi = 0xFE19 }, // Vertical forms
    .{ .lo = 0xFE30, .hi = 0xFE6F }, // CJK compat forms, small forms
    .{ .lo = 0xFF00, .hi = 0xFF60 }, // Fullwidth Forms
    .{ .lo = 0xFFE0, .hi = 0xFFE6 }, // Fullwidth signs
    .{ .lo = 0x1F300, .hi = 0x1F64F }, // Misc Symbols & Pictographs, Emoticons
    .{ .lo = 0x1F900, .hi = 0x1F9FF }, // Supplemental Symbols & Pictographs
    .{ .lo = 0x20000, .hi = 0x2FFFD }, // CJK Ext B-F
    .{ .lo = 0x30000, .hi = 0x3FFFD }, // CJK Ext G+
};

/// Return the number of display columns a single codepoint occupies.
///
/// Returns 0 for combining marks and zero-width codepoints, 2 for wide
/// East-Asian and emoji-class codepoints, and 1 otherwise. The NUL codepoint is
/// treated as width 0 to match terminal behaviour.
pub fn codepointWidth(cp: u21) u2 {
    if (cp == 0) return 0;
    if (inRanges(cp, &ZERO_WIDTH_RANGES)) return 0;
    if (inRanges(cp, &WIDE_RANGES)) return 2;
    return 1;
}

/// Return the total display width of a UTF-8 string in terminal columns.
///
/// Well-formed codepoints are summed via `codepointWidth`. Each malformed or
/// truncated byte is counted as a single column so the function is total and
/// allocation-free even on hostile input.
pub fn stringWidth(s: []const u8) usize {
    var total: usize = 0;
    var index: usize = 0;
    while (index < s.len) {
        const decoded = decodeNext(s, index);
        total += if (decoded.valid) codepointWidth(decoded.cp) else 1;
        index = decoded.next;
    }
    return total;
}

/// Truncate `s` to the longest prefix whose display width is `<= max_cols`,
/// cutting only on codepoint boundaries.
///
/// The returned slice aliases `s`; the `out` parameter is accepted for API
/// symmetry and is unused because no copying is required. The width of a single
/// wide codepoint that would straddle the limit causes that codepoint to be
/// dropped entirely rather than split. Malformed bytes count as width 1.
pub fn truncateToWidth(s: []const u8, max_cols: usize, out: []const u8) []const u8 {
    _ = out;
    var width: usize = 0;
    var index: usize = 0;
    while (index < s.len) {
        const decoded = decodeNext(s, index);
        const w: usize = if (decoded.valid) codepointWidth(decoded.cp) else 1;
        if (width + w > max_cols) break;
        width += w;
        index = decoded.next;
    }
    return s[0..index];
}

/// Result of decoding one codepoint (or one malformed byte) from a slice.
const Decoded = struct {
    cp: u21,
    /// Index just past the consumed bytes.
    next: usize,
    /// True when a well-formed UTF-8 scalar was decoded.
    valid: bool,
};

/// Decode the codepoint starting at `start`. On malformed input, consume exactly
/// one byte and report `valid = false`. Never reads past `s.len`.
fn decodeNext(s: []const u8, start: usize) Decoded {
    const first = s[start];

    if (first < 0x80) {
        return .{ .cp = first, .next = start + 1, .valid = true };
    }

    const len: usize = switch (first) {
        0xC2...0xDF => 2,
        0xE0...0xEF => 3,
        0xF0...0xF4 => 4,
        else => return invalidByte(start),
    };

    if (start + len > s.len) return invalidByte(start);

    for (s[start + 1 .. start + len]) |byte| {
        if (byte < 0x80 or byte > 0xBF) return invalidByte(start);
    }

    const cp: u21 = switch (len) {
        2 => (@as(u21, first & 0x1F) << 6) |
            @as(u21, s[start + 1] & 0x3F),
        3 => (@as(u21, first & 0x0F) << 12) |
            (@as(u21, s[start + 1] & 0x3F) << 6) |
            @as(u21, s[start + 2] & 0x3F),
        4 => (@as(u21, first & 0x07) << 18) |
            (@as(u21, s[start + 1] & 0x3F) << 12) |
            (@as(u21, s[start + 2] & 0x3F) << 6) |
            @as(u21, s[start + 3] & 0x3F),
        else => unreachable,
    };

    if (!isCanonicalScalar(cp, len)) return invalidByte(start);

    return .{ .cp = cp, .next = start + len, .valid = true };
}

/// Reject overlong encodings, surrogate scalars, and out-of-range scalars so a
/// malformed sequence is not mistaken for a wide or zero-width codepoint.
fn isCanonicalScalar(cp: u21, len: usize) bool {
    if (cp > 0x10FFFF) return false;
    if (cp >= 0xD800 and cp <= 0xDFFF) return false;
    return switch (len) {
        2 => cp >= 0x80,
        3 => cp >= 0x800,
        4 => cp >= 0x10000,
        else => false,
    };
}

fn invalidByte(start: usize) Decoded {
    return .{ .cp = 0xFFFD, .next = start + 1, .valid = false };
}

/// Binary search a sorted, non-overlapping range table for `cp`.
fn inRanges(cp: u21, ranges: []const Range) bool {
    var lo: usize = 0;
    var hi: usize = ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const range = ranges[mid];
        if (cp < range.lo) {
            hi = mid;
        } else if (cp > range.hi) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

test "ascii codepoints and strings are width one per char" {
    try std.testing.expectEqual(@as(u2, 1), codepointWidth('a'));
    try std.testing.expectEqual(@as(u2, 1), codepointWidth(' '));
    try std.testing.expectEqual(@as(u2, 1), codepointWidth('~'));
    try std.testing.expectEqual(@as(usize, 0), stringWidth(""));
    try std.testing.expectEqual(@as(usize, 5), stringWidth("hello"));
    try std.testing.expectEqual(@as(usize, 11), stringWidth("PRIVMSG foo"));
}

test "nul codepoint is width zero" {
    try std.testing.expectEqual(@as(u2, 0), codepointWidth(0));
}

test "combining marks are width zero" {
    try std.testing.expectEqual(@as(u2, 0), codepointWidth(0x0301)); // combining acute
    try std.testing.expectEqual(@as(u2, 0), codepointWidth(0x200B)); // zero width space
    try std.testing.expectEqual(@as(u2, 0), codepointWidth(0xFE0F)); // variation selector-16

    // "e" + U+0301 (combining acute) renders as one column.
    const e_acute = "e\xCC\x81";
    try std.testing.expectEqual(@as(usize, 1), stringWidth(e_acute));

    // Family of base + multiple combining marks stays width 1.
    const stacked = "a\xCC\x80\xCC\x81\xCC\x82";
    try std.testing.expectEqual(@as(usize, 1), stringWidth(stacked));
}

test "cjk and emoji codepoints are width two" {
    try std.testing.expectEqual(@as(u2, 2), codepointWidth(0x4E00)); // CJK ideograph
    try std.testing.expectEqual(@as(u2, 2), codepointWidth(0x3042)); // Hiragana A
    try std.testing.expectEqual(@as(u2, 2), codepointWidth(0xAC00)); // Hangul GA
    try std.testing.expectEqual(@as(u2, 2), codepointWidth(0xFF21)); // Fullwidth A
    try std.testing.expectEqual(@as(u2, 2), codepointWidth(0x1F600)); // grinning face

    // "日本" is two wide ideographs -> 4 columns.
    try std.testing.expectEqual(@as(usize, 4), stringWidth("\xE6\x97\xA5\xE6\x9C\xAC"));
    // Emoji (4-byte) -> 2 columns.
    try std.testing.expectEqual(@as(usize, 2), stringWidth("\xF0\x9F\x98\x80"));
}

test "mixed-width string measurement" {
    // "aあb" -> 1 + 2 + 1 = 4
    const mixed = "a\xE3\x81\x82b";
    try std.testing.expectEqual(@as(usize, 4), stringWidth(mixed));
}

test "truncation cuts on codepoint boundary" {
    var scratch: [0]u8 = undefined;
    const out = scratch[0..];

    // Plain ASCII truncation.
    try std.testing.expectEqualStrings("hel", truncateToWidth("hello", 3, out));
    try std.testing.expectEqualStrings("hello", truncateToWidth("hello", 99, out));
    try std.testing.expectEqualStrings("", truncateToWidth("hello", 0, out));

    // "aあb": budget 2 keeps only "a" because "あ" (width 2) would overflow at col 2..3.
    const mixed = "a\xE3\x81\x82b";
    try std.testing.expectEqualStrings("a", truncateToWidth(mixed, 2, out));
    // Budget 3 fits "a" + "あ".
    try std.testing.expectEqualStrings("a\xE3\x81\x82", truncateToWidth(mixed, 3, out));
}

test "wide codepoint never split at the limit" {
    var scratch: [0]u8 = undefined;
    const out = scratch[0..];

    // Single wide char with budget 1 -> dropped entirely, not split.
    const ja = "\xE6\x97\xA5"; // 日 (width 2)
    try std.testing.expectEqualStrings("", truncateToWidth(ja, 1, out));
    try std.testing.expectEqualStrings(ja, truncateToWidth(ja, 2, out));
}

test "combining marks do not consume truncation budget" {
    var scratch: [0]u8 = undefined;
    const out = scratch[0..];

    // "e" + combining acute is width 1, so budget 1 keeps the full grapheme.
    const e_acute = "e\xCC\x81";
    try std.testing.expectEqualStrings(e_acute, truncateToWidth(e_acute, 1, out));
}

test "invalid bytes count as width one" {
    // Lone continuation byte.
    try std.testing.expectEqual(@as(usize, 1), stringWidth("\x80"));
    // Truncated 3-byte sequence (only the lead byte present).
    try std.testing.expectEqual(@as(usize, 1), stringWidth("\xE2"));
    // Overlong encoding of '/' (0x2F) is rejected -> two width-1 bytes.
    try std.testing.expectEqual(@as(usize, 2), stringWidth("\xC0\xAF"));
    // Surrogate scalar is rejected -> three width-1 bytes.
    try std.testing.expectEqual(@as(usize, 3), stringWidth("\xED\xA0\x80"));

    // Valid char followed by a bad byte: 1 + 1.
    try std.testing.expectEqual(@as(usize, 2), stringWidth("a\xFF"));
}

test "truncation with invalid bytes stays on byte boundary" {
    var scratch: [0]u8 = undefined;
    const out = scratch[0..];

    // "a" + bad byte + "b": budget 2 keeps "a" + bad byte (each width 1).
    const bad = "a\xFFb";
    try std.testing.expectEqualStrings("a\xFF", truncateToWidth(bad, 2, out));
    try std.testing.expectEqualStrings("a", truncateToWidth(bad, 1, out));
}

test "range tables remain sorted and non-overlapping" {
    inline for (.{ ZERO_WIDTH_RANGES, WIDE_RANGES }) |table| {
        var prev_hi: i64 = -1;
        for (table) |range| {
            try std.testing.expect(range.lo <= range.hi);
            try std.testing.expect(@as(i64, range.lo) > prev_hi);
            prev_hi = range.hi;
        }
    }
}
