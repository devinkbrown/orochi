// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Leetspeak and ASCII confusable normalizer for content-filter keys.
//!
//! The normalizer is intentionally byte-oriented and allocation-free. It
//! lowercases ASCII letters, folds a small set of common leetspeak glyphs into
//! letters, strips bytes outside the resulting alphanumeric set, and caps each
//! run of identical output bytes at two characters. Keeping two repeats means
//! words with intentional doubles remain matchable: `fr33` becomes `free` and
//! `@ss` becomes `ass`, while longer padding such as `aaa` becomes `aa`.

const std = @import("std");

/// Errors returned by normalization.
pub const NormalizeError = error{
    /// The caller-provided output buffer cannot hold the normalized bytes.
    OutputTooSmall,
};

/// Normalize `input` into `out` and return the written slice.
pub fn normalize(out: []u8, input: []const u8) NormalizeError![]const u8 {
    var written: usize = 0;
    var last: u8 = 0;
    var run_len: usize = 0;

    for (input) |byte| {
        const folded = fold(byte) orelse continue;
        if (!isAlnum(folded)) continue;

        if (written > 0 and folded == last) {
            if (run_len >= 2) continue;
            run_len += 1;
        } else {
            last = folded;
            run_len = 1;
        }

        if (written >= out.len) return error.OutputTooSmall;
        out[written] = folded;
        written += 1;
    }

    return out[0..written];
}

/// Return the exact output length for `input` after normalization.
pub fn normalizedLen(input: []const u8) usize {
    var len: usize = 0;
    var last: u8 = 0;
    var run_len: usize = 0;

    for (input) |byte| {
        const folded = fold(byte) orelse continue;
        if (!isAlnum(folded)) continue;

        if (len > 0 and folded == last) {
            if (run_len >= 2) continue;
            run_len += 1;
        } else {
            last = folded;
            run_len = 1;
        }

        len += 1;
    }

    return len;
}

fn fold(byte: u8) ?u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        'a'...'z' => byte,
        '2', '6', '8', '9' => byte,
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '@' => 'a',
        '$' => 's',
        else => null,
    };
}

fn isAlnum(byte: u8) bool {
    return switch (byte) {
        'a'...'z', '0'...'9' => true,
        else => false,
    };
}

test "normalizes repeated leet vowels toward banned word keys" {
    var out: [16]u8 = undefined;

    const normalized = try normalize(&out, "fr33");

    try std.testing.expectEqualStrings("free", normalized);
    try std.testing.expectEqual(@as(usize, 4), normalizedLen("fr33"));
}

test "keeps two repeated letters after folding" {
    var out: [16]u8 = undefined;

    const padded = try normalize(&out, "@ss");
    try std.testing.expectEqualStrings("ass", padded);

    const collapsed = try normalize(&out, "aaa");
    try std.testing.expectEqualStrings("aa", collapsed);
}

test "strips punctuation while folding and lowercasing" {
    var out: [16]u8 = undefined;

    const normalized = try normalize(&out, "f.r3e_e!!");

    try std.testing.expectEqualStrings("free", normalized);
}

test "folds configured substitutions" {
    var out: [32]u8 = undefined;

    const normalized = try normalize(&out, "4 3 1 0 5 7 @ $");

    try std.testing.expectEqualStrings("aeiostas", normalized);
}

test "retains unmapped digits as alphanumerics" {
    var out: [16]u8 = undefined;

    const normalized = try normalize(&out, "Room-289");

    try std.testing.expectEqualStrings("room289", normalized);
}

test "reports OutputTooSmall before partial result escapes" {
    var out: [3]u8 = undefined;

    try std.testing.expectError(error.OutputTooSmall, normalize(&out, "fr33"));
}

test "empty and fully stripped inputs normalize to empty slices" {
    var out: [1]u8 = undefined;

    const empty = try normalize(&out, "");
    const stripped = try normalize(&out, ".!_-/");

    try std.testing.expectEqualStrings("", empty);
    try std.testing.expectEqualStrings("", stripped);
    try std.testing.expectEqual(@as(usize, 0), normalizedLen(".!_-/"));
}
