//! Ban-mask safety analysis.
//!
//! Operators set ban-style masks (channel `+b`, WARD, SHUN, and similar
//! enforcement entries) using IRC wildcard syntax where `*` matches any byte
//! run and `?` matches exactly one byte. A mask that is mostly wildcards, such
//! as `*!*@*`, matches nearly every connection and is almost always a mistake:
//! it is both dangerously broad and expensive to evaluate against every user.
//!
//! This module provides allocation-free helpers to count the wildcard content
//! of a mask and to decide, against a caller-supplied policy, whether a mask is
//! too broad to accept. It performs no matching itself; pattern matching lives
//! in `substrate/wildcard.zig`.
//!
//! Wildcard semantics match the matcher: a backslash escapes only `*`, `?`, and
//! `\`; before any other byte the backslash is an ordinary literal character.
//! An escaped `*` or `?` therefore counts as a non-wildcard literal, because it
//! constrains the match rather than widening it.

const std = @import("std");

const testing = std.testing;

/// A tally of the wildcard structure of a mask.
///
/// `non_wild` counts literal bytes that constrain the match. Escaped wildcards
/// (`\*`, `\?`) and the literal backslash they introduce are counted as
/// non-wildcard literals. Structural separators such as `!` and `@` in a
/// `nick!user@host` mask are ordinary literals and are included in `non_wild`.
pub const WildcardCounts = struct {
    /// Number of unescaped `*` tokens (each matches any byte run).
    stars: usize,
    /// Number of unescaped `?` tokens (each matches exactly one byte).
    questions: usize,
    /// Number of literal, match-constraining bytes.
    non_wild: usize,
};

/// Policy describing the minimum specificity a mask must have to be accepted.
///
/// A mask is rejected when it has fewer than `min_non_wildcard` literal bytes,
/// or more than `max_stars` unescaped `*` tokens. Pick thresholds to suit the
/// enforcement surface: a tighter policy for network-wide bans (WARD/SHUN), a
/// looser one for per-channel `+b`.
pub const Policy = struct {
    /// Minimum number of literal, constraining bytes a mask must contain.
    min_non_wildcard: usize,
    /// Maximum number of unescaped `*` tokens a mask may contain.
    max_stars: usize,

    /// A reasonable default for per-channel ban lists.
    pub const channel_ban: Policy = .{ .min_non_wildcard = 3, .max_stars = 3 };

    /// A stricter default for network-wide enforcement (WARD/SHUN).
    pub const network_enforcement: Policy = .{ .min_non_wildcard = 5, .max_stars = 2 };
};

/// Count the wildcard structure of `mask`.
///
/// Allocation-free and side-effect-free. Honors backslash escaping: `\*`, `\?`,
/// and `\\` contribute literal bytes to `non_wild` rather than wildcards. A
/// trailing lone backslash is treated as a literal byte.
pub fn countWildcards(mask: []const u8) WildcardCounts {
    var counts: WildcardCounts = .{ .stars = 0, .questions = 0, .non_wild = 0 };
    var index: usize = 0;

    while (index < mask.len) : (index += 1) {
        const byte = mask[index];
        if (byte == '\\') {
            const next_index = index + 1;
            if (next_index < mask.len) {
                const next = mask[next_index];
                if (next == '*' or next == '?' or next == '\\') {
                    // Escaped sequence: backslash plus an escaped literal byte.
                    counts.non_wild += 2;
                    index = next_index;
                    continue;
                }
            }
            // Lone backslash, or backslash before an ordinary byte: literal.
            counts.non_wild += 1;
            continue;
        }

        switch (byte) {
            '*' => counts.stars += 1,
            '?' => counts.questions += 1,
            else => counts.non_wild += 1,
        }
    }

    return counts;
}

/// Return true when `mask` is too broad to accept under `policy`.
///
/// A mask is too broad when it has fewer literal bytes than
/// `policy.min_non_wildcard`, or more `*` tokens than `policy.max_stars`. An
/// empty mask is always too broad. Allocation-free and side-effect-free.
pub fn isTooBroad(mask: []const u8, policy: Policy) bool {
    const counts = countWildcards(mask);
    if (counts.non_wild < policy.min_non_wildcard) return true;
    if (counts.stars > policy.max_stars) return true;
    return false;
}

test "countWildcards counts stars questions and literals" {
    const counts = countWildcards("a*b?c");
    try testing.expectEqual(@as(usize, 1), counts.stars);
    try testing.expectEqual(@as(usize, 1), counts.questions);
    try testing.expectEqual(@as(usize, 3), counts.non_wild);
}

test "countWildcards on all-wildcard mask" {
    const counts = countWildcards("*!*@*");
    try testing.expectEqual(@as(usize, 3), counts.stars);
    try testing.expectEqual(@as(usize, 0), counts.questions);
    // The two separators '!' and '@' are literals.
    try testing.expectEqual(@as(usize, 2), counts.non_wild);
}

test "countWildcards on empty mask" {
    const counts = countWildcards("");
    try testing.expectEqual(@as(usize, 0), counts.stars);
    try testing.expectEqual(@as(usize, 0), counts.questions);
    try testing.expectEqual(@as(usize, 0), counts.non_wild);
}

test "countWildcards treats escaped wildcards as literals" {
    const counts = countWildcards("a\\*b\\?c");
    try testing.expectEqual(@as(usize, 0), counts.stars);
    try testing.expectEqual(@as(usize, 0), counts.questions);
    // 'a' + "\*" (2) + 'b' + "\?" (2) + 'c' = 7 literal bytes.
    try testing.expectEqual(@as(usize, 7), counts.non_wild);
}

test "countWildcards treats lone trailing backslash as literal" {
    const counts = countWildcards("abc\\");
    try testing.expectEqual(@as(usize, 0), counts.stars);
    try testing.expectEqual(@as(usize, 0), counts.questions);
    try testing.expectEqual(@as(usize, 4), counts.non_wild);
}

test "countWildcards treats backslash before ordinary byte as literal" {
    const counts = countWildcards("\\nfoo");
    // Backslash is a literal byte, then 'n', 'f', 'o', 'o'.
    try testing.expectEqual(@as(usize, 0), counts.stars);
    try testing.expectEqual(@as(usize, 0), counts.questions);
    try testing.expectEqual(@as(usize, 5), counts.non_wild);
}

test "isTooBroad flags *!*@*" {
    try testing.expect(isTooBroad("*!*@*", Policy.channel_ban));
    try testing.expect(isTooBroad("*!*@*", Policy.network_enforcement));
}

test "isTooBroad accepts a specific mask" {
    // nick!user@host.example.com has many literal bytes and no stars.
    try testing.expect(!isTooBroad("nick!user@host.example.com", Policy.channel_ban));
    try testing.expect(!isTooBroad("nick!user@host.example.com", Policy.network_enforcement));
}

test "isTooBroad flags all-wildcard mask" {
    try testing.expect(isTooBroad("***", Policy.channel_ban));
    try testing.expect(isTooBroad("*", Policy.channel_ban));
    try testing.expect(isTooBroad("", Policy.channel_ban));
}

test "isTooBroad min-non-wildcard threshold" {
    const policy: Policy = .{ .min_non_wildcard = 4, .max_stars = 8 };
    // "abc" has 3 literals: below the threshold of 4.
    try testing.expect(isTooBroad("abc", policy));
    // "abcd" meets the threshold exactly.
    try testing.expect(!isTooBroad("abcd", policy));
    // A typical partial mask with enough literals despite stars.
    try testing.expect(!isTooBroad("*!evil@host", policy));
}

test "isTooBroad star count cap" {
    const policy: Policy = .{ .min_non_wildcard = 0, .max_stars = 2 };
    // Two stars is at the cap and accepted.
    try testing.expect(!isTooBroad("*a*b", policy));
    // Three stars exceeds the cap.
    try testing.expect(isTooBroad("*a*b*c", policy));
    // Escaped star does not count toward the cap.
    try testing.expect(!isTooBroad("\\*\\*\\*x", policy));
}

test "isTooBroad respects escaped wildcards as specificity" {
    // A mask of three escaped stars is all literals: specific, not broad.
    const policy: Policy = .{ .min_non_wildcard = 3, .max_stars = 0 };
    try testing.expect(!isTooBroad("\\*\\*", policy));
    // A single unescaped star pushes it over the star cap.
    try testing.expect(isTooBroad("\\*ab*", policy));
}
