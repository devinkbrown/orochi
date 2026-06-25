// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free IRC hostmask matching for bans, access lists, and extbans.
//!
//! Provides ASCII case-insensitive glob matching (`*` and `?`) with a strictly
//! iterative algorithm that cannot exhibit catastrophic backtracking, plus
//! helpers to match and normalize `nick!user@host` masks. All routines operate
//! on caller-supplied buffers and never allocate.
//!
//! Glob semantics:
//!   * `*` matches zero or more arbitrary characters
//!   * `?` matches exactly one arbitrary character
//!   * every other byte matches itself, compared case-insensitively (ASCII)
//!
//! Hostmask semantics:
//!   A mask is `nick!user@host`. `matchHostmask` splits the mask and matches
//!   each component as an independent glob. `normalize` fills missing
//!   components with `*` so partial masks become well-formed (e.g. `nick`
//!   becomes `nick!*@*`).

const std = @import("std");

/// ASCII-only lowercase fold. Non-letter bytes pass through unchanged.
fn fold(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// Case-insensitive (ASCII) glob match of `pattern` against `text`.
///
/// Supports `*` (zero or more) and `?` (exactly one). The implementation is
/// iterative with a single backtrack anchor, giving O(len(pattern) * len(text))
/// worst-case behavior with no recursion, so adversarial inputs such as
/// `a*a*a*a*...` cannot blow up the stack or hang.
pub fn matchGlob(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0; // cursor into pattern
    var t: usize = 0; // cursor into text
    var star: ?usize = null; // pattern index just after the last '*'
    var star_t: usize = 0; // text index where that '*' began matching

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or fold(pattern[p]) == fold(text[t]))) {
            // Literal or '?' match: advance both.
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            // Record backtrack anchor; tentatively match zero characters.
            star = p;
            star_t = t;
            p += 1;
        } else if (star) |s| {
            // Mismatch but a previous '*' can absorb one more text byte.
            p = s + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    // Consume any trailing '*' in the pattern.
    while (p < pattern.len and pattern[p] == '*') p += 1;

    return p == pattern.len;
}

/// Match a candidate `nick`, `user`, and `host` against a `nick!user@host`
/// mask. Each component is matched as an independent case-insensitive glob.
///
/// The mask is split on the first `!` and the first `@` after it. A mask
/// missing those separators is normalized internally (a bare component is
/// treated as `nick`, the rest defaulting to `*`).
pub fn matchHostmask(mask: []const u8, nick: []const u8, user: []const u8, host: []const u8) bool {
    const parts = splitMask(mask);
    return matchGlob(parts.nick, nick) and
        matchGlob(parts.user, user) and
        matchGlob(parts.host, host);
}

/// The three glob components of a parsed hostmask.
pub const MaskParts = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Split a raw mask into nick/user/host components, defaulting any missing
/// component to `*`. Does not copy; the returned slices borrow from `mask`.
///
/// Rules:
///   `nick!user@host` -> all three explicit
///   `nick!user`      -> host defaults to `*`
///   `nick@host`      -> user defaults to `*`
///   `nick`           -> user and host default to `*`
pub fn splitMask(mask: []const u8) MaskParts {
    const star = "*";
    var nick: []const u8 = mask;
    var user: []const u8 = star;
    var host: []const u8 = star;

    // Find the first '@'; everything after it is the host.
    if (std.mem.indexOfScalar(u8, mask, '@')) |at| {
        host = mask[at + 1 ..];
        nick = mask[0..at];
    }

    // Within the pre-`@` portion, split on the first '!' into nick/user.
    if (std.mem.indexOfScalar(u8, nick, '!')) |bang| {
        user = nick[bang + 1 ..];
        nick = nick[0..bang];
    }

    if (nick.len == 0) nick = star;
    if (user.len == 0) user = star;
    if (host.len == 0) host = star;

    return .{ .nick = nick, .user = user, .host = host };
}

/// Normalize a raw (possibly partial) mask into a full `nick!user@host` form,
/// writing into `buf` and returning the written slice. Missing components are
/// filled with `*`. Returns `error.NoSpace` if `buf` is too small.
///
/// The output borrows nothing; it is fully contained in `buf`.
pub fn normalize(buf: []u8, raw_mask: []const u8) error{NoSpace}![]const u8 {
    const parts = splitMask(raw_mask);
    const needed = parts.nick.len + 1 + parts.user.len + 1 + parts.host.len;
    if (needed > buf.len) return error.NoSpace;

    var i: usize = 0;
    @memcpy(buf[i .. i + parts.nick.len], parts.nick);
    i += parts.nick.len;
    buf[i] = '!';
    i += 1;
    @memcpy(buf[i .. i + parts.user.len], parts.user);
    i += parts.user.len;
    buf[i] = '@';
    i += 1;
    @memcpy(buf[i .. i + parts.host.len], parts.host);
    i += parts.host.len;

    return buf[0..i];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "matchGlob literal exact" {
    try std.testing.expect(matchGlob("hello", "hello"));
    try std.testing.expect(!matchGlob("hello", "hell"));
    try std.testing.expect(!matchGlob("hello", "helloo"));
    try std.testing.expect(matchGlob("", ""));
    try std.testing.expect(!matchGlob("", "x"));
}

test "matchGlob star wildcard" {
    try std.testing.expect(matchGlob("*", ""));
    try std.testing.expect(matchGlob("*", "anything"));
    try std.testing.expect(matchGlob("a*", "abc"));
    try std.testing.expect(matchGlob("*c", "abc"));
    try std.testing.expect(matchGlob("a*c", "abc"));
    try std.testing.expect(matchGlob("a*c", "ac"));
    try std.testing.expect(matchGlob("*.example.com", "irc.example.com"));
    try std.testing.expect(!matchGlob("a*c", "abd"));
    try std.testing.expect(matchGlob("**", "xy"));
}

test "matchGlob question wildcard" {
    try std.testing.expect(matchGlob("?", "a"));
    try std.testing.expect(!matchGlob("?", ""));
    try std.testing.expect(!matchGlob("?", "ab"));
    try std.testing.expect(matchGlob("h?llo", "hello"));
    try std.testing.expect(matchGlob("h?llo", "hallo"));
    try std.testing.expect(matchGlob("a?c*", "abcdef"));
}

test "matchGlob ASCII casefold" {
    try std.testing.expect(matchGlob("Hello", "hello"));
    try std.testing.expect(matchGlob("HELLO", "hello"));
    try std.testing.expect(matchGlob("*.EXAMPLE.com", "irc.example.COM"));
    try std.testing.expect(matchGlob("NiCk", "nick"));
}

test "matchHostmask components" {
    try std.testing.expect(matchHostmask("nick!user@host", "nick", "user", "host"));
    try std.testing.expect(matchHostmask("*!*@*.example.com", "anyone", "anyuser", "irc.example.com"));
    try std.testing.expect(matchHostmask("bad*!*@*", "badguy", "ident", "1.2.3.4"));
    try std.testing.expect(!matchHostmask("nick!user@host", "nick", "user", "other"));
    try std.testing.expect(!matchHostmask("nick!user@host", "other", "user", "host"));
    // Case-insensitive across components.
    try std.testing.expect(matchHostmask("Nick!User@Host", "nick", "user", "host"));
}

test "splitMask and normalize component fill" {
    const star = "*";

    const a = splitMask("nick");
    try std.testing.expectEqualStrings("nick", a.nick);
    try std.testing.expectEqualStrings(star, a.user);
    try std.testing.expectEqualStrings(star, a.host);

    const b = splitMask("nick!user");
    try std.testing.expectEqualStrings("nick", b.nick);
    try std.testing.expectEqualStrings("user", b.user);
    try std.testing.expectEqualStrings(star, b.host);

    const c = splitMask("nick@host");
    try std.testing.expectEqualStrings("nick", c.nick);
    try std.testing.expectEqualStrings(star, c.user);
    try std.testing.expectEqualStrings("host", c.host);

    const d = splitMask("nick!user@host");
    try std.testing.expectEqualStrings("nick", d.nick);
    try std.testing.expectEqualStrings("user", d.user);
    try std.testing.expectEqualStrings("host", d.host);

    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("nick!*@*", try normalize(&buf, "nick"));
    try std.testing.expectEqualStrings("nick!user@*", try normalize(&buf, "nick!user"));
    try std.testing.expectEqualStrings("nick!*@host", try normalize(&buf, "nick@host"));
    try std.testing.expectEqualStrings("nick!user@host", try normalize(&buf, "nick!user@host"));
    // Empty mask becomes the all-wildcard mask.
    try std.testing.expectEqualStrings("*!*@*", try normalize(&buf, ""));
}

test "normalize respects buffer bounds" {
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.NoSpace, normalize(&tiny, "longnick!longuser@longhost"));
}

test "matchGlob pathological no catastrophic backtracking" {
    // Patterns crafted to defeat naive backtracking matchers. These must
    // resolve quickly via the iterative single-anchor algorithm.
    const text = "a" ** 64;
    try std.testing.expect(matchGlob("a*a*a*a*a*a*a*a*a*a*", text));
    // Long run of stars followed by a final literal that is absent.
    try std.testing.expect(!matchGlob("a*a*a*a*a*a*a*a*a*b", text));
    // Many stars and questions interleaved.
    try std.testing.expect(matchGlob("*a*a?a*a*", "aaaaaaaa"));
    // Pattern of pure stars matches anything including empty.
    try std.testing.expect(matchGlob("*" ** 32, text));
    try std.testing.expect(matchGlob("*" ** 32, ""));
}
