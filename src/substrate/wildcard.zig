const std = @import("std");

const testing = std.testing;

pub const Mask = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

const TokenKind = enum {
    literal,
    any_one,
    any_run,
};

const Token = struct {
    kind: TokenKind,
    byte: u8 = 0,
    next: usize,
};

/// Match an IRC wildcard pattern against text.
///
/// `*` matches any byte run, including the empty run. `?` matches exactly one
/// byte. Matching is case-insensitive using RFC1459 casemapping: ASCII letters
/// fold normally and `[]\^` fold with `{|}~`.
///
/// A backslash escapes only `*`, `?`, and `\`; before any other byte it is a
/// literal backslash.
pub fn match(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var star_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len) {
            const token = nextToken(pattern, pattern_index);
            switch (token.kind) {
                .any_run => {
                    star_index = pattern_index;
                    pattern_index = token.next;
                    star_text_index = text_index;
                    continue;
                },
                .any_one => {
                    pattern_index = token.next;
                    text_index += 1;
                    continue;
                },
                .literal => {
                    if (rfc1459Equal(token.byte, text[text_index])) {
                        pattern_index = token.next;
                        text_index += 1;
                        continue;
                    }
                },
            }
        }

        if (star_index) |index| {
            const token = nextToken(pattern, index);
            star_text_index += 1;
            text_index = star_text_index;
            pattern_index = token.next;
        } else {
            return false;
        }
    }

    while (pattern_index < pattern.len) {
        const token = nextToken(pattern, pattern_index);
        if (token.kind != .any_run) return false;
        pattern_index = token.next;
    }

    return true;
}

/// Parse a complete `nick!user@host` mask into borrowed component slices.
pub fn toMask(source: []const u8) ?Mask {
    const bang = indexOf(source, '!', 0) orelse return null;
    const at = indexOf(source, '@', bang + 1) orelse return null;

    if (bang == 0 or at == bang + 1 or at + 1 == source.len) return null;
    if (indexOf(source, '!', bang + 1) != null) return null;
    if (indexOf(source, '@', at + 1) != null) return null;

    return .{
        .nick = source[0..bang],
        .user = source[bang + 1 .. at],
        .host = source[at + 1 ..],
    };
}

/// Match a wildcard hostmask pattern against a complete `nick!user@host` value.
///
/// Pattern wildcards apply inside each component; they do not cross the `!` or
/// `@` separators.
pub fn matchMask(pattern: []const u8, text: []const u8) bool {
    const pattern_mask = toMask(pattern) orelse return false;
    const text_mask = toMask(text) orelse return false;

    return match(pattern_mask.nick, text_mask.nick) and
        match(pattern_mask.user, text_mask.user) and
        match(pattern_mask.host, text_mask.host);
}

fn nextToken(pattern: []const u8, index: usize) Token {
    const byte = pattern[index];
    if (byte == '\\' and index + 1 < pattern.len and isEscapable(pattern[index + 1])) {
        return .{
            .kind = .literal,
            .byte = pattern[index + 1],
            .next = index + 2,
        };
    }

    return switch (byte) {
        '*' => .{ .kind = .any_run, .next = index + 1 },
        '?' => .{ .kind = .any_one, .next = index + 1 },
        else => .{ .kind = .literal, .byte = byte, .next = index + 1 },
    };
}

fn isEscapable(byte: u8) bool {
    return byte == '*' or byte == '?' or byte == '\\';
}

fn rfc1459Equal(a: u8, b: u8) bool {
    return rfc1459Fold(a) == rfc1459Fold(b);
}

fn rfc1459Fold(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        '^' => '~',
        else => byte,
    };
}

fn indexOf(bytes: []const u8, needle: u8, start: usize) ?usize {
    var index = start;
    while (index < bytes.len) : (index += 1) {
        if (bytes[index] == needle) return index;
    }
    return null;
}

test "star matches empty and any run" {
    try testing.expect(match("*", ""));
    try testing.expect(match("*", "anything"));
    try testing.expect(match("pre*post", "prepost"));
    try testing.expect(match("pre*post", "pre middle post"));
}

test "question mark matches exactly one byte" {
    try testing.expect(match("?", "a"));
    try testing.expect(match("a?c", "abc"));
    try testing.expect(match("a??", "abc"));
    try testing.expect(!match("?", ""));
    try testing.expect(!match("?", "ab"));
    try testing.expect(!match("a?c", "ac"));
}

test "literal matching is anchored and complete" {
    try testing.expect(match("", ""));
    try testing.expect(match("abc", "abc"));
    try testing.expect(!match("abc", ""));
    try testing.expect(!match("abc", "ab"));
    try testing.expect(!match("abc", "abcd"));
    try testing.expect(!match("abc", "zabc"));
}

test "star does not remove anchoring around literals" {
    try testing.expect(match("a*b", "ab"));
    try testing.expect(match("a*b", "axxb"));
    try testing.expect(match("a*b", "a/b"));
    try testing.expect(!match("a*b", "ba"));
    try testing.expect(!match("a*b", "a"));
    try testing.expect(!match("a*b", "baXb"));
}

test "rfc1459 case mapping folds ascii and irc bracket variants" {
    try testing.expect(match("NICK", "nick"));
    try testing.expect(match("nick", "NICK"));
    try testing.expect(match("[\\]^", "{|}~"));
    try testing.expect(match("{|}~", "[\\]^"));
    try testing.expect(!match("nick", "nock"));
}

test "escaped wildcard bytes are literals" {
    try testing.expect(match("\\*", "*"));
    try testing.expect(match("\\?", "?"));
    try testing.expect(match("\\\\", "\\"));
    try testing.expect(match("file\\*.txt", "file*.txt"));
    try testing.expect(match("what\\?", "what?"));
    try testing.expect(!match("file\\*.txt", "file123.txt"));
    try testing.expect(!match("what\\?", "whata"));
}

test "backslash before non escapable byte stays literal" {
    try testing.expect(match("\\a", "\\a"));
    try testing.expect(match("\\a*", "\\abc"));
    try testing.expect(!match("\\a", "a"));
}

test "toMask parses complete nick user host values" {
    const mask = toMask("Nick!user@example.com") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("Nick", mask.nick);
    try testing.expectEqualStrings("user", mask.user);
    try testing.expectEqualStrings("example.com", mask.host);
}

test "toMask rejects incomplete or ambiguous masks" {
    try testing.expect(toMask("") == null);
    try testing.expect(toMask("nick") == null);
    try testing.expect(toMask("nick!user") == null);
    try testing.expect(toMask("nick@host") == null);
    try testing.expect(toMask("!user@host") == null);
    try testing.expect(toMask("nick!@host") == null);
    try testing.expect(toMask("nick!user@") == null);
    try testing.expect(toMask("nick!user@host@extra") == null);
    try testing.expect(toMask("nick!user!again@host") == null);
}

test "matchMask handles common irc hostmask bans" {
    try testing.expect(matchMask("*!*@*.example.com", "nick!user@chat.example.com"));
    try testing.expect(matchMask("*!*@*.example.com", "NICK!~user@CHAT.EXAMPLE.COM"));
    try testing.expect(matchMask("nick!*@host.example.com", "Nick!ident@HOST.EXAMPLE.COM"));
    try testing.expect(matchMask("n?ck!u*@*.example.com", "nick!user@a.example.com"));
    try testing.expect(!matchMask("*!*@*.example.com", "nick!user@example.net"));
    try testing.expect(!matchMask("admin!*@*.example.com", "guest!user@a.example.com"));
}

test "matchMask wildcards do not cross separators" {
    try testing.expect(match("*!*@host", "nick!user@host"));
    try testing.expect(matchMask("*!*@host", "nick!user@host"));
    try testing.expect(match("nick*@host", "nick!user@host"));
    try testing.expect(!matchMask("nick*@host", "nick!user@host"));
    try testing.expect(match("nick!*", "nick!user@host"));
    try testing.expect(!matchMask("nick!*", "nick!user@host"));
    try testing.expect(!matchMask("*@host!*", "nick!user@host"));
}

test "matchMask requires complete hostmasks on both sides" {
    try testing.expect(!matchMask("*", "nick!user@host"));
    try testing.expect(!matchMask("*!*@*", "nick"));
    try testing.expect(!matchMask("nick!user@host", "nick"));
}

test "greedy star backtracking avoids exponential blowup" {
    const pattern = comptime repeatedStarPattern(64);
    var text: [256]u8 = undefined;
    @memset(&text, 'a');

    try testing.expect(!match(pattern[0..], text[0..]));
}

test "many stars and question marks still find anchored suffixes" {
    try testing.expect(match("*a*b?c*", "xxAyybZcqq"));
    try testing.expect(match("**a**b**", "ab"));
    try testing.expect(match("**a**b**", "A middle B"));
    try testing.expect(!match("**a**b?**", "A middle B"));
}

fn repeatedStarPattern(comptime count: usize) [count * 2 + 1]u8 {
    var pattern: [count * 2 + 1]u8 = undefined;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        pattern[index * 2] = 'a';
        pattern[index * 2 + 1] = '*';
    }
    pattern[count * 2] = 'x';
    return pattern;
}
