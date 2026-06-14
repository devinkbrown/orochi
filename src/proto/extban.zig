//! Extended ban parser and matcher.
//!
//! Ban masks are parsed once into a small fixed-node matcher. Matching borrows
//! the parsed pattern slices and the caller's client context, so the hot path is
//! allocation-free and bounded by the supplied pattern and channel list.
const std = @import("std");

/// Maximum bytes accepted for one ban mask.
pub const MAX_MASK_BYTES: usize = 512;

/// Default number of AST nodes for nested negation chains.
pub const DEFAULT_MAX_NODES: usize = 8;

pub const ParseError = error{
    EmptyMask,
    OversizeMask,
    InvalidByte,
    MissingType,
    MissingDelimiter,
    EmptyPattern,
    UnknownType,
    TooDeep,
};

/// Parsed matcher node kind.
pub const NodeKind = enum {
    hostmask,
    account,
    realname,
    country,
    channel,
    secure,
    mute,
    oper,
    negation,
};

/// One client view used by extended-ban matching.
///
/// All slices are caller-owned. `host` is the normalized hostmask/host string
/// used for plain ban mask fallthrough.
pub const ClientContext = struct {
    account: ?[]const u8 = null,
    realname: []const u8 = "",
    host: []const u8 = "",
    country: ?[]const u8 = null,
    channels: []const []const u8 = &.{},
    /// True when the client is connected over a secure (TLS) transport. Used by
    /// the `$z` secure-connection extban.
    secure: bool = false,
    /// True when the client holds IRC operator status. Used by the `$o`
    /// oper-status extban (most useful in `+e`/`+I` exception lists).
    is_oper: bool = false,
};

pub const Node = union(NodeKind) {
    hostmask: []const u8,
    account: []const u8,
    realname: []const u8,
    country: []const u8,
    channel: []const u8,
    /// `$z` secure-connection: the pattern is ignored; matches when the client
    /// is on a TLS transport.
    secure: []const u8,
    /// `$m` mute (quiet): a hostmask-style pattern, but classified separately so
    /// the ban-check path can apply it as speech suppression rather than a join
    /// denial. Matching semantics are identical to a plain hostmask.
    mute: []const u8,
    /// `$o` oper-status: the pattern is ignored; matches when the client holds
    /// IRC operator status.
    oper: []const u8,
    negation: usize,
};

/// Return a fixed-capacity matcher type.
pub fn Matcher(comptime max_nodes: usize) type {
    comptime {
        if (max_nodes == 0) @compileError("extban matcher needs at least one node");
    }

    return struct {
        const Self = @This();

        nodes: [max_nodes]Node = [_]Node{.{ .hostmask = "" }} ** max_nodes,
        node_count: usize = 0,
        root: usize = 0,

        /// Parse one plain hostmask or extended-ban mask.
        pub fn parse(input: []const u8) ParseError!Self {
            try validateInput(input);

            var matcher = Self{};
            matcher.root = try matcher.parseExpression(input);
            return matcher;
        }

        /// Match this parsed ban against a client context.
        pub fn matches(self: *const Self, ctx: ClientContext) bool {
            if (self.node_count == 0) return false;
            return self.matchNode(self.root, ctx);
        }

        /// Kind of the root node, useful for callers that need to classify bans.
        pub fn rootKind(self: *const Self) NodeKind {
            return nodeKind(self.nodes[self.root]);
        }

        /// Semantic kind after unwrapping root negation chains. Callers use this
        /// to keep `$m` quiet extbans out of join-denial paths even when negated.
        pub fn rootMatchKind(self: *const Self) NodeKind {
            if (self.node_count == 0) return .hostmask;
            return self.matchKind(self.root);
        }

        /// Pattern stored at the root node when it is a leaf matcher.
        pub fn rootPattern(self: *const Self) ?[]const u8 {
            return switch (self.nodes[self.root]) {
                .hostmask => |pattern| pattern,
                .account => |pattern| pattern,
                .realname => |pattern| pattern,
                .country => |pattern| pattern,
                .channel => |pattern| pattern,
                .secure => |pattern| pattern,
                .mute => |pattern| pattern,
                .oper => |pattern| pattern,
                .negation => null,
            };
        }

        fn parseExpression(self: *Self, input: []const u8) ParseError!usize {
            if (input.len == 0) return error.EmptyMask;
            if (input[0] != '$') return self.appendNode(.{ .hostmask = input });
            return self.parseDollar(input);
        }

        fn parseDollar(self: *Self, input: []const u8) ParseError!usize {
            if (input.len < 2) return error.MissingType;

            if (input[1] == '~') {
                if (input.len < 3) return error.EmptyPattern;

                const rest = input[2..];
                const child = if (rest[0] == ':') blk: {
                    if (rest.len == 1) return error.EmptyPattern;
                    break :blk try self.parseExpression(rest[1..]);
                } else if (rest[0] == '$') blk: {
                    break :blk try self.parseExpression(rest);
                } else blk: {
                    break :blk try self.parseTyped(rest);
                };

                return self.appendNode(.{ .negation = child });
            }

            return self.parseTyped(input[1..]);
        }

        fn parseTyped(self: *Self, typed: []const u8) ParseError!usize {
            if (typed.len == 0) return error.MissingType;

            // `$z` (secure connection) takes no pattern: bare `$z` is valid, and a
            // trailing `:pattern` is accepted but ignored (the pattern carries no
            // matching meaning for this type).
            if (typed[0] == 'z') {
                if (typed.len == 1) return self.appendNode(.{ .secure = "" });
                if (typed[1] != ':') return error.MissingDelimiter;
                return self.appendNode(.{ .secure = typed[2..] });
            }

            // `$o` (oper status) also takes no pattern: bare `$o` is valid, a
            // trailing `:pattern` is accepted but ignored.
            if (typed[0] == 'o') {
                if (typed.len == 1) return self.appendNode(.{ .oper = "" });
                if (typed[1] != ':') return error.MissingDelimiter;
                return self.appendNode(.{ .oper = typed[2..] });
            }

            if (typed.len < 2 or typed[1] != ':') return error.MissingDelimiter;
            if (typed.len == 2) return error.EmptyPattern;

            const pattern = typed[2..];
            return switch (typed[0]) {
                'a' => self.appendNode(.{ .account = pattern }),
                'r' => self.appendNode(.{ .realname = pattern }),
                'g' => self.appendNode(.{ .country = pattern }),
                'c' => self.appendNode(.{ .channel = pattern }),
                'm' => self.appendNode(.{ .mute = pattern }),
                else => error.UnknownType,
            };
        }

        fn appendNode(self: *Self, node: Node) ParseError!usize {
            if (self.node_count >= max_nodes) return error.TooDeep;
            const index = self.node_count;
            self.nodes[index] = node;
            self.node_count += 1;
            return index;
        }

        fn matchNode(self: *const Self, index: usize, ctx: ClientContext) bool {
            if (index >= self.node_count) return false;

            return switch (self.nodes[index]) {
                .hostmask => |pattern| patternMatch(pattern, ctx.host),
                .account => |pattern| if (ctx.account) |account| patternMatch(pattern, account) else false,
                .realname => |pattern| patternMatch(pattern, ctx.realname),
                .country => |pattern| if (ctx.country) |country| patternMatch(pattern, country) else false,
                .channel => |pattern| matchAnyChannel(pattern, ctx.channels),
                .secure => ctx.secure,
                .mute => |pattern| patternMatch(pattern, ctx.host),
                .oper => ctx.is_oper,
                .negation => |child| !self.matchNode(child, ctx),
            };
        }

        fn matchKind(self: *const Self, index: usize) NodeKind {
            if (index >= self.node_count) return .hostmask;
            return switch (self.nodes[index]) {
                .negation => |child| self.matchKind(child),
                else => nodeKind(self.nodes[index]),
            };
        }
    };
}

/// Default matcher used by simple callers and tests.
pub const ExtbanMatcher = Matcher(DEFAULT_MAX_NODES);

/// Parse using the default matcher capacity.
pub fn parse(input: []const u8) ParseError!ExtbanMatcher {
    return ExtbanMatcher.parse(input);
}

fn nodeKind(node: Node) NodeKind {
    return switch (node) {
        .hostmask => .hostmask,
        .account => .account,
        .realname => .realname,
        .country => .country,
        .channel => .channel,
        .secure => .secure,
        .mute => .mute,
        .oper => .oper,
        .negation => .negation,
    };
}

fn matchAnyChannel(pattern: []const u8, channels: []const []const u8) bool {
    for (channels) |channel| {
        if (patternMatch(pattern, channel)) return true;
    }
    return false;
}

fn validateInput(input: []const u8) ParseError!void {
    if (input.len == 0) return error.EmptyMask;
    if (input.len > MAX_MASK_BYTES) return error.OversizeMask;

    for (input) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ', '\t', 0x7f => return error.InvalidByte,
            else => {
                if (ch < 0x20) return error.InvalidByte;
            },
        }
    }
}

fn patternMatch(pattern: []const u8, value: []const u8) bool {
    if (hasGlobMeta(pattern)) return globMatch(pattern, value);
    return constantTimeEqlAsciiFold(pattern, value);
}

fn hasGlobMeta(pattern: []const u8) bool {
    for (pattern) |ch| {
        if (ch == '*' or ch == '?') return true;
    }
    return false;
}

/// Case-insensitive IRC-style glob. Supports `*` and `?`.
fn globMatch(pattern: []const u8, value: []const u8) bool {
    if (pattern.len == 0) return value.len == 0;

    var p: usize = 0;
    var v: usize = 0;
    var star: ?usize = null;
    var retry_v: usize = 0;

    while (v < value.len) {
        if (p < pattern.len and (pattern[p] == '?' or asciiLower(pattern[p]) == asciiLower(value[v]))) {
            p += 1;
            v += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            retry_v = v;
        } else if (star) |star_pos| {
            p = star_pos + 1;
            retry_v += 1;
            v = retry_v;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn constantTimeEqlAsciiFold(a: []const u8, b: []const u8) bool {
    const max_len = @max(a.len, b.len);
    var diff: usize = a.len ^ b.len;

    var idx: usize = 0;
    while (idx < max_len) : (idx += 1) {
        const ac: u8 = if (idx < a.len) asciiLower(a[idx]) else 0;
        const bc: u8 = if (idx < b.len) asciiLower(b[idx]) else 0;
        diff |= @as(usize, ac ^ bc);
    }

    return diff == 0;
}

fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + ('a' - 'A') else ch;
}

test "parses each extended ban type" {
    const account = try parse("$a:alice");
    try std.testing.expectEqual(NodeKind.account, account.rootKind());
    try std.testing.expectEqualStrings("alice", account.rootPattern().?);

    const realname = try parse("$r:*Example*");
    try std.testing.expectEqual(NodeKind.realname, realname.rootKind());
    try std.testing.expectEqualStrings("*Example*", realname.rootPattern().?);

    const country = try parse("$g:DE");
    try std.testing.expectEqual(NodeKind.country, country.rootKind());
    try std.testing.expectEqualStrings("DE", country.rootPattern().?);

    const channel = try parse("$c:#ops");
    try std.testing.expectEqual(NodeKind.channel, channel.rootKind());
    try std.testing.expectEqualStrings("#ops", channel.rootPattern().?);

    const secure = try parse("$z");
    try std.testing.expectEqual(NodeKind.secure, secure.rootKind());

    const secure_with_pattern = try parse("$z:ignored");
    try std.testing.expectEqual(NodeKind.secure, secure_with_pattern.rootKind());

    const mute = try parse("$m:*!*@spam.example");
    try std.testing.expectEqual(NodeKind.mute, mute.rootKind());
    try std.testing.expectEqualStrings("*!*@spam.example", mute.rootPattern().?);
}

test "matches secure-connection extban" {
    const secure_ban = try parse("$z");
    try std.testing.expect(secure_ban.matches(.{ .secure = true }));
    try std.testing.expect(!secure_ban.matches(.{ .secure = false }));

    // Negation: ban everyone NOT on a secure connection.
    const insecure_ban = try parse("$~z");
    try std.testing.expect(!insecure_ban.matches(.{ .secure = true }));
    try std.testing.expect(insecure_ban.matches(.{ .secure = false }));
}

test "matches mute extban against host like a plain hostmask" {
    const mute = try parse("$m:*.spam.example");
    try std.testing.expectEqual(NodeKind.mute, mute.rootMatchKind());
    try std.testing.expect(mute.matches(.{ .host = "node.spam.example" }));
    try std.testing.expect(!mute.matches(.{ .host = "node.good.example" }));

    const negated_mute = try parse("$~m:*.trusted.example");
    try std.testing.expectEqual(NodeKind.negation, negated_mute.rootKind());
    try std.testing.expectEqual(NodeKind.mute, negated_mute.rootMatchKind());
}

test "matches positive and negative account extbans" {
    const matched = ClientContext{ .account = "alice" };
    const missed = ClientContext{ .account = "bob" };

    const exact = try parse("$a:ALICE");
    try std.testing.expect(exact.matches(matched));
    try std.testing.expect(!exact.matches(missed));

    const glob = try parse("$a:a*");
    try std.testing.expect(glob.matches(matched));
    try std.testing.expect(!glob.matches(missed));
}

test "matches realname country and channel extbans" {
    const chans = [_][]const u8{ "#opers", "#chat" };
    const ctx = ClientContext{
        .realname = "Alice Example",
        .country = "de",
        .channels = &chans,
    };

    const realname = try parse("$r:*example");
    try std.testing.expect(realname.matches(ctx));

    const country = try parse("$g:DE");
    try std.testing.expect(country.matches(ctx));

    const channel = try parse("$c:#OPERS");
    try std.testing.expect(channel.matches(ctx));
    const missed_channel = try parse("$c:#staff");
    try std.testing.expect(!missed_channel.matches(ctx));
}

test "matches negation and nested negation" {
    const alice = ClientContext{ .account = "alice", .host = "user.example" };
    const bob = ClientContext{ .account = "bob", .host = "user.example" };

    const negated_account = try parse("$~a:alice");
    try std.testing.expect(!negated_account.matches(alice));
    try std.testing.expect(negated_account.matches(bob));

    const nested_account = try parse("$~:$a:alice");
    try std.testing.expect(!nested_account.matches(alice));
    try std.testing.expect(nested_account.matches(bob));

    const nested_host = try parse("$~:bad*");
    try std.testing.expect(nested_host.matches(alice));
    const bad_host = ClientContext{ .account = "alice", .host = "bad.example" };
    try std.testing.expect(!nested_host.matches(bad_host));
}

test "rejects malformed masks" {
    try std.testing.expectError(error.EmptyMask, parse(""));
    try std.testing.expectError(error.MissingType, parse("$"));
    try std.testing.expectError(error.EmptyPattern, parse("$a:"));
    try std.testing.expectError(error.MissingDelimiter, parse("$aalice"));
    try std.testing.expectError(error.UnknownType, parse("$x:value"));
    try std.testing.expectError(error.InvalidByte, parse("$a:bad\nvalue"));
    try std.testing.expectError(error.EmptyPattern, parse("$~"));
}

test "plain hostmask fallthrough uses host glob" {
    const matcher = try parse("*.example.net");
    try std.testing.expectEqual(NodeKind.hostmask, matcher.rootKind());
    try std.testing.expect(matcher.matches(.{ .host = "irc.example.net" }));
    try std.testing.expect(!matcher.matches(.{ .host = "irc.example.org" }));
}

test "caller can lower nesting capacity at comptime" {
    const SmallMatcher = Matcher(2);
    const matcher = try SmallMatcher.parse("$~a:alice");
    try std.testing.expect(matcher.matches(.{ .account = "bob" }));
    try std.testing.expectError(error.TooDeep, SmallMatcher.parse("$~$~a:alice"));
}
