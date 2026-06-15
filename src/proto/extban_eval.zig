//! Extended-ban evaluation over the parsed representation from extban.zig.
//!
//! This module deliberately does not parse extban syntax. Callers parse with
//! `extban.zig`, then evaluate the resulting matcher against a borrowed
//! candidate view. Evaluation is pure and allocation-free.
const std = @import("std");
const extban = @import("extban.zig");
const listx = @import("listx.zig");

pub const ParseError = extban.ParseError;
pub const NodeKind = extban.NodeKind;

/// Candidate data used when evaluating one parsed extban.
///
/// `hostmask` is the caller-provided full `nick!user@host` mask. The separate
/// `nick`, `user`, and `host` fields are present for callers that naturally
/// carry those pieces, but evaluation never builds a combined string.
pub const Candidate = struct {
    nick: []const u8 = "",
    user: []const u8 = "",
    host: []const u8 = "",
    hostmask: []const u8 = "",
    account: ?[]const u8 = null,
    realname: []const u8 = "",
    country: ?[]const u8 = null,
    channels: []const []const u8 = &.{},
    /// True when the client is connected over a secure (TLS) transport; matched
    /// by the bare `$z` secure-connection extban.
    secure: bool = false,
    /// The client's TLS certificate fingerprint (lowercase SHA-256 hex), or null
    /// when no certificate was presented. Matched by the patterned
    /// `$z:<fingerprint>` extban; a null certfp never matches a `$z:<fp>` ban.
    certfp: ?[]const u8 = null,
    /// True when the client holds IRC operator status; matched by the bare `$o`
    /// oper-status extban.
    is_oper: bool = false,
    /// The client's oper class/name (empty when not an oper or unknown); matched
    /// by the patterned `$o:<class>` extban.
    oper_class: []const u8 = "",
};

/// Parse through extban.zig and immediately evaluate the parsed mask.
///
/// The matching path remains allocation-free; this helper exists to keep parse
/// errors easy to test and propagate.
pub fn parseAndEvaluate(input: []const u8, candidate: Candidate) ParseError!bool {
    const parsed = try extban.parse(input);
    return evaluate(parsed, candidate);
}

/// Evaluate a parsed extban matcher from extban.zig.
pub fn evaluate(parsed: anytype, candidate: Candidate) bool {
    if (parsed.node_count == 0) return false;
    if (parsed.root >= parsed.node_count) return false;
    return evaluateNode(parsed, parsed.root, candidate);
}

/// Alias for callers that prefer predicate naming.
pub fn matches(parsed: anytype, candidate: Candidate) bool {
    return evaluate(parsed, candidate);
}

fn evaluateNode(parsed: anytype, index: usize, candidate: Candidate) bool {
    if (index >= parsed.node_count) return false;

    return switch (parsed.nodes[index]) {
        .hostmask => |pattern| matchMask(pattern, candidate),
        .account => |pattern| if (candidate.account) |account| glob(pattern, account) else false,
        .realname => |pattern| glob(pattern, candidate.realname),
        .country => |pattern| if (candidate.country) |country| glob(pattern, country) else false,
        .channel => |pattern| matchAnyChannel(pattern, candidate.channels),
        .secure => |pattern| matchSecure(pattern, candidate),
        .mute => |pattern| matchMask(pattern, candidate),
        .oper => |pattern| matchOper(pattern, candidate),
        .negation => |child| !evaluateNode(parsed, child, candidate),
    };
}

fn matchMask(pattern: []const u8, candidate: Candidate) bool {
    if (candidate.hostmask.len != 0) return glob(pattern, candidate.hostmask);
    return glob(pattern, candidate.host);
}

fn matchAnyChannel(pattern: []const u8, channels: []const []const u8) bool {
    for (channels) |channel| {
        if (glob(pattern, channel)) return true;
    }
    return false;
}

/// `$z` secure-connection: bare `$z` (empty pattern) matches any TLS client;
/// `$z:<fingerprint>` matches only a presented certfp equal to the pattern
/// (case-insensitive hex). A null/empty certfp never matches a patterned `$z`.
/// Mirrors extban.matchSecure so the live and helper paths agree.
fn matchSecure(pattern: []const u8, candidate: Candidate) bool {
    if (pattern.len == 0) return candidate.secure;
    const presented = candidate.certfp orelse return false;
    if (presented.len == 0) return false;
    return glob(pattern, presented);
}

/// `$o` oper-status: bare `$o` (empty pattern) matches any oper;
/// `$o:<class>` matches only an oper with a non-empty class equal to the pattern
/// (case-insensitive, glob-capable). Mirrors extban.matchOper.
fn matchOper(pattern: []const u8, candidate: Candidate) bool {
    if (pattern.len == 0) return candidate.is_oper;
    if (!candidate.is_oper) return false;
    if (candidate.oper_class.len == 0) return false;
    return glob(pattern, candidate.oper_class);
}

fn glob(pattern: []const u8, value: []const u8) bool {
    return listx.globMatch(pattern, value);
}

test "evaluates account extban match and no match" {
    const allocator = std.testing.allocator;
    const parsed = try extban.parse("$a:alice");

    const account = try allocator.dupe(u8, "ALICE");
    defer allocator.free(account);

    try std.testing.expect(evaluate(parsed, .{ .account = account }));
    try std.testing.expect(!evaluate(parsed, .{ .account = "bob" }));
    try std.testing.expect(!evaluate(parsed, .{}));
}

test "evaluates realname glob match and no match" {
    const parsed = try extban.parse("$r:*example?");

    try std.testing.expect(matches(parsed, .{ .realname = "Alice Example1" }));
    try std.testing.expect(!matches(parsed, .{ .realname = "Alice Sample1" }));
}

test "evaluates channel extban over candidate channel list" {
    const allocator = std.testing.allocator;
    const channels = try allocator.alloc([]const u8, 2);
    defer allocator.free(channels);
    channels[0] = "#chat";
    channels[1] = "#Ops-Team";

    const parsed = try extban.parse("$c:#ops-*");

    try std.testing.expect(evaluate(parsed, .{ .channels = channels }));
    try std.testing.expect(!evaluate(parsed, .{ .channels = &.{ "#help", "#chat" } }));
}

test "evaluates hostmask extban against full nick user host mask" {
    const parsed = try extban.parse("*!ident@*.example.net");

    try std.testing.expect(evaluate(parsed, .{
        .nick = "Alice",
        .user = "ident",
        .host = "client.example.net",
        .hostmask = "Alice!ident@client.example.net",
    }));
    try std.testing.expect(!evaluate(parsed, .{
        .nick = "Alice",
        .user = "ident",
        .host = "client.example.org",
        .hostmask = "Alice!ident@client.example.org",
    }));
}

test "evaluates host-only fallback when no full hostmask is supplied" {
    const parsed = try extban.parse("*.example.net");

    try std.testing.expect(evaluate(parsed, .{ .host = "client.example.net" }));
    try std.testing.expect(!evaluate(parsed, .{ .host = "client.example.org" }));
}

test "evaluates country extban match and no match" {
    const parsed = try extban.parse("$g:DE");

    try std.testing.expect(evaluate(parsed, .{ .country = "de" }));
    try std.testing.expect(!evaluate(parsed, .{ .country = "fr" }));
    try std.testing.expect(!evaluate(parsed, .{}));
}

test "evaluates secure-connection extban" {
    const parsed = try extban.parse("$z");

    try std.testing.expect(evaluate(parsed, .{ .secure = true }));
    try std.testing.expect(!evaluate(parsed, .{ .secure = false }));
    try std.testing.expect(!evaluate(parsed, .{}));
}

test "evaluates oper-status extban" {
    const parsed = try extban.parse("$o");

    try std.testing.expect(evaluate(parsed, .{ .is_oper = true }));
    try std.testing.expect(!evaluate(parsed, .{ .is_oper = false }));
    try std.testing.expect(!evaluate(parsed, .{}));
    // A negated `$~o` exempts/excludes opers.
    const neg = try extban.parse("$~o");
    try std.testing.expect(!evaluate(neg, .{ .is_oper = true }));
    try std.testing.expect(evaluate(neg, .{ .is_oper = false }));
}

test "evaluates patterned certfp secure extban with null-certfp safety" {
    const fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const other = "0000000000000000000000000000000000000000000000000000000000000000";
    const parsed = try extban.parse("$z:" ++ fp);

    // Exact match (case-insensitive).
    try std.testing.expect(evaluate(parsed, .{ .secure = true, .certfp = fp }));
    try std.testing.expect(evaluate(parsed, .{
        .secure = true,
        .certfp = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
    }));
    // Wrong fingerprint does not match.
    try std.testing.expect(!evaluate(parsed, .{ .secure = true, .certfp = other }));
    // Non-TLS / null certfp does not match (no bypass-by-absence).
    try std.testing.expect(!evaluate(parsed, .{ .secure = false, .certfp = null }));
    try std.testing.expect(!evaluate(parsed, .{ .secure = true, .certfp = null }));
    try std.testing.expect(!evaluate(parsed, .{}));

    // Bare `$z` still matches any TLS client without requiring a fingerprint.
    const bare = try extban.parse("$z");
    try std.testing.expect(evaluate(bare, .{ .secure = true, .certfp = null }));
}

test "evaluates patterned oper-class extban" {
    const parsed = try extban.parse("$o:netadmin");

    try std.testing.expect(evaluate(parsed, .{ .is_oper = true, .oper_class = "netadmin" }));
    try std.testing.expect(evaluate(parsed, .{ .is_oper = true, .oper_class = "NETADMIN" }));
    try std.testing.expect(!evaluate(parsed, .{ .is_oper = true, .oper_class = "helper" }));
    // Non-oper never matches a patterned `$o`.
    try std.testing.expect(!evaluate(parsed, .{ .is_oper = false, .oper_class = "netadmin" }));
    // Empty/unknown class never matches.
    try std.testing.expect(!evaluate(parsed, .{ .is_oper = true, .oper_class = "" }));
}

test "evaluates mute extban over hostmask" {
    const parsed = try extban.parse("$m:*!*@*.spam.example");

    try std.testing.expect(evaluate(parsed, .{ .hostmask = "nick!user@a.spam.example" }));
    try std.testing.expect(!evaluate(parsed, .{ .hostmask = "nick!user@a.good.example" }));
}

test "evaluates negated extbans" {
    const parsed = try extban.parse("$~a:alice");

    try std.testing.expect(!evaluate(parsed, .{ .account = "alice" }));
    try std.testing.expect(evaluate(parsed, .{ .account = "bob" }));
    try std.testing.expect(evaluate(parsed, .{}));
}

test "evaluates nested negation" {
    const parsed = try extban.parse("$~:$~:$a:alice");

    try std.testing.expect(evaluate(parsed, .{ .account = "alice" }));
    try std.testing.expect(!evaluate(parsed, .{ .account = "bob" }));
}

test "malformed parse errors are surfaced before evaluation" {
    try std.testing.expectError(error.EmptyMask, parseAndEvaluate("", .{}));
    try std.testing.expectError(error.MissingType, parseAndEvaluate("$", .{}));
    try std.testing.expectError(error.EmptyPattern, parseAndEvaluate("$a:", .{}));
    try std.testing.expectError(error.MissingDelimiter, parseAndEvaluate("$aalice", .{}));
    try std.testing.expectError(error.UnknownType, parseAndEvaluate("$x:*!*@host", .{}));
    try std.testing.expectError(error.InvalidByte, parseAndEvaluate("$r:bad\nname", .{}));
}

test "malformed parsed structure does not match" {
    var parsed = try extban.parse("$a:alice");
    parsed.root = parsed.node_count;

    try std.testing.expect(!evaluate(parsed, .{ .account = "alice" }));
}
