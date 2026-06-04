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
    try std.testing.expectError(error.UnknownType, parseAndEvaluate("$m:*!*@host", .{}));
    try std.testing.expectError(error.InvalidByte, parseAndEvaluate("$r:bad\nname", .{}));
}

test "malformed parsed structure does not match" {
    var parsed = try extban.parse("$a:alice");
    parsed.root = parsed.node_count;

    try std.testing.expect(!evaluate(parsed, .{ .account = "alice" }));
}
