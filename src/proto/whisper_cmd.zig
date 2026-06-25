// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure IRCX WHISPER command parser and relay-line builder.
//!
//! This command layer consumes `whisper.zig`: raw IRC lines are parsed into a
//! typed request whose slices borrow from the caller-owned line, while target
//! slice storage is allocator-owned by the request.
const std = @import("std");
const irc_line = @import("irc_line.zig");
const whisper = @import("whisper.zig");

pub const IRCX_COMMAND_ITEM: u16 = 48;
pub const COMMAND: []const u8 = "WHISPER";

pub const Params = whisper.Params;
pub const Prefix = whisper.Prefix;
pub const RecipientPresence = whisper.RecipientPresence;
pub const Preconditions = whisper.Preconditions;
pub const PrecheckResult = whisper.PrecheckResult;
pub const WhisperError = whisper.WhisperError;

pub const ParseError = std.mem.Allocator.Error || irc_line.ParseError || WhisperError || error{
    UnknownCommand,
};

pub const BuildError = WhisperError || error{
    TargetIndexOutOfBounds,
};

/// Parsed `WHISPER <channel> <nick[,nick...]> :<text>`.
pub const Request = struct {
    channel: []const u8,
    targets: []const []const u8,
    text: []const u8,
    target_storage: ?[][]const u8 = null,

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        if (self.target_storage) |storage| allocator.free(storage);
        self.* = undefined;
    }
};

/// Parse a raw IRC line whose command must be `WHISPER`.
pub fn parse(line: []const u8, allocator: std.mem.Allocator) ParseError!Request {
    return parseWith(.{}, line, allocator);
}

/// Parse a raw IRC line using caller-selected compile-time limits.
pub fn parseWith(
    comptime params: Params,
    line: []const u8,
    allocator: std.mem.Allocator,
) ParseError!Request {
    const parsed = try irc_line.parseLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, COMMAND)) return error.UnknownCommand;
    if (parsed.trailing == null) return error.MissingText;
    return parseParamsWith(params, parsed.paramSlice(), allocator);
}

/// Parse tokenized WHISPER parameters excluding the command name.
pub fn parseParams(params: []const []const u8, allocator: std.mem.Allocator) ParseError!Request {
    return parseParamsWith(.{}, params, allocator);
}

/// Parse tokenized WHISPER parameters using caller-selected compile-time limits.
pub fn parseParamsWith(
    comptime params_config: Params,
    params: []const []const u8,
    allocator: std.mem.Allocator,
) ParseError!Request {
    const target_storage = try allocator.alloc([]const u8, params_config.max_recipients);
    errdefer allocator.free(target_storage);

    var request = try parseParamsIntoWith(params_config, params, target_storage);
    request.target_storage = target_storage;
    return request;
}

/// Parse tokenized WHISPER parameters into caller-owned target storage.
pub fn parseParamsInto(
    params: []const []const u8,
    target_storage: [][]const u8,
) WhisperError!Request {
    return parseParamsIntoWith(.{}, params, target_storage);
}

/// Parse tokenized WHISPER parameters into caller-owned storage with custom limits.
pub fn parseParamsIntoWith(
    comptime params_config: Params,
    params: []const []const u8,
    target_storage: [][]const u8,
) WhisperError!Request {
    const args = try whisper.parseWhisperArgsWith(params_config, params, target_storage);
    return .{
        .channel = args.channel,
        .targets = args.recipients,
        .text = args.text,
    };
}

pub fn validateRequest(request: Request) WhisperError!void {
    return validateRequestWith(.{}, request);
}

pub fn validateRequestWith(comptime params: Params, request: Request) WhisperError!void {
    try whisper.validateChannelWith(params, request.channel);
    if (request.targets.len == 0) return error.MissingRecipients;
    for (request.targets) |target| try whisper.validateNickWith(params, target);
    try whisper.validateTextWith(params, request.text);
}

/// Apply daemon-supplied membership/mode facts for a parsed WHISPER request.
pub fn checkPreconditions(
    preconditions: Preconditions,
    deliverable_storage: [][]const u8,
) WhisperError!PrecheckResult {
    return whisper.checkWhisperPreconditions(preconditions, deliverable_storage);
}

/// Build `:sender!user@host WHISPER <channel> <target> :<text>` for one target.
pub fn buildRelayForTarget(
    out: []u8,
    sender: Prefix,
    request: Request,
    target_index: usize,
) BuildError![]const u8 {
    return buildRelayForTargetWith(.{}, out, sender, request, target_index);
}

/// Build one target's relay line using caller-selected compile-time limits.
pub fn buildRelayForTargetWith(
    comptime params: Params,
    out: []u8,
    sender: Prefix,
    request: Request,
    target_index: usize,
) BuildError![]const u8 {
    try validateRequestWith(params, request);
    if (target_index >= request.targets.len) return error.TargetIndexOutOfBounds;
    return whisper.buildWhisperLineWith(params, out, sender, request.channel, request.targets[target_index], request.text);
}

pub fn buildRelayLine(
    out: []u8,
    sender: Prefix,
    channel: []const u8,
    target: []const u8,
    text: []const u8,
) WhisperError![]const u8 {
    return whisper.buildWhisperLine(out, sender, channel, target, text);
}

test "parse single target WHISPER command" {
    const allocator = std.testing.allocator;
    var request = try parse("WHISPER #ops alice :quiet hello\r\n", allocator);
    defer request.deinit(allocator);

    try std.testing.expectEqualStrings("#ops", request.channel);
    try std.testing.expectEqual(@as(usize, 1), request.targets.len);
    try std.testing.expectEqualStrings("alice", request.targets[0]);
    try std.testing.expectEqualStrings("quiet hello", request.text);
}

test "parse multi target WHISPER command" {
    const allocator = std.testing.allocator;
    var request = try parse("whisper #ops alice,bob,carol :quiet hello", allocator);
    defer request.deinit(allocator);

    try std.testing.expectEqualStrings("#ops", request.channel);
    try std.testing.expectEqual(@as(usize, 3), request.targets.len);
    try std.testing.expectEqualStrings("alice", request.targets[0]);
    try std.testing.expectEqualStrings("bob", request.targets[1]);
    try std.testing.expectEqualStrings("carol", request.targets[2]);
    try std.testing.expectEqualStrings("quiet hello", request.text);
}

test "build relay bytes for each target" {
    const allocator = std.testing.allocator;
    var request = try parse("WHISPER #ops alice,bob :quiet hello", allocator);
    defer request.deinit(allocator);

    const out = try allocator.alloc(u8, 192);
    defer allocator.free(out);

    const sender = Prefix{ .nick = "sender", .user = "u", .host = "host.example" };
    const first = try buildRelayForTarget(out, sender, request, 0);
    try std.testing.expectEqualStrings(":sender!u@host.example WHISPER #ops alice :quiet hello", first);

    const second = try buildRelayForTarget(out, sender, request, 1);
    try std.testing.expectEqualStrings(":sender!u@host.example WHISPER #ops bob :quiet hello", second);
}

test "malformed WHISPER commands are rejected" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.UnknownCommand, parse("PRIVMSG #ops :hello", allocator));
    try std.testing.expectError(error.MissingText, parse("WHISPER #ops alice hello", allocator));
    try std.testing.expectError(error.InvalidChannel, parse("WHISPER ops alice :hello", allocator));
    try std.testing.expectError(error.EmptyRecipient, parse("WHISPER #ops alice,,bob :hello", allocator));
    try std.testing.expectError(error.EmptyText, parse("WHISPER #ops alice :", allocator));

    var request = try parse("WHISPER #ops alice :hello", allocator);
    defer request.deinit(allocator);
    var out: [128]u8 = undefined;
    try std.testing.expectError(
        error.TargetIndexOutOfBounds,
        buildRelayForTarget(&out, .{ .nick = "sender", .user = "u", .host = "h" }, request, 1),
    );
}
