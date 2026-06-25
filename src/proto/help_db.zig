// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Static HELP/HELPOP topic database and IRC help numeric builders.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const RPL_HELPSTART: u16 = 704;
pub const RPL_HELPTXT: u16 = 705;
pub const RPL_ENDOFHELP: u16 = 706;
pub const ERR_HELPNOTFOUND: u16 = @intFromEnum(numeric.Numeric.ERR_HELPNOTFOUND);

pub const HelpError = std.mem.Allocator.Error || error{
    InvalidParam,
    InvalidTrailing,
    InvalidNumeric,
};

pub const HelpTopic = struct {
    topic: []const u8,
    lines: []const []const u8,
};

pub const help_topics = [_]HelpTopic{
    .{
        .topic = "HELP",
        .lines = &[_][]const u8{
            "HELP [topic]",
            "Shows help for an IRC command or server topic.",
            "Use HELPOP [topic] for the same help text through the operator help path.",
        },
    },
    .{
        .topic = "JOIN",
        .lines = &[_][]const u8{
            "JOIN <channel>[,<channel>] [key[,key]]",
            "Joins one or more channels. Channel names normally begin with #.",
            "If keys are required, provide them in the same order as the channels.",
        },
    },
    .{
        .topic = "MODE",
        .lines = &[_][]const u8{
            "MODE <target> [modes] [mode parameters]",
            "Changes or displays user and channel modes.",
            "Channel modes such as +o, +v, +b, +k, and +l may require parameters.",
            "Operator user mode +j (override) enables audited channel override and SYSTEM kill attribution.",
        },
    },
    .{
        .topic = "PRIVMSG",
        .lines = &[_][]const u8{
            "PRIVMSG <target>{,<target>} :<text>",
            "Sends a private message to a user or channel.",
            "Messages to channels are delivered to channel members subject to channel modes.",
        },
    },
    .{
        .topic = "OPER",
        .lines = &[_][]const u8{
            "OPER <name> <password>",
            "Authenticates as an IRC operator when the supplied credentials match server config.",
            "Successful OPER grants operator privileges and may add user modes.",
        },
    },
    .{
        .topic = "CHATHISTORY",
        .lines = &[_][]const u8{
            "CHATHISTORY <subcommand> <target> [parameters]",
            "Retrieves IRCv3 message history for channels or conversations.",
            "Common subcommands include LATEST, BEFORE, AFTER, AROUND, and BETWEEN.",
        },
    },
};

comptime {
    @setEvalBranchQuota(10_000);

    for (help_topics, 0..) |left, left_index| {
        if (left.lines.len == 0) @compileError("help topics need at least one line");
        validateComptimeParam(left.topic);
        for (left.lines) |line| validateComptimeTrailing(line);

        for (help_topics[left_index + 1 ..]) |right| {
            if (asciiEqlIgnoreCase(left.topic, right.topic)) {
                @compileError("duplicate help topic");
            }
        }
    }
}

pub fn topics() []const HelpTopic {
    return &help_topics;
}

pub fn lookup(topic: []const u8) ?*const HelpTopic {
    for (&help_topics) |*entry| {
        if (asciiEqlIgnoreCase(entry.topic, topic)) return entry;
    }
    return null;
}

pub fn buildHelpLookupReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    requested_topic: []const u8,
) HelpError![]u8 {
    if (lookup(requested_topic)) |entry| {
        return buildHelpTopicReply(allocator, server_name, requester, entry);
    }
    return buildErrHelpNotFound(allocator, server_name, requester, requested_topic);
}

pub fn buildHelpTopicReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    entry: *const HelpTopic,
) HelpError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendRplHelpStart(&out, allocator, server_name, requester, entry.topic, entry.lines[0]);
    for (entry.lines[1..]) |line| {
        try appendRplHelpTxt(&out, allocator, server_name, requester, entry.topic, line);
    }
    try appendRplEndOfHelp(&out, allocator, server_name, requester, entry.topic);

    return out.toOwnedSlice(allocator);
}

pub fn buildRplHelpStart(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, RPL_HELPSTART, requester, topic, text);
}

pub fn buildRplHelpTxt(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, RPL_HELPTXT, requester, topic, text);
}

pub fn buildRplEndOfHelp(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, RPL_ENDOFHELP, requester, topic, "End of /HELP.");
}

pub fn buildErrHelpNotFound(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, ERR_HELPNOTFOUND, requester, topic, "Help not found");
}

pub fn appendRplHelpStart(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError!void {
    try appendNumericLine(out, allocator, server_name, RPL_HELPSTART, requester, topic, text);
}

pub fn appendRplHelpTxt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError!void {
    try appendNumericLine(out, allocator, server_name, RPL_HELPTXT, requester, topic, text);
}

pub fn appendRplEndOfHelp(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
) HelpError!void {
    try appendNumericLine(out, allocator, server_name, RPL_ENDOFHELP, requester, topic, "End of /HELP.");
}

fn buildNumericLine(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    code: u16,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendNumericLine(&out, allocator, server_name, code, requester, topic, text);
    return out.toOwnedSlice(allocator);
}

fn appendNumericLine(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    code: u16,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError!void {
    try validateParam(server_name);
    try validateCode(code);
    try validateParam(requester);
    try validateParam(topic);
    try validateTrailing(text);

    try out.append(allocator, ':');
    try out.appendSlice(allocator, server_name);
    try out.append(allocator, ' ');
    try appendCode(out, allocator, code);
    try out.append(allocator, ' ');
    try out.appendSlice(allocator, requester);
    try out.append(allocator, ' ');
    try out.appendSlice(allocator, topic);
    try out.appendSlice(allocator, " :");
    try out.appendSlice(allocator, text);
    try out.appendSlice(allocator, "\r\n");
}

fn appendCode(out: *std.ArrayList(u8), allocator: std.mem.Allocator, code_value: u16) HelpError!void {
    var buf: [3]u8 = undefined;
    if (code_value > 999) return error.InvalidNumeric;
    buf[0] = @as(u8, '0') + @as(u8, @intCast(code_value / 100));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((code_value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(code_value % 10));
    try out.appendSlice(allocator, &buf);
}

fn validateCode(code_value: u16) HelpError!void {
    if (code_value < 100 or code_value > 999) return error.InvalidNumeric;
}

fn validateParam(param: []const u8) HelpError!void {
    if (param.len == 0) return error.InvalidParam;
    for (param) |ch| {
        if (!validParamByte(ch)) return error.InvalidParam;
    }
}

fn validateTrailing(text: []const u8) HelpError!void {
    for (text) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidTrailing;
    }
}

fn validateComptimeParam(comptime param: []const u8) void {
    if (param.len == 0) @compileError("empty help topic");
    for (param) |ch| {
        if (!validParamByte(ch)) @compileError("invalid help topic byte");
    }
}

fn validateComptimeTrailing(comptime text: []const u8) void {
    for (text) |ch| {
        if (!validTrailingByte(ch)) @compileError("invalid help text byte");
    }
}

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => ch >= 0x21 and ch != 0x7f,
    };
}

fn validTrailingByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn asciiEqlIgnoreCase(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (asciiLower(a) != asciiLower(b)) return false;
    }
    return true;
}

fn asciiLower(ch: u8) u8 {
    return switch (ch) {
        'A'...'Z' => ch + ('a' - 'A'),
        else => ch,
    };
}

test "known topic returns 704, 705 lines, and 706 with exact bytes" {
    const allocator = std.testing.allocator;
    const entry = lookup("JOIN") orelse return error.TestUnexpectedResult;

    const bytes = try buildHelpTopicReply(allocator, "irc.example", "alice", entry);
    defer allocator.free(bytes);

    try std.testing.expectEqualStrings(
        ":irc.example 704 alice JOIN :JOIN <channel>[,<channel>] [key[,key]]\r\n" ++
            ":irc.example 705 alice JOIN :Joins one or more channels. Channel names normally begin with #.\r\n" ++
            ":irc.example 705 alice JOIN :If keys are required, provide them in the same order as the channels.\r\n" ++
            ":irc.example 706 alice JOIN :End of /HELP.\r\n",
        bytes,
    );
}

test "unknown topic returns 524" {
    const allocator = std.testing.allocator;

    const bytes = try buildHelpLookupReply(allocator, "irc.example", "alice", "NOPE");
    defer allocator.free(bytes);

    try std.testing.expectEqualStrings(
        ":irc.example 524 alice NOPE :Help not found\r\n",
        bytes,
    );
}

test "topic lookup is case-insensitive" {
    const allocator = std.testing.allocator;
    const entry = lookup("chAtHiStOrY") orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("CHATHISTORY", entry.topic);

    const bytes = try buildHelpLookupReply(allocator, "irc.example", "alice", "join");
    defer allocator.free(bytes);
    try std.testing.expect(std.mem.startsWith(u8, bytes, ":irc.example 704 alice JOIN :"));
}
