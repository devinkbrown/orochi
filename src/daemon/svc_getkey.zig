//! Pure GETKEY authorization helpers for Orochi services.
//!
//! This module intentionally imports only `std`. It does not know about daemon
//! state, clients, numerics, storage, or service dispatch. Integration code
//! supplies the caller's channel rank and global oper flag, then uses the
//! returned decision/reason to emit real server replies.

const std = @import("std");

/// Highest channel authority held by the requester in the target channel.
pub const Rank = enum(u8) {
    none = 0,
    voice = 1,
    op = 2,
    owner = 3,
    founder = 4,

    pub fn allowsGetKey(self: Rank) bool {
        return self == .owner or self == .founder;
    }
};

/// Stable allow/deny result for callers that want a compact enum.
pub const Verdict = enum {
    allow,
    deny,
};

/// Machine-readable reason for the GETKEY decision.
pub const Reason = enum {
    oper_override,
    founder,
    owner,
    rank_too_low,
};

/// Pure authorization outcome. No channel key material is stored here.
pub const Decision = struct {
    verdict: Verdict,
    reason: Reason,

    pub fn allowed(self: Decision) bool {
        return self.verdict == .allow;
    }
};

/// Parsed GETKEY command. Slices point into the caller-owned input line.
pub const Command = struct {
    /// Optional IRC source prefix, without the leading ':'.
    source: ?[]const u8 = null,
    /// Requested channel name.
    channel: []const u8,
};

pub const ParseError = error{
    EmptyLine,
    UnknownCommand,
    MissingChannel,
    TooManyParameters,
    InvalidChannel,
    InvalidPrefix,
    InvalidRank,
};

/// Decide whether a requester may retrieve the target channel's key.
///
/// Orochi services are real server commands, not pseudo-clients. This function
/// only answers the policy question: founder, owner, and global oper are
/// allowed; voice/op/none are denied.
pub fn authorize(rank: Rank, is_oper: bool) Decision {
    if (is_oper) return .{ .verdict = .allow, .reason = .oper_override };
    return switch (rank) {
        .founder => .{ .verdict = .allow, .reason = .founder },
        .owner => .{ .verdict = .allow, .reason = .owner },
        .none, .voice, .op => .{ .verdict = .deny, .reason = .rank_too_low },
    };
}

/// Parse a real server command line:
///
///   GETKEY #channel
///   :source GETKEY #channel
///
/// The parser is deliberately strict: no pseudo-client service names, no extra
/// parameters, and no empty/trailing IRC parameter for the channel.
pub fn parseCommand(line: []const u8) ParseError!Command {
    var it = TokenIterator.init(line);

    var source: ?[]const u8 = null;
    var command = it.next() orelse return ParseError.EmptyLine;
    if (command[0] == ':') {
        if (command.len == 1) return ParseError.InvalidPrefix;
        source = command[1..];
        command = it.next() orelse return ParseError.UnknownCommand;
    }

    if (!asciiEqlIgnoreCase(command, "GETKEY")) return ParseError.UnknownCommand;

    const channel = it.next() orelse return ParseError.MissingChannel;
    if (channel[0] == ':' or !isValidChannelName(channel)) return ParseError.InvalidChannel;
    if (it.next() != null) return ParseError.TooManyParameters;

    return .{ .source = source, .channel = channel };
}

/// Parse a rank name, numeric rank, or IRC prefix marker into a `Rank`.
pub fn parseRank(text: []const u8) ParseError!Rank {
    if (text.len == 0) return ParseError.InvalidRank;
    if (text.len == 1) {
        return switch (text[0]) {
            '0' => .none,
            '1', '+' => .voice,
            '2', '@' => .op,
            '3', '.' => .owner,
            '4', '!' => .founder,
            else => ParseError.InvalidRank,
        };
    }
    if (asciiEqlIgnoreCase(text, "none")) return .none;
    if (asciiEqlIgnoreCase(text, "voice")) return .voice;
    if (asciiEqlIgnoreCase(text, "op") or asciiEqlIgnoreCase(text, "operator")) return .op;
    if (asciiEqlIgnoreCase(text, "owner")) return .owner;
    if (asciiEqlIgnoreCase(text, "founder")) return .founder;
    return ParseError.InvalidRank;
}

/// Convenience wrapper for command parsing plus already-known requester state.
pub fn evaluate(line: []const u8, rank: Rank, is_oper: bool) ParseError!struct {
    command: Command,
    decision: Decision,
} {
    return .{
        .command = try parseCommand(line),
        .decision = authorize(rank, is_oper),
    };
}

fn isValidChannelName(channel: []const u8) bool {
    if (channel.len < 2) return false;
    return switch (channel[0]) {
        '#', '&', '+', '!' => blk: {
            for (channel) |c| {
                if (c == 0 or c == ' ' or c == ',' or c == 7 or c == '\r' or c == '\n') {
                    break :blk false;
                }
            }
            break :blk true;
        },
        else => false,
    };
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != std.ascii.toLower(bc)) return false;
    }
    return true;
}

const TokenIterator = struct {
    bytes: []const u8,
    index: usize = 0,

    fn init(bytes: []const u8) TokenIterator {
        return .{ .bytes = bytes };
    }

    fn next(self: *TokenIterator) ?[]const u8 {
        while (self.index < self.bytes.len and isSpace(self.bytes[self.index])) {
            self.index += 1;
        }
        if (self.index >= self.bytes.len) return null;

        const start = self.index;
        while (self.index < self.bytes.len and !isSpace(self.bytes[self.index])) {
            self.index += 1;
        }
        return self.bytes[start..self.index];
    }
};

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

test "authorize allows founder owner and oper only" {
    const cases = [_]struct {
        rank: Rank,
        oper: bool,
        verdict: Verdict,
        reason: Reason,
    }{
        .{ .rank = .founder, .oper = false, .verdict = .allow, .reason = .founder },
        .{ .rank = .owner, .oper = false, .verdict = .allow, .reason = .owner },
        .{ .rank = .op, .oper = true, .verdict = .allow, .reason = .oper_override },
        .{ .rank = .none, .oper = true, .verdict = .allow, .reason = .oper_override },
        .{ .rank = .op, .oper = false, .verdict = .deny, .reason = .rank_too_low },
        .{ .rank = .voice, .oper = false, .verdict = .deny, .reason = .rank_too_low },
        .{ .rank = .none, .oper = false, .verdict = .deny, .reason = .rank_too_low },
    };

    for (cases) |case| {
        const decision = authorize(case.rank, case.oper);
        try std.testing.expectEqual(case.verdict, decision.verdict);
        try std.testing.expectEqual(case.reason, decision.reason);
        try std.testing.expectEqual(case.verdict == .allow, decision.allowed());
    }
}

test "rank helper exposes getkey-capable tiers" {
    try std.testing.expect(!Rank.none.allowsGetKey());
    try std.testing.expect(!Rank.voice.allowsGetKey());
    try std.testing.expect(!Rank.op.allowsGetKey());
    try std.testing.expect(Rank.owner.allowsGetKey());
    try std.testing.expect(Rank.founder.allowsGetKey());
}

test "parseCommand accepts bare and prefixed real GETKEY commands" {
    const bare = try parseCommand("GETKEY #orochi");
    try std.testing.expect(bare.source == null);
    try std.testing.expectEqualStrings("#orochi", bare.channel);

    const mixed_case = try parseCommand("  :irc.example.net GeTkEy &ops\t");
    try std.testing.expectEqualStrings("irc.example.net", mixed_case.source.?);
    try std.testing.expectEqualStrings("&ops", mixed_case.channel);
}

test "parseCommand rejects malformed commands" {
    try std.testing.expectError(ParseError.EmptyLine, parseCommand(" \t\r\n "));
    try std.testing.expectError(ParseError.InvalidPrefix, parseCommand(": GETKEY #x"));
    try std.testing.expectError(ParseError.UnknownCommand, parseCommand(":server"));
    try std.testing.expectError(ParseError.UnknownCommand, parseCommand("PRIVMSG #x"));
    try std.testing.expectError(ParseError.MissingChannel, parseCommand("GETKEY"));
    try std.testing.expectError(ParseError.TooManyParameters, parseCommand("GETKEY #x extra"));
}

test "parseCommand rejects invalid channel parameters" {
    try std.testing.expectError(ParseError.InvalidChannel, parseCommand("GETKEY orochi"));
    try std.testing.expectError(ParseError.InvalidChannel, parseCommand("GETKEY #"));
    try std.testing.expectError(ParseError.InvalidChannel, parseCommand("GETKEY :#x"));
    try std.testing.expectError(ParseError.InvalidChannel, parseCommand("GETKEY #x,y"));
}

test "parseRank accepts names numerics and prefix markers" {
    try std.testing.expectEqual(Rank.none, try parseRank("none"));
    try std.testing.expectEqual(Rank.voice, try parseRank("VOICE"));
    try std.testing.expectEqual(Rank.op, try parseRank("operator"));
    try std.testing.expectEqual(Rank.owner, try parseRank("Owner"));
    try std.testing.expectEqual(Rank.founder, try parseRank("founder"));

    try std.testing.expectEqual(Rank.none, try parseRank("0"));
    try std.testing.expectEqual(Rank.voice, try parseRank("+"));
    try std.testing.expectEqual(Rank.op, try parseRank("@"));
    try std.testing.expectEqual(Rank.owner, try parseRank("."));
    try std.testing.expectEqual(Rank.founder, try parseRank("!"));

    try std.testing.expectError(ParseError.InvalidRank, parseRank(""));
    try std.testing.expectError(ParseError.InvalidRank, parseRank("admin"));
    try std.testing.expectError(ParseError.InvalidRank, parseRank("5"));
}

test "evaluate returns parsed channel and authorization decision" {
    const owner_eval = try evaluate(":services.local GETKEY #k", .owner, false);
    try std.testing.expectEqualStrings("services.local", owner_eval.command.source.?);
    try std.testing.expectEqualStrings("#k", owner_eval.command.channel);
    try std.testing.expect(owner_eval.decision.allowed());
    try std.testing.expectEqual(Reason.owner, owner_eval.decision.reason);

    const op_eval = try evaluate("GETKEY #k", .op, false);
    try std.testing.expectEqualStrings("#k", op_eval.command.channel);
    try std.testing.expect(!op_eval.decision.allowed());
    try std.testing.expectEqual(Reason.rank_too_low, op_eval.decision.reason);
}
