//! IRC WHOIS numeric reply builder.
//!
//! The daemon owns visibility and lookup policy; this module only validates the
//! caller-provided WHOIS subject and emits the canonical numeric sequence into
//! caller-owned storage. All complete lines include CRLF and channel lists are
//! folded without exceeding the configured IRC line limit.
const std = @import("std");
const numeric = @import("../proto/numeric.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_REALNAME_BYTES: usize = 512;
pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 64;
pub const DEFAULT_MAX_AWAY_BYTES: usize = 512;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_PREFIX_BYTES: usize = 16;

const whois_user_code = numeric.Numeric.RPL_WHOISUSER;
const whois_server_code = numeric.Numeric.RPL_WHOISSERVER;
const whois_idle_code = numeric.Numeric.RPL_WHOISIDLE;
const whois_channels_code = numeric.Numeric.RPL_WHOISCHANNELS;
const whois_logged_in_code = numeric.Numeric.RPL_WHOISLOGGEDIN;
const whois_bot_code = numeric.Numeric.RPL_WHOISBOT;
const whois_operator_code = numeric.Numeric.RPL_WHOISOPERATOR;
const away_code = numeric.Numeric.RPL_AWAY;
const endofwhois_code = numeric.Numeric.RPL_ENDOFWHOIS;
const nosuchnick_code = numeric.Numeric.ERR_NOSUCHNICK;

pub const WhoisError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidRealname,
    RealnameTooLong,
    InvalidAccount,
    AccountTooLong,
    InvalidAwayMessage,
    AwayMessageTooLong,
    InvalidChannel,
    ChannelTooLong,
    InvalidPrefix,
    PrefixTooLong,
    OutputTooSmall,
    TooManyLines,
    ChannelTokenTooLong,
};

/// Compile-time limits for WHOIS line builders and validators.
pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_realname_bytes: usize = DEFAULT_MAX_REALNAME_BYTES,
    max_account_bytes: usize = DEFAULT_MAX_ACCOUNT_BYTES,
    max_away_bytes: usize = DEFAULT_MAX_AWAY_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_prefix_bytes: usize = DEFAULT_MAX_PREFIX_BYTES,
};

/// One visible channel membership in caller-selected display order.
pub const ChannelMembership = struct {
    prefix: []const u8 = "",
    channel: []const u8,
};

/// Caller-provided subject data for a WHOIS response.
pub const WhoisSubject = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    realname: []const u8,
    account: ?[]const u8 = null,
    server: ?[]const u8 = null,
    /// Human server description for the RPL_WHOISSERVER (312) trailing — NOT the
    /// server name (the param). RFC: "<nick> <server> :<server info>".
    server_info: ?[]const u8 = null,
    idle_secs: u64 = 0,
    signon_ts: u64 = 0,
    is_bot: bool = false,
    is_oper: bool = false,
    away: ?[]const u8 = null,
    channels: []const ChannelMembership = &.{},
};

/// One complete IRC numeric line.
pub const WhoisLine = struct {
    bytes: []const u8,
};

/// Caller-owned storage for complete WHOIS numeric lines.
pub const WhoisLineSink = struct {
    lines: []WhoisLine,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn slice(self: *const WhoisLineSink) []const WhoisLine {
        return self.lines[0..self.count];
    }

    pub fn reset(self: *WhoisLineSink) void {
        self.count = 0;
        self.used = 0;
    }

    fn beginLine(self: *WhoisLineSink) WhoisError!LineBuilder {
        if (self.count >= self.lines.len) return error.TooManyLines;
        return LineBuilder.init(self.storage[self.used..]);
    }

    fn commitLine(self: *WhoisLineSink, builder: *const LineBuilder) WhoisError!void {
        if (self.count >= self.lines.len) return error.TooManyLines;
        if (self.storage.len - self.used < builder.len) return error.OutputTooSmall;

        const start = self.used;
        self.used += builder.len;
        self.lines[self.count] = .{ .bytes = self.storage[start..self.used] };
        self.count += 1;
    }
};

/// Short alias for call sites that prefer the protocol name.
pub const Sink = WhoisLineSink;

/// Emit the standard WHOIS numeric sequence into `sink`.
pub fn writeWhois(
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject: WhoisSubject,
) WhoisError!void {
    return writeWhoisWith(.{}, sink, server_name, requester_nick, subject);
}

/// Emit the standard WHOIS numeric sequence using caller-selected limits.
pub fn writeWhoisWith(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject: WhoisSubject,
) WhoisError!void {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateSubjectWith(params, subject);

    const subject_server = subject.server orelse server_name;
    const subject_server_info = subject.server_info orelse "Mizuchi IRC daemon";

    try writeWhoisUserLine(params, sink, server_name, requester_nick, subject);
    try writeWhoisServerLine(params, sink, server_name, requester_nick, subject.nick, subject_server, subject_server_info);
    try writeWhoisIdleLine(params, sink, server_name, requester_nick, subject);
    try writeWhoisChannelLines(params, sink, server_name, requester_nick, subject.nick, subject.channels);
    if (subject.account) |account| {
        try writeWhoisLoggedInLine(params, sink, server_name, requester_nick, subject.nick, account);
    }
    if (subject.is_bot) {
        try writeWhoisBotLine(params, sink, server_name, requester_nick, subject.nick);
    }
    if (subject.is_oper) {
        try writeWhoisOperatorLine(params, sink, server_name, requester_nick, subject.nick);
    }
    if (subject.away) |away_message| {
        try writeAwayLine(params, sink, server_name, requester_nick, subject.nick, away_message);
    }
    try writeEndOfWhoisLine(params, sink, server_name, requester_nick, subject.nick);
}

/// Emit `ERR_NOSUCHNICK` for a failed WHOIS lookup.
pub fn writeNoSuchNick(
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhoisError!void {
    return writeNoSuchNickWith(.{}, sink, server_name, requester_nick, target_nick);
}

/// Emit `ERR_NOSUCHNICK` using caller-selected limits.
pub fn writeNoSuchNickWith(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhoisError!void {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateNickWith(params, target_nick);

    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(nosuchnick_code, server_name, requester_nick);
    try b.spaceParam(target_nick);
    try b.spaceTrailing("No such nick/channel");
    try b.crlf();
    try sink.commitLine(&b);
}

pub fn validateSubject(subject: WhoisSubject) WhoisError!void {
    return validateSubjectWith(.{}, subject);
}

pub fn validateSubjectWith(comptime params: Params, subject: WhoisSubject) WhoisError!void {
    try validateNickWith(params, subject.nick);
    try validateUserWith(params, subject.user);
    try validateHostWith(params, subject.host);
    try validateRealnameWith(params, subject.realname);
    if (subject.account) |account| try validateAccountWith(params, account);
    if (subject.server) |server_name| try validateServerNameWith(params, server_name);
    if (subject.away) |away_message| try validateAwayMessageWith(params, away_message);
    for (subject.channels) |membership| {
        try validateChannelMembershipWith(params, membership);
    }
}

pub fn validateChannelMembership(membership: ChannelMembership) WhoisError!void {
    return validateChannelMembershipWith(.{}, membership);
}

pub fn validateChannelMembershipWith(comptime params: Params, membership: ChannelMembership) WhoisError!void {
    try validatePrefixWith(params, membership.prefix);
    try validateChannelWith(params, membership.channel);
}

pub fn validateServerName(server_name: []const u8) WhoisError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) WhoisError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateNick(nick: []const u8) WhoisError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) WhoisError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) WhoisError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) WhoisError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) WhoisError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) WhoisError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateRealname(realname: []const u8) WhoisError!void {
    return validateRealnameWith(.{}, realname);
}

pub fn validateRealnameWith(comptime params: Params, realname: []const u8) WhoisError!void {
    if (realname.len > params.max_realname_bytes) return error.RealnameTooLong;
    for (realname) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidRealname;
    }
}

pub fn validateAccount(account: []const u8) WhoisError!void {
    return validateAccountWith(.{}, account);
}

pub fn validateAccountWith(comptime params: Params, account: []const u8) WhoisError!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |ch| {
        if (!validParamByte(ch)) return error.InvalidAccount;
    }
}

pub fn validateAwayMessage(away_message: []const u8) WhoisError!void {
    return validateAwayMessageWith(.{}, away_message);
}

pub fn validateAwayMessageWith(comptime params: Params, away_message: []const u8) WhoisError!void {
    if (away_message.len > params.max_away_bytes) return error.AwayMessageTooLong;
    for (away_message) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidAwayMessage;
    }
}

pub fn validateChannel(channel: []const u8) WhoisError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) WhoisError!void {
    if (channel.len == 0) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!isChannelPrefix(channel[0])) return error.InvalidChannel;
    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
}

pub fn validatePrefix(prefix: []const u8) WhoisError!void {
    return validatePrefixWith(.{}, prefix);
}

pub fn validatePrefixWith(comptime params: Params, prefix: []const u8) WhoisError!void {
    if (prefix.len > params.max_prefix_bytes) return error.PrefixTooLong;
    for (prefix) |ch| {
        if (!validPrefixByte(ch)) return error.InvalidPrefix;
    }
}

fn writeWhoisUserLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject: WhoisSubject,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(whois_user_code, server_name, requester_nick);
    try b.spaceParam(subject.nick);
    try b.spaceParam(subject.user);
    try b.spaceParam(subject.host);
    try b.spaceParam("*");
    try b.spaceTrailing(subject.realname);
    try b.crlf();
    try sink.commitLine(&b);
}

fn writeWhoisServerLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
    subject_server: []const u8,
    subject_server_info: []const u8,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(whois_server_code, server_name, requester_nick);
    try b.spaceParam(subject_nick);
    try b.spaceParam(subject_server);
    try b.spaceTrailing(subject_server_info);
    try b.crlf();
    try sink.commitLine(&b);
}

fn writeWhoisIdleLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject: WhoisSubject,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(whois_idle_code, server_name, requester_nick);
    try b.spaceParam(subject.nick);
    try b.spaceUnsigned(subject.idle_secs);
    try b.spaceUnsigned(subject.signon_ts);
    try b.spaceTrailing("seconds idle, signon time");
    try b.crlf();
    try sink.commitLine(&b);
}

fn writeWhoisChannelLines(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
    channels: []const ChannelMembership,
) WhoisError!void {
    if (channels.len == 0) return;

    const header_len = whoisChannelsHeaderLen(server_name, requester_nick, subject_nick);
    if (header_len + 2 > params.max_line_bytes) return error.OutputTooSmall;

    var b = try beginWhoisChannelsLine(params, sink, server_name, requester_nick, subject_nick);
    var tokens_in_line: usize = 0;

    for (channels) |membership| {
        const token_len = membership.prefix.len + membership.channel.len;
        if (header_len + token_len + 2 > params.max_line_bytes) {
            return error.ChannelTokenTooLong;
        }

        const separator_len: usize = if (tokens_in_line == 0) 0 else 1;
        if (b.len + separator_len + token_len + 2 > params.max_line_bytes) {
            try b.crlf();
            try sink.commitLine(&b);
            b = try beginWhoisChannelsLine(params, sink, server_name, requester_nick, subject_nick);
            tokens_in_line = 0;
        }

        if (tokens_in_line != 0) {
            try b.appendByte(' ');
        }
        try b.appendBytes(membership.prefix);
        try b.appendBytes(membership.channel);
        tokens_in_line += 1;
    }

    try b.crlf();
    try sink.commitLine(&b);
}

fn beginWhoisChannelsLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
) WhoisError!LineBuilder {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(whois_channels_code, server_name, requester_nick);
    try b.spaceParam(subject_nick);
    try b.appendBytes(" :");
    return b;
}

fn writeWhoisLoggedInLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
    account: []const u8,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(whois_logged_in_code, server_name, requester_nick);
    try b.spaceParam(subject_nick);
    try b.spaceParam(account);
    try b.spaceTrailing("is logged in as");
    try b.crlf();
    try sink.commitLine(&b);
}

fn writeWhoisBotLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(whois_bot_code, server_name, requester_nick);
    try b.spaceParam(subject_nick);
    try b.spaceTrailing("is a bot");
    try b.crlf();
    try sink.commitLine(&b);
}

fn writeWhoisOperatorLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(whois_operator_code, server_name, requester_nick);
    try b.spaceParam(subject_nick);
    try b.spaceTrailing("is an IRC operator");
    try b.crlf();
    try sink.commitLine(&b);
}

fn writeAwayLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
    away_message: []const u8,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(away_code, server_name, requester_nick);
    try b.spaceParam(subject_nick);
    try b.spaceTrailing(away_message);
    try b.crlf();
    try sink.commitLine(&b);
}

fn writeEndOfWhoisLine(
    comptime params: Params,
    sink: *WhoisLineSink,
    server_name: []const u8,
    requester_nick: []const u8,
    subject_nick: []const u8,
) WhoisError!void {
    var b = try sink.beginLine();
    b.max_line_bytes = params.max_line_bytes;
    try b.numericPrefix(endofwhois_code, server_name, requester_nick);
    try b.spaceParam(subject_nick);
    try b.spaceTrailing("End of /WHOIS list");
    try b.crlf();
    try sink.commitLine(&b);
}

fn whoisChannelsHeaderLen(server_name: []const u8, requester_nick: []const u8, subject_nick: []const u8) usize {
    return 1 + server_name.len + 1 + 3 + 1 + requester_nick.len + 1 + subject_nick.len + 2;
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validUserByte(ch: u8) bool {
    if (ch <= 0x1f or ch == 0x7f) return false;
    return switch (ch) {
        '!', '@', ':', ' ' => false,
        else => true,
    };
}

fn validHostByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn validParamByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return ch != ':';
}

fn validTrailingByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn isChannelPrefix(ch: u8) bool {
    return switch (ch) {
        '#', '&', '+', '!' => true,
        else => false,
    };
}

fn validChannelByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return switch (ch) {
        ',', ':' => false,
        else => true,
    };
}

fn validPrefixByte(ch: u8) bool {
    return ch > 0x20 and ch != 0x7f and ch != ':';
}

const LineBuilder = struct {
    out: []u8,
    len: usize = 0,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,

    fn init(out: []u8) LineBuilder {
        return .{ .out = out };
    }

    fn numericPrefix(
        self: *LineBuilder,
        reply_code: numeric.Numeric,
        server_name: []const u8,
        requester_nick: []const u8,
    ) WhoisError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(reply_code, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester_nick);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) WhoisError!void {
        try self.appendByte(' ');
        try self.appendBytes(param);
    }

    fn spaceTrailing(self: *LineBuilder, trailing: []const u8) WhoisError!void {
        try self.appendBytes(" :");
        try self.appendBytes(trailing);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u64) WhoisError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) WhoisError!void {
        var buf: [20]u8 = undefined;
        var n: usize = buf.len;
        var current = value;

        while (true) {
            n -= 1;
            buf[n] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[n..]);
    }

    fn crlf(self: *LineBuilder) WhoisError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) WhoisError!void {
        if (self.max_line_bytes - self.len < bytes.len) return error.OutputTooSmall;
        if (self.out.len - self.len < bytes.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) WhoisError!void {
        if (self.max_line_bytes - self.len < 1) return error.OutputTooSmall;
        if (self.out.len - self.len < 1) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

fn sampleSubject() WhoisSubject {
    return .{
        .nick = "alice",
        .user = "auser",
        .host = "host.example",
        .realname = "Alice Example",
        .account = "alice-account",
        .server = "leaf.example",
        .idle_secs = 42,
        .signon_ts = 1_700_000_000,
        .is_bot = true,
        .away = "writing tests",
        .channels = &.{
            .{ .prefix = "@", .channel = "#zig" },
            .{ .prefix = "+", .channel = "#chat" },
        },
    };
}

test "full WHOIS sequence emits every supported numeric in order" {
    var storage: [1024]u8 = undefined;
    var lines_storage: [8]WhoisLine = undefined;
    var sink = WhoisLineSink{ .lines = &lines_storage, .storage = &storage };

    try writeWhois(&sink, "irc.example", "dan", sampleSubject());

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 8), lines.len);
    try std.testing.expectEqualStrings(":irc.example 311 dan alice auser host.example * :Alice Example\r\n", lines[0].bytes);
    try std.testing.expectEqualStrings(":irc.example 312 dan alice leaf.example :Mizuchi IRC daemon\r\n", lines[1].bytes);
    try std.testing.expectEqualStrings(":irc.example 317 dan alice 42 1700000000 :seconds idle, signon time\r\n", lines[2].bytes);
    try std.testing.expectEqualStrings(":irc.example 319 dan alice :@#zig +#chat\r\n", lines[3].bytes);
    try std.testing.expectEqualStrings(":irc.example 330 dan alice alice-account :is logged in as\r\n", lines[4].bytes);
    try std.testing.expectEqualStrings(":irc.example 335 dan alice :is a bot\r\n", lines[5].bytes);
    try std.testing.expectEqualStrings(":irc.example 301 dan alice :writing tests\r\n", lines[6].bytes);
    try std.testing.expectEqualStrings(":irc.example 318 dan alice :End of /WHOIS list\r\n", lines[7].bytes);
}

test "ERR_NOSUCHNICK builder emits 401" {
    var storage: [128]u8 = undefined;
    var lines_storage: [1]WhoisLine = undefined;
    var sink = WhoisLineSink{ .lines = &lines_storage, .storage = &storage };

    try writeNoSuchNick(&sink, "irc.example", "dan", "missing");

    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try std.testing.expectEqualStrings(":irc.example 401 dan missing :No such nick/channel\r\n", sink.slice()[0].bytes);
}

test "channel list folds across multiple 319 lines" {
    const channels = [_]ChannelMembership{
        .{ .prefix = "@", .channel = "#one" },
        .{ .prefix = "+", .channel = "#two" },
        .{ .prefix = "", .channel = "#three" },
    };

    var storage: [256]u8 = undefined;
    var lines_storage: [2]WhoisLine = undefined;
    var sink = WhoisLineSink{ .lines = &lines_storage, .storage = &storage };

    try writeWhoisChannelLines(.{ .max_line_bytes = 30 }, &sink, "s", "me", "alice", &channels);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings(":s 319 me alice :@#one +#two\r\n", lines[0].bytes);
    try std.testing.expectEqualStrings(":s 319 me alice :#three\r\n", lines[1].bytes);
}

test "no account bot away or channels omits optional numerics" {
    const subject = WhoisSubject{
        .nick = "bob",
        .user = "buser",
        .host = "host.example",
        .realname = "Bob Example",
        .idle_secs = 0,
        .signon_ts = 1,
    };

    var storage: [512]u8 = undefined;
    var lines_storage: [4]WhoisLine = undefined;
    var sink = WhoisLineSink{ .lines = &lines_storage, .storage = &storage };

    try writeWhois(&sink, "irc.example", "dan", subject);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 4), lines.len);
    try std.testing.expectEqualStrings(":irc.example 311 dan bob buser host.example * :Bob Example\r\n", lines[0].bytes);
    try std.testing.expectEqualStrings(":irc.example 312 dan bob irc.example :Mizuchi IRC daemon\r\n", lines[1].bytes);
    try std.testing.expectEqualStrings(":irc.example 317 dan bob 0 1 :seconds idle, signon time\r\n", lines[2].bytes);
    try std.testing.expectEqualStrings(":irc.example 318 dan bob :End of /WHOIS list\r\n", lines[3].bytes);
}

test "invalid attacker controlled bytes are rejected before writing" {
    var storage: [512]u8 = undefined;
    var lines_storage: [8]WhoisLine = undefined;
    var sink = WhoisLineSink{ .lines = &lines_storage, .storage = &storage };

    var bad_nick = sampleSubject();
    bad_nick.nick = "bad nick";
    try std.testing.expectError(error.InvalidNick, writeWhois(&sink, "irc.example", "dan", bad_nick));
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);

    var bad_away = sampleSubject();
    bad_away.away = "bad\rmessage";
    try std.testing.expectError(error.InvalidAwayMessage, writeWhois(&sink, "irc.example", "dan", bad_away));
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);

    var bad_channel = sampleSubject();
    bad_channel.channels = &.{.{ .prefix = "@", .channel = "#bad channel" }};
    try std.testing.expectError(error.InvalidChannel, writeWhois(&sink, "irc.example", "dan", bad_channel));
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
}

test "small output surfaces explicit capacity errors" {
    var tiny_storage: [16]u8 = undefined;
    var lines_storage: [8]WhoisLine = undefined;
    var tiny_sink = WhoisLineSink{ .lines = &lines_storage, .storage = &tiny_storage };
    try std.testing.expectError(error.OutputTooSmall, writeWhois(&tiny_sink, "irc.example", "dan", sampleSubject()));

    var storage: [512]u8 = undefined;
    var one_line_storage: [1]WhoisLine = undefined;
    var one_line_sink = WhoisLineSink{ .lines = &one_line_storage, .storage = &storage };
    try std.testing.expectError(error.TooManyLines, writeWhois(&one_line_sink, "irc.example", "dan", sampleSubject()));
}

test "single channel token too large for line limit is rejected" {
    const channels = [_]ChannelMembership{
        .{ .prefix = "@", .channel = "#toolong" },
    };

    var storage: [256]u8 = undefined;
    var lines_storage: [1]WhoisLine = undefined;
    var sink = WhoisLineSink{ .lines = &lines_storage, .storage = &storage };
    try std.testing.expectError(
        error.ChannelTokenTooLong,
        writeWhoisChannelLines(.{ .max_line_bytes = 26 }, &sink, "s", "me", "alice", &channels),
    );
}
