// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRC RPL_NAMREPLY and RPL_ENDOFNAMES builders.
//!
//! Channel membership ordering and visibility are owned by the caller. This
//! module validates attacker-controlled NAMES fields, applies the IRCv3
//! multi-prefix and userhost-in-names capabilities, and folds complete 353
//! lines into caller-owned storage without exceeding the configured line limit.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = 510;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_PREFIX_BYTES: usize = 16;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 256;

const namreply_code = numeric.Numeric.RPL_NAMREPLY;
const endofnames_code = numeric.Numeric.RPL_ENDOFNAMES;
const default_end_text = "End of /NAMES list";

pub const NamesReplyError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidChannel,
    ChannelTooLong,
    InvalidPrefix,
    PrefixesTooLong,
    InvalidText,
    TextTooLong,
    OutputTooSmall,
    TooManyRecipients,
    TokenTooLong,
};

/// Compile-time limits for NAMES reply builders and validators.
pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_prefix_bytes: usize = DEFAULT_MAX_PREFIX_BYTES,
    max_text_bytes: usize = DEFAULT_MAX_TEXT_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes`, `max_prefix_bytes`, and `max_text_bytes` are wire/format
    /// budgets and keep their defaults.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_server_bytes = limits.server_name_len,
            .max_nick_bytes = limits.nick_len,
            .max_user_bytes = limits.user_len,
            .max_host_bytes = limits.host_len,
            .max_channel_bytes = limits.target_len_128,
        };
    }
};

/// One visible channel member in caller-defined channel order.
pub const Member = struct {
    prefixes: []const u8,
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// IRCv3 NAMES capabilities negotiated by the requester.
pub const RequesterCaps = struct {
    multi_prefix: bool = false,
    userhost_in_names: bool = false,
};

/// One complete IRC reply line stored in caller-owned output bytes.
pub const NamesLine = struct {
    bytes: []const u8,
};

/// Caller-provided storage for complete 353 and 366 reply lines.
pub const NamesLineSink = struct {
    lines: []NamesLine,
    count: usize = 0,

    pub fn append(self: *NamesLineSink, bytes: []const u8) NamesReplyError!void {
        if (self.count >= self.lines.len) return error.TooManyRecipients;
        self.lines[self.count] = .{ .bytes = bytes };
        self.count += 1;
    }

    pub fn slice(self: *const NamesLineSink) []const NamesLine {
        return self.lines[0..self.count];
    }

    pub fn reset(self: *NamesLineSink) void {
        self.count = 0;
    }
};

/// Write folded 353 replies followed by one 366 reply into caller-owned storage.
pub fn writeNamesReplies(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    channel: []const u8,
    channel_status: u8,
    members: []const Member,
    caps: RequesterCaps,
    sink: *NamesLineSink,
) NamesReplyError!void {
    return writeNamesRepliesWith(.{}, out, server_name, requester_nick, channel, channel_status, members, caps, sink);
}

/// Write only folded RPL_NAMREPLY (353) lines — no trailing 366. Returns the
/// number of bytes of `out` consumed. Callers that must stream a large roster
/// across multiple output buffers (mesh NAMES can exceed a single
/// `default_reply_bytes` arena under userhost-in-names) use this per chunk,
/// then finish with `buildEndOfNamesLine` exactly once.
///
/// Members that fail wire validation or whose token cannot fit a single 353
/// line are **skipped** rather than aborting the whole list: one hostile or
/// malformed remote host must never collapse NAMES to a bare 366 (the
/// late-partial / empty-roster desync). Capacity errors (`OutputTooSmall`,
/// `TooManyRecipients`) still surface so the caller can shrink the chunk and
/// retry.
pub fn writeNamReplyLines(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    channel: []const u8,
    channel_status: u8,
    members: []const Member,
    caps: RequesterCaps,
    sink: *NamesLineSink,
) NamesReplyError!usize {
    return writeNamReplyLinesWith(.{}, out, server_name, requester_nick, channel, channel_status, members, caps, sink);
}

/// Write NAMES replies using caller-selected compile-time limits. `channel_status`
/// is the 353 visibility symbol: '=' public, '@' secret (+s), '*' private (+p).
pub fn writeNamesRepliesWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    channel: []const u8,
    channel_status: u8,
    members: []const Member,
    caps: RequesterCaps,
    sink: *NamesLineSink,
) NamesReplyError!void {
    const used = try writeNamReplyLinesWith(params, out, server_name, requester_nick, channel, channel_status, members, caps, sink);
    const end_line = try buildEndOfNamesLineWith(
        params,
        out[used..],
        server_name,
        requester_nick,
        channel,
        default_end_text,
    );
    try sink.append(end_line);
}

/// 353-only writer (see `writeNamReplyLines`). Compile-time limits variant.
/// Returns bytes of `out` consumed by the emitted 353 lines.
pub fn writeNamReplyLinesWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    channel: []const u8,
    channel_status: u8,
    members: []const Member,
    caps: RequesterCaps,
    sink: *NamesLineSink,
) NamesReplyError!usize {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateChannelWith(params, channel);

    const header_len = namReplyHeaderLen(server_name, requester_nick, channel);
    if (header_len >= params.max_line_bytes) return error.OutputTooSmall;

    var n: usize = 0;
    var line_start: usize = 0;
    var line_len: usize = 0;
    var names_in_line: usize = 0;
    var line_open = false;

    for (members) |member| {
        // Skip a single bad/overlong token rather than failing the whole NAMES
        // burst (one mesh peer advertising a hostile host used to empty the
        // roster for every local client — 366-only, permanent nicklist desync).
        validateMemberWith(params, member) catch continue;
        const token_len = memberTokenLen(member, caps);
        if (header_len + token_len > params.max_line_bytes) continue;

        if (!line_open) {
            line_start = n;
            line_len = try appendNamReplyHeader(out, &n, server_name, requester_nick, channel, channel_status);
            names_in_line = 0;
            line_open = true;
        }

        const separator_len: usize = if (names_in_line == 0) 0 else 1;
        if (line_len + separator_len + token_len > params.max_line_bytes) {
            try sink.append(out[line_start .. line_start + line_len]);
            line_start = n;
            line_len = try appendNamReplyHeader(out, &n, server_name, requester_nick, channel, channel_status);
            names_in_line = 0;
        }

        if (names_in_line != 0) {
            try appendByte(out, &n, ' ');
            line_len += 1;
        }
        try appendMemberTokenUnchecked(out, &n, member, caps);
        line_len += token_len;
        names_in_line += 1;
    }

    if (line_open) {
        try sink.append(out[line_start .. line_start + line_len]);
    }
    return n;
}

/// Build one member token as it appears in the trailing NAMES list.
pub fn formatMemberToken(
    out: []u8,
    member: Member,
    caps: RequesterCaps,
) NamesReplyError![]const u8 {
    return formatMemberTokenWith(.{}, out, member, caps);
}

/// Build one member token using caller-selected compile-time limits.
pub fn formatMemberTokenWith(
    comptime params: Params,
    out: []u8,
    member: Member,
    caps: RequesterCaps,
) NamesReplyError![]const u8 {
    try validateMemberWith(params, member);

    var n: usize = 0;
    try appendMemberTokenUnchecked(out, &n, member, caps);
    return out[0..n];
}

/// Build `:<server> 366 <requester> <channel> :<text>`.
pub fn buildEndOfNamesLine(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    channel: []const u8,
    text: []const u8,
) NamesReplyError![]const u8 {
    return buildEndOfNamesLineWith(.{}, out, server_name, requester_nick, channel, text);
}

/// Build an ENDOFNAMES line using caller-selected compile-time limits.
pub fn buildEndOfNamesLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    channel: []const u8,
    text: []const u8,
) NamesReplyError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateChannelWith(params, channel);
    try validateTextWith(params, text);

    var code_buf: [3]u8 = undefined;
    const code = numeric.formatCode(endofnames_code, &code_buf);
    const line_len = 1 + server_name.len + 1 + code.len + 1 + requester_nick.len + 1 + channel.len + 2 + text.len;
    if (line_len > params.max_line_bytes) return error.OutputTooSmall;

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, server_name);
    try appendByte(out, &n, ' ');
    try append(out, &n, code);
    try appendByte(out, &n, ' ');
    try append(out, &n, requester_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :");
    try append(out, &n, text);
    return out[0..n];
}

pub fn validateMember(member: Member) NamesReplyError!void {
    return validateMemberWith(.{}, member);
}

pub fn validateMemberWith(comptime params: Params, member: Member) NamesReplyError!void {
    try validatePrefixesWith(params, member.prefixes);
    try validateNickWith(params, member.nick);
    try validateUserWith(params, member.user);
    try validateHostWith(params, member.host);
}

pub fn validateNick(nick: []const u8) NamesReplyError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) NamesReplyError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) NamesReplyError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) NamesReplyError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) NamesReplyError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) NamesReplyError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateChannel(channel: []const u8) NamesReplyError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) NamesReplyError!void {
    if (channel.len == 0) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!isChannelPrefix(channel[0])) return error.InvalidChannel;
    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
}

pub fn validateServerName(server_name: []const u8) NamesReplyError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) NamesReplyError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

pub fn validatePrefixes(prefixes: []const u8) NamesReplyError!void {
    return validatePrefixesWith(.{}, prefixes);
}

pub fn validatePrefixesWith(comptime params: Params, prefixes: []const u8) NamesReplyError!void {
    if (prefixes.len > params.max_prefix_bytes) return error.PrefixesTooLong;
    for (prefixes) |ch| {
        if (!validPrefixByte(ch)) return error.InvalidPrefix;
    }
}

pub fn validateText(text: []const u8) NamesReplyError!void {
    return validateTextWith(.{}, text);
}

pub fn validateTextWith(comptime params: Params, text: []const u8) NamesReplyError!void {
    if (text.len == 0) return error.InvalidText;
    if (text.len > params.max_text_bytes) return error.TextTooLong;
    for (text) |ch| {
        if (!validTextByte(ch)) return error.InvalidText;
    }
}

fn namReplyHeaderLen(server_name: []const u8, requester_nick: []const u8, channel: []const u8) usize {
    return 1 + server_name.len + 1 + 3 + 1 + requester_nick.len + 3 + channel.len + 2;
}

fn appendNamReplyHeader(
    out: []u8,
    n: *usize,
    server_name: []const u8,
    requester_nick: []const u8,
    channel: []const u8,
    status: u8,
) NamesReplyError!usize {
    const start = n.*;
    var code_buf: [3]u8 = undefined;
    const code = numeric.formatCode(namreply_code, &code_buf);

    try appendByte(out, n, ':');
    try append(out, n, server_name);
    try appendByte(out, n, ' ');
    try append(out, n, code);
    try appendByte(out, n, ' ');
    try append(out, n, requester_nick);
    // Channel visibility symbol: '=' public, '@' secret (+s), '*' private (+p).
    try appendByte(out, n, ' ');
    try appendByte(out, n, status);
    try appendByte(out, n, ' ');
    try append(out, n, channel);
    try append(out, n, " :");
    return n.* - start;
}

fn memberTokenLen(member: Member, caps: RequesterCaps) usize {
    var len: usize = visiblePrefixLen(member.prefixes, caps) + member.nick.len;
    if (caps.userhost_in_names) {
        len += 1 + member.user.len + 1 + member.host.len;
    }
    return len;
}

fn visiblePrefixLen(prefixes: []const u8, caps: RequesterCaps) usize {
    if (prefixes.len == 0) return 0;
    if (caps.multi_prefix) return prefixes.len;
    return 1;
}

fn appendMemberTokenUnchecked(
    out: []u8,
    n: *usize,
    member: Member,
    caps: RequesterCaps,
) NamesReplyError!void {
    const prefix_len = visiblePrefixLen(member.prefixes, caps);
    if (prefix_len != 0) try append(out, n, member.prefixes[0..prefix_len]);
    try append(out, n, member.nick);
    if (caps.userhost_in_names) {
        try appendByte(out, n, '!');
        try append(out, n, member.user);
        try appendByte(out, n, '@');
        try append(out, n, member.host);
    }
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

fn validTextByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn append(out: []u8, n: *usize, bytes: []const u8) NamesReplyError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) NamesReplyError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

test "member token cap gating" {
    const member = Member{ .prefixes = "@+", .nick = "alice", .user = "u", .host = "h.example" };
    var buf: [64]u8 = undefined;

    try std.testing.expectEqualStrings("@alice", try formatMemberToken(&buf, member, .{}));
    try std.testing.expectEqualStrings("@+alice", try formatMemberToken(&buf, member, .{ .multi_prefix = true }));
    try std.testing.expectEqualStrings("@alice!u@h.example", try formatMemberToken(&buf, member, .{ .userhost_in_names = true }));
    try std.testing.expectEqualStrings("@+alice!u@h.example", try formatMemberToken(&buf, member, .{
        .multi_prefix = true,
        .userhost_in_names = true,
    }));
}

test "names replies fold complete 353 lines and append 366" {
    const members = [_]Member{
        .{ .prefixes = "@+", .nick = "alice", .user = "aliceu", .host = "a.example" },
        .{ .prefixes = "+", .nick = "bob", .user = "bobu", .host = "b.example" },
        .{ .prefixes = "", .nick = "carol", .user = "carolu", .host = "c.example" },
    };

    var out: [256]u8 = undefined;
    var line_storage: [4]NamesLine = undefined;
    var sink = NamesLineSink{ .lines = &line_storage };
    try writeNamesRepliesWith(
        .{ .max_line_bytes = 69 },
        &out,
        "irc.example",
        "guest",
        "#test",
        '=',
        &members,
        .{ .multi_prefix = true, .userhost_in_names = true },
        &sink,
    );

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 4), lines.len);
    try std.testing.expectEqualStrings(":irc.example 353 guest = #test :@+alice!aliceu@a.example", lines[0].bytes);
    try std.testing.expectEqualStrings(":irc.example 353 guest = #test :+bob!bobu@b.example", lines[1].bytes);
    try std.testing.expectEqualStrings(":irc.example 353 guest = #test :carol!carolu@c.example", lines[2].bytes);
    try std.testing.expectEqualStrings(":irc.example 366 guest #test :End of /NAMES list", lines[3].bytes);
}

test "names replies use bare nicks without IRCv3 caps" {
    const members = [_]Member{
        .{ .prefixes = "@+", .nick = "alice", .user = "aliceu", .host = "a.example" },
        .{ .prefixes = "+", .nick = "bob", .user = "bobu", .host = "b.example" },
        .{ .prefixes = "", .nick = "carol", .user = "carolu", .host = "c.example" },
    };

    var out: [192]u8 = undefined;
    var line_storage: [2]NamesLine = undefined;
    var sink = NamesLineSink{ .lines = &line_storage };
    try writeNamesReplies(&out, "irc.example", "guest", "#test", '=', &members, .{}, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings(":irc.example 353 guest = #test :@alice +bob carol", lines[0].bytes);
    try std.testing.expectEqualStrings(":irc.example 366 guest #test :End of /NAMES list", lines[1].bytes);
}

test "empty member list emits only end of names" {
    const members = [_]Member{};
    var out: [96]u8 = undefined;
    var line_storage: [1]NamesLine = undefined;
    var sink = NamesLineSink{ .lines = &line_storage };
    try writeNamesReplies(&out, "irc.example", "guest", "#empty", '=', &members, .{}, &sink);

    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try std.testing.expectEqualStrings(":irc.example 366 guest #empty :End of /NAMES list", sink.slice()[0].bytes);
}

test "output and line sink capacity errors are reported" {
    const members = [_]Member{
        .{ .prefixes = "@", .nick = "alice", .user = "aliceu", .host = "a.example" },
    };

    var small_out: [16]u8 = undefined;
    var enough_lines_storage: [2]NamesLine = undefined;
    var enough_lines = NamesLineSink{ .lines = &enough_lines_storage };
    try std.testing.expectError(
        error.OutputTooSmall,
        writeNamesReplies(&small_out, "irc.example", "guest", "#test", '=', &members, .{}, &enough_lines),
    );

    var out: [128]u8 = undefined;
    var one_line_storage: [1]NamesLine = undefined;
    var one_line = NamesLineSink{ .lines = &one_line_storage };
    try std.testing.expectError(
        error.TooManyRecipients,
        writeNamesReplies(&out, "irc.example", "guest", "#test", '=', &members, .{}, &one_line),
    );
}

test "token too long for configured line size is skipped rather than aborting NAMES" {
    // A single overlong token must not collapse the whole roster to a bare 366
    // (mesh nicklist desync: one bad remote host → empty NAMES). The overlong
    // member is dropped; the valid peer still appears; 366 still closes.
    //
    // max_line_bytes=50 fits the 366 terminator (~48) and bob's userhost token
    // (header 32 + "bob!bobu@b.example" 18 = 50) but NOT alice's multi-prefix
    // userhost token (header 32 + "@+alice!aliceu@a.example" 24 = 56).
    const members = [_]Member{
        .{ .prefixes = "@+", .nick = "alice", .user = "aliceu", .host = "a.example" },
        .{ .prefixes = "", .nick = "bob", .user = "bobu", .host = "b.example" },
    };
    var out: [128]u8 = undefined;
    var line_storage: [2]NamesLine = undefined;
    var sink = NamesLineSink{ .lines = &line_storage };

    try writeNamesRepliesWith(
        .{ .max_line_bytes = 50 },
        &out,
        "irc.example",
        "guest",
        "#test",
        '=',
        &members,
        .{ .multi_prefix = true, .userhost_in_names = true },
        &sink,
    );
    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 2), lines.len); // one 353 + 366
    try std.testing.expect(std.mem.indexOf(u8, lines[0].bytes, "alice") == null);
    try std.testing.expect(std.mem.indexOf(u8, lines[0].bytes, "bob") != null);
    try std.testing.expectEqualStrings(":irc.example 366 guest #test :End of /NAMES list", lines[1].bytes);
}

test "a single malformed remote host is skipped so the rest of NAMES still lands" {
    // Mesh regression: one remote member with a host that fails wire validation
    // used to abort writeNamesReplies entirely; sendNames then emitted only 366
    // and both sides of the mesh saw an empty nicklist until the next re-NAMES.
    const members = [_]Member{
        .{ .prefixes = "@", .nick = "alice", .user = "aliceu", .host = "a.example" },
        .{ .prefixes = "", .nick = "evil", .user = "u", .host = "bad host" }, // space = InvalidHost
        .{ .prefixes = "+", .nick = "carol", .user = "carolu", .host = "c.example" },
    };
    var out: [256]u8 = undefined;
    var line_storage: [2]NamesLine = undefined;
    var sink = NamesLineSink{ .lines = &line_storage };
    try writeNamesReplies(&out, "irc.example", "guest", "#mesh", '=', &members, .{}, &sink);
    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expect(std.mem.indexOf(u8, lines[0].bytes, "alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines[0].bytes, "carol") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines[0].bytes, "evil") == null);
    try std.testing.expectEqualStrings(":irc.example 366 guest #mesh :End of /NAMES list", lines[1].bytes);
}

test "writeNamReplyLines streams 353s without a trailing 366 so callers can chunk" {
    const members = [_]Member{
        .{ .prefixes = "@", .nick = "alice", .user = "u", .host = "h" },
        .{ .prefixes = "", .nick = "bob", .user = "u", .host = "h" },
    };
    var out: [128]u8 = undefined;
    var line_storage: [2]NamesLine = undefined;
    var sink = NamesLineSink{ .lines = &line_storage };
    const used = try writeNamReplyLines(&out, "irc.example", "guest", "#chat", '=', &members, .{}, &sink);
    try std.testing.expect(used > 0);
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try std.testing.expect(std.mem.startsWith(u8, sink.slice()[0].bytes, ":irc.example 353 "));
    // No 366 — caller appends it once after every chunk.
    try std.testing.expect(std.mem.indexOf(u8, sink.slice()[0].bytes, "366") == null);
}

test "invalid attacker controlled bytes are rejected" {
    try std.testing.expectError(error.InvalidNick, validateNick("bad nick"));
    try std.testing.expectError(error.InvalidUser, validateUser("bad@user"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad\nhost"));
    try std.testing.expectError(error.InvalidChannel, validateChannel("#bad channel"));
    try std.testing.expectError(error.InvalidPrefix, validatePrefixes("@\r"));
    try std.testing.expectError(error.InvalidText, validateText("bad\rtext"));

    var buf: [128]u8 = undefined;
    try std.testing.expectError(
        error.InvalidChannel,
        buildEndOfNamesLine(&buf, "irc.example", "guest", "not-channel", default_end_text),
    );
}

// ---------------------------------------------------------------------------
// exploit: hostile NAMES — partial 353 + CRLF injection fail-closed
// ---------------------------------------------------------------------------

test "exploit: NAMES rejects CRLF/NUL-smuggled member fields (no wire injection)" {
    // CWE-93: a hostile remote membership identity that reached the NAMES
    // builder must never split an outbound 353 into a second command line.
    // Validators still fail-closed at the field API; the writer SKIPS a bad
    // member (so one hostile host cannot empty the whole roster) and never
    // copies its bytes onto the wire. A pure-hostile list therefore yields
    // only the terminating 366 — no smuggled 353 payload.
    const cases = [_]struct { member: Member, err: NamesReplyError }{
        .{ .member = .{ .prefixes = "", .nick = "al\rice", .user = "u", .host = "h.example" }, .err = error.InvalidNick },
        .{ .member = .{ .prefixes = "", .nick = "alice", .user = "u\nX", .host = "h.example" }, .err = error.InvalidUser },
        .{ .member = .{ .prefixes = "", .nick = "alice", .user = "u", .host = "h\x00.example" }, .err = error.InvalidHost },
        .{ .member = .{ .prefixes = "@\n", .nick = "alice", .user = "u", .host = "h.example" }, .err = error.InvalidPrefix },
    };
    var out: [256]u8 = undefined;
    var line_storage: [4]NamesLine = undefined;
    for (cases) |case| {
        // Field validators still reject (callers that want hard-fail use them).
        try std.testing.expectError(case.err, validateMember(case.member));

        var sink = NamesLineSink{ .lines = &line_storage };
        const members = [_]Member{
            case.member,
            .{ .prefixes = "", .nick = "safe", .user = "u", .host = "h.example" },
        };
        try writeNamesReplies(&out, "irc.example", "guest", "#test", '=', &members, .{}, &sink);
        const lines = sink.slice();
        try std.testing.expect(lines.len >= 1);
        // Hostile payload never appears; the safe peer still does; no CRLF/NUL.
        for (lines) |line| {
            try std.testing.expect(std.mem.indexOfScalar(u8, line.bytes, '\r') == null);
            try std.testing.expect(std.mem.indexOfScalar(u8, line.bytes, '\n') == null);
            try std.testing.expect(std.mem.indexOfScalar(u8, line.bytes, 0) == null);
            try std.testing.expect(std.mem.indexOf(u8, line.bytes, "al\rice") == null);
            try std.testing.expect(std.mem.indexOf(u8, line.bytes, "u\nX") == null);
        }
        // Safe member survived the skip.
        var saw_safe = false;
        for (lines) |line| {
            if (std.mem.indexOf(u8, line.bytes, "safe") != null) saw_safe = true;
        }
        try std.testing.expect(saw_safe);
        try std.testing.expect(std.mem.indexOf(u8, lines[lines.len - 1].bytes, " 366 ") != null);
    }
}

test "exploit: partial 353 fold always terminates with exactly one 366 (or errors fail-closed)" {
    // Multi-line NAMES (partial 353s) must never strand a client without
    // RPL_ENDOFNAMES, and must never emit a second 366. Sink exhaustion mid-list
    // returns an error so the daemon can close with a clean 366 alone.
    const members = [_]Member{
        .{ .prefixes = "@+", .nick = "alice", .user = "aliceu", .host = "a.example" },
        .{ .prefixes = "+", .nick = "bob", .user = "bobu", .host = "b.example" },
        .{ .prefixes = "", .nick = "carol", .user = "carolu", .host = "c.example" },
        .{ .prefixes = "", .nick = "dave", .user = "daveu", .host = "d.example" },
    };

    // Happy path: tight line budget forces multiple 353s + one 366.
    {
        var out: [512]u8 = undefined;
        var line_storage: [8]NamesLine = undefined;
        var sink = NamesLineSink{ .lines = &line_storage };
        try writeNamesRepliesWith(
            .{ .max_line_bytes = 64 },
            &out,
            "irc.example",
            "guest",
            "#test",
            '=',
            &members,
            .{ .multi_prefix = true, .userhost_in_names = true },
            &sink,
        );
        const lines = sink.slice();
        try std.testing.expect(lines.len >= 2);
        var namreply: usize = 0;
        var endofnames: usize = 0;
        for (lines) |line| {
            if (std.mem.indexOf(u8, line.bytes, " 353 ") != null) namreply += 1;
            if (std.mem.indexOf(u8, line.bytes, " 366 ") != null) endofnames += 1;
            // No CRLF inside a stored line (terminator is applied by the caller).
            try std.testing.expect(std.mem.indexOfScalar(u8, line.bytes, '\r') == null);
            try std.testing.expect(std.mem.indexOfScalar(u8, line.bytes, '\n') == null);
        }
        try std.testing.expect(namreply >= 1);
        try std.testing.expectEqual(@as(usize, 1), endofnames);
        // 366 is always last.
        try std.testing.expect(std.mem.indexOf(u8, lines[lines.len - 1].bytes, " 366 ") != null);
    }

    // Sink too small for the full fold: error, and the caller must discard any
    // partial 353s already staged (sendNames shrinks the chunk and retries).
    {
        var out: [512]u8 = undefined;
        var line_storage: [1]NamesLine = undefined; // cannot hold 353+366
        var sink = NamesLineSink{ .lines = &line_storage };
        try std.testing.expectError(
            error.TooManyRecipients,
            writeNamesRepliesWith(
                .{ .max_line_bytes = 64 },
                &out,
                "irc.example",
                "guest",
                "#test",
                '=',
                &members,
                .{ .userhost_in_names = true },
                &sink,
            ),
        );
        // Contract: on error the sink is incomplete — never treat it as a finished
        // NAMES. (It may hold a partial 353; it must not hold a lone complete list.)
        for (sink.slice()) |line| {
            try std.testing.expect(std.mem.indexOf(u8, line.bytes, " 366 ") == null);
        }
    }
}
