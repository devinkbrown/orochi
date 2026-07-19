// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! KICK command parsing, privilege checks, and wire-line builders.
//!
//! Channel membership lookup, channel existence, and delivery fanout are owned
//! by the caller. This module validates attacker-controlled command fields,
//! parses `KICK <channel> <user> [:reason]`, compares Onyx Server member-prefix
//! tiers for authorization, and builds KICK broadcasts plus common KICK
//! numerics into caller-owned buffers without allocation.
const std = @import("std");
const numerics = @import("numeric.zig");

pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 200;
pub const DEFAULT_MAX_REASON_BYTES: usize = 512;
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 512;
pub const DEFAULT_CHANNEL_PREFIXES: []const u8 = "#+&!";

pub const KickError = error{
    MissingChannel,
    MissingUser,
    TooManyParameters,
    InvalidChannel,
    ChannelTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidServerName,
    ServerNameTooLong,
    InvalidReason,
    ReasonTooLong,
    InvalidDescription,
    DescriptionTooLong,
    OutputTooSmall,
};

/// Compile-time limits and protocol-edge validation policy.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_server_name_bytes: usize = DEFAULT_MAX_SERVER_NAME_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_reason_bytes: usize = DEFAULT_MAX_REASON_BYTES,
    max_description_bytes: usize = DEFAULT_MAX_DESCRIPTION_BYTES,
    channel_prefixes: []const u8 = DEFAULT_CHANNEL_PREFIXES,
    require_utf8: bool = true,
};

/// Identity used as the IRC message prefix: `nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Parsed `KICK <channel> <user> [:reason]` command parameters.
pub const KickArgs = struct {
    channel: []const u8,
    user: []const u8,
    reason: []const u8 = "",
};

/// Numeric failures commonly emitted while handling KICK.
pub const KickNumeric = enum {
    ERR_CHANOPRIVSNEEDED,
    ERR_USERNOTINCHANNEL,
    ERR_NOTONCHANNEL,
    ERR_NOSUCHCHANNEL,

    pub fn numericCode(self: KickNumeric) numerics.Numeric {
        return switch (self) {
            .ERR_CHANOPRIVSNEEDED => .ERR_CHANOPRIVSNEEDED,
            .ERR_USERNOTINCHANNEL => .ERR_USERNOTINCHANNEL,
            .ERR_NOTONCHANNEL => .ERR_NOTONCHANNEL,
            .ERR_NOSUCHCHANNEL => .ERR_NOSUCHCHANNEL,
        };
    }
};

/// Parse KICK parameters after IRC line parsing.
///
/// The optional trailing reason should be supplied as the third parameter
/// without its leading `:`.
pub fn parseKickArgs(params: []const []const u8) KickError!KickArgs {
    return parseKickArgsWith(.{}, params);
}

/// Parse KICK parameters with caller-selected compile-time limits.
pub fn parseKickArgsWith(comptime params_config: Params, params: []const []const u8) KickError!KickArgs {
    if (params.len == 0) return error.MissingChannel;
    if (params.len == 1) return error.MissingUser;
    if (params.len > 3) return error.TooManyParameters;

    const reason = if (params.len == 3) params[2] else "";
    try validateChannelWith(params_config, params[0]);
    try validateNickWith(params_config, params[1]);
    try validateReasonWith(params_config, reason);

    return .{
        .channel = params[0],
        .user = params[1],
        .reason = reason,
    };
}

/// Return true when the integer tiers satisfy KICK's privilege rule.
///
/// Tier mapping is: none=0, voice=1, op=2, owner=3, founder=4.
pub fn canKickTiers(kicker_tier: u8, target_tier: u8) bool {
    return kicker_tier >= memberTierOp() and kicker_tier >= target_tier;
}

pub fn memberTierNone() u8 {
    return 0;
}

pub fn memberTierVoice() u8 {
    return 1;
}

pub fn memberTierOp() u8 {
    return 2;
}

pub fn memberTierOwner() u8 {
    return 3;
}

pub fn memberTierFounder() u8 {
    return 4;
}

/// Build `:nick!user@host KICK <channel> <user> :<reason>`.
pub fn buildKickBroadcast(
    out: []u8,
    kicker: Prefix,
    channel: []const u8,
    user: []const u8,
    reason: []const u8,
) KickError![]const u8 {
    return buildKickBroadcastWith(.{}, out, kicker, channel, user, reason);
}

/// Build a KICK broadcast using caller-selected compile-time limits.
pub fn buildKickBroadcastWith(
    comptime params: Params,
    out: []u8,
    kicker: Prefix,
    channel: []const u8,
    user: []const u8,
    reason: []const u8,
) KickError![]const u8 {
    try validatePrefix(params, kicker);
    try validateChannelWith(params, channel);
    try validateNickWith(params, user);
    try validateReasonWith(params, reason);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try appendPrefix(out, &n, kicker);
    try append(out, &n, " KICK ");
    try append(out, &n, channel);
    try appendByte(out, &n, ' ');
    try append(out, &n, user);
    try append(out, &n, " :");
    try append(out, &n, reason);
    return out[0..n];
}

/// Build `ERR_CHANOPRIVSNEEDED` 482.
pub fn buildChanOpPrivsNeededNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) KickError![]const u8 {
    return buildChannelNumeric(
        out,
        server_name,
        recipient_nick,
        channel,
        .ERR_CHANOPRIVSNEEDED,
        "You're not channel operator",
    );
}

/// Build `ERR_USERNOTINCHANNEL` 441.
pub fn buildUserNotInChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    channel: []const u8,
) KickError![]const u8 {
    return buildUserChannelNumeric(
        out,
        server_name,
        recipient_nick,
        target_nick,
        channel,
        .ERR_USERNOTINCHANNEL,
        "They aren't on that channel",
    );
}

/// Build `ERR_NOTONCHANNEL` 442.
pub fn buildNotOnChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) KickError![]const u8 {
    return buildChannelNumeric(
        out,
        server_name,
        recipient_nick,
        channel,
        .ERR_NOTONCHANNEL,
        "You're not on that channel",
    );
}

/// Build `ERR_NOSUCHCHANNEL` 403.
pub fn buildNoSuchChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) KickError![]const u8 {
    return buildChannelNumeric(
        out,
        server_name,
        recipient_nick,
        channel,
        .ERR_NOSUCHCHANNEL,
        "No such channel",
    );
}

/// Build a channel-scoped KICK numeric using caller-selected limits.
pub fn buildChannelNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: KickNumeric,
    description: []const u8,
) KickError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);
    try validateChannelWith(params, channel);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, failure.numericCode(), recipient_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

/// Build a channel-scoped KICK numeric with the default validation policy.
pub fn buildChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: KickNumeric,
    description: []const u8,
) KickError![]const u8 {
    return buildChannelNumericWith(.{}, out, server_name, recipient_nick, channel, failure, description);
}

/// Build a target-and-channel-scoped KICK numeric using caller-selected limits.
pub fn buildUserChannelNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    channel: []const u8,
    failure: KickNumeric,
    description: []const u8,
) KickError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);
    try validateNickWith(params, target_nick);
    try validateChannelWith(params, channel);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, failure.numericCode(), recipient_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, target_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

/// Build a target-and-channel-scoped KICK numeric with the default policy.
pub fn buildUserChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    channel: []const u8,
    failure: KickNumeric,
    description: []const u8,
) KickError![]const u8 {
    return buildUserChannelNumericWith(.{}, out, server_name, recipient_nick, target_nick, channel, failure, description);
}

pub fn validateChannel(channel: []const u8) KickError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) KickError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefix(params, channel[0])) return error.InvalidChannel;
    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(channel)) return error.InvalidChannel;
}

pub fn validateNick(nick: []const u8) KickError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) KickError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateReason(reason: []const u8) KickError!void {
    return validateReasonWith(.{}, reason);
}

pub fn validateReasonWith(comptime params: Params, reason: []const u8) KickError!void {
    if (reason.len > params.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |ch| {
        if (!validTextByte(ch)) return error.InvalidReason;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(reason)) return error.InvalidReason;
}

pub fn validateServerName(server_name: []const u8) KickError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) KickError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

fn validateDescriptionWith(comptime params: Params, description: []const u8) KickError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (description.len > params.max_description_bytes) return error.DescriptionTooLong;
    for (description) |ch| {
        if (!validTextByte(ch)) return error.InvalidDescription;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(description)) return error.InvalidDescription;
}

fn validatePrefix(comptime params: Params, prefix: Prefix) KickError!void {
    try validateNickWith(params, prefix.nick);
    try validateUserWith(params, prefix.user);
    try validateHostWith(params, prefix.host);
}

fn validateUserWith(comptime params: Params, user: []const u8) KickError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(user)) return error.InvalidUser;
}

fn validateHostWith(comptime params: Params, host: []const u8) KickError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(host)) return error.InvalidHost;
}

fn validChannelPrefix(comptime params: Params, prefix: u8) bool {
    for (params.channel_prefixes) |candidate| {
        if (prefix == candidate) return true;
    }
    return false;
}

fn validChannelByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return switch (ch) {
        ',', ':', '|' => false,
        else => true,
    };
}

fn validTextByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
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

fn appendPrefix(out: []u8, n: *usize, prefix: Prefix) KickError!void {
    try append(out, n, prefix.nick);
    try appendByte(out, n, '!');
    try append(out, n, prefix.user);
    try appendByte(out, n, '@');
    try append(out, n, prefix.host);
}

fn appendServerNumericHead(
    out: []u8,
    n: *usize,
    server_name: []const u8,
    failure: numerics.Numeric,
    recipient_nick: []const u8,
) KickError!void {
    var code_buf: [3]u8 = undefined;
    try appendByte(out, n, ':');
    try append(out, n, server_name);
    try appendByte(out, n, ' ');
    try append(out, n, numerics.formatCode(failure, &code_buf));
    try appendByte(out, n, ' ');
    try append(out, n, recipient_nick);
}

fn append(out: []u8, n: *usize, bytes: []const u8) KickError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) KickError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

test "parse kick args with optional reason" {
    const with_reason = [_][]const u8{ "#ops", "bob", "rule violation" };
    const parsed = try parseKickArgs(&with_reason);
    try std.testing.expectEqualStrings("#ops", parsed.channel);
    try std.testing.expectEqualStrings("bob", parsed.user);
    try std.testing.expectEqualStrings("rule violation", parsed.reason);

    const without_reason = [_][]const u8{ "#ops", "bob" };
    const parsed_without = try parseKickArgs(&without_reason);
    try std.testing.expectEqualStrings("#ops", parsed_without.channel);
    try std.testing.expectEqualStrings("bob", parsed_without.user);
    try std.testing.expectEqualStrings("", parsed_without.reason);
}

test "malformed kick args are rejected" {
    const missing_channel = [_][]const u8{};
    try std.testing.expectError(error.MissingChannel, parseKickArgs(&missing_channel));

    const missing_user = [_][]const u8{"#ops"};
    try std.testing.expectError(error.MissingUser, parseKickArgs(&missing_user));

    const too_many = [_][]const u8{ "#ops", "bob", "reason", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseKickArgs(&too_many));

    const bad_channel = [_][]const u8{ "#bad channel", "bob" };
    try std.testing.expectError(error.InvalidChannel, parseKickArgs(&bad_channel));

    const bad_user = [_][]const u8{ "#ops", "bad nick" };
    try std.testing.expectError(error.InvalidNick, parseKickArgs(&bad_user));

    const bad_reason = [_][]const u8{ "#ops", "bob", "bad\rreason" };
    try std.testing.expectError(error.InvalidReason, parseKickArgs(&bad_reason));
}

test "privilege ranking requires op and protects higher tiers" {
    const none = memberTierNone();
    const voice = memberTierVoice();
    const op = memberTierOp();
    const owner = memberTierOwner();
    const founder = memberTierFounder();

    try std.testing.expect(!canKickTiers(voice, none));
    try std.testing.expect(canKickTiers(op, none));
    try std.testing.expect(canKickTiers(op, voice));
    try std.testing.expect(canKickTiers(op, op));
    try std.testing.expect(!canKickTiers(op, owner));
    try std.testing.expect(!canKickTiers(op, founder));
    try std.testing.expect(canKickTiers(owner, op));
    try std.testing.expect(canKickTiers(owner, owner));
    try std.testing.expect(!canKickTiers(owner, founder));
    try std.testing.expect(canKickTiers(founder, founder));
}

test "broadcast format validates prefix target and reason" {
    var buf: [160]u8 = undefined;
    const line = try buildKickBroadcast(&buf, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#ops", "bob", "cleanup");
    try std.testing.expectEqualStrings(":alice!u@h KICK #ops bob :cleanup", line);

    const empty_reason = try buildKickBroadcast(&buf, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#ops", "bob", "");
    try std.testing.expectEqualStrings(":alice!u@h KICK #ops bob :", empty_reason);

    try std.testing.expectError(error.InvalidUser, buildKickBroadcast(&buf, .{
        .nick = "alice",
        .user = "bad user",
        .host = "h",
    }, "#ops", "bob", "cleanup"));
    try std.testing.expectError(error.InvalidReason, buildKickBroadcast(&buf, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#ops", "bob", "bad\nreason"));
}

test "kick error numerics use exact codes and parameter order" {
    var buf: [192]u8 = undefined;

    const chanop = try buildChanOpPrivsNeededNumeric(&buf, "irc.example", "alice", "#ops");
    try std.testing.expectEqualStrings(":irc.example 482 alice #ops :You're not channel operator", chanop);

    const user_not_in = try buildUserNotInChannelNumeric(&buf, "irc.example", "alice", "bob", "#ops");
    try std.testing.expectEqualStrings(":irc.example 441 alice bob #ops :They aren't on that channel", user_not_in);

    const not_on = try buildNotOnChannelNumeric(&buf, "irc.example", "alice", "#ops");
    try std.testing.expectEqualStrings(":irc.example 442 alice #ops :You're not on that channel", not_on);

    const no_such = try buildNoSuchChannelNumeric(&buf, "irc.example", "alice", "#ops");
    try std.testing.expectEqualStrings(":irc.example 403 alice #ops :No such channel", no_such);
}

test "numeric builders validate attacker controlled bytes and buffer size" {
    var buf: [96]u8 = undefined;
    var small: [8]u8 = undefined;

    try std.testing.expectError(error.InvalidServerName, buildNoSuchChannelNumeric(&buf, "irc example", "alice", "#ops"));
    try std.testing.expectError(error.InvalidNick, buildNoSuchChannelNumeric(&buf, "irc.example", "bad nick", "#ops"));
    try std.testing.expectError(error.InvalidChannel, buildNoSuchChannelNumeric(&buf, "irc.example", "alice", "#bad:chan"));
    try std.testing.expectError(error.InvalidDescription, buildChannelNumeric(&buf, "irc.example", "alice", "#ops", .ERR_NOSUCHCHANNEL, "bad\ndescription"));
    try std.testing.expectError(error.OutputTooSmall, buildNoSuchChannelNumeric(&small, "irc.example", "alice", "#ops"));
}

test "validators support utf8 policy and length limits" {
    try validateChannel("#caf\xc3\xa9");
    try std.testing.expectError(error.InvalidChannel, validateChannel("#bad\xff"));
    try validateChannelWith(.{ .require_utf8 = false }, "#raw\xff");

    try std.testing.expectError(error.ChannelTooLong, validateChannelWith(.{ .max_channel_bytes = 4 }, "#toolong"));
    try std.testing.expectError(error.NickTooLong, validateNickWith(.{ .max_nick_bytes = 3 }, "alice"));
    try std.testing.expectError(error.ReasonTooLong, validateReasonWith(.{ .max_reason_bytes = 3 }, "four"));
}
