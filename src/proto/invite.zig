//! INVITE command parsing, precondition checks, and wire-line builders.
//!
//! Channel lookup, target lookup, invite state mutation, and `invite-notify`
//! broadcast fanout are owned by the caller. This module validates
//! attacker-controlled IRC fields, parses `INVITE <nick> <channel>`, checks the
//! RFC-compatible channel privilege preconditions, and builds success/error
//! replies into caller-owned buffers without allocation.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 200;
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 512;
pub const DEFAULT_CHANNEL_PREFIXES: []const u8 = "#+&!";

pub const InviteError = error{
    MissingNick,
    MissingChannel,
    TooManyParameters,
    InvalidNick,
    NickTooLong,
    InvalidChannel,
    ChannelTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidServerName,
    ServerNameTooLong,
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
    max_description_bytes: usize = DEFAULT_MAX_DESCRIPTION_BYTES,
    channel_prefixes: []const u8 = DEFAULT_CHANNEL_PREFIXES,
    require_utf8: bool = true,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_channel_bytes` keeps its builder default (does not share the 64-byte
    /// CHANNELLEN policy). `channel_prefixes` aliases the config value, which
    /// must outlive any use of the returned `Params`.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_nick_bytes = limits.nick_len,
            .max_user_bytes = limits.user_len,
            .max_host_bytes = limits.host_len,
            .max_server_name_bytes = limits.server_name_len,
            .max_description_bytes = limits.realname_len,
            .channel_prefixes = limits.channel_prefixes.slice(),
        };
    }
};

/// Identity used as the IRC message prefix: `nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Parsed `INVITE <nick> <channel>` command parameters.
pub const InviteArgs = struct {
    nick: []const u8,
    channel: []const u8,
};

/// Caller-computed facts required by INVITE's channel precondition check.
pub const InvitePreconditions = struct {
    on_channel: bool,
    is_operator: bool,
    invite_only: bool,
    free_invite: bool,
    target_on_channel: bool,
};

/// Result of checking INVITE channel preconditions.
pub const InviteCheckResult = enum {
    allow,
    deny_not_on_channel,
    deny_user_on_channel,
    deny_chan_op_privs_needed,
};

/// Numeric failures commonly emitted while handling INVITE.
pub const InviteNumeric = enum {
    ERR_NOSUCHNICK,
    ERR_NOSUCHCHANNEL,
    ERR_NOTONCHANNEL,
    ERR_USERONCHANNEL,
    ERR_CHANOPRIVSNEEDED,

    pub fn numericCode(self: InviteNumeric) numeric.Numeric {
        return switch (self) {
            .ERR_NOSUCHNICK => .ERR_NOSUCHNICK,
            .ERR_NOSUCHCHANNEL => .ERR_NOSUCHCHANNEL,
            .ERR_NOTONCHANNEL => .ERR_NOTONCHANNEL,
            .ERR_USERONCHANNEL => .ERR_USERONCHANNEL,
            .ERR_CHANOPRIVSNEEDED => .ERR_CHANOPRIVSNEEDED,
        };
    }
};

/// Parse INVITE parameters after IRC line parsing.
pub fn parseInviteArgs(params: []const []const u8) InviteError!InviteArgs {
    return parseInviteArgsWith(.{}, params);
}

/// Parse INVITE parameters with caller-selected compile-time limits.
pub fn parseInviteArgsWith(comptime params_config: Params, params: []const []const u8) InviteError!InviteArgs {
    if (params.len == 0) return error.MissingNick;
    if (params.len == 1) return error.MissingChannel;
    if (params.len > 2) return error.TooManyParameters;

    try validateNickWith(params_config, params[0]);
    try validateChannelWith(params_config, params[1]);

    return .{
        .nick = params[0],
        .channel = params[1],
    };
}

/// Check the INVITE channel preconditions.
///
/// `is_operator` means op-or-higher in Mizuchi's member tiers:
/// founder `!`, owner `.`, and op `@` all satisfy it. Invite-only channels
/// require that privilege unless the channel has free-invite `+g`.
pub fn checkInvitePreconditions(flags: InvitePreconditions) InviteCheckResult {
    if (!flags.on_channel) return .deny_not_on_channel;
    if (flags.invite_only and !flags.free_invite and !flags.is_operator) {
        return .deny_chan_op_privs_needed;
    }
    if (flags.target_on_channel) return .deny_user_on_channel;
    return .allow;
}

/// Build `:server 341 inviter invitee #channel`.
pub fn buildInvitingNumeric(
    out: []u8,
    server_name: []const u8,
    inviter_nick: []const u8,
    invitee_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    return buildInvitingNumericWith(.{}, out, server_name, inviter_nick, invitee_nick, channel);
}

/// Build RPL_INVITING using caller-selected compile-time limits.
pub fn buildInvitingNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    inviter_nick: []const u8,
    invitee_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, inviter_nick);
    try validateNickWith(params, invitee_nick);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, .RPL_INVITING, inviter_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, invitee_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    return out[0..n];
}

/// Build `:nick!user@host INVITE invitee :#channel` for target delivery.
pub fn buildTargetInviteLine(
    out: []u8,
    inviter: Prefix,
    invitee_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    return buildTargetInviteLineWith(.{}, out, inviter, invitee_nick, channel);
}

/// Build a target INVITE line using caller-selected compile-time limits.
pub fn buildTargetInviteLineWith(
    comptime params: Params,
    out: []u8,
    inviter: Prefix,
    invitee_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    try validatePrefix(params, inviter);
    try validateNickWith(params, invitee_nick);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try appendPrefix(out, &n, inviter);
    try append(out, &n, " INVITE ");
    try append(out, &n, invitee_nick);
    try append(out, &n, " :");
    try append(out, &n, channel);
    return out[0..n];
}

/// Build `ERR_NOSUCHNICK` 401.
pub fn buildNoSuchNickNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
) InviteError![]const u8 {
    return buildNickNumeric(
        out,
        server_name,
        recipient_nick,
        target_nick,
        .ERR_NOSUCHNICK,
        "No such nick/channel",
    );
}

/// Build `ERR_NOSUCHCHANNEL` 403.
pub fn buildNoSuchChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    return buildChannelNumeric(
        out,
        server_name,
        recipient_nick,
        channel,
        .ERR_NOSUCHCHANNEL,
        "No such channel",
    );
}

/// Build `ERR_NOTONCHANNEL` 442.
pub fn buildNotOnChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    return buildChannelNumeric(
        out,
        server_name,
        recipient_nick,
        channel,
        .ERR_NOTONCHANNEL,
        "You're not on that channel",
    );
}

/// Build `ERR_USERONCHANNEL` 443.
pub fn buildUserOnChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    return buildNickChannelNumeric(
        out,
        server_name,
        recipient_nick,
        target_nick,
        channel,
        .ERR_USERONCHANNEL,
        "is already on channel",
    );
}

/// Build `ERR_CHANOPRIVSNEEDED` 482.
pub fn buildChanOpPrivsNeededNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) InviteError![]const u8 {
    return buildChannelNumeric(
        out,
        server_name,
        recipient_nick,
        channel,
        .ERR_CHANOPRIVSNEEDED,
        "You're not channel operator",
    );
}

/// Build a nick-scoped INVITE numeric using caller-selected limits.
pub fn buildNickNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    failure: InviteNumeric,
    description: []const u8,
) InviteError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);
    try validateNickWith(params, target_nick);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, failure.numericCode(), recipient_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, target_nick);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

/// Build a nick-scoped INVITE numeric with the default validation policy.
pub fn buildNickNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    failure: InviteNumeric,
    description: []const u8,
) InviteError![]const u8 {
    return buildNickNumericWith(.{}, out, server_name, recipient_nick, target_nick, failure, description);
}

/// Build a channel-scoped INVITE numeric using caller-selected limits.
pub fn buildChannelNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: InviteNumeric,
    description: []const u8,
) InviteError![]const u8 {
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

/// Build a channel-scoped INVITE numeric with the default validation policy.
pub fn buildChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: InviteNumeric,
    description: []const u8,
) InviteError![]const u8 {
    return buildChannelNumericWith(.{}, out, server_name, recipient_nick, channel, failure, description);
}

/// Build a nick-and-channel-scoped INVITE numeric using caller-selected limits.
pub fn buildNickChannelNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    channel: []const u8,
    failure: InviteNumeric,
    description: []const u8,
) InviteError![]const u8 {
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

/// Build a nick-and-channel-scoped INVITE numeric with the default policy.
pub fn buildNickChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    channel: []const u8,
    failure: InviteNumeric,
    description: []const u8,
) InviteError![]const u8 {
    return buildNickChannelNumericWith(.{}, out, server_name, recipient_nick, target_nick, channel, failure, description);
}

pub fn validateNick(nick: []const u8) InviteError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) InviteError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateChannel(channel: []const u8) InviteError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) InviteError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefix(params, channel[0])) return error.InvalidChannel;
    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(channel)) return error.InvalidChannel;
}

pub fn validateUser(user: []const u8) InviteError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) InviteError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(user)) return error.InvalidUser;
}

pub fn validateHost(host: []const u8) InviteError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) InviteError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(host)) return error.InvalidHost;
}

pub fn validateServerName(server_name: []const u8) InviteError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) InviteError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

fn validateDescriptionWith(comptime params: Params, description: []const u8) InviteError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (description.len > params.max_description_bytes) return error.DescriptionTooLong;
    for (description) |ch| {
        if (!validTextByte(ch)) return error.InvalidDescription;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(description)) return error.InvalidDescription;
}

fn validatePrefix(comptime params: Params, prefix: Prefix) InviteError!void {
    try validateNickWith(params, prefix.nick);
    try validateUserWith(params, prefix.user);
    try validateHostWith(params, prefix.host);
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

fn appendPrefix(out: []u8, n: *usize, prefix: Prefix) InviteError!void {
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
    code: numeric.Numeric,
    recipient_nick: []const u8,
) InviteError!void {
    var code_buf: [3]u8 = undefined;
    try appendByte(out, n, ':');
    try append(out, n, server_name);
    try appendByte(out, n, ' ');
    try append(out, n, numeric.formatCode(code, &code_buf));
    try appendByte(out, n, ' ');
    try append(out, n, recipient_nick);
}

fn append(out: []u8, n: *usize, bytes: []const u8) InviteError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) InviteError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

test "parse invite args" {
    const raw = [_][]const u8{ "bob", "#mizuchi" };
    const parsed = try parseInviteArgs(&raw);
    try std.testing.expectEqualStrings("bob", parsed.nick);
    try std.testing.expectEqualStrings("#mizuchi", parsed.channel);
}

test "malformed invite args are rejected" {
    const missing_nick = [_][]const u8{};
    try std.testing.expectError(error.MissingNick, parseInviteArgs(&missing_nick));

    const missing_channel = [_][]const u8{"bob"};
    try std.testing.expectError(error.MissingChannel, parseInviteArgs(&missing_channel));

    const too_many = [_][]const u8{ "bob", "#mizuchi", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseInviteArgs(&too_many));

    const bad_nick = [_][]const u8{ "bad nick", "#mizuchi" };
    try std.testing.expectError(error.InvalidNick, parseInviteArgs(&bad_nick));

    const bad_channel = [_][]const u8{ "bob", "#bad channel" };
    try std.testing.expectError(error.InvalidChannel, parseInviteArgs(&bad_channel));
}

test "precondition checker allows basic and privileged invites" {
    try std.testing.expectEqual(.allow, checkInvitePreconditions(.{
        .on_channel = true,
        .is_operator = false,
        .invite_only = false,
        .free_invite = false,
        .target_on_channel = false,
    }));

    try std.testing.expectEqual(.allow, checkInvitePreconditions(.{
        .on_channel = true,
        .is_operator = true,
        .invite_only = true,
        .free_invite = false,
        .target_on_channel = false,
    }));

    try std.testing.expectEqual(.allow, checkInvitePreconditions(.{
        .on_channel = true,
        .is_operator = false,
        .invite_only = true,
        .free_invite = true,
        .target_on_channel = false,
    }));
}

test "precondition checker denies each failure path" {
    try std.testing.expectEqual(.deny_not_on_channel, checkInvitePreconditions(.{
        .on_channel = false,
        .is_operator = true,
        .invite_only = false,
        .free_invite = false,
        .target_on_channel = false,
    }));

    try std.testing.expectEqual(.deny_user_on_channel, checkInvitePreconditions(.{
        .on_channel = true,
        .is_operator = true,
        .invite_only = false,
        .free_invite = false,
        .target_on_channel = true,
    }));

    try std.testing.expectEqual(.deny_chan_op_privs_needed, checkInvitePreconditions(.{
        .on_channel = true,
        .is_operator = false,
        .invite_only = true,
        .free_invite = false,
        .target_on_channel = false,
    }));
}

test "success builders format rpl inviting and target invite" {
    var buf: [160]u8 = undefined;
    const rpl = try buildInvitingNumeric(&buf, "irc.example", "alice", "bob", "#mizuchi");
    try std.testing.expectEqualStrings(":irc.example 341 alice bob #mizuchi", rpl);

    const invite = try buildTargetInviteLine(&buf, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "bob", "#mizuchi");
    try std.testing.expectEqualStrings(":alice!u@h INVITE bob :#mizuchi", invite);
}

test "error numeric builders format each required reply" {
    var buf: [160]u8 = undefined;

    const nosuchnick = try buildNoSuchNickNumeric(&buf, "irc.example", "alice", "bob");
    try std.testing.expectEqualStrings(":irc.example 401 alice bob :No such nick/channel", nosuchnick);

    const nosuchchannel = try buildNoSuchChannelNumeric(&buf, "irc.example", "alice", "#missing");
    try std.testing.expectEqualStrings(":irc.example 403 alice #missing :No such channel", nosuchchannel);

    const noton = try buildNotOnChannelNumeric(&buf, "irc.example", "alice", "#mizuchi");
    try std.testing.expectEqualStrings(":irc.example 442 alice #mizuchi :You're not on that channel", noton);

    const useron = try buildUserOnChannelNumeric(&buf, "irc.example", "alice", "bob", "#mizuchi");
    try std.testing.expectEqualStrings(":irc.example 443 alice bob #mizuchi :is already on channel", useron);

    const chanop = try buildChanOpPrivsNeededNumeric(&buf, "irc.example", "alice", "#mizuchi");
    try std.testing.expectEqualStrings(":irc.example 482 alice #mizuchi :You're not channel operator", chanop);
}

test "builders reject invalid fields and small buffers" {
    var buf: [160]u8 = undefined;
    var small: [8]u8 = undefined;

    try std.testing.expectError(error.InvalidServerName, buildInvitingNumeric(&buf, "bad server", "alice", "bob", "#mizuchi"));
    try std.testing.expectError(error.InvalidNick, buildInvitingNumeric(&buf, "irc.example", "bad\rnick", "bob", "#mizuchi"));
    try std.testing.expectError(error.InvalidChannel, buildInvitingNumeric(&buf, "irc.example", "alice", "bob", "#bad\nchannel"));
    try std.testing.expectError(error.InvalidUser, buildTargetInviteLine(&buf, .{
        .nick = "alice",
        .user = "bad:user",
        .host = "h",
    }, "bob", "#mizuchi"));
    try std.testing.expectError(error.InvalidHost, buildTargetInviteLine(&buf, .{
        .nick = "alice",
        .user = "u",
        .host = "bad\x00host",
    }, "bob", "#mizuchi"));

    try std.testing.expectError(error.OutputTooSmall, buildTargetInviteLine(&small, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "bob", "#mizuchi"));
    try std.testing.expectError(error.OutputTooSmall, buildUserOnChannelNumeric(&small, "irc.example", "alice", "bob", "#mizuchi"));
}

test "length limits reject oversized attacker-controlled fields" {
    try std.testing.expectError(error.NickTooLong, validateNickWith(.{ .max_nick_bytes = 3 }, "alice"));
    try std.testing.expectError(error.ChannelTooLong, validateChannelWith(.{ .max_channel_bytes = 3 }, "#chan"));
    try std.testing.expectError(error.UserTooLong, validateUserWith(.{ .max_user_bytes = 1 }, "user"));
    try std.testing.expectError(error.HostTooLong, validateHostWith(.{ .max_host_bytes = 3 }, "host.example"));
    try std.testing.expectError(error.ServerNameTooLong, validateServerNameWith(.{ .max_server_name_bytes = 3 }, "irc.example"));
}
