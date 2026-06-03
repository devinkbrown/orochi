//! IRCX CREATE command parsing and initial reply helpers.
//!
//! `CREATE <channel> [<modes>]` explicitly creates a new IRCX channel. Channel
//! existence, policy checks, state mutation, and mode application are owned by
//! the caller. This module validates attacker-controlled command parameters,
//! returns borrowed parse slices, describes Mizuchi's initial founder status,
//! and builds the JOIN/NAMES wire lines into caller-owned buffers.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 200;
pub const DEFAULT_MAX_MODE_BYTES: usize = 64;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 256;
pub const DEFAULT_CHANNEL_PREFIXES: []const u8 = "#+&!";

pub const IrcxCreateError = error{
    MissingChannel,
    TooManyParameters,
    InvalidChannel,
    ChannelTooLong,
    InvalidModes,
    ModesTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidServerName,
    ServerNameTooLong,
    InvalidText,
    TextTooLong,
    OutputTooSmall,
};

/// Compile-time limits and protocol-edge validation policy.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_server_name_bytes: usize = DEFAULT_MAX_SERVER_NAME_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_mode_bytes: usize = DEFAULT_MAX_MODE_BYTES,
    max_text_bytes: usize = DEFAULT_MAX_TEXT_BYTES,
    channel_prefixes: []const u8 = DEFAULT_CHANNEL_PREFIXES,
    require_utf8: bool = true,
};

/// Identity used as the IRC message prefix: `nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Parsed `CREATE <channel> [<modes>]` parameters.
pub const CreateArgs = struct {
    channel: []const u8,
    modes: ?[]const u8 = null,
};

/// Mizuchi's ordered IRCX member tiers.
pub const MemberTier = enum(u8) {
    voice = 1,
    op = 2,
    owner = 3,
    founder = 4,

    pub fn mode(self: MemberTier) u8 {
        return switch (self) {
            .voice => 'v',
            .op => 'o',
            .owner => 'q',
            .founder => 'Q',
        };
    }

    pub fn prefix(self: MemberTier) u8 {
        return switch (self) {
            .voice => '+',
            .op => '@',
            .owner => '.',
            .founder => '~',
        };
    }
};

/// Caller-visible result for the creator's initial channel membership.
pub const CreateResult = struct {
    channel: []const u8,
    requested_modes: ?[]const u8 = null,
    creator_status: MemberTier = .founder,
};

/// Parse CREATE parameters after IRC line tokenization.
pub fn parseCreateArgs(params: []const []const u8) IrcxCreateError!CreateArgs {
    return parseCreateArgsWith(.{}, params);
}

/// Parse CREATE parameters with caller-selected compile-time limits.
pub fn parseCreateArgsWith(comptime params_config: Params, params: []const []const u8) IrcxCreateError!CreateArgs {
    if (params.len == 0) return error.MissingChannel;
    if (params.len > 2) return error.TooManyParameters;

    const modes = if (params.len == 2) params[1] else null;
    try validateChannelWith(params_config, params[0]);
    if (modes) |mode_text| try validateModesWith(params_config, mode_text);

    return .{
        .channel = params[0],
        .modes = modes,
    };
}

/// Parse CREATE and attach Mizuchi's initial founder status.
pub fn parseCreate(params: []const []const u8) IrcxCreateError!CreateResult {
    return parseCreateWith(.{}, params);
}

/// Parse CREATE with caller-selected limits and attach initial founder status.
pub fn parseCreateWith(comptime params_config: Params, params: []const []const u8) IrcxCreateError!CreateResult {
    const args = try parseCreateArgsWith(params_config, params);
    return .{
        .channel = args.channel,
        .requested_modes = args.modes,
        .creator_status = .founder,
    };
}

/// Validate one IRC channel name accepted by CREATE.
pub fn validateChannel(channel: []const u8) IrcxCreateError!void {
    return validateChannelWith(.{}, channel);
}

/// Validate one IRC channel name with caller-selected limits.
pub fn validateChannelWith(comptime params: Params, channel: []const u8) IrcxCreateError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefix(params, channel[0])) return error.InvalidChannel;
    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(channel)) return error.InvalidChannel;
}

/// Validate the optional raw mode string from `CREATE <channel> <modes>`.
pub fn validateModes(modes: []const u8) IrcxCreateError!void {
    return validateModesWith(.{}, modes);
}

/// Validate a mode string with caller-selected limits.
pub fn validateModesWith(comptime params: Params, modes: []const u8) IrcxCreateError!void {
    if (modes.len == 0) return error.InvalidModes;
    if (modes.len > params.max_mode_bytes) return error.ModesTooLong;
    for (modes) |ch| {
        if (!validModeByte(ch)) return error.InvalidModes;
    }
}

/// Build `:nick!user@host JOIN <channel>` for the CREATE broadcast.
pub fn buildJoinBroadcast(
    out: []u8,
    creator: Prefix,
    channel: []const u8,
) IrcxCreateError![]const u8 {
    return buildJoinBroadcastWith(.{}, out, creator, channel);
}

/// Build the CREATE JOIN broadcast using caller-selected limits.
pub fn buildJoinBroadcastWith(
    comptime params: Params,
    out: []u8,
    creator: Prefix,
    channel: []const u8,
) IrcxCreateError![]const u8 {
    try validatePrefix(params, creator);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try appendPrefix(out, &n, creator);
    try append(out, &n, " JOIN ");
    try append(out, &n, channel);
    return out[0..n];
}

/// Build initial `RPL_NAMREPLY` for the creator: `~<nick>`.
pub fn buildFounderNamesReply(
    out: []u8,
    server_name: []const u8,
    creator_nick: []const u8,
    channel: []const u8,
) IrcxCreateError![]const u8 {
    return buildFounderNamesReplyWith(.{}, out, server_name, creator_nick, channel);
}

/// Build initial `RPL_NAMREPLY` using caller-selected limits.
pub fn buildFounderNamesReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    creator_nick: []const u8,
    channel: []const u8,
) IrcxCreateError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, creator_nick);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, .RPL_NAMREPLY, creator_nick);
    try append(out, &n, " = ");
    try append(out, &n, channel);
    try append(out, &n, " :");
    try appendByte(out, &n, MemberTier.founder.prefix());
    try append(out, &n, creator_nick);
    return out[0..n];
}

/// Build `RPL_ENDOFNAMES` after the initial CREATE NAMES reply.
pub fn buildEndOfNamesReply(
    out: []u8,
    server_name: []const u8,
    creator_nick: []const u8,
    channel: []const u8,
) IrcxCreateError![]const u8 {
    return buildEndOfNamesReplyWith(.{}, out, server_name, creator_nick, channel, "End of /NAMES list");
}

/// Build `RPL_ENDOFNAMES` with caller-selected limits and text.
pub fn buildEndOfNamesReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    creator_nick: []const u8,
    channel: []const u8,
    text: []const u8,
) IrcxCreateError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, creator_nick);
    try validateChannelWith(params, channel);
    try validateTextWith(params, text);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, .RPL_ENDOFNAMES, creator_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :");
    try append(out, &n, text);
    return out[0..n];
}

/// Build `ERR_NEEDMOREPARAMS` for malformed CREATE input.
pub fn buildNeedMoreParamsReply(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
) IrcxCreateError![]const u8 {
    return buildNeedMoreParamsReplyWith(.{}, out, server_name, recipient_nick);
}

/// Build `ERR_NEEDMOREPARAMS` using caller-selected limits.
pub fn buildNeedMoreParamsReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
) IrcxCreateError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, .ERR_NEEDMOREPARAMS, recipient_nick);
    try append(out, &n, " CREATE :Not enough parameters");
    return out[0..n];
}

/// Build `ERR_BADCHANNAME` for invalid CREATE channel names.
pub fn buildBadChannelNameReply(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) IrcxCreateError![]const u8 {
    return buildBadChannelNameReplyWith(.{}, out, server_name, recipient_nick, channel);
}

/// Build `ERR_BADCHANNAME` using caller-selected limits.
pub fn buildBadChannelNameReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
) IrcxCreateError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);
    try validateTextWith(params, channel);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, .ERR_BADCHANNAME, recipient_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :Invalid channel name");
    return out[0..n];
}

pub fn validateNick(nick: []const u8) IrcxCreateError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) IrcxCreateError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) IrcxCreateError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) IrcxCreateError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(user)) return error.InvalidUser;
}

pub fn validateHost(host: []const u8) IrcxCreateError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) IrcxCreateError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(host)) return error.InvalidHost;
}

pub fn validateServerName(server_name: []const u8) IrcxCreateError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) IrcxCreateError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

fn validateTextWith(comptime params: Params, text: []const u8) IrcxCreateError!void {
    if (text.len == 0) return error.InvalidText;
    if (text.len > params.max_text_bytes) return error.TextTooLong;
    for (text) |ch| {
        if (!validTextByte(ch)) return error.InvalidText;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(text)) return error.InvalidText;
}

fn validatePrefix(comptime params: Params, prefix: Prefix) IrcxCreateError!void {
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

fn validModeByte(ch: u8) bool {
    return switch (ch) {
        '+', '-' => true,
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        else => false,
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

fn appendPrefix(out: []u8, n: *usize, prefix: Prefix) IrcxCreateError!void {
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
) IrcxCreateError!void {
    var code_buf: [3]u8 = undefined;
    try appendByte(out, n, ':');
    try append(out, n, server_name);
    try appendByte(out, n, ' ');
    try append(out, n, numeric.formatCode(code, &code_buf));
    try appendByte(out, n, ' ');
    try append(out, n, recipient_nick);
}

fn append(out: []u8, n: *usize, bytes: []const u8) IrcxCreateError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) IrcxCreateError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

test "parse create args without modes" {
    const raw = [_][]const u8{"#mizuchi"};
    const parsed = try parseCreateArgs(&raw);
    try std.testing.expectEqualStrings("#mizuchi", parsed.channel);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.modes);

    const result = try parseCreate(&raw);
    try std.testing.expectEqual(.founder, result.creator_status);
    try std.testing.expectEqual(@as(u8, 'Q'), result.creator_status.mode());
    try std.testing.expectEqual(@as(u8, '~'), result.creator_status.prefix());
}

test "parse create args with modes" {
    const raw = [_][]const u8{ "#mizuchi", "+nt" };
    const parsed = try parseCreateArgs(&raw);
    try std.testing.expectEqualStrings("#mizuchi", parsed.channel);
    try std.testing.expect(parsed.modes != null);
    try std.testing.expectEqualStrings("+nt", parsed.modes.?);

    const result = try parseCreate(&raw);
    try std.testing.expectEqualStrings("+nt", result.requested_modes.?);
    try std.testing.expectEqual(.founder, result.creator_status);
}

test "invalid create channel is rejected" {
    const missing = [_][]const u8{};
    try std.testing.expectError(error.MissingChannel, parseCreateArgs(&missing));

    const too_many = [_][]const u8{ "#mizuchi", "+nt", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseCreateArgs(&too_many));

    const no_prefix = [_][]const u8{"mizuchi"};
    try std.testing.expectError(error.InvalidChannel, parseCreateArgs(&no_prefix));

    const bad_space = [_][]const u8{"#bad channel"};
    try std.testing.expectError(error.InvalidChannel, parseCreateArgs(&bad_space));

    const bad_colon = [_][]const u8{"#bad:channel"};
    try std.testing.expectError(error.InvalidChannel, parseCreateArgs(&bad_colon));
}

test "invalid create modes are rejected" {
    const empty_modes = [_][]const u8{ "#mizuchi", "" };
    try std.testing.expectError(error.InvalidModes, parseCreateArgs(&empty_modes));

    const bad_modes = [_][]const u8{ "#mizuchi", "+n t" };
    try std.testing.expectError(error.InvalidModes, parseCreateArgs(&bad_modes));

    try std.testing.expectError(error.ModesTooLong, validateModesWith(.{ .max_mode_bytes = 3 }, "+ntk"));
}

test "create line builders format join and initial names replies" {
    var buf: [180]u8 = undefined;
    const creator = Prefix{ .nick = "alice", .user = "u", .host = "cloak.example" };

    const join = try buildJoinBroadcast(&buf, creator, "#mizuchi");
    try std.testing.expectEqualStrings(":alice!u@cloak.example JOIN #mizuchi", join);

    const names = try buildFounderNamesReply(&buf, "irc.example", "alice", "#mizuchi");
    try std.testing.expectEqualStrings(":irc.example 353 alice = #mizuchi :~alice", names);

    const end = try buildEndOfNamesReply(&buf, "irc.example", "alice", "#mizuchi");
    try std.testing.expectEqualStrings(":irc.example 366 alice #mizuchi :End of /NAMES list", end);
}

test "create error builders format numerics" {
    var buf: [180]u8 = undefined;

    const need_more = try buildNeedMoreParamsReply(&buf, "irc.example", "alice");
    try std.testing.expectEqualStrings(":irc.example 461 alice CREATE :Not enough parameters", need_more);

    const bad_chan = try buildBadChannelNameReply(&buf, "irc.example", "alice", "#bad channel");
    try std.testing.expectEqualStrings(":irc.example 479 alice #bad channel :Invalid channel name", bad_chan);
}

test "builders reject invalid fields and small buffers" {
    var buf: [180]u8 = undefined;
    var small: [8]u8 = undefined;

    try std.testing.expectError(error.InvalidNick, buildJoinBroadcast(&buf, .{
        .nick = "bad nick",
        .user = "u",
        .host = "h",
    }, "#mizuchi"));

    try std.testing.expectError(error.InvalidUser, buildJoinBroadcast(&buf, .{
        .nick = "alice",
        .user = "bad:user",
        .host = "h",
    }, "#mizuchi"));

    try std.testing.expectError(error.InvalidHost, buildJoinBroadcast(&buf, .{
        .nick = "alice",
        .user = "u",
        .host = "bad\x00host",
    }, "#mizuchi"));

    try std.testing.expectError(error.InvalidServerName, buildFounderNamesReply(&buf, "bad server", "alice", "#mizuchi"));
    try std.testing.expectError(error.OutputTooSmall, buildJoinBroadcast(&small, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#mizuchi"));
}
