//! IRCv3 draft/channel-rename RENAME parsing and framing helpers.
//!
//! Channel state, authorization, conflict checks, and fallback PART/JOIN
//! emission are owned by the caller. This module validates attacker-controlled
//! parameters, builds allocation-free RENAME and FAIL messages into
//! caller-owned storage, and selects cap-gated recipients.
const std = @import("std");
const limits_config = @import("limits_config.zig");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_SOURCE_BYTES: usize = 512;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 200;
pub const DEFAULT_MAX_REASON_BYTES: usize = 512;
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 512;
pub const DEFAULT_CHANNEL_PREFIXES: []const u8 = "#+&!";

pub const RenameError = error{
    MissingOldChannel,
    MissingNewChannel,
    TooManyParameters,
    InvalidChannel,
    ChannelTooLong,
    NeedSameType,
    InvalidReason,
    ReasonTooLong,
    InvalidDescription,
    DescriptionTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidSource,
    SourceTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits and protocol-edge validation policy.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_source_bytes: usize = DEFAULT_MAX_SOURCE_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_reason_bytes: usize = DEFAULT_MAX_REASON_BYTES,
    max_description_bytes: usize = DEFAULT_MAX_DESCRIPTION_BYTES,
    channel_prefixes: []const u8 = DEFAULT_CHANNEL_PREFIXES,
    require_utf8: bool = true,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_channel_bytes` keeps its builder default. `channel_prefixes` aliases
    /// the config value, which must outlive any use of the returned `Params`.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_nick_bytes = limits.nick_len,
            .max_user_bytes = limits.user_len,
            .max_host_bytes = limits.host_len,
            .max_source_bytes = limits.source_len,
            .max_reason_bytes = limits.reason_len,
            .max_description_bytes = limits.realname_len,
            .channel_prefixes = limits.channel_prefixes.slice(),
        };
    }
};

/// Identity used as the IRC message prefix: `:nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Parsed RENAME command parameters.
pub const RenameArgs = struct {
    old_channel: []const u8,
    new_channel: []const u8,
    reason: []const u8 = "",
};

/// One visible client that may receive an IRCv3 channel-rename broadcast.
pub const Watcher = struct {
    client: ClientId,
    channel_rename: bool = false,
};

pub const RenameFallback = enum {
    none,
    part_join,
};

pub const RenameAction = enum {
    rename,
    part_join,
};

/// One selected RENAME recipient and how the daemon should represent it.
pub const RenameRecipient = struct {
    client: ClientId,
    action: RenameAction,
};

/// Caller-provided storage for selected RENAME recipients.
pub const RenameRecipientSink = struct {
    recipients: []RenameRecipient,
    count: usize = 0,

    pub fn append(self: *RenameRecipientSink, client: ClientId, action: RenameAction) RenameError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client, .action = action };
        self.count += 1;
    }

    pub fn slice(self: *const RenameRecipientSink) []const RenameRecipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *RenameRecipientSink) void {
        self.count = 0;
    }
};

/// Standard-reply FAIL codes used by draft/channel-rename.
pub const FailCode = enum {
    CHANNEL_NAME_IN_USE,
    CANNOT_RENAME,
    NEED_SAME_TYPE,
    NEED_MORE_PARAMS,
    INVALID_PARAMS,

    pub fn token(self: FailCode) []const u8 {
        return @tagName(self);
    }
};

/// Parse `RENAME <oldchannel> <newchannel> [:reason]` parameters.
///
/// `params` must be the command parameter slice after IRC line parsing. The
/// optional trailing reason should be supplied as the third parameter without
/// the leading `:`.
pub fn parseRenameArgs(params: []const []const u8) RenameError!RenameArgs {
    return parseRenameArgsWith(.{}, params);
}

/// Parse RENAME parameters with caller-selected compile-time limits.
pub fn parseRenameArgsWith(comptime params_config: Params, params: []const []const u8) RenameError!RenameArgs {
    if (params.len == 0) return error.MissingOldChannel;
    if (params.len == 1) return error.MissingNewChannel;
    if (params.len > 3) return error.TooManyParameters;

    const reason = if (params.len == 3) params[2] else "";
    try validateChannelRenameWith(params_config, params[0], params[1]);
    try validateReasonWith(params_config, reason);

    return .{
        .old_channel = params[0],
        .new_channel = params[1],
        .reason = reason,
    };
}

/// Validate one channel name with the default channel policy.
pub fn validateChannelName(channel: []const u8) RenameError!void {
    return validateChannelNameWith(.{}, channel);
}

/// Validate one channel name with caller-selected compile-time limits.
pub fn validateChannelNameWith(comptime params: Params, channel: []const u8) RenameError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefix(params, channel[0])) return error.InvalidChannel;

    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(channel)) return error.InvalidChannel;
}

/// Validate that both RENAME names are valid channels with the same type prefix.
pub fn validateChannelRename(old_channel: []const u8, new_channel: []const u8) RenameError!void {
    return validateChannelRenameWith(.{}, old_channel, new_channel);
}

/// Validate a channel rename pair with caller-selected compile-time limits.
pub fn validateChannelRenameWith(
    comptime params: Params,
    old_channel: []const u8,
    new_channel: []const u8,
) RenameError!void {
    try validateChannelNameWith(params, old_channel);
    try validateChannelNameWith(params, new_channel);
    if (old_channel[0] != new_channel[0]) return error.NeedSameType;
}

/// Build `:nick!user@host RENAME <oldchannel> <newchannel> :<reason>`.
pub fn buildRenameBroadcast(
    out: []u8,
    prefix: Prefix,
    old_channel: []const u8,
    new_channel: []const u8,
    reason: []const u8,
) RenameError![]const u8 {
    return buildRenameBroadcastWith(.{}, out, prefix, old_channel, new_channel, reason);
}

/// Build a RENAME broadcast using caller-selected compile-time limits.
pub fn buildRenameBroadcastWith(
    comptime params: Params,
    out: []u8,
    prefix: Prefix,
    old_channel: []const u8,
    new_channel: []const u8,
    reason: []const u8,
) RenameError![]const u8 {
    try validatePrefix(params, prefix);
    try validateChannelRenameWith(params, old_channel, new_channel);
    try validateReasonWith(params, reason);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try append(out, &n, " RENAME ");
    try append(out, &n, old_channel);
    try appendByte(out, &n, ' ');
    try append(out, &n, new_channel);
    try append(out, &n, " :");
    try append(out, &n, reason);
    return out[0..n];
}

/// Build `:source RENAME <oldchannel> <newchannel> :<reason>`.
pub fn buildRenameBroadcastFromSource(
    out: []u8,
    source: []const u8,
    old_channel: []const u8,
    new_channel: []const u8,
    reason: []const u8,
) RenameError![]const u8 {
    return buildRenameBroadcastFromSourceWith(.{}, out, source, old_channel, new_channel, reason);
}

/// Build a source-prefixed RENAME broadcast with caller-selected limits.
pub fn buildRenameBroadcastFromSourceWith(
    comptime params: Params,
    out: []u8,
    source: []const u8,
    old_channel: []const u8,
    new_channel: []const u8,
    reason: []const u8,
) RenameError![]const u8 {
    try validateSourceWith(params, source);
    try validateChannelRenameWith(params, old_channel, new_channel);
    try validateReasonWith(params, reason);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, source);
    try append(out, &n, " RENAME ");
    try append(out, &n, old_channel);
    try appendByte(out, &n, ' ');
    try append(out, &n, new_channel);
    try append(out, &n, " :");
    try append(out, &n, reason);
    return out[0..n];
}

/// Build `FAIL RENAME <code> <oldchannel> <newchannel> :<description>`.
pub fn buildFailLine(
    out: []u8,
    code: FailCode,
    old_channel: []const u8,
    new_channel: []const u8,
    description: []const u8,
) RenameError![]const u8 {
    return buildFailLineWith(.{}, out, code, old_channel, new_channel, description);
}

/// Build a RENAME FAIL line with caller-selected compile-time limits.
pub fn buildFailLineWith(
    comptime params: Params,
    out: []u8,
    code: FailCode,
    old_channel: []const u8,
    new_channel: []const u8,
    description: []const u8,
) RenameError![]const u8 {
    try validateChannelNameWith(params, old_channel);
    try validateChannelNameWith(params, new_channel);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try append(out, &n, "FAIL RENAME ");
    try append(out, &n, code.token());
    try appendByte(out, &n, ' ');
    try append(out, &n, old_channel);
    try appendByte(out, &n, ' ');
    try append(out, &n, new_channel);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

/// Build a CHANNEL_NAME_IN_USE RENAME failure.
pub fn buildChannelNameInUseFail(out: []u8, old_channel: []const u8, new_channel: []const u8) RenameError![]const u8 {
    return buildFailLine(out, .CHANNEL_NAME_IN_USE, old_channel, new_channel, "Channel name is already in use");
}

/// Build a CANNOT_RENAME RENAME failure.
pub fn buildCannotRenameFail(out: []u8, old_channel: []const u8, new_channel: []const u8) RenameError![]const u8 {
    return buildFailLine(out, .CANNOT_RENAME, old_channel, new_channel, "Channel cannot be renamed");
}

/// Build a NEED_SAME_TYPE RENAME failure.
pub fn buildNeedSameTypeFail(out: []u8, old_channel: []const u8, new_channel: []const u8) RenameError![]const u8 {
    return buildFailLine(out, .NEED_SAME_TYPE, old_channel, new_channel, "Channel names must use the same type prefix");
}

/// Select visible clients for a channel rename broadcast.
///
/// Clients with `channel_rename` receive the native IRCv3 RENAME message.
/// Clients without it receive the caller-selected fallback action or are
/// omitted. The caller remains responsible for case-mapping decisions where a
/// fallback PART/JOIN would be redundant.
pub fn selectRenameRecipients(
    watchers: []const Watcher,
    fallback: RenameFallback,
    sink: *RenameRecipientSink,
) RenameError!void {
    for (watchers) |watcher| {
        if (watcher.channel_rename) {
            try sink.append(watcher.client, .rename);
        } else if (fallback == .part_join) {
            try sink.append(watcher.client, .part_join);
        }
    }
}

pub fn validateReason(reason: []const u8) RenameError!void {
    return validateReasonWith(.{}, reason);
}

pub fn validateReasonWith(comptime params: Params, reason: []const u8) RenameError!void {
    if (reason.len > params.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |ch| {
        if (!validTextByte(ch)) return error.InvalidReason;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(reason)) return error.InvalidReason;
}

pub fn validateSource(source: []const u8) RenameError!void {
    return validateSourceWith(.{}, source);
}

pub fn validateSourceWith(comptime params: Params, source: []const u8) RenameError!void {
    if (source.len == 0) return error.InvalidSource;
    if (source.len > params.max_source_bytes) return error.SourceTooLong;
    for (source) |ch| {
        if (!validSourceByte(ch)) return error.InvalidSource;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(source)) return error.InvalidSource;
}

fn validateDescriptionWith(comptime params: Params, description: []const u8) RenameError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (description.len > params.max_description_bytes) return error.DescriptionTooLong;
    for (description) |ch| {
        if (!validTextByte(ch)) return error.InvalidDescription;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(description)) return error.InvalidDescription;
}

fn validatePrefix(comptime params: Params, prefix: Prefix) RenameError!void {
    try validateNickWith(params, prefix.nick);
    try validateUserWith(params, prefix.user);
    try validateHostWith(params, prefix.host);
}

fn validateNickWith(comptime params: Params, nick: []const u8) RenameError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

fn validateUserWith(comptime params: Params, user: []const u8) RenameError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(user)) return error.InvalidUser;
}

fn validateHostWith(comptime params: Params, host: []const u8) RenameError!void {
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

fn validSourceByte(ch: u8) bool {
    return ch > 0x20 and ch != 0x7f and ch != ':';
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

fn append(out: []u8, n: *usize, bytes: []const u8) RenameError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) RenameError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectRenameRecipient(recipient: RenameRecipient, client: ClientId, action: RenameAction) !void {
    try std.testing.expectEqual(client, recipient.client);
    try std.testing.expectEqual(action, recipient.action);
}

test "parse rename args with optional reason" {
    const with_reason = [_][]const u8{ "#old", "#new", "moving the room" };
    const parsed = try parseRenameArgs(&with_reason);
    try std.testing.expectEqualStrings("#old", parsed.old_channel);
    try std.testing.expectEqualStrings("#new", parsed.new_channel);
    try std.testing.expectEqualStrings("moving the room", parsed.reason);

    const without_reason = [_][]const u8{ "#old", "#new" };
    const parsed_without = try parseRenameArgs(&without_reason);
    try std.testing.expectEqualStrings("", parsed_without.reason);
}

test "rename broadcast build" {
    var buf: [160]u8 = undefined;
    const line = try buildRenameBroadcast(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "#old", "#new", "moving");

    try std.testing.expectEqualStrings(":alice!user@cloak.example RENAME #old #new :moving", line);
}

test "source rename broadcast build keeps empty reason parameter" {
    var buf: [128]u8 = undefined;
    const line = try buildRenameBroadcastFromSource(&buf, "irc.example", "#old", "#new", "");
    try std.testing.expectEqualStrings(":irc.example RENAME #old #new :", line);
}

test "fail line builders" {
    var buf: [160]u8 = undefined;
    const in_use = try buildChannelNameInUseFail(&buf, "#old", "#new");
    try std.testing.expectEqualStrings("FAIL RENAME CHANNEL_NAME_IN_USE #old #new :Channel name is already in use", in_use);

    const same_type = try buildNeedSameTypeFail(&buf, "#old", "+new");
    try std.testing.expectEqualStrings("FAIL RENAME NEED_SAME_TYPE #old +new :Channel names must use the same type prefix", same_type);
}

test "cap-gated recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .channel_rename = true },
        .{ .client = 2, .channel_rename = false },
        .{ .client = 3, .channel_rename = true },
    };

    var storage: [3]RenameRecipient = undefined;
    var sink = RenameRecipientSink{ .recipients = &storage };
    try selectRenameRecipients(&watchers, .none, &sink);
    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try expectRenameRecipient(sink.slice()[0], 1, .rename);
    try expectRenameRecipient(sink.slice()[1], 3, .rename);

    sink.reset();
    try selectRenameRecipients(&watchers, .part_join, &sink);
    try std.testing.expectEqual(@as(usize, 3), sink.slice().len);
    try expectRenameRecipient(sink.slice()[0], 1, .rename);
    try expectRenameRecipient(sink.slice()[1], 2, .part_join);
    try expectRenameRecipient(sink.slice()[2], 3, .rename);
}

test "recipient sink reports capacity errors" {
    const watchers = [_]Watcher{
        .{ .client = 1, .channel_rename = true },
        .{ .client = 2, .channel_rename = true },
    };
    var storage: [1]RenameRecipient = undefined;
    var sink = RenameRecipientSink{ .recipients = &storage };
    try std.testing.expectError(error.TooManyRecipients, selectRenameRecipients(&watchers, .none, &sink));
}

test "buffer too small reported by broadcast and fail builders" {
    var small: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildRenameBroadcast(&small, .{
        .nick = "alice",
        .user = "user",
        .host = "host",
    }, "#old", "#new", "moving"));
    try std.testing.expectError(error.OutputTooSmall, buildChannelNameInUseFail(&small, "#old", "#new"));
}

test "invalid rename parameters rejected" {
    const missing_old = [_][]const u8{};
    try std.testing.expectError(error.MissingOldChannel, parseRenameArgs(&missing_old));

    const missing_new = [_][]const u8{"#old"};
    try std.testing.expectError(error.MissingNewChannel, parseRenameArgs(&missing_new));

    const too_many = [_][]const u8{ "#old", "#new", "reason", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseRenameArgs(&too_many));

    const different_types = [_][]const u8{ "#old", "+new" };
    try std.testing.expectError(error.NeedSameType, parseRenameArgs(&different_types));

    const bad_channel = [_][]const u8{ "#bad channel", "#new" };
    try std.testing.expectError(error.InvalidChannel, parseRenameArgs(&bad_channel));

    const bad_reason = [_][]const u8{ "#old", "#new", "bad\rreason" };
    try std.testing.expectError(error.InvalidReason, parseRenameArgs(&bad_reason));
}

test "validator covers bytes and configurable channel policy" {
    try validateChannelName("#caf\xc3\xa9");
    try std.testing.expectError(error.InvalidChannel, validateChannelName("#bad\xff"));
    try std.testing.expectError(error.InvalidChannel, validateChannelName("#bad:name"));
    try std.testing.expectError(error.InvalidChannel, validateChannelName("bad"));

    try validateChannelNameWith(.{ .channel_prefixes = "#" }, "#ok");
    try std.testing.expectError(error.InvalidChannel, validateChannelNameWith(.{ .channel_prefixes = "#" }, "+nope"));
    try validateChannelNameWith(.{ .require_utf8 = false }, "#raw\xff");
}

test "source and prefix validation reject injection bytes" {
    var buf: [160]u8 = undefined;
    try std.testing.expectError(error.InvalidNick, buildRenameBroadcast(&buf, .{
        .nick = "bad nick",
        .user = "user",
        .host = "host",
    }, "#old", "#new", "moving"));
    try std.testing.expectError(error.InvalidSource, buildRenameBroadcastFromSource(&buf, "irc.example\rbad", "#old", "#new", "moving"));
    try std.testing.expectError(error.InvalidDescription, buildFailLine(&buf, .CANNOT_RENAME, "#old", "#new", "bad\ndescription"));
}
