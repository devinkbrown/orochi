//! IRCv3 extended-monitor recipient selection.
//!
//! The MONITOR list itself is owned by `monitor.zig` and by the caller. This
//! module only validates the changed nick and selects monitoring clients that
//! should receive an already-built away-notify/account-notify/chghost/setname
//! style broadcast because they monitor the target and negotiated the required
//! capabilities.
const std = @import("std");
const limits_config = @import("limits_config.zig");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_VERB_BYTES: usize = 32;
pub const DEFAULT_MAX_PARAM_BYTES: usize = 512;

pub const ExtendedMonitorError = error{
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidVerb,
    VerbTooLong,
    InvalidParams,
    ParamsTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits for selectors, builders, and validators.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_verb_bytes: usize = DEFAULT_MAX_VERB_BYTES,
    max_param_bytes: usize = DEFAULT_MAX_PARAM_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_nick_bytes = limits.nick_len,
            .max_user_bytes = limits.user_len,
            .max_host_bytes = limits.host_len,
            .max_verb_bytes = limits.ext_monitor_verb_len,
            .max_param_bytes = limits.ext_monitor_param_len,
        };
    }
};

/// Identity used as the IRC message prefix: `:nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// One client watching the changed target.
///
/// `has_cap` is caller-computed for the concrete notification: it must mean the
/// client negotiated `extended-monitor` and the relevant event capability, such
/// as `away-notify`, `account-notify`, `chghost`, or `setname`.
pub const Watcher = struct {
    client: ClientId,
    monitors_target: bool = false,
    has_cap: bool = false,
};

/// One selected recipient for an extended-monitor notification.
pub const Recipient = struct {
    client: ClientId,
};

/// Caller-provided storage for selected extended-monitor recipients.
pub const Sink = struct {
    recipients: []Recipient,
    count: usize = 0,

    pub fn append(self: *Sink, client: ClientId) ExtendedMonitorError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client };
        self.count += 1;
    }

    pub fn slice(self: *const Sink) []const Recipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *Sink) void {
        self.count = 0;
    }
};

/// Select monitoring clients that should receive an extended-monitor broadcast.
pub fn selectRecipients(
    changed_target_nick: []const u8,
    watchers: []const Watcher,
    sink: *Sink,
) ExtendedMonitorError!void {
    return selectRecipientsWith(.{}, changed_target_nick, watchers, sink);
}

/// Select recipients using caller-selected compile-time limits.
pub fn selectRecipientsWith(
    comptime params: Params,
    changed_target_nick: []const u8,
    watchers: []const Watcher,
    sink: *Sink,
) ExtendedMonitorError!void {
    try validateNickWith(params, changed_target_nick);

    for (watchers) |watcher| {
        if (watcher.monitors_target and watcher.has_cap) {
            try sink.append(watcher.client);
        }
    }
}

/// Build `:nick!user@host VERB params` into caller-owned storage.
///
/// `params_text` is appended after one separating space when non-empty. Pass a
/// leading `:` in `params_text` when the caller needs an IRC trailing parameter.
pub fn buildNotificationLine(
    out: []u8,
    prefix: Prefix,
    verb: []const u8,
    params_text: []const u8,
) ExtendedMonitorError![]const u8 {
    return buildNotificationLineWith(.{}, out, prefix, verb, params_text);
}

/// Build a generic notification line using caller-selected compile-time limits.
pub fn buildNotificationLineWith(
    comptime params: Params,
    out: []u8,
    prefix: Prefix,
    verb: []const u8,
    params_text: []const u8,
) ExtendedMonitorError![]const u8 {
    try validatePrefix(params, prefix);
    try validateVerbWith(params, verb);
    try validateParamsTextWith(params, params_text);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try appendByte(out, &n, ' ');
    try append(out, &n, verb);
    if (params_text.len != 0) {
        try appendByte(out, &n, ' ');
        try append(out, &n, params_text);
    }
    return out[0..n];
}

pub fn validateNick(nick: []const u8) ExtendedMonitorError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) ExtendedMonitorError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) ExtendedMonitorError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) ExtendedMonitorError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) ExtendedMonitorError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) ExtendedMonitorError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateVerb(verb: []const u8) ExtendedMonitorError!void {
    return validateVerbWith(.{}, verb);
}

pub fn validateVerbWith(comptime params: Params, verb: []const u8) ExtendedMonitorError!void {
    if (verb.len == 0) return error.InvalidVerb;
    if (verb.len > params.max_verb_bytes) return error.VerbTooLong;
    for (verb) |ch| {
        if (!validVerbByte(ch)) return error.InvalidVerb;
    }
}

pub fn validateParamsText(params_text: []const u8) ExtendedMonitorError!void {
    return validateParamsTextWith(.{}, params_text);
}

pub fn validateParamsTextWith(
    comptime params: Params,
    params_text: []const u8,
) ExtendedMonitorError!void {
    if (params_text.len > params.max_param_bytes) return error.ParamsTooLong;
    for (params_text) |ch| {
        if (!validParamsByte(ch)) return error.InvalidParams;
    }
}

fn validatePrefix(comptime params: Params, prefix: Prefix) ExtendedMonitorError!void {
    try validateNickWith(params, prefix.nick);
    try validateUserWith(params, prefix.user);
    try validateHostWith(params, prefix.host);
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

fn validVerbByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        else => false,
    };
}

fn validParamsByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn append(out: []u8, n: *usize, bytes: []const u8) ExtendedMonitorError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) ExtendedMonitorError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectRecipient(recipient: Recipient, client: ClientId) !void {
    try std.testing.expectEqual(client, recipient.client);
}

test "extended-monitor selects only monitored targets with event cap" {
    const watchers = [_]Watcher{
        .{ .client = 1, .monitors_target = true, .has_cap = true },
        .{ .client = 2, .monitors_target = true, .has_cap = false },
        .{ .client = 3, .monitors_target = false, .has_cap = true },
        .{ .client = 4, .monitors_target = false, .has_cap = false },
        .{ .client = 5, .monitors_target = true, .has_cap = true },
    };

    var storage: [2]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try selectRecipients("alice", &watchers, &sink);

    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
    try expectRecipient(sink.slice()[1], 5);

    sink.reset();
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
}

test "extended-monitor rejects invalid changed target nick" {
    const watchers = [_]Watcher{
        .{ .client = 1, .monitors_target = true, .has_cap = true },
    };

    var storage: [1]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try std.testing.expectError(error.InvalidNick, selectRecipients("bad nick", &watchers, &sink));
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
    try std.testing.expectError(error.NickTooLong, selectRecipientsWith(.{ .max_nick_bytes = 3 }, "four", &watchers, &sink));
}

test "extended-monitor sink reports too many recipients" {
    const watchers = [_]Watcher{
        .{ .client = 1, .monitors_target = true, .has_cap = true },
        .{ .client = 2, .monitors_target = true, .has_cap = true },
    };

    var storage: [1]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try std.testing.expectError(error.TooManyRecipients, selectRecipients("alice", &watchers, &sink));
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
}

test "extended-monitor selects more than the old fixed daemon watcher buffer" {
    const count = 129;
    var watchers: [count]Watcher = undefined;
    for (&watchers, 0..) |*watcher, i| {
        watcher.* = .{ .client = @intCast(i + 1), .monitors_target = true, .has_cap = true };
    }
    var storage: [count]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };

    try selectRecipients("alice", &watchers, &sink);
    try std.testing.expectEqual(@as(usize, count), sink.slice().len);
    for (sink.slice(), 0..) |recipient, i| try expectRecipient(recipient, @intCast(i + 1));
}

test "generic notification builder emits passthrough line" {
    var buf: [128]u8 = undefined;
    const line = try buildNotificationLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "CHGHOST", "newuser new.example");

    try std.testing.expectEqualStrings(":alice!user@cloak.example CHGHOST newuser new.example", line);
}

test "generic notification builder allows trailing parameters and empty params" {
    var with_params: [128]u8 = undefined;
    const setname = try buildNotificationLine(&with_params, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "SETNAME", ":Alice Example");
    try std.testing.expectEqualStrings(":alice!user@cloak.example SETNAME :Alice Example", setname);

    var without_params: [128]u8 = undefined;
    const away = try buildNotificationLine(&without_params, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "AWAY", "");
    try std.testing.expectEqualStrings(":alice!user@cloak.example AWAY", away);
}

test "generic notification builder reports output too small" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildNotificationLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "ACCOUNT", "account"));
}

test "generic notification builder rejects invalid input" {
    var buf: [128]u8 = undefined;

    try std.testing.expectError(error.InvalidNick, buildNotificationLine(&buf, .{
        .nick = "bad nick",
        .user = "user",
        .host = "cloak.example",
    }, "ACCOUNT", "account"));
    try std.testing.expectError(error.InvalidUser, buildNotificationLine(&buf, .{
        .nick = "alice",
        .user = "bad user",
        .host = "cloak.example",
    }, "ACCOUNT", "account"));
    try std.testing.expectError(error.InvalidHost, buildNotificationLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "bad host",
    }, "ACCOUNT", "account"));
    try std.testing.expectError(error.InvalidVerb, buildNotificationLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "BAD VERB", "account"));
    try std.testing.expectError(error.InvalidParams, buildNotificationLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "ACCOUNT", "bad\raccount"));
    try std.testing.expectError(error.ParamsTooLong, buildNotificationLineWith(.{ .max_param_bytes = 4 }, &buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "ACCOUNT", "alice"));
}
