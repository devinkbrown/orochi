// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 invite-notify broadcast helpers.
//!
//! Channel membership, invite authorization, and channel privilege computation
//! are owned by the caller. This module validates attacker-controlled IRC
//! fields, builds canonical INVITE notification and RPL_INVITING lines into
//! caller-provided storage, and selects only watchers that negotiated
//! `invite-notify` and were marked privileged by the caller.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 64;

pub const InviteNotifyError = error{
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidServerName,
    ServerNameTooLong,
    InvalidChannel,
    ChannelTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits for builders and validators.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_server_name_bytes: usize = DEFAULT_MAX_SERVER_NAME_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
};

/// Identity used as the IRC message prefix: `:nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// One channel member that may receive an IRCv3 invite-notify broadcast.
pub const Watcher = struct {
    client: ClientId,
    invite_notify: bool = false,
    privileged: bool = false,
};

/// One selected invite-notify recipient.
pub const Recipient = struct {
    client: ClientId,
};

/// Caller-provided storage for selected invite-notify recipients.
pub const Sink = struct {
    recipients: []Recipient,
    count: usize = 0,

    pub fn append(self: *Sink, client: ClientId) InviteNotifyError!void {
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

/// Build `:nick!user@host INVITE invitee #channel` into caller-owned storage.
pub fn buildInviteNotifyLine(
    out: []u8,
    inviter: Prefix,
    invitee_nick: []const u8,
    channel: []const u8,
) InviteNotifyError![]const u8 {
    return buildInviteNotifyLineWith(.{}, out, inviter, invitee_nick, channel);
}

/// Build an invite-notify line using caller-selected compile-time limits.
pub fn buildInviteNotifyLineWith(
    comptime params: Params,
    out: []u8,
    inviter: Prefix,
    invitee_nick: []const u8,
    channel: []const u8,
) InviteNotifyError![]const u8 {
    try validatePrefix(params, inviter);
    try validateNickWith(params, invitee_nick);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, inviter.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, inviter.user);
    try appendByte(out, &n, '@');
    try append(out, &n, inviter.host);
    try append(out, &n, " INVITE ");
    try append(out, &n, invitee_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    return out[0..n];
}

/// Build `:server 341 inviter invitee #channel` into caller-owned storage.
pub fn buildInvitingNumeric(
    out: []u8,
    server_name: []const u8,
    inviter_nick: []const u8,
    invitee_nick: []const u8,
    channel: []const u8,
) InviteNotifyError![]const u8 {
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
) InviteNotifyError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, inviter_nick);
    try validateNickWith(params, invitee_nick);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, server_name);
    try appendByte(out, &n, ' ');

    var code_buf: [3]u8 = undefined;
    try append(out, &n, numeric.formatCode(.RPL_INVITING, &code_buf));
    try appendByte(out, &n, ' ');
    try append(out, &n, inviter_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, invitee_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    return out[0..n];
}

/// Select channel members that negotiated invite-notify and have sufficient privilege.
pub fn selectRecipients(
    watchers: []const Watcher,
    sink: *Sink,
) InviteNotifyError!void {
    for (watchers) |watcher| {
        if (watcher.invite_notify and watcher.privileged) {
            try sink.append(watcher.client);
        }
    }
}

pub fn validateNick(nick: []const u8) InviteNotifyError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) InviteNotifyError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) InviteNotifyError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) InviteNotifyError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) InviteNotifyError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) InviteNotifyError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateServerName(server_name: []const u8) InviteNotifyError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) InviteNotifyError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateChannel(channel: []const u8) InviteNotifyError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) InviteNotifyError!void {
    if (channel.len == 0) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefix(channel[0])) return error.InvalidChannel;

    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
}

fn validatePrefix(comptime params: Params, prefix: Prefix) InviteNotifyError!void {
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

fn validChannelPrefix(ch: u8) bool {
    return switch (ch) {
        '#', '&', '+', '!', '%' => true,
        else => false,
    };
}

fn validChannelByte(ch: u8) bool {
    if (ch <= 0x1f or ch == 0x7f) return false;
    return switch (ch) {
        ' ', ',', 7 => false,
        else => true,
    };
}

fn append(out: []u8, n: *usize, bytes: []const u8) InviteNotifyError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) InviteNotifyError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectRecipient(recipient: Recipient, client: ClientId) !void {
    try std.testing.expectEqual(client, recipient.client);
}

test "invite-notify line build" {
    var buf: [128]u8 = undefined;
    const line = try buildInviteNotifyLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "bob", "#onyx");

    try std.testing.expectEqualStrings(":alice!user@cloak.example INVITE bob #onyx", line);
}

test "rpl inviting numeric build" {
    var buf: [128]u8 = undefined;
    const line = try buildInvitingNumeric(&buf, "irc.example", "alice", "bob", "#onyx");

    try std.testing.expectEqualStrings(":irc.example 341 alice bob #onyx", line);
}

test "cap and privilege gated recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .invite_notify = true, .privileged = true },
        .{ .client = 2, .invite_notify = true, .privileged = false },
        .{ .client = 3, .invite_notify = false, .privileged = true },
        .{ .client = 4, .invite_notify = false, .privileged = false },
    };

    var storage: [4]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try selectRecipients(&watchers, &sink);

    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);

    sink.reset();
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
}

test "recipient sink reports overflow" {
    const watchers = [_]Watcher{
        .{ .client = 1, .invite_notify = true, .privileged = true },
        .{ .client = 2, .invite_notify = true, .privileged = true },
    };

    var storage: [1]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };

    try std.testing.expectError(error.TooManyRecipients, selectRecipients(&watchers, &sink));
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
}

test "builders report output too small" {
    var small: [8]u8 = undefined;
    const prefix = Prefix{ .nick = "alice", .user = "user", .host = "cloak.example" };

    try std.testing.expectError(
        error.OutputTooSmall,
        buildInviteNotifyLine(&small, prefix, "bob", "#onyx"),
    );
    try std.testing.expectError(
        error.OutputTooSmall,
        buildInvitingNumeric(&small, "irc.example", "alice", "bob", "#onyx"),
    );
}

test "invalid attacker-controlled fields rejected" {
    var buf: [128]u8 = undefined;

    try std.testing.expectError(error.InvalidNick, validateNick("bad nick"));
    try std.testing.expectError(error.NickTooLong, validateNickWith(.{ .max_nick_bytes = 3 }, "alice"));
    try std.testing.expectError(error.InvalidUser, validateUser("bad:user"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad host.example"));
    try std.testing.expectError(error.InvalidChannel, validateChannel("onyx"));
    try std.testing.expectError(error.InvalidChannel, validateChannel("#bad,channel"));
    try std.testing.expectError(error.ChannelTooLong, validateChannelWith(.{ .max_channel_bytes = 3 }, "#chan"));
    try std.testing.expectError(error.InvalidServerName, validateServerName("irc example"));

    try std.testing.expectError(error.InvalidUser, buildInviteNotifyLine(&buf, .{
        .nick = "alice",
        .user = "bad user",
        .host = "cloak.example",
    }, "bob", "#onyx"));
    try std.testing.expectError(error.InvalidNick, buildInviteNotifyLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "bad\nnick", "#onyx"));
    try std.testing.expectError(error.InvalidChannel, buildInvitingNumeric(
        &buf,
        "irc.example",
        "alice",
        "bob",
        "#bad channel",
    ));
}
