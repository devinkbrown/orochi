// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 CHGHOST and SETNAME broadcast helpers.
//!
//! Channel membership and visibility are owned by the caller. This module
//! validates attacker-controlled identity fields, builds canonical IRC lines
//! into caller-provided storage, and selects which already-visible clients
//! receive native IRCv3 broadcasts versus legacy fallback actions.
const std = @import("std");
const numeric = @import("../proto/numeric.zig");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_REALNAME_BYTES: usize = 256;

/// Numeric callers can use when validation rejects a CHGHOST/SETNAME field.
pub const invalidChangeNumeric: numeric.Numeric = .ERR_INVALIDUSERNAME;

pub const ChghostError = error{
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidRealname,
    RealnameTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits for builders and validators.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_realname_bytes: usize = DEFAULT_MAX_REALNAME_BYTES,
    allow_empty_realname: bool = false,
};

/// Identity used as the IRC message prefix: `:nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// One visible client that may receive an IRCv3 identity-change broadcast.
pub const Watcher = struct {
    client: ClientId,
    chghost: bool = false,
    setname: bool = false,
};

pub const ChghostFallback = enum {
    none,
    quit_join,
};

pub const ChghostAction = enum {
    chghost,
    quit_join,
};

/// One selected CHGHOST recipient and how the daemon should represent it.
pub const ChghostRecipient = struct {
    client: ClientId,
    action: ChghostAction,
};

/// Caller-provided storage for selected CHGHOST recipients.
pub const ChghostRecipientSink = struct {
    recipients: []ChghostRecipient,
    count: usize = 0,

    pub fn append(self: *ChghostRecipientSink, client: ClientId, action: ChghostAction) ChghostError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client, .action = action };
        self.count += 1;
    }

    pub fn slice(self: *const ChghostRecipientSink) []const ChghostRecipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *ChghostRecipientSink) void {
        self.count = 0;
    }
};

/// One selected SETNAME recipient.
pub const SetnameRecipient = struct {
    client: ClientId,
};

/// Caller-provided storage for selected SETNAME recipients.
pub const SetnameRecipientSink = struct {
    recipients: []SetnameRecipient,
    count: usize = 0,

    pub fn append(self: *SetnameRecipientSink, client: ClientId) ChghostError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client };
        self.count += 1;
    }

    pub fn slice(self: *const SetnameRecipientSink) []const SetnameRecipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *SetnameRecipientSink) void {
        self.count = 0;
    }
};

/// Build `:nick!user@host CHGHOST newuser newhost` into caller-owned storage.
pub fn buildChghostLine(
    out: []u8,
    prefix: Prefix,
    new_user: []const u8,
    new_host: []const u8,
) ChghostError![]const u8 {
    return buildChghostLineWith(.{}, out, prefix, new_user, new_host);
}

/// Build a CHGHOST line using caller-selected compile-time limits.
pub fn buildChghostLineWith(
    comptime params: Params,
    out: []u8,
    prefix: Prefix,
    new_user: []const u8,
    new_host: []const u8,
) ChghostError![]const u8 {
    validatePrefix(params, prefix) catch |err| return err;
    try validateUserWith(params, new_user);
    try validateHostWith(params, new_host);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try append(out, &n, " CHGHOST ");
    try append(out, &n, new_user);
    try appendByte(out, &n, ' ');
    try append(out, &n, new_host);
    return out[0..n];
}

/// Build `:nick!user@host SETNAME :realname` into caller-owned storage.
pub fn buildSetnameLine(
    out: []u8,
    prefix: Prefix,
    realname: []const u8,
) ChghostError![]const u8 {
    return buildSetnameLineWith(.{}, out, prefix, realname);
}

/// Build a SETNAME line using caller-selected compile-time limits.
pub fn buildSetnameLineWith(
    comptime params: Params,
    out: []u8,
    prefix: Prefix,
    realname: []const u8,
) ChghostError![]const u8 {
    validatePrefix(params, prefix) catch |err| return err;
    try validateRealnameWith(params, realname);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try append(out, &n, " SETNAME :");
    try append(out, &n, realname);
    return out[0..n];
}

/// Select visible clients for a host/user change.
///
/// Clients with `chghost` receive the native IRCv3 CHGHOST broadcast. Clients
/// without it either receive the caller's quit/join fallback action or are
/// omitted, depending on `fallback`.
pub fn selectChghostRecipients(
    watchers: []const Watcher,
    fallback: ChghostFallback,
    sink: *ChghostRecipientSink,
) ChghostError!void {
    for (watchers) |watcher| {
        if (watcher.chghost) {
            try sink.append(watcher.client, .chghost);
        } else if (fallback == .quit_join) {
            try sink.append(watcher.client, .quit_join);
        }
    }
}

/// Select visible clients that negotiated IRCv3 setname.
pub fn selectSetnameRecipients(
    watchers: []const Watcher,
    sink: *SetnameRecipientSink,
) ChghostError!void {
    for (watchers) |watcher| {
        if (watcher.setname) try sink.append(watcher.client);
    }
}

pub fn validateUser(user: []const u8) ChghostError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) ChghostError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) ChghostError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) ChghostError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateRealname(realname: []const u8) ChghostError!void {
    return validateRealnameWith(.{}, realname);
}

pub fn validateRealnameWith(comptime params: Params, realname: []const u8) ChghostError!void {
    if (!params.allow_empty_realname and realname.len == 0) return error.InvalidRealname;
    if (realname.len > params.max_realname_bytes) return error.RealnameTooLong;
    for (realname) |ch| {
        if (!validRealnameByte(ch)) return error.InvalidRealname;
    }
}

pub fn validateNick(nick: []const u8) ChghostError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) ChghostError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

fn validatePrefix(comptime params: Params, prefix: Prefix) ChghostError!void {
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

fn validRealnameByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn append(out: []u8, n: *usize, bytes: []const u8) ChghostError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) ChghostError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectChghostRecipient(
    recipient: ChghostRecipient,
    client: ClientId,
    action: ChghostAction,
) !void {
    try std.testing.expectEqual(client, recipient.client);
    try std.testing.expectEqual(action, recipient.action);
}

test "chghost line build" {
    var buf: [128]u8 = undefined;
    const line = try buildChghostLine(&buf, .{
        .nick = "alice",
        .user = "olduser",
        .host = "old.example",
    }, "newuser", "cloak/new.example");

    try std.testing.expectEqualStrings(":alice!olduser@old.example CHGHOST newuser cloak/new.example", line);
}

test "setname line build" {
    var buf: [128]u8 = undefined;
    const line = try buildSetnameLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "Alice Example");

    try std.testing.expectEqualStrings(":alice!user@cloak.example SETNAME :Alice Example", line);
}

test "cap-gated recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .chghost = true, .setname = true },
        .{ .client = 2, .chghost = false, .setname = true },
        .{ .client = 3, .chghost = false, .setname = false },
    };

    var chghost_storage: [3]ChghostRecipient = undefined;
    var chghost_sink = ChghostRecipientSink{ .recipients = &chghost_storage };
    try selectChghostRecipients(&watchers, .none, &chghost_sink);
    try std.testing.expectEqual(@as(usize, 1), chghost_sink.slice().len);
    try expectChghostRecipient(chghost_sink.slice()[0], 1, .chghost);

    chghost_sink.reset();
    try selectChghostRecipients(&watchers, .quit_join, &chghost_sink);
    try std.testing.expectEqual(@as(usize, 3), chghost_sink.slice().len);
    try expectChghostRecipient(chghost_sink.slice()[0], 1, .chghost);
    try expectChghostRecipient(chghost_sink.slice()[1], 2, .quit_join);
    try expectChghostRecipient(chghost_sink.slice()[2], 3, .quit_join);

    var setname_storage: [3]SetnameRecipient = undefined;
    var setname_sink = SetnameRecipientSink{ .recipients = &setname_storage };
    try selectSetnameRecipients(&watchers, &setname_sink);
    try std.testing.expectEqual(@as(usize, 2), setname_sink.slice().len);
    try std.testing.expectEqual(@as(ClientId, 1), setname_sink.slice()[0].client);
    try std.testing.expectEqual(@as(ClientId, 2), setname_sink.slice()[1].client);
}

test "invalid host and user rejected" {
    try std.testing.expectError(error.InvalidUser, validateUser("bad user"));
    try std.testing.expectError(error.InvalidUser, validateUser("bad\ruser"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad host.example"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad\nhost.example"));

    var buf: [128]u8 = undefined;
    try std.testing.expectError(error.InvalidUser, buildChghostLine(&buf, .{
        .nick = "alice",
        .user = "olduser",
        .host = "old.example",
    }, "bad user", "new.example"));
}
