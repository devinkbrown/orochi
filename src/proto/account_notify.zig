// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 account-notify broadcast helpers.
//!
//! Channel membership and visibility are owned by the caller. This module
//! validates attacker-controlled identity and account fields, builds canonical
//! IRC ACCOUNT lines into caller-provided storage, and selects which
//! already-visible clients negotiated the `account-notify` capability.
const std = @import("std");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 64;

/// IRCv3 logout sentinel used as the ACCOUNT parameter.
pub const LOGOUT_SENTINEL = "*";

pub const AccountNotifyError = error{
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidAccount,
    AccountTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits for builders and validators.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_account_bytes: usize = DEFAULT_MAX_ACCOUNT_BYTES,
};

/// Identity used as the IRC message prefix: `:nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Account state transition encoded by IRCv3 ACCOUNT.
pub const AccountChange = union(enum) {
    login: []const u8,
    logout,
};

/// One visible client that may receive an IRCv3 account-notify broadcast.
pub const Watcher = struct {
    client: ClientId,
    account_notify: bool = false,
};

/// One selected account-notify recipient.
pub const AccountNotifyRecipient = struct {
    client: ClientId,
};

/// Caller-provided storage for selected account-notify recipients.
pub const AccountNotifyRecipientSink = struct {
    recipients: []AccountNotifyRecipient,
    count: usize = 0,

    pub fn append(self: *AccountNotifyRecipientSink, client: ClientId) AccountNotifyError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client };
        self.count += 1;
    }

    pub fn slice(self: *const AccountNotifyRecipientSink) []const AccountNotifyRecipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *AccountNotifyRecipientSink) void {
        self.count = 0;
    }
};

/// Build `:nick!user@host ACCOUNT account` or `:nick!user@host ACCOUNT *`.
pub fn buildAccountNotifyLine(
    out: []u8,
    prefix: Prefix,
    change: AccountChange,
) AccountNotifyError![]const u8 {
    return buildAccountNotifyLineWith(.{}, out, prefix, change);
}

/// Build an ACCOUNT line using caller-selected compile-time limits.
pub fn buildAccountNotifyLineWith(
    comptime params: Params,
    out: []u8,
    prefix: Prefix,
    change: AccountChange,
) AccountNotifyError![]const u8 {
    validatePrefix(params, prefix) catch |err| return err;
    const account = try accountParam(params, change);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try append(out, &n, " ACCOUNT ");
    try append(out, &n, account);
    return out[0..n];
}

/// Select visible clients that negotiated IRCv3 account-notify.
pub fn selectAccountNotifyRecipients(
    watchers: []const Watcher,
    sink: *AccountNotifyRecipientSink,
) AccountNotifyError!void {
    for (watchers) |watcher| {
        if (watcher.account_notify) try sink.append(watcher.client);
    }
}

pub fn validateAccount(account: []const u8) AccountNotifyError!void {
    return validateAccountWith(.{}, account);
}

pub fn validateAccountWith(comptime params: Params, account: []const u8) AccountNotifyError!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    if (std.mem.eql(u8, account, LOGOUT_SENTINEL)) return error.InvalidAccount;
    for (account) |ch| {
        if (!validAccountByte(ch)) return error.InvalidAccount;
    }
}

pub fn validateUser(user: []const u8) AccountNotifyError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) AccountNotifyError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) AccountNotifyError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) AccountNotifyError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateNick(nick: []const u8) AccountNotifyError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) AccountNotifyError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

fn accountParam(comptime params: Params, change: AccountChange) AccountNotifyError![]const u8 {
    return switch (change) {
        .login => |account| blk: {
            try validateAccountWith(params, account);
            break :blk account;
        },
        .logout => LOGOUT_SENTINEL,
    };
}

fn validatePrefix(comptime params: Params, prefix: Prefix) AccountNotifyError!void {
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

fn validAccountByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_' => true,
        else => false,
    };
}

fn append(out: []u8, n: *usize, bytes: []const u8) AccountNotifyError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) AccountNotifyError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectRecipient(
    recipient: AccountNotifyRecipient,
    client: ClientId,
) !void {
    try std.testing.expectEqual(client, recipient.client);
}

test "account-notify login line build" {
    var buf: [128]u8 = undefined;
    const line = try buildAccountNotifyLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, .{ .login = "account.name" });

    try std.testing.expectEqualStrings(":alice!user@cloak.example ACCOUNT account.name", line);
}

test "account-notify logout line build uses explicit sentinel" {
    var buf: [128]u8 = undefined;
    const line = try buildAccountNotifyLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, .logout);

    try std.testing.expectEqualStrings(":alice!user@cloak.example ACCOUNT *", line);
}

test "cap-gated recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .account_notify = true },
        .{ .client = 2, .account_notify = false },
        .{ .client = 3, .account_notify = true },
    };

    var storage: [2]AccountNotifyRecipient = undefined;
    var sink = AccountNotifyRecipientSink{ .recipients = &storage };
    try selectAccountNotifyRecipients(&watchers, &sink);

    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
    try expectRecipient(sink.slice()[1], 3);

    sink.reset();
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
}

test "recipient sink reports too many recipients" {
    const watchers = [_]Watcher{
        .{ .client = 1, .account_notify = true },
        .{ .client = 2, .account_notify = true },
    };

    var storage: [1]AccountNotifyRecipient = undefined;
    var sink = AccountNotifyRecipientSink{ .recipients = &storage };
    try std.testing.expectError(error.TooManyRecipients, selectAccountNotifyRecipients(&watchers, &sink));
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
}

test "builder reports output too small" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildAccountNotifyLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, .{ .login = "account" }));
}

test "invalid prefix and account fields rejected" {
    try std.testing.expectError(error.InvalidNick, validateNick("bad nick"));
    try std.testing.expectError(error.InvalidUser, validateUser("bad user"));
    try std.testing.expectError(error.InvalidUser, validateUser("bad\ruser"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad host.example"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad\nhost.example"));
    try std.testing.expectError(error.InvalidAccount, validateAccount(""));
    try std.testing.expectError(error.InvalidAccount, validateAccount(LOGOUT_SENTINEL));
    try std.testing.expectError(error.InvalidAccount, validateAccount("bad account"));
    try std.testing.expectError(error.InvalidAccount, validateAccount("bad:account"));

    var buf: [128]u8 = undefined;
    try std.testing.expectError(error.InvalidAccount, buildAccountNotifyLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, .{ .login = LOGOUT_SENTINEL }));
}

test "custom account limit applies" {
    try validateAccountWith(.{ .max_account_bytes = 4 }, "acct");
    try std.testing.expectError(error.AccountTooLong, validateAccountWith(.{ .max_account_bytes = 4 }, "alice"));
}
