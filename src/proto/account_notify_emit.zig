// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sink-oriented IRCv3 account-notify line emitters.
//!
//! `account_notify.zig` owns validation and the fixed-buffer ACCOUNT composer.
//! This module adapts that builder to appendable caller sinks. Channel
//! visibility and negotiated `account-notify` recipient selection remain owned
//! by the caller.
const std = @import("std");
const account_notify = @import("account_notify.zig");

pub const Prefix = account_notify.Prefix;
pub const AccountChange = account_notify.AccountChange;
pub const AccountNotifyError = account_notify.AccountNotifyError;
pub const Params = account_notify.Params;
pub const LOGOUT_SENTINEL = account_notify.LOGOUT_SENTINEL;

pub const LINE_ENDING = "\r\n";
pub const DEFAULT_MAX_BODY_BYTES: usize =
    1 +
    account_notify.DEFAULT_MAX_NICK_BYTES +
    1 +
    account_notify.DEFAULT_MAX_USER_BYTES +
    1 +
    account_notify.DEFAULT_MAX_HOST_BYTES +
    " ACCOUNT ".len +
    account_notify.DEFAULT_MAX_ACCOUNT_BYTES;
pub const DEFAULT_MAX_LINE_BYTES: usize = DEFAULT_MAX_BODY_BYTES + LINE_ENDING.len;

pub const EmitError = AccountNotifyError || std.mem.Allocator.Error;

pub const Builder = struct {
    prefix: Prefix,
    change: AccountChange,

    /// Return the exact ACCOUNT message length before CRLF.
    pub fn requiredBodyLen(self: Builder) AccountNotifyError!usize {
        var scratch: [DEFAULT_MAX_BODY_BYTES]u8 = undefined;
        const body = try account_notify.buildAccountNotifyLine(&scratch, self.prefix, self.change);
        return body.len;
    }

    /// Return the exact complete IRC line length including CRLF.
    pub fn requiredLineLen(self: Builder) AccountNotifyError!usize {
        return (try self.requiredBodyLen()) + LINE_ENDING.len;
    }

    /// Append `:nick!user@host ACCOUNT <account|*>` without CRLF.
    pub fn appendBody(
        self: Builder,
        allocator: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) EmitError!void {
        var scratch: [DEFAULT_MAX_BODY_BYTES]u8 = undefined;
        const body = try account_notify.buildAccountNotifyLine(&scratch, self.prefix, self.change);
        try sink.ensureUnusedCapacity(allocator, body.len);
        sink.appendSliceAssumeCapacity(body);
    }

    /// Append a complete IRC line with CRLF.
    pub fn appendLine(
        self: Builder,
        allocator: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) EmitError!void {
        var scratch: [DEFAULT_MAX_BODY_BYTES]u8 = undefined;
        const body = try account_notify.buildAccountNotifyLine(&scratch, self.prefix, self.change);
        try sink.ensureUnusedCapacity(allocator, body.len + LINE_ENDING.len);
        sink.appendSliceAssumeCapacity(body);
        sink.appendSliceAssumeCapacity(LINE_ENDING);
    }

    /// Alias for `appendLine`.
    pub fn emit(
        self: Builder,
        allocator: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) EmitError!void {
        try self.appendLine(allocator, sink);
    }
};

/// Start an account login notification.
pub fn login(prefix: Prefix, account: []const u8) Builder {
    return .{ .prefix = prefix, .change = .{ .login = account } };
}

/// Start an account logout notification.
pub fn logout(prefix: Prefix) Builder {
    return .{ .prefix = prefix, .change = .logout };
}

/// Emit `:nick!user@host ACCOUNT account\r\n` directly into `sink`.
pub fn emitLogin(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    prefix: Prefix,
    account: []const u8,
) EmitError!void {
    try login(prefix, account).emit(allocator, sink);
}

/// Emit `:nick!user@host ACCOUNT *\r\n` directly into `sink`.
pub fn emitLogout(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    prefix: Prefix,
) EmitError!void {
    try logout(prefix).emit(allocator, sink);
}

pub fn validateAccount(account: []const u8) AccountNotifyError!void {
    return account_notify.validateAccount(account);
}

test "emit login account line exact bytes" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try emitLogin(allocator, &sink, .{
        .nick = "nick",
        .user = "u",
        .host = "h",
    }, "acct");

    try std.testing.expectEqualStrings(":nick!u@h ACCOUNT acct\r\n", sink.items);
}

test "emit logout sentinel line exact bytes" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try logout(.{
        .nick = "nick",
        .user = "u",
        .host = "h",
    }).appendLine(allocator, &sink);

    try std.testing.expectEqualStrings(":nick!u@h ACCOUNT *\r\n", sink.items);
}

test "append body omits crlf for caller-framed sinks" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try login(.{
        .nick = "nick",
        .user = "u",
        .host = "h",
    }, "acct").appendBody(allocator, &sink);

    try std.testing.expectEqualStrings(":nick!u@h ACCOUNT acct", sink.items);
}

test "required lengths match emitted line" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    const builder = login(.{
        .nick = "nick",
        .user = "u",
        .host = "h",
    }, "acct");

    try builder.emit(allocator, &sink);
    try std.testing.expectEqual(@as(usize, 22), try builder.requiredBodyLen());
    try std.testing.expectEqual(sink.items.len, try builder.requiredLineLen());
}

test "account validation rejects empty sentinel and unsafe bytes" {
    try validateAccount("acct.name-01");
    try std.testing.expectError(error.InvalidAccount, validateAccount(""));
    try std.testing.expectError(error.InvalidAccount, validateAccount(LOGOUT_SENTINEL));
    try std.testing.expectError(error.InvalidAccount, validateAccount("bad account"));
    try std.testing.expectError(error.InvalidAccount, validateAccount("bad:account"));
}

test "login emission validates account through underlying builder" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try std.testing.expectError(error.InvalidAccount, emitLogin(allocator, &sink, .{
        .nick = "nick",
        .user = "u",
        .host = "h",
    }, LOGOUT_SENTINEL));
}
