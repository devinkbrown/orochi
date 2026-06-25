// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-recipient identity-change notification fan-out helpers.
//!
//! Callers own channel membership and daemon state. This module only validates
//! the actor/change fields, gates already-visible recipients by the matching
//! IRCv3 capability, and copies canonical wire lines into caller storage.
const std = @import("std");
const account_notify = @import("account_notify.zig");
const chghost = @import("chghost.zig");

pub const ClientId = u64;
pub const Prefix = chghost.Prefix;
pub const AccountChange = account_notify.AccountChange;

pub const DEFAULT_MAX_LINE_BYTES: usize = 1024;

pub const Error = chghost.ChghostError || account_notify.AccountNotifyError;

pub const Params = struct {
    chghost: chghost.Params = .{},
    account: account_notify.Params = .{},
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
};

pub const UserHost = struct {
    user: []const u8,
    host: []const u8,
};

pub const Change = union(enum) {
    setname: []const u8,
    chghost: UserHost,
    account: AccountChange,
};

pub const Event = struct {
    prefix: Prefix,
    change: Change,
};

/// Caller-provided recipient visibility and negotiated capability facts.
pub const Recipient = struct {
    client: ClientId,
    common_channel: bool = false,
    setname: bool = false,
    chghost: bool = false,
    account_notify: bool = false,
};

pub const Notification = struct {
    client: ClientId,
    line: []const u8,
};

/// Bounded caller-owned storage for selected per-recipient wire lines.
pub const Sink = struct {
    notifications: []Notification,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(self: *Sink, client: ClientId, line: []const u8) Error!void {
        if (self.count >= self.notifications.len) return error.TooManyRecipients;
        if (self.storage.len - self.used < line.len) return error.OutputTooSmall;

        const start = self.used;
        const end = start + line.len;
        @memcpy(self.storage[start..end], line);
        self.used = end;

        self.notifications[self.count] = .{
            .client = client,
            .line = self.storage[start..end],
        };
        self.count += 1;
    }

    pub fn slice(self: *const Sink) []const Notification {
        return self.notifications[0..self.count];
    }

    pub fn reset(self: *Sink) void {
        self.count = 0;
        self.used = 0;
    }
};

pub fn shouldReceive(recipient: Recipient, change: Change) bool {
    if (!recipient.common_channel) return false;
    return switch (change) {
        .setname => recipient.setname,
        .chghost => recipient.chghost,
        .account => recipient.account_notify,
    };
}

/// Build the canonical wire line for one identity-change event.
pub fn buildLine(out: []u8, event: Event) Error![]const u8 {
    return buildLineWith(.{}, out, event);
}

pub fn buildLineWith(comptime params: Params, out: []u8, event: Event) Error![]const u8 {
    return switch (event.change) {
        .setname => |realname| chghost.buildSetnameLineWith(
            params.chghost,
            out,
            event.prefix,
            realname,
        ),
        .chghost => |new_identity| chghost.buildChghostLineWith(
            params.chghost,
            out,
            event.prefix,
            new_identity.user,
            new_identity.host,
        ),
        .account => |account| account_notify.buildAccountNotifyLineWith(
            params.account,
            out,
            .{
                .nick = event.prefix.nick,
                .user = event.prefix.user,
                .host = event.prefix.host,
            },
            account,
        ),
    };
}

pub fn validateEvent(event: Event) Error!void {
    var buf: [DEFAULT_MAX_LINE_BYTES]u8 = undefined;
    _ = try buildLine(&buf, event);
}

/// Build one line for each common-channel recipient with the matching cap.
pub fn buildNotifications(event: Event, recipients: []const Recipient, sink: *Sink) Error!void {
    return buildNotificationsWith(.{}, event, recipients, sink);
}

pub fn buildNotificationsWith(
    comptime params: Params,
    event: Event,
    recipients: []const Recipient,
    sink: *Sink,
) Error!void {
    comptime {
        if (params.max_line_bytes == 0) @compileError("identity-change line buffer must be non-zero");
    }

    var line_buf: [params.max_line_bytes]u8 = undefined;
    const line = try buildLineWith(params, &line_buf, event);

    for (recipients) |recipient| {
        if (shouldReceive(recipient, event.change)) {
            try sink.append(recipient.client, line);
        }
    }
}

fn testSink(allocator: std.mem.Allocator, max_notifications: usize, max_bytes: usize) !struct {
    list: std.ArrayList(Notification),
    bytes: std.ArrayList(u8),
    sink: Sink,

    fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        self.list.deinit(alloc);
        self.bytes.deinit(alloc);
    }
} {
    var list: std.ArrayList(Notification) = .empty;
    errdefer list.deinit(allocator);
    try list.resize(allocator, max_notifications);

    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.resize(allocator, max_bytes);

    return .{
        .list = list,
        .bytes = bytes,
        .sink = .{ .notifications = list.items, .storage = bytes.items },
    };
}

fn actor() Prefix {
    return .{ .nick = "alice", .user = "user", .host = "host.example" };
}

test "setname notification exact bytes and cap gating" {
    var storage = try testSink(std.testing.allocator, 4, 512);
    defer storage.deinit(std.testing.allocator);

    const recipients = [_]Recipient{
        .{ .client = 10, .common_channel = true, .setname = true },
        .{ .client = 11, .common_channel = true, .setname = false },
        .{ .client = 12, .common_channel = false, .setname = true },
    };

    try buildNotifications(.{
        .prefix = actor(),
        .change = .{ .setname = "Alice Example" },
    }, &recipients, &storage.sink);

    const got = storage.sink.slice();
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqual(@as(ClientId, 10), got[0].client);
    try std.testing.expectEqualStrings(":alice!user@host.example SETNAME :Alice Example", got[0].line);
}

test "chghost notification exact bytes and cap gating" {
    var storage = try testSink(std.testing.allocator, 4, 512);
    defer storage.deinit(std.testing.allocator);

    const recipients = [_]Recipient{
        .{ .client = 20, .common_channel = true, .chghost = false },
        .{ .client = 21, .common_channel = true, .chghost = true },
        .{ .client = 22, .common_channel = false, .chghost = true },
    };

    try buildNotifications(.{
        .prefix = actor(),
        .change = .{ .chghost = .{ .user = "newuser", .host = "cloak.example" } },
    }, &recipients, &storage.sink);

    const got = storage.sink.slice();
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqual(@as(ClientId, 21), got[0].client);
    try std.testing.expectEqualStrings(":alice!user@host.example CHGHOST newuser cloak.example", got[0].line);
}

test "account-notify notification exact bytes and cap gating" {
    var storage = try testSink(std.testing.allocator, 4, 512);
    defer storage.deinit(std.testing.allocator);

    const recipients = [_]Recipient{
        .{ .client = 30, .common_channel = true, .account_notify = true },
        .{ .client = 31, .common_channel = true, .account_notify = false },
        .{ .client = 32, .common_channel = false, .account_notify = true },
    };

    try buildNotifications(.{
        .prefix = actor(),
        .change = .{ .account = .{ .login = "alice_acc" } },
    }, &recipients, &storage.sink);

    const got = storage.sink.slice();
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqual(@as(ClientId, 30), got[0].client);
    try std.testing.expectEqualStrings(":alice!user@host.example ACCOUNT alice_acc", got[0].line);
}

test "validation rejects malformed fields" {
    try std.testing.expectError(error.InvalidNick, validateEvent(.{
        .prefix = .{ .nick = "bad nick", .user = "user", .host = "host.example" },
        .change = .{ .setname = "Alice Example" },
    }));
    try std.testing.expectError(error.InvalidRealname, validateEvent(.{
        .prefix = actor(),
        .change = .{ .setname = "bad\nrealname" },
    }));
    try std.testing.expectError(error.InvalidUser, validateEvent(.{
        .prefix = actor(),
        .change = .{ .chghost = .{ .user = "bad user", .host = "cloak.example" } },
    }));
    try std.testing.expectError(error.InvalidHost, validateEvent(.{
        .prefix = actor(),
        .change = .{ .chghost = .{ .user = "newuser", .host = "bad host" } },
    }));
    try std.testing.expectError(error.InvalidAccount, validateEvent(.{
        .prefix = actor(),
        .change = .{ .account = .{ .login = "bad account" } },
    }));
}

test "bounded sink reports capacity failures" {
    var small_lines = try testSink(std.testing.allocator, 0, 512);
    defer small_lines.deinit(std.testing.allocator);

    const recipients = [_]Recipient{
        .{ .client = 40, .common_channel = true, .setname = true },
    };
    try std.testing.expectError(error.TooManyRecipients, buildNotifications(.{
        .prefix = actor(),
        .change = .{ .setname = "Alice Example" },
    }, &recipients, &small_lines.sink));

    var small_bytes = try testSink(std.testing.allocator, 1, 8);
    defer small_bytes.deinit(std.testing.allocator);
    try std.testing.expectError(error.OutputTooSmall, buildNotifications(.{
        .prefix = actor(),
        .change = .{ .setname = "Alice Example" },
    }, &recipients, &small_bytes.sink));
}
