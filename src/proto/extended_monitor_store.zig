//! IRCv3 extended-monitor notification fan-out helpers.
//!
//! `monitor.zig` owns the actual MONITOR lists. Callers pass watchers derived
//! from that store, with `has_cap` already meaning the watcher negotiated both
//! `extended-monitor` and the event-specific capability.
const std = @import("std");
const monitor = @import("monitor.zig");
const extended_monitor = @import("extended_monitor.zig");
const metadata = @import("metadata.zig");
const limits_config = @import("limits_config.zig");

pub const ClientId = monitor.ClientId;
pub const Watcher = extended_monitor.Watcher;
pub const Prefix = extended_monitor.Prefix;

pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 64;
pub const DEFAULT_MAX_METADATA_KEY_BYTES: usize = 64;
pub const DEFAULT_MAX_METADATA_VALUE_BYTES: usize = 512;
pub const DEFAULT_MAX_LINE_BYTES: usize = 1024;

pub const Error = extended_monitor.ExtendedMonitorError || error{
    InvalidAccount,
    AccountTooLong,
    InvalidMetadataKey,
    MetadataKeyTooLong,
    InvalidMetadataValue,
    MetadataValueTooLong,
};

pub const Params = struct {
    extended: extended_monitor.Params = .{},
    max_account_bytes: usize = DEFAULT_MAX_ACCOUNT_BYTES,
    max_metadata_key_bytes: usize = DEFAULT_MAX_METADATA_KEY_BYTES,
    max_metadata_value_bytes: usize = DEFAULT_MAX_METADATA_VALUE_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` is a wire budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .extended = extended_monitor.Params.fromLimits(limits),
            .max_account_bytes = limits.ext_monitor_account_len,
            .max_metadata_key_bytes = limits.ext_monitor_meta_key_len,
            .max_metadata_value_bytes = limits.ext_monitor_meta_value_len,
        };
    }
};

pub const AccountChange = union(enum) {
    login: []const u8,
    logout,
};

pub const MetadataChange = struct {
    key: []const u8,
    value: ?[]const u8,
    visibility: metadata.Visibility = .public,
};

pub const Change = union(enum) {
    away: ?[]const u8,
    account: AccountChange,
    chghost: struct {
        user: []const u8,
        host: []const u8,
    },
    setname: []const u8,
    metadata: MetadataChange,
};

pub const Event = struct {
    prefix: Prefix,
    change: Change,
};

pub const Notification = struct {
    client: ClientId,
    line: []const u8,
};

pub const Sink = struct {
    notifications: []Notification,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(self: *Sink, client: ClientId, line: []const u8) Error!void {
        if (self.count >= self.notifications.len) return error.TooManyRecipients;
        if (self.used + line.len > self.storage.len) return error.OutputTooSmall;

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

/// Build one line per watcher selected by IRCv3 extended-monitor rules.
pub fn buildNotifications(
    event: Event,
    watchers: []const Watcher,
    sink: *Sink,
) Error!void {
    return buildNotificationsWith(.{}, event, watchers, sink);
}

pub fn buildNotificationsWith(
    comptime params: Params,
    event: Event,
    watchers: []const Watcher,
    sink: *Sink,
) Error!void {
    comptime {
        if (params.max_line_bytes == 0) @compileError("extended-monitor line buffer must be non-zero");
    }

    var recipients_storage: [256]extended_monitor.Recipient = undefined;
    if (watchers.len > recipients_storage.len) return error.TooManyRecipients;

    var recipient_sink = extended_monitor.Sink{ .recipients = recipients_storage[0..watchers.len] };
    try extended_monitor.selectRecipientsWith(params.extended, event.prefix.nick, watchers, &recipient_sink);

    var line_buf: [params.max_line_bytes]u8 = undefined;
    const line = try buildEventLineWith(params, &line_buf, event);

    for (recipient_sink.slice()) |recipient| {
        try sink.append(recipient.client, line);
    }
}

pub fn buildEventLine(out: []u8, event: Event) Error![]const u8 {
    return buildEventLineWith(.{}, out, event);
}

pub fn buildEventLineWith(comptime params: Params, out: []u8, event: Event) Error![]const u8 {
    var param_buf: [params.extended.max_param_bytes]u8 = undefined;
    const spec = try eventSpecWith(params, &param_buf, event);
    return extended_monitor.buildNotificationLineWith(
        params.extended,
        out,
        event.prefix,
        spec.verb,
        spec.params_text,
    );
}

const EventSpec = struct {
    verb: []const u8,
    params_text: []const u8,
};

fn eventSpecWith(comptime params: Params, buf: []u8, event: Event) Error!EventSpec {
    return switch (event.change) {
        .away => |message| .{
            .verb = "AWAY",
            .params_text = if (message) |msg| try trailingParam(buf, msg) else "",
        },
        .account => |change| .{
            .verb = "ACCOUNT",
            .params_text = switch (change) {
                .login => |account| try accountParam(params, account),
                .logout => "*",
            },
        },
        .chghost => |change| .{
            .verb = "CHGHOST",
            .params_text = try twoParams(buf, change.user, change.host),
        },
        .setname => |realname| .{
            .verb = "SETNAME",
            .params_text = try trailingParam(buf, realname),
        },
        .metadata => |change| .{
            .verb = "METADATA",
            .params_text = try metadataParams(params, buf, event.prefix.nick, change),
        },
    };
}

fn accountParam(comptime params: Params, account: []const u8) Error![]const u8 {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    if (std.mem.eql(u8, account, "*")) return error.InvalidAccount;
    for (account) |ch| {
        const ok = switch (ch) {
            'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_' => true,
            else => false,
        };
        if (!ok) return error.InvalidAccount;
    }
    return account;
}

fn metadataParams(
    comptime params: Params,
    buf: []u8,
    target: []const u8,
    change: MetadataChange,
) Error![]const u8 {
    try validateMetadataKey(params, change.key);
    if (change.value) |value| {
        try validateMetadataValue(params, value);
        return join(buf, &.{
            target,
            " SET ",
            change.key,
            " ",
            change.visibility.token(),
            " :",
            value,
        });
    }
    return join(buf, &.{ target, " CLEAR ", change.key });
}

fn validateMetadataKey(comptime params: Params, key: []const u8) Error!void {
    if (key.len == 0) return error.InvalidMetadataKey;
    if (key.len > params.max_metadata_key_bytes) return error.MetadataKeyTooLong;
    for (key) |ch| {
        const ok = switch (ch) {
            'a'...'z', '0'...'9', '_', '.', '/', '-' => true,
            else => false,
        };
        if (!ok) return error.InvalidMetadataKey;
    }
}

fn validateMetadataValue(comptime params: Params, value: []const u8) Error!void {
    if (value.len > params.max_metadata_value_bytes) return error.MetadataValueTooLong;
    for (value) |ch| {
        if (ch == 0 or ch == '\r' or ch == '\n') return error.InvalidMetadataValue;
    }
}

fn twoParams(buf: []u8, first: []const u8, second: []const u8) Error![]const u8 {
    return join(buf, &.{ first, " ", second });
}

fn trailingParam(buf: []u8, value: []const u8) Error![]const u8 {
    return join(buf, &.{ ":", value });
}

fn join(buf: []u8, parts: []const []const u8) Error![]const u8 {
    var used: usize = 0;
    for (parts) |part| {
        if (buf.len - used < part.len) return error.OutputTooSmall;
        @memcpy(buf[used..][0..part.len], part);
        used += part.len;
    }
    return buf[0..used];
}

fn eventPrefix() Prefix {
    return .{ .nick = "alice", .user = "user", .host = "host.example" };
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

test "build away-change notifications with exact bytes" {
    var storage = try testSink(std.testing.allocator, 4, 512);
    defer storage.deinit(std.testing.allocator);

    const watchers = [_]Watcher{
        .{ .client = 10, .monitors_target = true, .has_cap = true },
        .{ .client = 11, .monitors_target = true, .has_cap = false },
        .{ .client = 12, .monitors_target = false, .has_cap = true },
        .{ .client = 13, .monitors_target = true, .has_cap = true },
    };

    try buildNotifications(.{
        .prefix = eventPrefix(),
        .change = .{ .away = "at lunch" },
    }, &watchers, &storage.sink);

    const got = storage.sink.slice();
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqual(@as(ClientId, 10), got[0].client);
    try std.testing.expectEqualStrings(":alice!user@host.example AWAY :at lunch", got[0].line);
    try std.testing.expectEqual(@as(ClientId, 13), got[1].client);
    try std.testing.expectEqualStrings(":alice!user@host.example AWAY :at lunch", got[1].line);
}

test "build account-change notifications with exact bytes" {
    var storage = try testSink(std.testing.allocator, 2, 256);
    defer storage.deinit(std.testing.allocator);

    const watchers = [_]Watcher{
        .{ .client = 21, .monitors_target = true, .has_cap = true },
        .{ .client = 22, .monitors_target = true, .has_cap = true },
    };

    try buildNotifications(.{
        .prefix = eventPrefix(),
        .change = .{ .account = .{ .login = "alice_acc" } },
    }, &watchers, &storage.sink);

    const got = storage.sink.slice();
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqual(@as(ClientId, 21), got[0].client);
    try std.testing.expectEqualStrings(":alice!user@host.example ACCOUNT alice_acc", got[0].line);
    try std.testing.expectEqual(@as(ClientId, 22), got[1].client);
    try std.testing.expectEqualStrings(":alice!user@host.example ACCOUNT alice_acc", got[1].line);
}

test "watcher filtering omits unmonitored and missing capability watchers" {
    var storage = try testSink(std.testing.allocator, 4, 512);
    defer storage.deinit(std.testing.allocator);

    const watchers = [_]Watcher{
        .{ .client = 31, .monitors_target = false, .has_cap = true },
        .{ .client = 32, .monitors_target = true, .has_cap = false },
        .{ .client = 33, .monitors_target = true, .has_cap = true },
    };

    try buildNotifications(.{
        .prefix = eventPrefix(),
        .change = .{ .account = .logout },
    }, &watchers, &storage.sink);

    const got = storage.sink.slice();
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqual(@as(ClientId, 33), got[0].client);
    try std.testing.expectEqualStrings(":alice!user@host.example ACCOUNT *", got[0].line);
}

test "line builders cover identity and metadata changes" {
    var buf: [256]u8 = undefined;

    const chghost = try buildEventLine(&buf, .{
        .prefix = eventPrefix(),
        .change = .{ .chghost = .{ .user = "newuser", .host = "cloak.example" } },
    });
    try std.testing.expectEqualStrings(":alice!user@host.example CHGHOST newuser cloak.example", chghost);

    const setname = try buildEventLine(&buf, .{
        .prefix = eventPrefix(),
        .change = .{ .setname = "Alice Example" },
    });
    try std.testing.expectEqualStrings(":alice!user@host.example SETNAME :Alice Example", setname);

    const meta = try buildEventLine(&buf, .{
        .prefix = eventPrefix(),
        .change = .{ .metadata = .{ .key = "display-name", .value = "Alice A." } },
    });
    try std.testing.expectEqualStrings(":alice!user@host.example METADATA alice SET display-name * :Alice A.", meta);
}
