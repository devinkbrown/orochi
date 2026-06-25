// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure services alias resolution and routed-line builders.
//!
//! This mirrors the small, static shape of charybdis `m_alias`: service
//! pseudo-commands such as `NS` route their parameters as a `PRIVMSG` to the
//! configured service nick, while direct targets such as `NickServ` resolve to
//! that same service nick without being treated as pseudo-commands.
const std = @import("std");
const limits_config = @import("limits_config.zig");

pub const DEFAULT_MAX_SERVICE_NICK_BYTES: usize = 32;
pub const DEFAULT_MAX_TARGET_NICK_BYTES: usize = 32;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 8191;

pub const ServicesAliasError = error{
    InvalidServiceNick,
    ServiceNickTooLong,
    InvalidTargetNick,
    TargetNickTooLong,
    InvalidText,
    TextTooLong,
    OutputTooSmall,
};

pub const Params = struct {
    max_service_nick_bytes: usize = DEFAULT_MAX_SERVICE_NICK_BYTES,
    max_target_nick_bytes: usize = DEFAULT_MAX_TARGET_NICK_BYTES,
    max_text_bytes: usize = DEFAULT_MAX_TEXT_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_text_bytes` is a multiline-wire budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_service_nick_bytes = limits.service_nick_len,
            .max_target_nick_bytes = limits.service_target_nick_len,
        };
    }
};

pub const Alias = struct {
    token: []const u8,
    service_nick: []const u8,
    is_command: bool,
};

pub const Resolution = struct {
    service_nick: []const u8,
    is_command: bool,
};

pub const ALIASES: []const Alias = &.{
    .{ .token = "NS", .service_nick = "NickServ", .is_command = true },
    .{ .token = "CS", .service_nick = "ChanServ", .is_command = true },
    .{ .token = "OS", .service_nick = "OperServ", .is_command = true },
    .{ .token = "MS", .service_nick = "MemoServ", .is_command = true },
    .{ .token = "HS", .service_nick = "HostServ", .is_command = true },
    .{ .token = "BS", .service_nick = "BotServ", .is_command = true },
    .{ .token = "SS", .service_nick = "StatServ", .is_command = true },

    .{ .token = "NICKSERV", .service_nick = "NickServ", .is_command = false },
    .{ .token = "CHANSERV", .service_nick = "ChanServ", .is_command = false },
    .{ .token = "OPERSERV", .service_nick = "OperServ", .is_command = false },
    .{ .token = "MEMOSERV", .service_nick = "MemoServ", .is_command = false },
    .{ .token = "HOSTSERV", .service_nick = "HostServ", .is_command = false },
    .{ .token = "BOTSERV", .service_nick = "BotServ", .is_command = false },
    .{ .token = "STATSERV", .service_nick = "StatServ", .is_command = false },
    .{ .token = "HELPSERV", .service_nick = "HelpServ", .is_command = false },
    .{ .token = "GLOBAL", .service_nick = "Global", .is_command = false },
};

pub fn resolve(command_or_target: []const u8) ?Resolution {
    return resolveFrom(ALIASES, command_or_target);
}

pub fn resolveFrom(aliases: []const Alias, command_or_target: []const u8) ?Resolution {
    for (aliases) |alias| {
        if (std.ascii.eqlIgnoreCase(command_or_target, alias.token)) {
            return .{
                .service_nick = alias.service_nick,
                .is_command = alias.is_command,
            };
        }
    }

    return null;
}

/// Build `PRIVMSG <service> :<text>` into caller-owned storage.
pub fn buildRoutedPrivmsg(
    out: []u8,
    service_nick: []const u8,
    text: []const u8,
) ServicesAliasError![]const u8 {
    return buildRoutedPrivmsgWith(.{}, out, service_nick, text);
}

/// Build `PRIVMSG <service> :<text>` using caller-selected limits.
pub fn buildRoutedPrivmsgWith(
    comptime params: Params,
    out: []u8,
    service_nick: []const u8,
    text: []const u8,
) ServicesAliasError![]const u8 {
    try validateServiceNickWith(params, service_nick);
    try validateTextWith(params, text);

    var n: usize = 0;
    try append(out, &n, "PRIVMSG ");
    try append(out, &n, service_nick);
    try append(out, &n, " :");
    try append(out, &n, text);
    return out[0..n];
}

/// Build `:<service> NOTICE <target> :<text>` into caller-owned storage.
pub fn buildServiceNotice(
    out: []u8,
    service_nick: []const u8,
    target_nick: []const u8,
    text: []const u8,
) ServicesAliasError![]const u8 {
    return buildServiceNoticeWith(.{}, out, service_nick, target_nick, text);
}

/// Build `:<service> NOTICE <target> :<text>` using caller-selected limits.
pub fn buildServiceNoticeWith(
    comptime params: Params,
    out: []u8,
    service_nick: []const u8,
    target_nick: []const u8,
    text: []const u8,
) ServicesAliasError![]const u8 {
    try validateServiceNickWith(params, service_nick);
    try validateTargetNickWith(params, target_nick);
    try validateTextWith(params, text);

    var n: usize = 0;
    try append(out, &n, ":");
    try append(out, &n, service_nick);
    try append(out, &n, " NOTICE ");
    try append(out, &n, target_nick);
    try append(out, &n, " :");
    try append(out, &n, text);
    return out[0..n];
}

pub fn validateServiceNick(service_nick: []const u8) ServicesAliasError!void {
    return validateServiceNickWith(.{}, service_nick);
}

pub fn validateServiceNickWith(comptime params: Params, service_nick: []const u8) ServicesAliasError!void {
    if (service_nick.len == 0) return error.InvalidServiceNick;
    if (service_nick.len > params.max_service_nick_bytes) return error.ServiceNickTooLong;
    if (!validNick(service_nick)) return error.InvalidServiceNick;
}

pub fn validateTargetNick(target_nick: []const u8) ServicesAliasError!void {
    return validateTargetNickWith(.{}, target_nick);
}

pub fn validateTargetNickWith(comptime params: Params, target_nick: []const u8) ServicesAliasError!void {
    if (target_nick.len == 0) return error.InvalidTargetNick;
    if (target_nick.len > params.max_target_nick_bytes) return error.TargetNickTooLong;
    if (!validNick(target_nick)) return error.InvalidTargetNick;
}

pub fn validateText(text: []const u8) ServicesAliasError!void {
    return validateTextWith(.{}, text);
}

pub fn validateTextWith(comptime params: Params, text: []const u8) ServicesAliasError!void {
    if (text.len > params.max_text_bytes) return error.TextTooLong;

    for (text) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidText,
            else => {},
        }
    }
}

fn validNick(nick: []const u8) bool {
    for (nick, 0..) |ch, index| {
        const valid = if (index == 0) validNickFirstByte(ch) else validNickByte(ch);
        if (!valid) return false;
    }

    return true;
}

fn validNickFirstByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '[', ']', '\\', '`', '_', '^', '{', '|', '}' => true,
        else => false,
    };
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '[', ']', '\\', '`', '_', '^', '{', '|', '}' => true,
        else => false,
    };
}

fn append(out: []u8, n: *usize, bytes: []const u8) ServicesAliasError!void {
    if (bytes.len > out.len - n.*) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn expectResolution(
    input: []const u8,
    service_nick: []const u8,
    is_command: bool,
) !void {
    const resolved = resolve(input) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqualStrings(service_nick, resolved.service_nick);
    try std.testing.expectEqual(is_command, resolved.is_command);
}

test "resolve services command aliases" {
    try expectResolution("NS", "NickServ", true);
    try expectResolution("cs", "ChanServ", true);
    try expectResolution("Os", "OperServ", true);
    try expectResolution("MS", "MemoServ", true);
    try expectResolution("hs", "HostServ", true);
    try expectResolution("BS", "BotServ", true);
    try expectResolution("ss", "StatServ", true);
}

test "resolve services target nicks" {
    try expectResolution("NICKSERV", "NickServ", false);
    try expectResolution("chanserv", "ChanServ", false);
    try expectResolution("OperServ", "OperServ", false);
    try expectResolution("MEMOSERV", "MemoServ", false);
    try expectResolution("HostServ", "HostServ", false);
    try expectResolution("BOTSERV", "BotServ", false);
    try expectResolution("HelpServ", "HelpServ", false);
    try expectResolution("GLOBAL", "Global", false);
}

test "unknown aliases pass through as null" {
    try std.testing.expectEqual(@as(?Resolution, null), resolve("PRIVMSG"));
    try std.testing.expectEqual(@as(?Resolution, null), resolve("alice"));
    try std.testing.expectEqual(@as(?Resolution, null), resolve(""));
}

test "routed message builders emit exact bytes" {
    const allocator = std.testing.allocator;
    const buf = try allocator.alloc(u8, 128);
    defer allocator.free(buf);

    const routed = try buildRoutedPrivmsg(buf, "NickServ", "IDENTIFY hunter2");
    try std.testing.expectEqualStrings("PRIVMSG NickServ :IDENTIFY hunter2", routed);

    const notice = try buildServiceNotice(buf, "NickServ", "alice", "Syntax: NS IDENTIFY <password>");
    try std.testing.expectEqualStrings(":NickServ NOTICE alice :Syntax: NS IDENTIFY <password>", notice);
}

test "builders are bounded and validate message bytes" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildRoutedPrivmsg(&buf, "NickServ", "IDENTIFY hunter2"));
    try std.testing.expectError(error.InvalidServiceNick, buildRoutedPrivmsg(&buf, "1NickServ", "help"));
    try std.testing.expectError(error.InvalidText, buildRoutedPrivmsg(&buf, "NickServ", "bad\ntext"));
    try std.testing.expectError(error.InvalidTargetNick, buildServiceNotice(&buf, "NickServ", "#chan", "help"));
    try std.testing.expectError(error.TextTooLong, buildRoutedPrivmsgWith(.{ .max_text_bytes = 4 }, &buf, "NickServ", "hello"));
}
