// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extra WHOIS numeric reply builders.
//!
//! `src/daemon/whois.zig` owns the daemon's standard WHOIS sequence. This
//! protocol module only appends optional, caller-selected WHOIS numerics into a
//! caller-owned byte sink.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_PARAM_BYTES: usize = 512;

const rpl_whoiscertfp = numeric.Numeric.RPL_WHOISCERTFP;
const rpl_whoisactually = numeric.Numeric.RPL_WHOISACTUALLY;
const rpl_whoisidle = numeric.Numeric.RPL_WHOISIDLE;
const rpl_whoissecure_code: u16 = 671;

pub const WhoisExtraError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    InvalidHost,
    HostTooLong,
    InvalidParam,
    ParamTooLong,
    MessageTooLong,
} || std.mem.Allocator.Error;

pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_param_bytes: usize = DEFAULT_MAX_PARAM_BYTES,
};

/// Append `RPL_WHOISSECURE` (671).
pub fn writeWhoisSecure(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhoisExtraError!void {
    return writeWhoisSecureWith(.{}, allocator, sink, server_name, requester_nick, target_nick);
}

/// Append `RPL_WHOISSECURE` (671) using caller-selected limits.
pub fn writeWhoisSecureWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhoisExtraError!void {
    try validateEnvelopeWith(params, server_name, requester_nick, target_nick);
    try appendNumericLineRaw(
        params,
        allocator,
        sink,
        rpl_whoissecure_code,
        server_name,
        requester_nick,
        &.{target_nick},
        "is using a secure connection",
    );
}

/// Append `RPL_WHOISSECURE` (671) carrying the negotiated cipher suite name,
/// e.g. `:is using a secure connection (TLS_AES_128_GCM_SHA256)`.
pub fn writeWhoisSecureCipher(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    cipher: []const u8,
) WhoisExtraError!void {
    return writeWhoisSecureCipherWith(.{}, allocator, sink, server_name, requester_nick, target_nick, cipher);
}

/// Append `RPL_WHOISSECURE` (671) with a cipher name, caller-selected limits.
pub fn writeWhoisSecureCipherWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    cipher: []const u8,
) WhoisExtraError!void {
    try validateEnvelopeWith(params, server_name, requester_nick, target_nick);
    try validateParamWith(params, cipher);

    var trailing_buf: [160]u8 = undefined;
    const trailing = std.fmt.bufPrint(
        &trailing_buf,
        "is using a secure connection ({s})",
        .{cipher},
    ) catch return error.MessageTooLong;

    try appendNumericLineRaw(
        params,
        allocator,
        sink,
        rpl_whoissecure_code,
        server_name,
        requester_nick,
        &.{target_nick},
        trailing,
    );
}

/// Append `RPL_WHOISCERTFP` (276).
pub fn writeWhoisCertfp(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    fingerprint: []const u8,
) WhoisExtraError!void {
    return writeWhoisCertfpWith(.{}, allocator, sink, server_name, requester_nick, target_nick, fingerprint);
}

/// Append `RPL_WHOISCERTFP` (276) using caller-selected limits.
pub fn writeWhoisCertfpWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    fingerprint: []const u8,
) WhoisExtraError!void {
    try validateEnvelopeWith(params, server_name, requester_nick, target_nick);
    try validateParamWith(params, fingerprint);
    try appendNumericLine(
        params,
        allocator,
        sink,
        rpl_whoiscertfp,
        server_name,
        requester_nick,
        &.{ target_nick, fingerprint },
        "has client certificate fingerprint",
    );
}

/// Append `RPL_WHOISACTUALLY` (338) with the subject's real host and IP.
pub fn writeWhoisActually(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    real_host: []const u8,
    real_ip: []const u8,
) WhoisExtraError!void {
    return writeWhoisActuallyWith(.{}, allocator, sink, server_name, requester_nick, target_nick, real_host, real_ip);
}

/// Append `RPL_WHOISACTUALLY` (338) using caller-selected limits.
pub fn writeWhoisActuallyWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    real_host: []const u8,
    real_ip: []const u8,
) WhoisExtraError!void {
    try validateEnvelopeWith(params, server_name, requester_nick, target_nick);
    try validateHostWith(params, real_host);
    try validateHostWith(params, real_ip);
    try appendNumericLine(
        params,
        allocator,
        sink,
        rpl_whoisactually,
        server_name,
        requester_nick,
        &.{ target_nick, real_host, real_ip },
        "actually using host",
    );
}

/// Append `RPL_WHOISIDLE` (317) with idle seconds and signon timestamp.
pub fn writeWhoisIdle(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    idle_secs: u64,
    signon_ts: u64,
) WhoisExtraError!void {
    return writeWhoisIdleWith(.{}, allocator, sink, server_name, requester_nick, target_nick, idle_secs, signon_ts);
}

/// Append `RPL_WHOISIDLE` (317) using caller-selected limits.
pub fn writeWhoisIdleWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    idle_secs: u64,
    signon_ts: u64,
) WhoisExtraError!void {
    try validateEnvelopeWith(params, server_name, requester_nick, target_nick);

    var idle_buf: [20]u8 = undefined;
    var signon_buf: [20]u8 = undefined;
    const idle = unsignedToken(idle_secs, &idle_buf);
    const signon = unsignedToken(signon_ts, &signon_buf);

    try appendNumericLine(
        params,
        allocator,
        sink,
        rpl_whoisidle,
        server_name,
        requester_nick,
        &.{ target_nick, idle, signon },
        "seconds idle, signon time",
    );
}

pub fn validateServerName(server_name: []const u8) WhoisExtraError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) WhoisExtraError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateNick(nick: []const u8) WhoisExtraError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) WhoisExtraError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateHost(host: []const u8) WhoisExtraError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) WhoisExtraError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateParam(param: []const u8) WhoisExtraError!void {
    return validateParamWith(.{}, param);
}

pub fn validateParamWith(comptime params: Params, param: []const u8) WhoisExtraError!void {
    if (param.len == 0) return error.InvalidParam;
    if (param.len > params.max_param_bytes) return error.ParamTooLong;
    for (param) |ch| {
        if (!validParamByte(ch)) return error.InvalidParam;
    }
}

fn validateEnvelopeWith(
    comptime params: Params,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhoisExtraError!void {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateNickWith(params, target_nick);
}

fn appendNumericLine(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    reply_numeric: numeric.Numeric,
    server_name: []const u8,
    requester_nick: []const u8,
    middle_params: []const []const u8,
    trailing: []const u8,
) WhoisExtraError!void {
    var code_buf: [3]u8 = undefined;
    try appendNumericLineCode(
        params,
        allocator,
        sink,
        numeric.formatCode(reply_numeric, &code_buf),
        server_name,
        requester_nick,
        middle_params,
        trailing,
    );
}

fn appendNumericLineRaw(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    reply_code: u16,
    server_name: []const u8,
    requester_nick: []const u8,
    middle_params: []const []const u8,
    trailing: []const u8,
) WhoisExtraError!void {
    var code_buf: [3]u8 = undefined;
    try appendNumericLineCode(
        params,
        allocator,
        sink,
        formatRawCode(reply_code, &code_buf),
        server_name,
        requester_nick,
        middle_params,
        trailing,
    );
}

fn appendNumericLineCode(
    comptime params: Params,
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    reply_code: []const u8,
    server_name: []const u8,
    requester_nick: []const u8,
    middle_params: []const []const u8,
    trailing: []const u8,
) WhoisExtraError!void {
    const len = numericLineLen(server_name, requester_nick, middle_params, trailing);
    if (len > params.max_line_bytes) return error.MessageTooLong;

    try sink.ensureUnusedCapacity(allocator, len);
    sink.appendSliceAssumeCapacity(":");
    sink.appendSliceAssumeCapacity(server_name);
    sink.appendSliceAssumeCapacity(" ");
    sink.appendSliceAssumeCapacity(reply_code);
    sink.appendSliceAssumeCapacity(" ");
    sink.appendSliceAssumeCapacity(requester_nick);
    for (middle_params) |param| {
        sink.appendSliceAssumeCapacity(" ");
        sink.appendSliceAssumeCapacity(param);
    }
    sink.appendSliceAssumeCapacity(" :");
    sink.appendSliceAssumeCapacity(trailing);
    sink.appendSliceAssumeCapacity("\r\n");
}

fn numericLineLen(
    server_name: []const u8,
    requester_nick: []const u8,
    middle_params: []const []const u8,
    trailing: []const u8,
) usize {
    var total: usize = 1 + server_name.len + 1 + 3 + 1 + requester_nick.len;
    for (middle_params) |param| {
        total += 1 + param.len;
    }
    total += 2 + trailing.len + 2;
    return total;
}

fn formatRawCode(value: u16, buf: *[3]u8) []const u8 {
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

fn unsignedToken(value: u64, buf: *[20]u8) []const u8 {
    var n = buf.len;
    var current = value;
    while (true) {
        n -= 1;
        buf[n] = @as(u8, '0') + @as(u8, @intCast(current % 10));
        current /= 10;
        if (current == 0) break;
    }
    return buf[n..];
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validHostByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn validParamByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return ch != ':';
}

test "builds WHOIS secure 671" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    try writeWhoisSecure(std.testing.allocator, &out, "irc.example", "dan", "alice");

    try std.testing.expectEqualStrings(
        ":irc.example 671 dan alice :is using a secure connection\r\n",
        out.items,
    );
}

test "builds WHOIS secure 671 with negotiated cipher" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    try writeWhoisSecureCipher(std.testing.allocator, &out, "irc.example", "dan", "alice", "TLS_AES_128_GCM_SHA256");

    try std.testing.expectEqualStrings(
        ":irc.example 671 dan alice :is using a secure connection (TLS_AES_128_GCM_SHA256)\r\n",
        out.items,
    );
}

test "builds WHOIS certfp 276" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    try writeWhoisCertfp(std.testing.allocator, &out, "irc.example", "dan", "alice", "abcdef0123456789");

    try std.testing.expectEqualStrings(
        ":irc.example 276 dan alice abcdef0123456789 :has client certificate fingerprint\r\n",
        out.items,
    );
}

test "builds WHOIS actually 338" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    try writeWhoisActually(std.testing.allocator, &out, "irc.example", "dan", "alice", "real.example", "203.0.113.9");

    try std.testing.expectEqualStrings(
        ":irc.example 338 dan alice real.example 203.0.113.9 :actually using host\r\n",
        out.items,
    );
}

test "builds WHOIS idle 317" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    try writeWhoisIdle(std.testing.allocator, &out, "irc.example", "dan", "alice", 42, 1700000000);

    try std.testing.expectEqualStrings(
        ":irc.example 317 dan alice 42 1700000000 :seconds idle, signon time\r\n",
        out.items,
    );
}
