// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-side IRCv3 STS policy builder/parser.
//!
//! This module is intentionally pure: callers provide config text and output
//! storage, and the wire value formatting is delegated to `sts.zig`.
const std = @import("std");
const sts = @import("sts.zig");

pub const MAX_CAP_VALUE_LEN: usize = sts.MAX_VALUE_LEN;

pub const Error = sts.StsError || error{
    DuplicateKey,
    InvalidBoolean,
    InvalidConfig,
    InvalidInteger,
    InvalidKey,
    MissingDuration,
    MissingPort,
    UnknownKey,
};

pub const AdvertisementForm = enum {
    /// Secure-client persistence policy. Includes the configured secure port so
    /// one config can generate a complete advertised policy value.
    tls,
    /// Insecure-client upgrade policy. Per IRCv3 STS, the port is the required
    /// actionable token for clients that need to reconnect securely.
    plaintext_redirect,
    /// Complete server policy value, useful for CAP LS value overrides.
    combined,
};

pub const ServerConfig = struct {
    duration_seconds: ?u64 = null,
    port: ?u16 = null,
    preload: bool = false,

    pub fn policy(self: ServerConfig) Error!Policy {
        return .{
            .duration_seconds = self.duration_seconds orelse return error.MissingDuration,
            .port = self.port orelse return error.MissingPort,
            .preload = self.preload,
        };
    }
};

pub const Policy = struct {
    duration_seconds: u64,
    port: u16,
    preload: bool = false,

    pub fn value(self: Policy, form: AdvertisementForm) sts.Value {
        return switch (form) {
            .tls, .combined => .{
                .duration_seconds = self.duration_seconds,
                .port = self.port,
                .preload = self.preload,
            },
            .plaintext_redirect => .{ .port = self.port },
        };
    }
};

/// Build the STS capability value without the `sts=` capability name.
pub fn writeCapValue(policy: Policy, form: AdvertisementForm, out: []u8) Error![]const u8 {
    return sts.writeValue(policy.value(form), out);
}

/// Build the CAP LS token, including the `sts=` capability name.
pub fn writeCapLsToken(policy: Policy, form: AdvertisementForm, out: []u8) Error![]const u8 {
    return sts.writeAdvertisement(.{
        .duration_seconds = policy.value(form).duration_seconds,
        .port = policy.value(form).port,
        .preload = policy.value(form).preload,
    }, out);
}

/// Parse a small STS server config fragment and return a validated policy.
///
/// Accepted keys are:
///   duration = 2592000
///   duration_seconds = 2592000
///   port = 6697
///   preload = true
///
/// Lines may be blank and may contain `#` comments outside quoted strings.
pub fn parseConfig(input: []const u8) Error!ServerConfig {
    var config = ServerConfig{};
    var seen_duration = false;
    var seen_port = false;
    var seen_preload = false;

    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, stripComment(raw_line), " \t\r");
        if (line.len == 0) continue;

        const equals = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidConfig;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const raw_value = std.mem.trim(u8, line[equals + 1 ..], " \t");
        if (key.len == 0 or raw_value.len == 0) return error.InvalidConfig;
        if (!validKey(key)) return error.InvalidKey;

        if (std.mem.eql(u8, key, "duration") or std.mem.eql(u8, key, "duration_seconds")) {
            if (seen_duration) return error.DuplicateKey;
            config.duration_seconds = try parseU64(raw_value);
            seen_duration = true;
        } else if (std.mem.eql(u8, key, "port")) {
            if (seen_port) return error.DuplicateKey;
            config.port = try parsePort(raw_value);
            seen_port = true;
        } else if (std.mem.eql(u8, key, "preload")) {
            if (seen_preload) return error.DuplicateKey;
            config.preload = try parseBool(raw_value);
            seen_preload = true;
        } else {
            return error.UnknownKey;
        }
    }

    return config;
}

/// Parse server config and build the complete STS policy value.
pub fn parseConfigCapValue(input: []const u8, out: []u8) Error![]const u8 {
    const policy = try (try parseConfig(input)).policy();
    return writeCapValue(policy, .combined, out);
}

fn parseU64(raw: []const u8) Error!u64 {
    const value = unquote(raw);
    if (value.len == 0 or value[0] == '+') return error.InvalidInteger;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidInteger;
    }
    return std.fmt.parseInt(u64, value, 10) catch return error.InvalidInteger;
}

fn parsePort(raw: []const u8) Error!u16 {
    const raw_port = try parseU64(raw);
    if (raw_port == 0 or raw_port > std.math.maxInt(u16)) return error.InvalidPort;
    return @intCast(raw_port);
}

fn parseBool(raw: []const u8) Error!bool {
    const value = unquote(raw);
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBoolean;
}

fn unquote(raw: []const u8) []const u8 {
    if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
        return raw[1 .. raw.len - 1];
    }
    return raw;
}

fn stripComment(line: []const u8) []const u8 {
    var quoted = false;
    for (line, 0..) |ch, index| {
        if (ch == '"') quoted = !quoted;
        if (ch == '#' and !quoted) return line[0..index];
    }
    return line;
}

fn validKey(key: []const u8) bool {
    for (key) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '_' => {},
            else => return false,
        }
    }
    return true;
}

test "build sts cap value for tls and plaintext redirect forms" {
    const allocator = std.testing.allocator;
    const policy = Policy{
        .duration_seconds = 2_592_000,
        .port = 6697,
        .preload = true,
    };

    const tls_buf = try allocator.alloc(u8, MAX_CAP_VALUE_LEN);
    defer allocator.free(tls_buf);
    const tls_value = try writeCapValue(policy, .tls, tls_buf);
    try std.testing.expectEqualStrings("duration=2592000,port=6697,preload", tls_value);

    const redirect_buf = try allocator.alloc(u8, MAX_CAP_VALUE_LEN);
    defer allocator.free(redirect_buf);
    const redirect_value = try writeCapValue(policy, .plaintext_redirect, redirect_buf);
    try std.testing.expectEqualStrings("port=6697", redirect_value);
}

test "build sts cap ls token exact bytes" {
    const allocator = std.testing.allocator;
    const policy = Policy{
        .duration_seconds = 604800,
        .port = 6697,
    };

    const out = try allocator.alloc(u8, MAX_CAP_VALUE_LEN);
    defer allocator.free(out);
    const token = try writeCapLsToken(policy, .combined, out);
    try std.testing.expectEqualStrings("sts=duration=604800,port=6697", token);
}

test "parse server sts config into cap value exact bytes" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, MAX_CAP_VALUE_LEN);
    defer allocator.free(out);

    const value = try parseConfigCapValue(
        \\# server STS policy
        \\duration = 2592000
        \\port = 6697
        \\preload = true
    , out);

    try std.testing.expectEqualStrings("duration=2592000,port=6697,preload", value);
}

test "parse config validates required policy parts" {
    const config = try parseConfig(
        \\duration_seconds = "0"
        \\port = "6697"
        \\preload = false
    );
    const policy = try config.policy();

    try std.testing.expectEqual(@as(u64, 0), policy.duration_seconds);
    try std.testing.expectEqual(@as(u16, 6697), policy.port);
    try std.testing.expect(!policy.preload);
    try std.testing.expectError(error.MissingPort, (try parseConfig("duration = 60")).policy());
    try std.testing.expectError(error.DuplicateKey, parseConfig(
        \\duration = 60
        \\duration_seconds = 61
    ));
}
