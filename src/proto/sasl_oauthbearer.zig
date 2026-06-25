// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure SASL OAUTHBEARER helpers (RFC 7628).
//!
//! This module parses the already-base64-decoded client initial response and
//! delegates token checks to a caller-provided verifier. It performs no I/O,
//! token introspection, networking, or allocation.
const std = @import("std");

const field_separator: u8 = 0x01;
const bearer_prefix = "Bearer ";
const failure_invalid_token =
    "{\"status\":\"invalid_token\",\"schemes\":\"bearer\"}";

/// SASL mechanism name advertised at the protocol boundary.
pub const mechanism = "OAUTHBEARER";

/// Parser limits for one OAUTHBEARER client initial response.
pub const Params = struct {
    /// Maximum decoded SASL response size.
    max_message_bytes: usize = 8192,
    /// Maximum raw GS2 authorization identity bytes.
    max_authzid_bytes: usize = 255,
    /// Maximum bearer token bytes after `Bearer `.
    max_token_bytes: usize = 4096,
    /// Maximum optional host field bytes.
    max_host_bytes: usize = 255,
};

/// Errors returned while parsing or formatting OAUTHBEARER messages.
pub const ParseError = error{
    DuplicateField,
    InvalidAuthScheme,
    InvalidAuthzid,
    InvalidField,
    InvalidHost,
    InvalidPort,
    InvalidToken,
    MalformedMessage,
    MessageTooLarge,
    MissingAuth,
    OutputTooSmall,
    UnsupportedChannelBinding,
    UnsupportedField,
};

/// Parsed OAUTHBEARER client initial response.
pub const ClientFirst = struct {
    /// Optional GS2 authorization identity, borrowed from the input.
    authzid: ?[]const u8,
    /// Bearer token bytes after `auth=Bearer `, borrowed from the input.
    token: []const u8,
    /// Optional `host` key-value field, borrowed from the input.
    host: ?[]const u8,
    /// Optional `port` key-value field parsed as a TCP port.
    port: ?u16,

    /// Parse one already-base64-decoded OAUTHBEARER client initial response.
    pub fn parse(msg: []const u8) ParseError!ClientFirst {
        return parseBounded(.{}, msg);
    }

    /// Parse one decoded OAUTHBEARER response with explicit size limits.
    pub fn parseBounded(comptime params: Params, msg: []const u8) ParseError!ClientFirst {
        if (msg.len > params.max_message_bytes) return error.MessageTooLarge;

        const gs2 = try parseGs2Header(params, msg);
        if (gs2.header_len >= msg.len or msg[gs2.header_len] != field_separator) {
            return error.MalformedMessage;
        }
        if (msg.len < gs2.header_len + 3) return error.MalformedMessage;
        if (msg[msg.len - 1] != field_separator or msg[msg.len - 2] != field_separator) {
            return error.MalformedMessage;
        }

        const fields = msg[gs2.header_len + 1 .. msg.len - 2];
        if (fields.len == 0) return error.MissingAuth;

        var parsed = ClientFirst{
            .authzid = gs2.authzid,
            .token = "",
            .host = null,
            .port = null,
        };
        var seen_auth = false;
        var seen_host = false;
        var seen_port = false;

        var it = std.mem.splitScalar(u8, fields, field_separator);
        while (it.next()) |field| {
            if (field.len == 0) return error.InvalidField;
            const kv = try splitField(field);
            if (!validKey(kv.key)) return error.InvalidField;

            if (std.mem.eql(u8, kv.key, "auth")) {
                if (seen_auth) return error.DuplicateField;
                seen_auth = true;
                parsed.token = try parseAuthValue(params, kv.value);
            } else if (std.mem.eql(u8, kv.key, "host")) {
                if (seen_host) return error.DuplicateField;
                seen_host = true;
                if (!validHost(params, kv.value)) return error.InvalidHost;
                parsed.host = kv.value;
            } else if (std.mem.eql(u8, kv.key, "port")) {
                if (seen_port) return error.DuplicateField;
                seen_port = true;
                parsed.port = parsePort(kv.value) catch return error.InvalidPort;
            } else {
                return error.UnsupportedField;
            }
        }

        if (!seen_auth) return error.MissingAuth;
        return parsed;
    }
};

/// Caller-provided bearer-token verifier.
pub const Verifier = struct {
    /// Opaque verifier context supplied by the caller.
    ctx: *anyopaque,
    /// Return the authenticated account name, or null when the token fails.
    verify: *const fn (*anyopaque, token: []const u8, authzid: ?[]const u8) ?[]const u8,
};

/// Server failure status encoded as an OAUTHBEARER JSON challenge.
pub const FailureStatus = enum {
    invalid_token,
};

/// One OAUTHBEARER authentication step outcome.
pub const StepDecision = union(enum) {
    /// Authenticated account name returned by the verifier.
    success: []const u8,
    /// JSON failure challenge to send before the client terminates with `^A`.
    failure: []const u8,
};

/// Result of processing one OAUTHBEARER client initial response.
pub const Result = ParseError!StepDecision;

/// Parse and verify one OAUTHBEARER client initial response.
pub fn step(msg: []const u8, verifier: Verifier, out: []u8) Result {
    const first = try ClientFirst.parse(msg);
    if (verifier.verify(verifier.ctx, first.token, first.authzid)) |account| {
        return .{ .success = account };
    }

    const failure = formatFailure(out, .invalid_token);
    if (failure.len == 0 and out.len < failurePayload(.invalid_token).len) {
        return error.OutputTooSmall;
    }
    return .{ .failure = failure };
}

/// Format the RFC 7628 JSON failure challenge into caller-owned storage.
pub fn formatFailure(out: []u8, status: FailureStatus) []const u8 {
    const payload = failurePayload(status);
    if (out.len < payload.len) return out[0..0];
    @memcpy(out[0..payload.len], payload);
    return out[0..payload.len];
}

const Gs2Header = struct {
    header_len: usize,
    authzid: ?[]const u8,
};

const Field = struct {
    key: []const u8,
    value: []const u8,
};

fn parseGs2Header(comptime params: Params, msg: []const u8) ParseError!Gs2Header {
    if (msg.len < 4) return error.MalformedMessage;

    switch (msg[0]) {
        'n', 'y' => {},
        'p' => return error.UnsupportedChannelBinding,
        else => return error.MalformedMessage,
    }
    if (msg[1] != ',') return error.MalformedMessage;

    const comma_rel = std.mem.indexOfScalar(u8, msg[2..], ',') orelse {
        return error.MalformedMessage;
    };
    const authzid_field = msg[2 .. 2 + comma_rel];
    const header_len = 2 + comma_rel + 1;

    if (authzid_field.len == 0) {
        return .{ .header_len = header_len, .authzid = null };
    }
    if (!std.mem.startsWith(u8, authzid_field, "a=")) return error.MalformedMessage;

    const authzid = authzid_field["a=".len..];
    if (!validAuthzid(params, authzid)) return error.InvalidAuthzid;
    return .{ .header_len = header_len, .authzid = authzid };
}

fn splitField(field: []const u8) ParseError!Field {
    const eq = std.mem.indexOfScalar(u8, field, '=') orelse return error.InvalidField;
    if (eq == 0) return error.InvalidField;
    return .{ .key = field[0..eq], .value = field[eq + 1 ..] };
}

fn parseAuthValue(comptime params: Params, value: []const u8) ParseError![]const u8 {
    if (!std.mem.startsWith(u8, value, bearer_prefix)) return error.InvalidAuthScheme;
    const token = value[bearer_prefix.len..];
    if (token.len == 0 or token.len > params.max_token_bytes) return error.InvalidToken;
    if (!validBearerToken(token)) return error.InvalidToken;
    return token;
}

fn parsePort(value: []const u8) !u16 {
    if (value.len == 0) return error.EmptyPort;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidCharacter;
    }
    const parsed = try std.fmt.parseInt(u16, value, 10);
    if (parsed == 0) return error.ZeroPort;
    return parsed;
}

fn failurePayload(status: FailureStatus) []const u8 {
    return switch (status) {
        .invalid_token => failure_invalid_token,
    };
}

fn validAuthzid(comptime params: Params, value: []const u8) bool {
    if (value.len == 0 or value.len > params.max_authzid_bytes) return false;

    var index: usize = 0;
    while (index < value.len) {
        const byte = value[index];
        if (byte == ',') return false;
        if (byte == '=') {
            if (index + 2 >= value.len) return false;
            const esc = value[index + 1 .. index + 3];
            if (!std.mem.eql(u8, esc, "2C") and !std.mem.eql(u8, esc, "3D")) {
                return false;
            }
            index += 3;
            continue;
        }
        if (byte < 0x21 or byte == 0x7f) return false;
        index += 1;
    }
    return true;
}

fn validBearerToken(token: []const u8) bool {
    var padding = false;
    for (token) |byte| {
        if (byte == '=') {
            padding = true;
            continue;
        }
        if (padding) return false;
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '-', '.', '_', '~', '+', '/' => {},
            else => return false,
        }
    }
    return true;
}

fn validHost(comptime params: Params, value: []const u8) bool {
    if (value.len == 0 or value.len > params.max_host_bytes) return false;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '.', '-', '_', ':', '[', ']' => {},
            else => return false,
        }
    }
    return true;
}

fn validKey(key: []const u8) bool {
    if (key.len == 0) return false;
    for (key) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '.', '-', '_' => {},
            else => return false,
        }
    }
    return true;
}

test "parse valid initial response with token only" {
    const allocator = std.testing.allocator;
    const raw = "n,," ++ "\x01" ++ "auth=Bearer abc.DEF-123_~+/==" ++ "\x01\x01";

    // Arrange.
    const msg = try allocator.dupe(u8, raw);
    defer allocator.free(msg);

    // Act.
    const parsed = try ClientFirst.parse(msg);

    // Assert.
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.authzid);
    try std.testing.expectEqualStrings("abc.DEF-123_~+/==", parsed.token);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.host);
    try std.testing.expectEqual(@as(?u16, null), parsed.port);
}

test "parse valid initial response with authzid" {
    const allocator = std.testing.allocator;
    const raw = "n,a=alice," ++ "\x01" ++ "auth=Bearer token.123" ++ "\x01\x01";

    // Arrange.
    const msg = try allocator.dupe(u8, raw);
    defer allocator.free(msg);

    // Act.
    const parsed = try ClientFirst.parse(msg);

    // Assert.
    try std.testing.expectEqualStrings("alice", parsed.authzid.?);
    try std.testing.expectEqualStrings("token.123", parsed.token);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.host);
    try std.testing.expectEqual(@as(?u16, null), parsed.port);
}

test "parse valid initial response with host and port" {
    const allocator = std.testing.allocator;
    const raw =
        "y,," ++ "\x01" ++
        "host=irc.example.net" ++ "\x01" ++
        "port=6697" ++ "\x01" ++
        "auth=Bearer header.payload.signature" ++ "\x01\x01";

    // Arrange.
    const msg = try allocator.dupe(u8, raw);
    defer allocator.free(msg);

    // Act.
    const parsed = try ClientFirst.parse(msg);

    // Assert.
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.authzid);
    try std.testing.expectEqualStrings("header.payload.signature", parsed.token);
    try std.testing.expectEqualStrings("irc.example.net", parsed.host.?);
    try std.testing.expectEqual(@as(?u16, 6697), parsed.port);
}

test "parse rejects malformed messages and bad key-value fields" {
    const allocator = std.testing.allocator;

    // Arrange.
    const missing_auth = try allocator.dupe(u8, "n,," ++ "\x01" ++ "host=irc.example.net" ++ "\x01\x01");
    defer allocator.free(missing_auth);
    const bad_kv = try allocator.dupe(u8, "n,," ++ "\x01" ++ "host" ++ "\x01" ++ "auth=Bearer token" ++ "\x01\x01");
    defer allocator.free(bad_kv);
    const duplicate_auth = try allocator.dupe(
        u8,
        "n,," ++ "\x01" ++ "auth=Bearer one" ++ "\x01" ++ "auth=Bearer two" ++ "\x01\x01",
    );
    defer allocator.free(duplicate_auth);
    const unknown_field = try allocator.dupe(u8, "n,," ++ "\x01" ++ "scope=read" ++ "\x01" ++ "auth=Bearer token" ++ "\x01\x01");
    defer allocator.free(unknown_field);
    const bad_port = try allocator.dupe(u8, "n,," ++ "\x01" ++ "port=70000" ++ "\x01" ++ "auth=Bearer token" ++ "\x01\x01");
    defer allocator.free(bad_port);
    const channel_binding = try allocator.dupe(u8, "p=tls-exporter,," ++ "\x01" ++ "auth=Bearer token" ++ "\x01\x01");
    defer allocator.free(channel_binding);

    // Act and assert.
    try std.testing.expectError(error.MissingAuth, ClientFirst.parse(missing_auth));
    try std.testing.expectError(error.InvalidField, ClientFirst.parse(bad_kv));
    try std.testing.expectError(error.DuplicateField, ClientFirst.parse(duplicate_auth));
    try std.testing.expectError(error.UnsupportedField, ClientFirst.parse(unknown_field));
    try std.testing.expectError(error.InvalidPort, ClientFirst.parse(bad_port));
    try std.testing.expectError(error.UnsupportedChannelBinding, ClientFirst.parse(channel_binding));
}

test "step returns verifier account on successful token check" {
    const allocator = std.testing.allocator;
    const Stub = struct {
        fn verify(ctx: *anyopaque, token: []const u8, authzid: ?[]const u8) ?[]const u8 {
            const calls: *usize = @ptrCast(@alignCast(ctx));
            calls.* += 1;
            if (!std.mem.eql(u8, token, "good.token")) return null;
            if (authzid == null or !std.mem.eql(u8, authzid.?, "alice")) return null;
            return "alice-account";
        }
    };

    // Arrange.
    var calls: usize = 0;
    const verifier = Verifier{ .ctx = &calls, .verify = Stub.verify };
    const msg = try allocator.dupe(
        u8,
        "n,a=alice," ++ "\x01" ++ "auth=Bearer good.token" ++ "\x01\x01",
    );
    defer allocator.free(msg);
    var out: [128]u8 = undefined;

    // Act.
    const decision = try step(msg, verifier, &out);

    // Assert.
    switch (decision) {
        .success => |account| try std.testing.expectEqualStrings("alice-account", account),
        .failure => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), calls);
}

test "step formats invalid token JSON on failed token check" {
    const allocator = std.testing.allocator;
    const Stub = struct {
        fn verify(ctx: *anyopaque, token: []const u8, authzid: ?[]const u8) ?[]const u8 {
            _ = ctx;
            _ = token;
            _ = authzid;
            return null;
        }
    };

    // Arrange.
    var ctx: u8 = 0;
    const verifier = Verifier{ .ctx = &ctx, .verify = Stub.verify };
    const msg = try allocator.dupe(u8, "n,," ++ "\x01" ++ "auth=Bearer expired" ++ "\x01\x01");
    defer allocator.free(msg);
    var out: [128]u8 = undefined;

    // Act.
    const decision = try step(msg, verifier, &out);

    // Assert.
    switch (decision) {
        .success => return error.TestUnexpectedResult,
        .failure => |json| try std.testing.expectEqualStrings(failure_invalid_token, json),
    }
}

test "format failure returns empty slice when output is too small" {
    const allocator = std.testing.allocator;

    // Arrange.
    const out = try allocator.alloc(u8, failure_invalid_token.len - 1);
    defer allocator.free(out);

    // Act.
    const json = formatFailure(out, .invalid_token);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), json.len);
}

test {
    std.testing.refAllDecls(@This());
}
