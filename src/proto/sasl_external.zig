//! Pure SASL EXTERNAL helpers.
//!
//! This module does no TLS, socket, or IRC session I/O. Callers provide the
//! TLS-authenticated external identity and send the returned AUTHENTICATE
//! payloads or lines through their own transport.
const std = @import("std");

pub const mechanism = "EXTERNAL";
pub const authenticate_command = "AUTHENTICATE";
pub const max_authenticate_payload: usize = 400;
pub const empty_response_payload = "+";

pub const Error = error{
    AuthorizationIdentityMismatch,
    EmptyTlsIdentity,
    IncompletePayload,
    InvalidAuthenticateLine,
    InvalidChunkSequence,
    PayloadTooLong,
    UnknownExternalIdentity,
};

pub const IdentityMapping = struct {
    /// TLS-authenticated peer identity, such as a certificate fingerprint or CN.
    external_identity: []const u8,
    /// Local account name granted when the external identity is accepted.
    account: []const u8,
    /// Optional explicit authorization identity accepted from the client.
    /// When null, `account` is the accepted explicit authzid.
    authzid: ?[]const u8 = null,
};

pub const ServerDecision = union(enum) {
    success: []const u8,
    failure: Error,
};

pub const AuthenticateChunks = struct {
    encoded: []u8,
    chunks: []const []const u8,

    pub fn deinit(self: *AuthenticateChunks, allocator: std.mem.Allocator) void {
        allocator.free(self.chunks);
        allocator.free(self.encoded);
        self.* = undefined;
    }
};

pub const AuthenticateLines = struct {
    storage: []u8,
    lines: []const []const u8,

    pub fn deinit(self: *AuthenticateLines, allocator: std.mem.Allocator) void {
        allocator.free(self.lines);
        allocator.free(self.storage);
        self.* = undefined;
    }
};

/// Build the client initial response payload for SASL EXTERNAL.
///
/// The raw response is the authorization identity. An empty authzid is encoded
/// as IRC SASL's special `+` empty-response payload.
pub fn clientInitialResponsePayload(
    allocator: std.mem.Allocator,
    authzid: []const u8,
) std.mem.Allocator.Error![]u8 {
    return encodeAuthenticatePayload(allocator, authzid);
}

/// Encode one AUTHENTICATE payload using standard padded Base64.
///
/// Empty raw responses use the IRC SASL `+` convention instead of Base64.
pub fn encodeAuthenticatePayload(
    allocator: std.mem.Allocator,
    response: []const u8,
) std.mem.Allocator.Error![]u8 {
    if (response.len == 0) return allocator.dupe(u8, empty_response_payload);

    const len = std.base64.standard.Encoder.calcSize(response.len);
    const out = try allocator.alloc(u8, len);
    _ = std.base64.standard.Encoder.encode(out, response);
    return out;
}

/// Decode one AUTHENTICATE payload.
///
/// `+` decodes to an empty response. Other payloads must be standard padded
/// Base64.
pub fn decodeAuthenticatePayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
) (std.mem.Allocator.Error || std.base64.Error)![]u8 {
    if (std.mem.eql(u8, payload, empty_response_payload)) {
        return allocator.alloc(u8, 0);
    }

    const len = try std.base64.standard.Decoder.calcSizeForSlice(payload);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    try std.base64.standard.Decoder.decode(out, payload);
    return out;
}

/// Encode a raw SASL response into IRC AUTHENTICATE payload chunks.
///
/// Each returned chunk is at most 400 bytes. If the Base64 output is exactly a
/// multiple of 400 bytes, a terminal `+` chunk is added to mark completion.
pub fn encodeAuthenticateChunks(
    allocator: std.mem.Allocator,
    response: []const u8,
) std.mem.Allocator.Error!AuthenticateChunks {
    const encoded = try encodeAuthenticatePayload(allocator, response);
    errdefer allocator.free(encoded);

    if (std.mem.eql(u8, encoded, empty_response_payload)) {
        const chunks = try allocator.alloc([]const u8, 1);
        chunks[0] = encoded;
        return .{ .encoded = encoded, .chunks = chunks };
    }

    const data_chunks = (encoded.len + max_authenticate_payload - 1) / max_authenticate_payload;
    const needs_terminal_empty = encoded.len % max_authenticate_payload == 0;
    const total_chunks = data_chunks + @intFromBool(needs_terminal_empty);
    const chunks = try allocator.alloc([]const u8, total_chunks);
    errdefer allocator.free(chunks);

    var index: usize = 0;
    while (index < data_chunks) : (index += 1) {
        const start = index * max_authenticate_payload;
        const end = @min(start + max_authenticate_payload, encoded.len);
        chunks[index] = encoded[start..end];
    }
    if (needs_terminal_empty) {
        chunks[data_chunks] = empty_response_payload;
    }

    return .{ .encoded = encoded, .chunks = chunks };
}

/// Reassemble IRC AUTHENTICATE payload chunks and decode the raw SASL response.
pub fn decodeAuthenticateChunks(
    allocator: std.mem.Allocator,
    chunks: []const []const u8,
) (std.mem.Allocator.Error || std.base64.Error || Error)![]u8 {
    if (chunks.len == 0) return error.InvalidChunkSequence;
    if (chunks.len == 1) {
        if (chunks[0].len > max_authenticate_payload) return error.PayloadTooLong;
        if (chunks[0].len == max_authenticate_payload) return error.IncompletePayload;
        return decodeAuthenticatePayload(allocator, chunks[0]);
    }

    var data_end = chunks.len;
    const has_terminal_empty = std.mem.eql(u8, chunks[chunks.len - 1], empty_response_payload);
    if (has_terminal_empty) data_end -= 1;
    if (data_end == 0) return error.InvalidChunkSequence;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    for (chunks[0..data_end], 0..) |chunk, index| {
        if (std.mem.eql(u8, chunk, empty_response_payload)) {
            return error.InvalidChunkSequence;
        }
        if (chunk.len > max_authenticate_payload) return error.PayloadTooLong;
        if (index + 1 < data_end and chunk.len != max_authenticate_payload) {
            return error.InvalidChunkSequence;
        }
        if (index + 1 == data_end and chunk.len == max_authenticate_payload and !has_terminal_empty) {
            return error.IncompletePayload;
        }
        try encoded.appendSlice(allocator, chunk);
    }

    const joined = try encoded.toOwnedSlice(allocator);
    defer allocator.free(joined);
    return decodeAuthenticatePayload(allocator, joined);
}

/// Encode raw SASL response bytes as complete `AUTHENTICATE <payload>` lines.
pub fn encodeAuthenticateLines(
    allocator: std.mem.Allocator,
    response: []const u8,
) std.mem.Allocator.Error!AuthenticateLines {
    var chunks = try encodeAuthenticateChunks(allocator, response);
    defer chunks.deinit(allocator);

    var storage_len: usize = 0;
    for (chunks.chunks) |chunk| {
        storage_len += authenticate_command.len + 1 + chunk.len;
    }

    const storage = try allocator.alloc(u8, storage_len);
    errdefer allocator.free(storage);
    const lines = try allocator.alloc([]const u8, chunks.chunks.len);
    errdefer allocator.free(lines);

    var cursor: usize = 0;
    for (chunks.chunks, 0..) |chunk, index| {
        const start = cursor;
        @memcpy(storage[cursor .. cursor + authenticate_command.len], authenticate_command);
        cursor += authenticate_command.len;
        storage[cursor] = ' ';
        cursor += 1;
        @memcpy(storage[cursor .. cursor + chunk.len], chunk);
        cursor += chunk.len;
        lines[index] = storage[start..cursor];
    }

    return .{ .storage = storage, .lines = lines };
}

/// Return the payload from an `AUTHENTICATE <payload>` line.
pub fn payloadFromAuthenticateLine(line: []const u8) Error![]const u8 {
    const prefix = authenticate_command ++ " ";
    if (!std.mem.startsWith(u8, line, prefix)) return error.InvalidAuthenticateLine;
    const payload = line[prefix.len..];
    if (payload.len == 0) return error.InvalidAuthenticateLine;
    return payload;
}

/// Decode complete `AUTHENTICATE <payload>` lines.
pub fn decodeAuthenticateLines(
    allocator: std.mem.Allocator,
    lines: []const []const u8,
) (std.mem.Allocator.Error || std.base64.Error || Error)![]u8 {
    var payloads: std.ArrayList([]const u8) = .empty;
    defer payloads.deinit(allocator);

    for (lines) |line| {
        try payloads.append(allocator, try payloadFromAuthenticateLine(line));
    }

    const owned_payloads = try payloads.toOwnedSlice(allocator);
    defer allocator.free(owned_payloads);
    return decodeAuthenticateChunks(allocator, owned_payloads);
}

/// Decide whether a TLS-authenticated identity may authenticate via EXTERNAL.
///
/// Empty client authzid selects the mapped account. Explicit client authzid
/// must match `mapping.authzid` when set, otherwise `mapping.account`.
pub fn decideServer(
    tls_identity: ?[]const u8,
    client_authzid: []const u8,
    mappings: []const IdentityMapping,
) ServerDecision {
    const identity = tls_identity orelse return .{ .failure = error.EmptyTlsIdentity };
    if (identity.len == 0) return .{ .failure = error.EmptyTlsIdentity };

    var saw_identity = false;
    for (mappings) |mapping| {
        if (!secureEql(identity, mapping.external_identity)) continue;
        saw_identity = true;

        if (client_authzid.len == 0) return .{ .success = mapping.account };

        const accepted_authzid = mapping.authzid orelse mapping.account;
        if (std.mem.eql(u8, client_authzid, accepted_authzid)) {
            return .{ .success = mapping.account };
        }
    }

    if (saw_identity) return .{ .failure = error.AuthorizationIdentityMismatch };
    return .{ .failure = error.UnknownExternalIdentity };
}

fn secureEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |left, right| {
        diff |= left ^ right;
    }
    return diff == 0;
}

test "empty authzid round-trip" {
    const allocator = std.testing.allocator;

    const payload = try clientInitialResponsePayload(allocator, "");
    defer allocator.free(payload);
    try std.testing.expectEqualStrings(empty_response_payload, payload);

    const decoded = try decodeAuthenticatePayload(allocator, payload);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("", decoded);

    var chunks = try encodeAuthenticateChunks(allocator, "");
    defer chunks.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), chunks.chunks.len);
    try std.testing.expectEqualStrings(empty_response_payload, chunks.chunks[0]);

    var lines = try encodeAuthenticateLines(allocator, "");
    defer lines.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), lines.lines.len);
    try std.testing.expectEqualStrings("AUTHENTICATE +", lines.lines[0]);

    const from_lines = try decodeAuthenticateLines(allocator, lines.lines);
    defer allocator.free(from_lines);
    try std.testing.expectEqualStrings("", from_lines);
}

test "explicit authzid round-trip" {
    const allocator = std.testing.allocator;

    const payload = try clientInitialResponsePayload(allocator, "alice");
    defer allocator.free(payload);
    try std.testing.expectEqualStrings("YWxpY2U=", payload);

    const decoded = try decodeAuthenticatePayload(allocator, payload);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("alice", decoded);

    var chunks = try encodeAuthenticateChunks(allocator, "alice");
    defer chunks.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), chunks.chunks.len);
    try std.testing.expectEqualStrings("YWxpY2U=", chunks.chunks[0]);
}

test "chunking long response into authenticate lines and reassembly" {
    const allocator = std.testing.allocator;

    var response: [350]u8 = undefined;
    for (&response, 0..) |*byte, index| {
        byte.* = @intCast('a' + (index % 26));
    }

    var chunks = try encodeAuthenticateChunks(allocator, response[0..]);
    defer chunks.deinit(allocator);
    try std.testing.expect(chunks.encoded.len > max_authenticate_payload);
    try std.testing.expectEqual(@as(usize, 2), chunks.chunks.len);
    try std.testing.expectEqual(max_authenticate_payload, chunks.chunks[0].len);
    try std.testing.expect(chunks.chunks[1].len < max_authenticate_payload);

    const decoded_chunks = try decodeAuthenticateChunks(allocator, chunks.chunks);
    defer allocator.free(decoded_chunks);
    try std.testing.expectEqualSlices(u8, response[0..], decoded_chunks);

    var lines = try encodeAuthenticateLines(allocator, response[0..]);
    defer lines.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), lines.lines.len);
    try std.testing.expect(std.mem.startsWith(u8, lines.lines[0], "AUTHENTICATE "));

    const decoded_lines = try decodeAuthenticateLines(allocator, lines.lines);
    defer allocator.free(decoded_lines);
    try std.testing.expectEqualSlices(u8, response[0..], decoded_lines);
}

test "exact 400-byte base64 chunk gets terminal empty payload" {
    const allocator = std.testing.allocator;

    var response: [300]u8 = undefined;
    @memset(&response, 'x');

    var chunks = try encodeAuthenticateChunks(allocator, response[0..]);
    defer chunks.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 400), chunks.encoded.len);
    try std.testing.expectEqual(@as(usize, 2), chunks.chunks.len);
    try std.testing.expectEqualStrings(empty_response_payload, chunks.chunks[1]);

    const decoded = try decodeAuthenticateChunks(allocator, chunks.chunks);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, response[0..], decoded);

    try std.testing.expectError(
        error.IncompletePayload,
        decodeAuthenticateChunks(allocator, chunks.chunks[0..1]),
    );
}

test "server accepts matching identity and rejects mismatch" {
    const mappings = [_]IdentityMapping{
        .{ .external_identity = "cert:abc123", .account = "alice" },
        .{ .external_identity = "cn:service", .account = "service-account", .authzid = "service" },
    };

    const empty_authzid = decideServer("cert:abc123", "", &mappings);
    switch (empty_authzid) {
        .success => |account| try std.testing.expectEqualStrings("alice", account),
        .failure => return error.TestUnexpectedResult,
    }

    const explicit_account = decideServer("cert:abc123", "alice", &mappings);
    switch (explicit_account) {
        .success => |account| try std.testing.expectEqualStrings("alice", account),
        .failure => return error.TestUnexpectedResult,
    }

    const explicit_alias = decideServer("cn:service", "service", &mappings);
    switch (explicit_alias) {
        .success => |account| try std.testing.expectEqualStrings("service-account", account),
        .failure => return error.TestUnexpectedResult,
    }

    const mismatch = decideServer("cert:abc123", "bob", &mappings);
    switch (mismatch) {
        .success => return error.TestUnexpectedResult,
        .failure => |err| try std.testing.expectEqual(error.AuthorizationIdentityMismatch, err),
    }

    const unknown = decideServer("cert:def456", "", &mappings);
    switch (unknown) {
        .success => return error.TestUnexpectedResult,
        .failure => |err| try std.testing.expectEqual(error.UnknownExternalIdentity, err),
    }

    const missing = decideServer(null, "", &mappings);
    switch (missing) {
        .success => return error.TestUnexpectedResult,
        .failure => |err| try std.testing.expectEqual(error.EmptyTlsIdentity, err),
    }
}

test "base64 correctness" {
    const allocator = std.testing.allocator;

    const encoded_hello = try encodeAuthenticatePayload(allocator, "hello");
    defer allocator.free(encoded_hello);
    try std.testing.expectEqualStrings("aGVsbG8=", encoded_hello);

    const decoded_foo = try decodeAuthenticatePayload(allocator, "Zm9v");
    defer allocator.free(decoded_foo);
    try std.testing.expectEqualStrings("foo", decoded_foo);

    const decoded_empty = try decodeAuthenticatePayload(allocator, "+");
    defer allocator.free(decoded_empty);
    try std.testing.expectEqualStrings("", decoded_empty);
}
