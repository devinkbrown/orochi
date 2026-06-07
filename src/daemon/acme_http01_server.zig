//! Pure ACME HTTP-01 response helper.
//!
//! This module owns challenge tokens and key authorizations, parses a single
//! HTTP/1.1 request buffer, and writes a complete response into caller storage.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("acme_http01_server requires a 64-bit target");
}

const challenge_path_prefix = "/.well-known/acme-challenge/";
const not_found_body = "not found\n";

pub const TokenStoreError = std.mem.Allocator.Error || error{
    InvalidToken,
    InvalidKeyAuthorization,
};

pub const ResponseError = error{
    NoSpaceLeft,
};

pub const TokenStore = struct {
    allocator: std.mem.Allocator,
    tokens: std.StringHashMap([]u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .tokens = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tokens.deinit();
        self.* = undefined;
    }

    pub fn put(self: *Self, token: []const u8, key_auth: []const u8) TokenStoreError!void {
        try validateToken(token);
        try validateKeyAuthorization(key_auth);

        const owned_value = try self.allocator.dupe(u8, key_auth);
        errdefer self.allocator.free(owned_value);

        if (self.tokens.getPtr(token)) |stored_value| {
            self.allocator.free(stored_value.*);
            stored_value.* = owned_value;
            return;
        }

        const owned_token = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(owned_token);

        try self.tokens.putNoClobber(owned_token, owned_value);
    }

    pub fn remove(self: *Self, token: []const u8) bool {
        if (self.tokens.fetchRemove(token)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }

    pub fn get(self: *const Self, token: []const u8) ?[]const u8 {
        validateToken(token) catch return null;
        return self.tokens.get(token);
    }
};

pub fn handleRequest(store: *const TokenStore, request_bytes: []const u8, out: []u8) ResponseError![]const u8 {
    const body = if (parseChallengeToken(request_bytes)) |token|
        store.get(token) orelse not_found_body
    else
        not_found_body;

    const status = if (body.ptr == not_found_body.ptr and body.len == not_found_body.len)
        "404 Not Found"
    else
        "200 OK";

    return writeResponse(out, status, body);
}

fn parseChallengeToken(request_bytes: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOfScalar(u8, request_bytes, '\n') orelse request_bytes.len;
    var line = request_bytes[0..line_end];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];

    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    if (!std.mem.eql(u8, line[0..first_space], "GET")) return null;

    const rest = line[first_space + 1 ..];
    const second_space = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const target = rest[0..second_space];
    const version = rest[second_space + 1 ..];
    if (!std.mem.eql(u8, version, "HTTP/1.1")) return null;

    if (!std.mem.startsWith(u8, target, challenge_path_prefix)) return null;
    const token = target[challenge_path_prefix.len..];
    validateToken(token) catch return null;
    return token;
}

fn writeResponse(out: []u8, status: []const u8, body: []const u8) ResponseError![]const u8 {
    const header = std.fmt.bufPrint(
        out,
        "HTTP/1.1 {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status, body.len },
    ) catch |err| switch (err) {
        error.NoSpaceLeft => return error.NoSpaceLeft,
    };
    if (out.len - header.len < body.len) return error.NoSpaceLeft;
    @memcpy(out[header.len .. header.len + body.len], body);
    return out[0 .. header.len + body.len];
}

fn validateToken(token: []const u8) TokenStoreError!void {
    if (token.len == 0) return error.InvalidToken;
    for (token) |byte| {
        if (!isTokenByte(byte)) return error.InvalidToken;
    }
}

fn validateKeyAuthorization(key_auth: []const u8) TokenStoreError!void {
    if (key_auth.len == 0) return error.InvalidKeyAuthorization;
    for (key_auth) |byte| {
        if (byte == '\r' or byte == '\n') return error.InvalidKeyAuthorization;
    }
}

fn isTokenByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => true,
        else => false,
    };
}

const testing = std.testing;

test "TokenStore put stores owned key authorization" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    var mutable_value = [_]u8{ 'k', 'e', 'y' };

    // Act
    try store.put("token-1", &mutable_value);
    mutable_value[0] = 'x';

    // Assert
    try testing.expectEqualStrings("key", store.get("token-1").?);
}

test "TokenStore put replaces existing value" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    try store.put("token_1", "old.auth");

    // Act
    try store.put("token_1", "new.auth");

    // Assert
    try testing.expectEqualStrings("new.auth", store.get("token_1").?);
}

test "TokenStore remove clears owned entry" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    try store.put("token", "key.auth");

    // Act
    const removed = store.remove("token");

    // Assert
    try testing.expect(removed);
    try testing.expect(store.get("token") == null);
    try testing.expect(!store.remove("token"));
}

test "TokenStore rejects empty and traversal-shaped tokens" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();

    // Act and assert
    try testing.expectError(error.InvalidToken, store.put("", "key.auth"));
    try testing.expectError(error.InvalidToken, store.put("../token", "key.auth"));
    try testing.expectError(error.InvalidToken, store.put("token.with.dot", "key.auth"));
    try testing.expectError(error.InvalidKeyAuthorization, store.put("token", "key.auth\n"));
}

test "handleRequest returns 200 for known challenge token" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    try store.put("abc_123-XYZ", "abc_123-XYZ.thumbprint");
    const request =
        "GET /.well-known/acme-challenge/abc_123-XYZ HTTP/1.1\r\n" ++
        "Host: example.test\r\n" ++
        "\r\n";
    var out: [512]u8 = undefined;

    // Act
    const response = try handleRequest(&store, request, &out);

    // Assert
    try testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, response, 1, "Content-Type: text/plain\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, response, 1, "Content-Length: 22\r\n"));
    try testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nabc_123-XYZ.thumbprint"));
}

test "handleRequest returns 404 for unknown token" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    const request = "GET /.well-known/acme-challenge/missing HTTP/1.1\r\n\r\n";
    var out: [256]u8 = undefined;

    // Act
    const response = try handleRequest(&store, request, &out);

    // Assert
    try testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 404 Not Found\r\n"));
    try testing.expect(std.mem.containsAtLeast(u8, response, 1, "Content-Length: 10\r\n"));
    try testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nnot found\n"));
}

test "handleRequest returns 404 for other methods and paths" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    try store.put("known", "known.auth");
    var out: [256]u8 = undefined;

    // Act
    const post_response = try handleRequest(&store, "POST /.well-known/acme-challenge/known HTTP/1.1\r\n\r\n", &out);
    const root_response = try handleRequest(&store, "GET / HTTP/1.1\r\n\r\n", &out);

    // Assert
    try testing.expect(std.mem.startsWith(u8, post_response, "HTTP/1.1 404 Not Found\r\n"));
    try testing.expect(std.mem.startsWith(u8, root_response, "HTTP/1.1 404 Not Found\r\n"));
}

test "handleRequest rejects traversal and extra path segments" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    try store.put("known", "known.auth");
    var out: [256]u8 = undefined;

    // Act
    const dotdot = try handleRequest(&store, "GET /.well-known/acme-challenge/../known HTTP/1.1\r\n\r\n", &out);
    const segment = try handleRequest(&store, "GET /.well-known/acme-challenge/known/extra HTTP/1.1\r\n\r\n", &out);
    const encoded = try handleRequest(&store, "GET /.well-known/acme-challenge/%2e%2e%2fknown HTTP/1.1\r\n\r\n", &out);

    // Assert
    try testing.expect(std.mem.startsWith(u8, dotdot, "HTTP/1.1 404 Not Found\r\n"));
    try testing.expect(std.mem.startsWith(u8, segment, "HTTP/1.1 404 Not Found\r\n"));
    try testing.expect(std.mem.startsWith(u8, encoded, "HTTP/1.1 404 Not Found\r\n"));
}

test "handleRequest returns NoSpaceLeft when output buffer is too small" {
    // Arrange
    var store = TokenStore.init(testing.allocator);
    defer store.deinit();
    try store.put("known", "known.auth");
    var out: [16]u8 = undefined;

    // Act and assert
    try testing.expectError(
        error.NoSpaceLeft,
        handleRequest(&store, "GET /.well-known/acme-challenge/known HTTP/1.1\r\n\r\n", &out),
    );
}
