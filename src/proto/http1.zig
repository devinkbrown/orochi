const std = @import("std");

pub const Error = error{
    Malformed,
    Oversized,
    TooManyHeaders,
    UnsupportedVersion,
    Injection,
    Truncated,
    MissingWebSocketKey,
    InvalidWebSocketKey,
    InvalidChunk,
};

pub const Limits = struct {
    max_headers: usize = 64,
    max_header_bytes: usize = 8192,
    max_line_len: usize = 4096,
    max_body_bytes: usize = 1024 * 1024,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: []const u8,
    target: []const u8,
    version: []const u8,
    headers: []Header,
    header_bytes: usize,

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        self.* = undefined;
    }

    pub fn header(self: Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn hasHeaderToken(self: Request, name: []const u8, token: []const u8) bool {
        const value = self.header(name) orelse return false;
        return valueHasToken(value, token);
    }

    pub fn isWebSocketUpgrade(self: Request) bool {
        return self.hasHeaderToken("connection", "upgrade") and
            (self.header("upgrade") != null and std.ascii.eqlIgnoreCase(self.header("upgrade").?, "websocket")) and
            self.header("sec-websocket-key") != null;
    }

    pub fn websocketAccept(self: Request, allocator: std.mem.Allocator) ![]u8 {
        const key = self.header("sec-websocket-key") orelse return Error.MissingWebSocketKey;
        return secWebSocketAccept(allocator, key);
    }
};

pub const ChunkedBody = struct {
    body: []u8,
    trailers: []Header,

    pub fn deinit(self: *ChunkedBody, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        allocator.free(self.trailers);
        self.* = undefined;
    }

    pub fn trailer(self: ChunkedBody, name: []const u8) ?[]const u8 {
        for (self.trailers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }
};

pub fn parseRequest(allocator: std.mem.Allocator, input: []const u8, limits: Limits) !Request {
    const header_end = findHeaderEnd(input) orelse return Error.Truncated;
    const header_bytes = header_end + 4;
    if (header_bytes > limits.max_header_bytes) return Error.Oversized;
    try validateCrlfOnly(input[0..header_bytes]);

    const block = input[0..header_end];
    const first_line_end = findCrlf(block, 0) orelse block.len;
    if (first_line_end > limits.max_line_len) return Error.Oversized;

    const line = block[0..first_line_end];
    const parts = try parseRequestLine(line);
    if (!std.mem.eql(u8, parts.version, "HTTP/1.1")) return Error.UnsupportedVersion;

    var headers: std.ArrayList(Header) = .empty;
    errdefer headers.deinit(allocator);

    var pos = if (first_line_end == block.len) block.len else first_line_end + 2;
    while (pos < block.len) {
        const line_end = findCrlf(block, pos) orelse block.len;
        const header_line = block[pos..line_end];
        if (header_line.len > limits.max_line_len) return Error.Oversized;
        if (headers.items.len >= limits.max_headers) return Error.TooManyHeaders;
        try appendParsedHeader(allocator, &headers, header_line);
        pos = line_end + 2;
    }

    return .{
        .method = parts.method,
        .target = parts.target,
        .version = parts.version,
        .headers = try headers.toOwnedSlice(allocator),
        .header_bytes = header_bytes,
    };
}

pub fn secWebSocketAccept(allocator: std.mem.Allocator, raw_key: []const u8) ![]u8 {
    const key = std.mem.trim(u8, raw_key, " \t");
    try validateWebSocketKey(key);

    const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var input: [128]u8 = undefined;
    if (key.len + guid.len > input.len) return Error.InvalidWebSocketKey;
    @memcpy(input[0..key.len], key);
    @memcpy(input[key.len .. key.len + guid.len], guid);

    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(input[0 .. key.len + guid.len], &digest, .{});

    const out = try allocator.alloc(u8, base64EncodedLen(digest.len));
    _ = base64Encode(out, &digest);
    return out;
}

pub fn buildResponse(
    allocator: std.mem.Allocator,
    status: u16,
    headers: []const Header,
    body: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var line_buf: [64]u8 = undefined;
    const status_line = try std.fmt.bufPrint(&line_buf, "HTTP/1.1 {} {s}\r\n", .{
        status,
        reasonPhrase(status),
    });
    try out.appendSlice(allocator, status_line);

    var has_content_length = false;
    var has_transfer_encoding = false;
    for (headers) |h| {
        try validateResponseHeader(h);
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) has_content_length = true;
        if (std.ascii.eqlIgnoreCase(h.name, "transfer-encoding")) has_transfer_encoding = true;
        try appendHeaderLine(allocator, &out, h);
    }

    if (!has_content_length and !has_transfer_encoding and statusAllowsBodyLength(status)) {
        var len_buf: [32]u8 = undefined;
        const len = try std.fmt.bufPrint(&len_buf, "{}", .{body.len});
        try appendHeaderLine(allocator, &out, .{ .name = "Content-Length", .value = len });
    }

    try out.appendSlice(allocator, "\r\n");
    try out.appendSlice(allocator, body);
    return out.toOwnedSlice(allocator);
}

pub fn buildWebSocketSwitchingProtocols(
    allocator: std.mem.Allocator,
    accept: []const u8,
) ![]u8 {
    const headers = [_]Header{
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Sec-WebSocket-Accept", .value = accept },
    };
    return buildResponse(allocator, 101, &headers, "");
}

pub fn decodeChunked(allocator: std.mem.Allocator, input: []const u8, limits: Limits) !ChunkedBody {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var trailers: std.ArrayList(Header) = .empty;
    errdefer trailers.deinit(allocator);

    var pos: usize = 0;
    while (true) {
        const line_end = findCrlf(input, pos) orelse return Error.Truncated;
        if (line_end - pos > limits.max_line_len) return Error.Oversized;
        const line = input[pos..line_end];
        const size = try parseChunkSize(line);
        pos = line_end + 2;

        if (size == 0) {
            var trailer_bytes: usize = 0;
            while (true) {
                const trailer_end = findCrlf(input, pos) orelse return Error.Truncated;
                const trailer_line = input[pos..trailer_end];
                if (trailer_line.len > limits.max_line_len) return Error.Oversized;
                trailer_bytes += trailer_line.len + 2;
                if (trailer_bytes > limits.max_header_bytes) return Error.Oversized;
                pos = trailer_end + 2;
                if (trailer_line.len == 0) break;
                if (trailers.items.len >= limits.max_headers) return Error.TooManyHeaders;
                try appendParsedHeader(allocator, &trailers, trailer_line);
            }
            if (pos != input.len) return Error.Malformed;
            return .{
                .body = try body.toOwnedSlice(allocator),
                .trailers = try trailers.toOwnedSlice(allocator),
            };
        }

        if (size > limits.max_body_bytes - body.items.len) return Error.Oversized;
        if (size > input.len - pos) return Error.Truncated;
        try body.appendSlice(allocator, input[pos .. pos + size]);
        pos += size;
        if (input.len - pos < 2) return Error.Truncated;
        if (!std.mem.eql(u8, input[pos .. pos + 2], "\r\n")) return Error.Malformed;
        pos += 2;
    }
}

fn appendParsedHeader(
    allocator: std.mem.Allocator,
    headers: *std.ArrayList(Header),
    line: []const u8,
) !void {
    const h = try parseHeaderLine(line);
    try headers.append(allocator, h);
}

fn parseRequestLine(line: []const u8) !struct {
    method: []const u8,
    target: []const u8,
    version: []const u8,
} {
    const first = std.mem.indexOfScalar(u8, line, ' ') orelse return Error.Malformed;
    const rest = line[first + 1 ..];
    const second_rel = std.mem.indexOfScalar(u8, rest, ' ') orelse return Error.Malformed;
    const second = first + 1 + second_rel;
    if (first == 0 or second == first + 1 or second + 1 >= line.len) return Error.Malformed;
    if (std.mem.indexOfScalar(u8, line[second + 1 ..], ' ') != null) return Error.Malformed;

    const method = line[0..first];
    const target = line[first + 1 .. second];
    const version = line[second + 1 ..];
    try validateToken(method);
    try validateNoCtl(target);
    try validateNoCtl(version);
    return .{ .method = method, .target = target, .version = version };
}

fn parseHeaderLine(line: []const u8) !Header {
    if (line.len == 0) return Error.Malformed;
    if (line[0] == ' ' or line[0] == '\t') return Error.Injection;
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return Error.Malformed;
    if (colon == 0) return Error.Malformed;

    const name = line[0..colon];
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
    try validateHeaderName(name);
    try validateHeaderValue(value);
    return .{ .name = name, .value = value };
}

fn validateCrlfOnly(bytes: []const u8) !void {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == '\n') {
            if (i == 0 or bytes[i - 1] != '\r') return Error.Injection;
        } else if (bytes[i] == '\r') {
            if (i + 1 >= bytes.len or bytes[i + 1] != '\n') return Error.Injection;
        }
    }
}

fn findHeaderEnd(input: []const u8) ?usize {
    return std.mem.indexOf(u8, input, "\r\n\r\n");
}

fn findCrlf(input: []const u8, start: usize) ?usize {
    if (start > input.len) return null;
    const rel = std.mem.indexOf(u8, input[start..], "\r\n") orelse return null;
    return start + rel;
}

fn validateToken(token: []const u8) !void {
    if (token.len == 0) return Error.Malformed;
    for (token) |c| {
        if (!isTokenChar(c)) return Error.Malformed;
    }
}

fn validateHeaderName(name: []const u8) !void {
    try validateToken(name);
}

fn validateHeaderValue(value: []const u8) !void {
    for (value) |c| {
        if (c == '\r' or c == '\n') return Error.Injection;
        if ((c < 0x20 and c != '\t') or c == 0x7f) return Error.Malformed;
    }
}

fn validateNoCtl(value: []const u8) !void {
    for (value) |c| {
        if (c < 0x20 or c == 0x7f) return Error.Malformed;
    }
}

fn isTokenChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '/', ':', '=', '?', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

fn valueHasToken(value: []const u8, token: []const u8) bool {
    var start: usize = 0;
    while (start <= value.len) {
        const comma = std.mem.indexOfScalarPos(u8, value, start, ',') orelse value.len;
        const item = std.mem.trim(u8, value[start..comma], " \t");
        if (std.ascii.eqlIgnoreCase(item, token)) return true;
        if (comma == value.len) break;
        start = comma + 1;
    }
    return false;
}

fn validateResponseHeader(h: Header) !void {
    try validateHeaderName(h.name);
    try validateHeaderValue(h.value);
}

fn appendHeaderLine(allocator: std.mem.Allocator, out: *std.ArrayList(u8), h: Header) !void {
    try out.appendSlice(allocator, h.name);
    try out.appendSlice(allocator, ": ");
    try out.appendSlice(allocator, h.value);
    try out.appendSlice(allocator, "\r\n");
}

fn statusAllowsBodyLength(status: u16) bool {
    return status != 101 and status != 204 and status != 304;
}

fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        101 => "Switching Protocols",
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        else => "Status",
    };
}

fn parseChunkSize(line: []const u8) !usize {
    const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
    const hex = std.mem.trim(u8, line[0..semi], " \t");
    if (hex.len == 0) return Error.InvalidChunk;
    var size: usize = 0;
    for (hex) |c| {
        const digit: usize = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return Error.InvalidChunk,
        };
        if (size > (std.math.maxInt(usize) - digit) / 16) return Error.Oversized;
        size = size * 16 + digit;
    }
    return size;
}

fn validateWebSocketKey(key: []const u8) !void {
    if (key.len == 0 or key.len > 88) return Error.InvalidWebSocketKey;
    const decoded_len = try base64DecodedLen(key);
    if (decoded_len != 16) return Error.InvalidWebSocketKey;
    var buf: [16]u8 = undefined;
    _ = try base64Decode(buf[0..], key);
}

const b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64EncodedLen(n: usize) usize {
    return ((n + 2) / 3) * 4;
}

fn base64Encode(out: []u8, input: []const u8) []u8 {
    var i: usize = 0;
    var j: usize = 0;
    while (i + 3 <= input.len) {
        const b0 = input[i];
        const b1 = input[i + 1];
        const b2 = input[i + 2];
        out[j] = b64_table[b0 >> 2];
        out[j + 1] = b64_table[((b0 & 0x03) << 4) | (b1 >> 4)];
        out[j + 2] = b64_table[((b1 & 0x0f) << 2) | (b2 >> 6)];
        out[j + 3] = b64_table[b2 & 0x3f];
        i += 3;
        j += 4;
    }
    if (input.len - i == 1) {
        const b0 = input[i];
        out[j] = b64_table[b0 >> 2];
        out[j + 1] = b64_table[(b0 & 0x03) << 4];
        out[j + 2] = '=';
        out[j + 3] = '=';
        j += 4;
    } else if (input.len - i == 2) {
        const b0 = input[i];
        const b1 = input[i + 1];
        out[j] = b64_table[b0 >> 2];
        out[j + 1] = b64_table[((b0 & 0x03) << 4) | (b1 >> 4)];
        out[j + 2] = b64_table[(b1 & 0x0f) << 2];
        out[j + 3] = '=';
        j += 4;
    }
    return out[0..j];
}

fn base64DecodedLen(input: []const u8) !usize {
    if (input.len % 4 != 0) return Error.InvalidWebSocketKey;
    if (input.len == 0) return 0;
    var padding: usize = 0;
    if (input[input.len - 1] == '=') padding += 1;
    if (input[input.len - 2] == '=') padding += 1;
    return (input.len / 4) * 3 - padding;
}

fn base64Decode(out: []u8, input: []const u8) !usize {
    const expected = try base64DecodedLen(input);
    if (out.len < expected) return Error.InvalidWebSocketKey;

    var i: usize = 0;
    var j: usize = 0;
    while (i < input.len) {
        const c0 = try base64Value(input[i]);
        const c1 = try base64Value(input[i + 1]);
        const c2_pad = input[i + 2] == '=';
        const c3_pad = input[i + 3] == '=';
        if (c2_pad and !c3_pad) return Error.InvalidWebSocketKey;
        if ((c2_pad or c3_pad) and i + 4 != input.len) return Error.InvalidWebSocketKey;
        const c2 = if (c2_pad) 0 else try base64Value(input[i + 2]);
        const c3 = if (c3_pad) 0 else try base64Value(input[i + 3]);

        out[j] = (c0 << 2) | (c1 >> 4);
        j += 1;
        if (!c2_pad) {
            out[j] = ((c1 & 0x0f) << 4) | (c2 >> 2);
            j += 1;
        }
        if (!c3_pad) {
            out[j] = ((c2 & 0x03) << 6) | c3;
            j += 1;
        }
        i += 4;
    }
    return j;
}

fn base64Value(c: u8) !u8 {
    return switch (c) {
        'A'...'Z' => c - 'A',
        'a'...'z' => c - 'a' + 26,
        '0'...'9' => c - '0' + 52,
        '+' => 62,
        '/' => 63,
        else => Error.InvalidWebSocketKey,
    };
}

test "parse GET with headers and case-insensitive lookup" {
    const alloc = std.testing.allocator;
    var req = try parseRequest(
        alloc,
        "GET /health HTTP/1.1\r\n" ++
            "Host: example.test\r\n" ++
            "Connection: keep-alive, Upgrade\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "\r\n",
        .{},
    );
    defer req.deinit(alloc);

    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/health", req.target);
    try std.testing.expectEqualStrings("HTTP/1.1", req.version);
    try std.testing.expectEqualStrings("example.test", req.header("host").?);
    try std.testing.expect(req.hasHeaderToken("CONNECTION", "upgrade"));
    try std.testing.expect(req.isWebSocketUpgrade());
}

test "reject malformed and oversized requests" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(Error.Truncated, parseRequest(alloc, "GET / HTTP/1.1\r\n", .{}));
    try std.testing.expectError(Error.Malformed, parseRequest(alloc, "GET / HTTP/1.1\r\nBroken\r\n\r\n", .{}));
    try std.testing.expectError(Error.UnsupportedVersion, parseRequest(alloc, "GET / HTTP/1.0\r\n\r\n", .{}));
    try std.testing.expectError(Error.Injection, parseRequest(alloc, "GET / HTTP/1.1\nHost: x\r\n\r\n", .{}));
    try std.testing.expectError(Error.Oversized, parseRequest(alloc, "GET / HTTP/1.1\r\n\r\n", .{ .max_header_bytes = 8 }));
    try std.testing.expectError(Error.TooManyHeaders, parseRequest(alloc, "GET / HTTP/1.1\r\nA: b\r\n\r\n", .{ .max_headers = 0 }));
}

test "websocket accept matches RFC 6455 example" {
    const alloc = std.testing.allocator;
    const accept = try secWebSocketAccept(alloc, "dGhlIHNhbXBsZSBub25jZQ==");
    defer alloc.free(accept);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "build 200 response" {
    const alloc = std.testing.allocator;
    const headers = [_]Header{.{ .name = "Content-Type", .value = "text/plain" }};
    const res = try buildResponse(alloc, 200, &headers, "ok\n");
    defer alloc.free(res);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nok\n",
        res,
    );
}

test "build 101 websocket response" {
    const alloc = std.testing.allocator;
    const res = try buildWebSocketSwitchingProtocols(alloc, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    defer alloc.free(res);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
            "\r\n",
        res,
    );
}

test "build 404 response and reject response header injection" {
    const alloc = std.testing.allocator;
    const res = try buildResponse(alloc, 404, &.{}, "missing");
    defer alloc.free(res);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\n\r\nmissing",
        res,
    );
    try std.testing.expectError(
        Error.Injection,
        buildResponse(alloc, 200, &.{.{ .name = "X-Test", .value = "ok\r\nBad: yes" }}, ""),
    );
}

test "chunked decode with extension and trailer" {
    const alloc = std.testing.allocator;
    var decoded = try decodeChunked(
        alloc,
        "4;ignored=true\r\nWiki\r\n" ++
            "5\r\npedia\r\n" ++
            "0\r\n" ++
            "Digest: abc123\r\n" ++
            "\r\n",
        .{},
    );
    defer decoded.deinit(alloc);

    try std.testing.expectEqualStrings("Wikipedia", decoded.body);
    try std.testing.expectEqualStrings("abc123", decoded.trailer("digest").?);
}

test "chunked decode truncation and malformed errors" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(Error.Truncated, decodeChunked(alloc, "4\r\nWi", .{}));
    try std.testing.expectError(Error.Truncated, decodeChunked(alloc, "1\r\na\r\n0\r\nTrailer: x\r\n", .{}));
    try std.testing.expectError(Error.InvalidChunk, decodeChunked(alloc, "z\r\nx\r\n", .{}));
    try std.testing.expectError(Error.Malformed, decodeChunked(alloc, "1\r\na\n0\r\n\r\n", .{}));
    try std.testing.expectError(Error.Oversized, decodeChunked(alloc, "2\r\nab\r\n0\r\n\r\n", .{ .max_body_bytes = 1 }));
}
