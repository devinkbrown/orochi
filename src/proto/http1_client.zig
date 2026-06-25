// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal HTTP/1.1 client request builder and response parser.
//!
//! Pure: depends only on `std`. No sockets, clock, or RNG; the caller owns all
//! I/O and storage. Intended for ACME-over-TLS: requests are built into a caller
//! buffer and responses are parsed out of a caller read buffer.
//!
//! - `buildRequest` writes raw request bytes into `out` and returns the slice.
//! - `parseResponse` parses a complete response, decoding chunked bodies in
//!   place (decoded body lives inside the original `bytes` buffer).
//! - `isComplete` lets a read loop decide whether more bytes are needed.

const std = @import("std");

pub const Error = error{
    NoSpaceLeft,
    Truncated,
    Malformed,
    TooManyHeaders,
    UnsupportedVersion,
    InvalidChunk,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Response = struct {
    status: u16,
    headers: []Header,
    body: []const u8,
};

/// Build a raw HTTP/1.1 request into `out`:
///   METHOD path HTTP/1.1 / Host: host / <extra headers> /
///   Content-Length: N (only when body non-empty) / blank line / body.
/// `Host` is always emitted first; callers supply Content-Type, Accept, etc.
/// via `headers`. Returns the written slice.
pub fn buildRequest(
    out: []u8,
    method: []const u8,
    host: []const u8,
    path: []const u8,
    headers: []const Header,
    body: []const u8,
) ![]const u8 {
    var w = Writer{ .buf = out };
    try w.write(method);
    try w.write(" ");
    try w.write(path);
    try w.write(" HTTP/1.1\r\nHost: ");
    try w.write(host);
    try w.write("\r\n");
    for (headers) |h| {
        try w.write(h.name);
        try w.write(": ");
        try w.write(h.value);
        try w.write("\r\n");
    }
    if (body.len != 0) {
        try w.write("Content-Length: ");
        var num_buf: [20]u8 = undefined;
        const num = std.fmt.bufPrint(&num_buf, "{d}", .{body.len}) catch return Error.NoSpaceLeft;
        try w.write(num);
        try w.write("\r\n");
    }
    try w.write("\r\n");
    try w.write(body);
    return w.slice();
}

/// Parse a complete HTTP/1.1 response out of `bytes`. Parsed headers are stored
/// into `header_storage`; `Response.headers` is a subslice of it. Chunked bodies
/// are decoded in place within `bytes`, so the returned `body` aliases the input
/// buffer. The caller must pass a full response (see `isComplete`).
pub fn parseResponse(bytes: []u8, header_storage: []Header) !Response {
    const head_end = headerEnd(bytes) orelse return Error.Truncated;
    const status_line_end = indexCrlf(bytes, 0) orelse return Error.Malformed;
    const status = try parseStatusLine(bytes[0..status_line_end]);

    var count: usize = 0;
    var pos = status_line_end + 2;
    while (pos < head_end) {
        const line_end = indexCrlf(bytes, pos) orelse return Error.Malformed;
        const h = try parseHeaderLine(bytes[pos..line_end]);
        if (count >= header_storage.len) return Error.TooManyHeaders;
        header_storage[count] = h;
        count += 1;
        pos = line_end + 2;
    }
    const headers = header_storage[0..count];
    const body_start = head_end + 4;
    const raw_body = bytes[body_start..];
    const resp = Response{ .status = status, .headers = headers, .body = "" };

    var body: []const u8 = raw_body; // default: no framing, remainder is body
    if (isChunked(resp)) {
        const decoded_len = try decodeChunkedInPlace(bytes[body_start..]);
        body = bytes[body_start .. body_start + decoded_len];
    } else if (header(resp, "content-length")) |cl_str| {
        const cl = parseUint(cl_str) orelse return Error.Malformed;
        if (cl > raw_body.len) return Error.Truncated;
        body = raw_body[0..cl];
    }
    return Response{ .status = status, .headers = headers, .body = body };
}

/// Case-insensitive header lookup. Returns the first matching value or null.
pub fn header(resp: Response, name: []const u8) ?[]const u8 {
    for (resp.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

/// Whether `bytes` holds a complete response: full header block plus a body
/// satisfying either Content-Length or a terminating zero-length chunk.
/// Returns false when more bytes are required, so a read loop can keep reading.
pub fn isComplete(bytes: []const u8) bool {
    const head_end = headerEnd(bytes) orelse return false;
    const body_start = head_end + 4;
    const body = bytes[body_start..];

    if (findHeaderValueCI(bytes[0..head_end], "transfer-encoding")) |te| {
        if (containsTokenCI(te, "chunked")) return chunkedComplete(body);
    }
    if (findHeaderValueCI(bytes[0..head_end], "content-length")) |cl| {
        const n = parseUint(cl) orelse return false;
        return body.len >= n;
    }
    return true; // no framing headers: a complete header block is enough
}

// --- internals ---------------------------------------------------------------

const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn write(self: *Writer, data: []const u8) !void {
        if (self.len + data.len > self.buf.len) return Error.NoSpaceLeft;
        @memcpy(self.buf[self.len .. self.len + data.len], data);
        self.len += data.len;
    }
    fn slice(self: *Writer) []const u8 {
        return self.buf[0..self.len];
    }
};

fn parseStatusLine(line: []const u8) !u16 {
    // e.g. "HTTP/1.1 200 OK"
    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse return Error.Malformed;
    const version = line[0..sp1];
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) {
        return Error.UnsupportedVersion;
    }
    const rest = line[sp1 + 1 ..];
    const code_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    const code_str = rest[0..code_end];
    if (code_str.len != 3) return Error.Malformed;
    const status = parseUint(code_str) orelse return Error.Malformed;
    if (status < 100 or status > 599) return Error.Malformed;
    return @intCast(status);
}

fn parseHeaderLine(line: []const u8) !Header {
    if (line.len == 0) return Error.Malformed;
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return Error.Malformed;
    if (colon == 0) return Error.Malformed;
    const name = line[0..colon];
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
    return .{ .name = name, .value = value };
}

fn isChunked(resp: Response) bool {
    const te = header(resp, "transfer-encoding") orelse return false;
    return containsTokenCI(te, "chunked");
}

/// Decode a chunked body in place. `region` starts at the first chunk-size line
/// and must hold the full chunked stream. Decoded bytes are written back to the
/// front of `region`; returns the decoded length.
fn decodeChunkedInPlace(region: []u8) !usize {
    var read_pos: usize = 0;
    var write_pos: usize = 0;
    while (true) {
        const line_end = indexCrlf(region, read_pos) orelse return Error.Truncated;
        const size = try parseChunkSize(region[read_pos..line_end]);
        read_pos = line_end + 2;

        if (size == 0) {
            // Consume trailers up to the final CRLF.
            while (true) {
                const t_end = indexCrlf(region, read_pos) orelse return Error.Truncated;
                const is_blank = t_end == read_pos;
                read_pos = t_end + 2;
                if (is_blank) break;
            }
            return write_pos;
        }

        if (size > region.len - read_pos) return Error.Truncated;
        // Move chunk data toward the front; overlapping copy goes forward only.
        std.mem.copyForwards(u8, region[write_pos .. write_pos + size], region[read_pos .. read_pos + size]);
        write_pos += size;
        read_pos += size;
        if (region.len - read_pos < 2) return Error.Truncated;
        if (!std.mem.eql(u8, region[read_pos .. read_pos + 2], "\r\n")) return Error.Malformed;
        read_pos += 2;
    }
}

fn chunkedComplete(region: []const u8) bool {
    var pos: usize = 0;
    while (true) {
        const line_end = indexCrlf(region, pos) orelse return false;
        const size = parseChunkSize(region[pos..line_end]) catch return false;
        pos = line_end + 2;
        if (size == 0) {
            // Need a terminating blank line (possibly after trailers).
            while (true) {
                const t_end = indexCrlf(region, pos) orelse return false;
                const blank = t_end == pos;
                pos = t_end + 2;
                if (blank) return true;
            }
        }
        if (size > region.len - pos) return false;
        pos += size;
        if (region.len - pos < 2) return false;
        pos += 2;
    }
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
        if (size > (std.math.maxInt(usize) - digit) / 16) return Error.InvalidChunk;
        size = size * 16 + digit;
    }
    return size;
}

fn parseUint(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var n: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        const d: u64 = c - '0';
        if (n > (std.math.maxInt(u64) - d) / 10) return null;
        n = n * 10 + d;
    }
    return n;
}

fn headerEnd(bytes: []const u8) ?usize {
    return std.mem.indexOf(u8, bytes, "\r\n\r\n");
}

fn indexCrlf(bytes: []const u8, start: usize) ?usize {
    if (start > bytes.len) return null;
    const rel = std.mem.indexOf(u8, bytes[start..], "\r\n") orelse return null;
    return start + rel;
}

fn findHeaderValueCI(head: []const u8, name: []const u8) ?[]const u8 {
    // Skip status line.
    const first = indexCrlf(head, 0) orelse return null;
    var pos = first + 2;
    while (pos < head.len) {
        const line_end = indexCrlf(head, pos) orelse head.len;
        const line = head[pos..line_end];
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const hn = line[0..colon];
            if (std.ascii.eqlIgnoreCase(hn, name)) {
                return std.mem.trim(u8, line[colon + 1 ..], " \t");
            }
        }
        if (line_end >= head.len) break;
        pos = line_end + 2;
    }
    return null;
}

fn containsTokenCI(value: []const u8, token: []const u8) bool {
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

// --- tests -------------------------------------------------------------------

test "buildRequest GET has no Content-Length" {
    // Arrange
    var buf: [256]u8 = undefined;
    const headers = [_]Header{.{ .name = "Accept", .value = "application/json" }};

    // Act
    const req = try buildRequest(&buf, "GET", "acme.example", "/dir", &headers, "");

    // Assert
    try std.testing.expectEqualStrings(
        "GET /dir HTTP/1.1\r\n" ++
            "Host: acme.example\r\n" ++
            "Accept: application/json\r\n" ++
            "\r\n",
        req,
    );
}

test "buildRequest POST with body adds Content-Length" {
    // Arrange
    var buf: [256]u8 = undefined;
    const headers = [_]Header{.{ .name = "Content-Type", .value = "application/jose+json" }};
    const body = "{\"k\":1}";

    // Act
    const req = try buildRequest(&buf, "POST", "acme.example", "/new-order", &headers, body);

    // Assert
    try std.testing.expectEqualStrings(
        "POST /new-order HTTP/1.1\r\n" ++
            "Host: acme.example\r\n" ++
            "Content-Type: application/jose+json\r\n" ++
            "Content-Length: 7\r\n" ++
            "\r\n" ++
            "{\"k\":1}",
        req,
    );
}

test "buildRequest reports NoSpaceLeft when buffer too small" {
    // Arrange
    var buf: [8]u8 = undefined;

    // Act / Assert
    try std.testing.expectError(Error.NoSpaceLeft, buildRequest(&buf, "GET", "h", "/p", &.{}, ""));
}

test "parseResponse 200 with Content-Length body" {
    // Arrange
    var bytes = "HTTP/1.1 200 OK\r\n".* ++
        "Content-Type: application/json\r\n".* ++
        "Content-Length: 5\r\n".* ++
        "\r\n".* ++
        "hello".*;
    var storage: [8]Header = undefined;

    // Act
    const resp = try parseResponse(&bytes, &storage);

    // Assert
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("application/json", header(resp, "content-type").?);
}

test "parseResponse decodes chunked body in place (extension + trailer)" {
    // Arrange: chunk extension (;x=y) and a trailer after the 0-chunk.
    var bytes = "HTTP/1.1 200 OK\r\n".* ++
        "Transfer-Encoding: chunked\r\n".* ++
        "\r\n".* ++
        "4;x=y\r\nWiki\r\n".* ++
        "5\r\npedia\r\n".* ++
        "0\r\n".* ++
        "Digest: zzz\r\n".* ++
        "\r\n".*;
    var storage: [8]Header = undefined;

    // Act
    const resp = try parseResponse(&bytes, &storage);

    // Assert
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("Wikipedia", resp.body);
}

test "header case-insensitive lookup of nonce and location" {
    // Arrange
    var bytes = "HTTP/1.1 201 Created\r\n".* ++
        "Replay-Nonce: aXarbXnonce\r\n".* ++
        "Location: https://acme.example/acct/1\r\n".* ++
        "Content-Length: 0\r\n".* ++
        "\r\n".*;
    var storage: [8]Header = undefined;

    // Act
    const resp = try parseResponse(&bytes, &storage);

    // Assert
    try std.testing.expectEqual(@as(u16, 201), resp.status);
    try std.testing.expectEqualStrings("aXarbXnonce", header(resp, "replay-nonce").?);
    try std.testing.expectEqualStrings("aXarbXnonce", header(resp, "REPLAY-NONCE").?);
    try std.testing.expectEqualStrings("https://acme.example/acct/1", header(resp, "Location").?);
    try std.testing.expect(header(resp, "missing") == null);
}

test "isComplete false on partial then true on full (content-length)" {
    // Arrange
    const partial = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
    const full = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    const no_head = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";

    // Act / Assert
    try std.testing.expect(!isComplete(no_head));
    try std.testing.expect(!isComplete(partial));
    try std.testing.expect(isComplete(full));
}

test "isComplete chunked false until terminator" {
    // Arrange
    const partial = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n";
    const full = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n";

    // Act / Assert
    try std.testing.expect(!isComplete(partial));
    try std.testing.expect(isComplete(full));
}

test "parseResponse truncated and malformed errors" {
    // Arrange / Act / Assert: each malformed input maps to a distinct error.
    var storage: [8]Header = undefined;
    var no_head = "HTTP/1.1 200 OK\r\n".*;
    try std.testing.expectError(Error.Truncated, parseResponse(&no_head, &storage));
    var short_body = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi".*;
    try std.testing.expectError(Error.Truncated, parseResponse(&short_body, &storage));
    var bad_status = "FOO 200 OK\r\n\r\n".*;
    try std.testing.expectError(Error.UnsupportedVersion, parseResponse(&bad_status, &storage));
    var bad_code = "HTTP/1.1 99 X\r\n\r\n".*;
    try std.testing.expectError(Error.Malformed, parseResponse(&bad_code, &storage));
    var bad_header = "HTTP/1.1 200 OK\r\nNoColonHere\r\n\r\n".*;
    try std.testing.expectError(Error.Malformed, parseResponse(&bad_header, &storage));

    var many = "HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\nContent-Length: 0\r\n\r\n".*;
    var one: [1]Header = undefined;
    try std.testing.expectError(Error.TooManyHeaders, parseResponse(&many, &one));
}
