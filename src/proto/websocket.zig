//! RFC 6455 WebSocket server helpers.
//!
//! This module is intentionally allocation-free: callers provide request,
//! response, frame, and payload buffers. It covers the browser-client side of
//! the protocol that Mizuchi needs for IRC-over-WebSocket frontends.
const std = @import("std");

const Sha1 = std.crypto.hash.Sha1;
const ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const ACCEPT_LEN = std.base64.standard.Encoder.calcSize(Sha1.digest_length);
pub const MAX_RESPONSE_LEN = 129;

/// HTTP upgrade parsing and response construction failures.
pub const HandshakeError = error{
    MissingHeaderEnd,
    EmptyRequest,
    InvalidRequestLine,
    UnsupportedMethod,
    UnsupportedProtocol,
    MalformedHeader,
    MissingHost,
    MissingUpgrade,
    MissingConnection,
    MissingKey,
    MissingVersion,
    InvalidUpgrade,
    InvalidConnection,
    InvalidKey,
    UnsupportedVersion,
    OutputTooSmall,
};

/// Frame parse failures for attacker-controlled wire bytes.
pub const FrameError = error{
    Truncated,
    ReservedBitsSet,
    InvalidOpcode,
    FragmentedControlFrame,
    ControlFrameTooLarge,
    NonCanonicalLength,
    PayloadTooLarge,
    UnmaskedClientFrame,
    MaskedServerFrame,
    OutputTooSmall,
};

/// Frame construction failures for caller-supplied payloads.
pub const BuildError = error{
    FragmentedControlFrame,
    ControlFrameTooLarge,
    PayloadTooLarge,
    OutputTooSmall,
};

pub const Direction = enum {
    client_to_server,
    server_to_client,
};

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    pub fn isData(self: Opcode) bool {
        return self == .text or self == .binary;
    }
};

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload: []const u8,

    pub fn isFragment(self: Frame) bool {
        return !self.fin or self.opcode == .continuation;
    }
};

pub const DecodeResult = struct {
    frame: Frame,
    consumed: usize,
};

pub const BuildOptions = struct {
    fin: bool = true,
    opcode: Opcode,
    mask_key: ?[4]u8 = null,
};

pub const IrcLine = struct {
    line: []const u8,
    consumed: usize,
};

/// Compute Sec-WebSocket-Accept into `out` after validating the client key.
pub fn computeAccept(key: []const u8, out: *[ACCEPT_LEN]u8) HandshakeError![]const u8 {
    var decoded_key: [16]u8 = undefined;
    const trimmed = trimHeaderValue(key);
    if (trimmed.len == 0) return error.InvalidKey;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidKey;
    if (decoded_len != decoded_key.len) return error.InvalidKey;
    std.base64.standard.Decoder.decode(&decoded_key, trimmed) catch return error.InvalidKey;

    var sha = Sha1.init(.{});
    sha.update(trimmed);
    sha.update(ACCEPT_GUID);
    var digest: [Sha1.digest_length]u8 = undefined;
    sha.final(&digest);
    return std.base64.standard.Encoder.encode(out, &digest);
}

/// Parse and validate an HTTP/1.1 WebSocket upgrade request.
pub fn parseHandshake(request: []const u8) HandshakeError!void {
    const headers = try requestHeaders(request);
    var cursor: usize = 0;
    const request_line = nextHeaderLine(headers, &cursor) orelse return error.EmptyRequest;
    try validateRequestLine(request_line);

    var saw_host = false;
    var saw_upgrade = false;
    var saw_connection = false;
    var saw_key = false;
    var saw_version = false;

    while (nextHeaderLine(headers, &cursor)) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        const name = trimHeaderName(line[0..colon]);
        const value = trimHeaderValue(line[colon + 1 ..]);
        if (name.len == 0) return error.MalformedHeader;

        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (value.len == 0) return error.MalformedHeader;
            saw_host = true;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (!std.ascii.eqlIgnoreCase(value, "websocket")) return error.InvalidUpgrade;
            saw_upgrade = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (!hasHeaderToken(value, "upgrade")) return error.InvalidConnection;
            saw_connection = true;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            var accept_buf: [ACCEPT_LEN]u8 = undefined;
            _ = try computeAccept(value, &accept_buf);
            saw_key = true;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-version")) {
            if (!std.mem.eql(u8, value, "13")) return error.UnsupportedVersion;
            saw_version = true;
        }
    }

    if (!saw_host) return error.MissingHost;
    if (!saw_upgrade) return error.MissingUpgrade;
    if (!saw_connection) return error.MissingConnection;
    if (!saw_key) return error.MissingKey;
    if (!saw_version) return error.MissingVersion;
}

/// Build the complete 101 Switching Protocols response into `out`.
pub fn buildHandshakeResponse(request: []const u8, out: []u8) HandshakeError![]const u8 {
    const key = try findHandshakeKey(request);
    var accept_buf: [ACCEPT_LEN]u8 = undefined;
    const accept = try computeAccept(key, &accept_buf);
    return std.fmt.bufPrint(
        out,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    ) catch return error.OutputTooSmall;
}

/// Decode one complete WebSocket frame from `input`.
///
/// Masked payloads are unmasked into `payload_out`. Unmasked payloads are
/// returned as a slice of `input`, so `payload_out` can be empty when parsing
/// server-to-client frames.
pub fn decodeFrame(
    comptime max_frame_size: usize,
    direction: Direction,
    input: []const u8,
    payload_out: []u8,
) FrameError!DecodeResult {
    if (input.len < 2) return error.Truncated;

    const first = input[0];
    const second = input[1];
    if ((first & 0x70) != 0) return error.ReservedBitsSet;

    const fin = (first & 0x80) != 0;
    const opcode = try opcodeFromRaw(@as(u4, @truncate(first & 0x0f)));
    const masked = (second & 0x80) != 0;
    const len_tag = second & 0x7f;

    if (opcode.isControl()) {
        if (!fin) return error.FragmentedControlFrame;
        if (len_tag > 125) return error.ControlFrameTooLarge;
    }

    switch (direction) {
        .client_to_server => if (!masked) return error.UnmaskedClientFrame,
        .server_to_client => if (masked) return error.MaskedServerFrame,
    }

    var cursor: usize = 2;
    var payload_len64: u64 = len_tag;
    if (len_tag == 126) {
        if (input.len < cursor + 2) return error.Truncated;
        payload_len64 = std.mem.readInt(u16, input[cursor..][0..2], .big);
        if (payload_len64 < 126) return error.NonCanonicalLength;
        cursor += 2;
    } else if (len_tag == 127) {
        if (input.len < cursor + 8) return error.Truncated;
        payload_len64 = std.mem.readInt(u64, input[cursor..][0..8], .big);
        if ((payload_len64 & (@as(u64, 1) << 63)) != 0) return error.PayloadTooLarge;
        if (payload_len64 <= 0xffff) return error.NonCanonicalLength;
        cursor += 8;
    }

    if (payload_len64 > max_frame_size) return error.PayloadTooLarge;
    if (payload_len64 > std.math.maxInt(usize)) return error.PayloadTooLarge;
    const payload_len: usize = @intCast(payload_len64);

    var mask_key: [4]u8 = undefined;
    if (masked) {
        if (input.len < cursor + 4) return error.Truncated;
        @memcpy(&mask_key, input[cursor..][0..4]);
        cursor += 4;
    }

    if (input.len < cursor + payload_len) return error.Truncated;
    const wire_payload = input[cursor..][0..payload_len];
    const payload = if (masked) blk: {
        if (payload_out.len < payload_len) return error.OutputTooSmall;
        xorMask(payload_out[0..payload_len], wire_payload, mask_key);
        break :blk payload_out[0..payload_len];
    } else wire_payload;

    return .{
        .frame = .{
            .fin = fin,
            .opcode = opcode,
            .masked = masked,
            .payload = payload,
        },
        .consumed = cursor + payload_len,
    };
}

/// Encode one WebSocket frame into `out`.
pub fn encodeFrame(
    comptime max_frame_size: usize,
    options: BuildOptions,
    payload: []const u8,
    out: []u8,
) BuildError![]const u8 {
    if (payload.len > max_frame_size) return error.PayloadTooLarge;
    if (options.opcode.isControl()) {
        if (!options.fin) return error.FragmentedControlFrame;
        if (payload.len > 125) return error.ControlFrameTooLarge;
    }

    const masked = options.mask_key != null;
    const header_len: usize = 2 +
        (if (payload.len <= 125) @as(usize, 0) else if (payload.len <= 0xffff) @as(usize, 2) else @as(usize, 8)) +
        (if (masked) @as(usize, 4) else @as(usize, 0));
    if (out.len < header_len + payload.len) return error.OutputTooSmall;

    var cursor: usize = 0;
    out[cursor] = (if (options.fin) @as(u8, 0x80) else 0) | @as(u8, @intFromEnum(options.opcode));
    cursor += 1;

    const mask_bit: u8 = if (masked) 0x80 else 0;
    if (payload.len <= 125) {
        out[cursor] = mask_bit | @as(u8, @intCast(payload.len));
        cursor += 1;
    } else if (payload.len <= 0xffff) {
        out[cursor] = mask_bit | 126;
        cursor += 1;
        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(payload.len), .big);
        cursor += 2;
    } else {
        out[cursor] = mask_bit | 127;
        cursor += 1;
        std.mem.writeInt(u64, out[cursor..][0..8], @intCast(payload.len), .big);
        cursor += 8;
    }

    if (options.mask_key) |key| {
        @memcpy(out[cursor..][0..4], &key);
        cursor += 4;
        xorMask(out[cursor..][0..payload.len], payload, key);
    } else {
        @memcpy(out[cursor..][0..payload.len], payload);
    }

    return out[0 .. header_len + payload.len];
}

/// Return the next complete IRC line in a text-frame payload, excluding CR/LF.
pub fn nextIrcLine(payload: []const u8) ?IrcLine {
    const lf = std.mem.indexOfScalar(u8, payload, '\n') orelse return null;
    var line_end = lf;
    if (line_end > 0 and payload[line_end - 1] == '\r') line_end -= 1;
    return .{
        .line = payload[0..line_end],
        .consumed = lf + 1,
    };
}

fn requestHeaders(request: []const u8) HandshakeError![]const u8 {
    const end = std.mem.indexOf(u8, request, "\r\n\r\n") orelse return error.MissingHeaderEnd;
    return request[0 .. end + 2];
}

fn findHandshakeKey(request: []const u8) HandshakeError![]const u8 {
    const headers = try requestHeaders(request);
    var cursor: usize = 0;
    const request_line = nextHeaderLine(headers, &cursor) orelse return error.EmptyRequest;
    try validateRequestLine(request_line);

    var key: ?[]const u8 = null;
    var saw_host = false;
    var saw_upgrade = false;
    var saw_connection = false;
    var saw_version = false;

    while (nextHeaderLine(headers, &cursor)) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        const name = trimHeaderName(line[0..colon]);
        const value = trimHeaderValue(line[colon + 1 ..]);
        if (name.len == 0) return error.MalformedHeader;

        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (value.len == 0) return error.MalformedHeader;
            saw_host = true;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (!std.ascii.eqlIgnoreCase(value, "websocket")) return error.InvalidUpgrade;
            saw_upgrade = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (!hasHeaderToken(value, "upgrade")) return error.InvalidConnection;
            saw_connection = true;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            var accept_buf: [ACCEPT_LEN]u8 = undefined;
            _ = try computeAccept(value, &accept_buf);
            key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-version")) {
            if (!std.mem.eql(u8, value, "13")) return error.UnsupportedVersion;
            saw_version = true;
        }
    }

    if (!saw_host) return error.MissingHost;
    if (!saw_upgrade) return error.MissingUpgrade;
    if (!saw_connection) return error.MissingConnection;
    if (key == null) return error.MissingKey;
    if (!saw_version) return error.MissingVersion;
    return key.?;
}

fn validateRequestLine(line: []const u8) HandshakeError!void {
    if (line.len == 0) return error.EmptyRequest;
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next() orelse return error.InvalidRequestLine;
    const target = parts.next() orelse return error.InvalidRequestLine;
    const protocol = parts.next() orelse return error.InvalidRequestLine;
    if (target.len == 0 or parts.next() != null) return error.InvalidRequestLine;
    if (!std.mem.eql(u8, method, "GET")) return error.UnsupportedMethod;
    if (!std.mem.eql(u8, protocol, "HTTP/1.1")) return error.UnsupportedProtocol;
}

fn nextHeaderLine(headers: []const u8, cursor: *usize) ?[]const u8 {
    if (cursor.* >= headers.len) return null;
    const rest = headers[cursor.*..];
    const rel = std.mem.indexOf(u8, rest, "\r\n") orelse return null;
    const line = rest[0..rel];
    cursor.* += rel + 2;
    return line;
}

fn trimHeaderName(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

fn trimHeaderValue(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

fn hasHeaderToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (std.ascii.eqlIgnoreCase(trimHeaderValue(part), token)) return true;
    }
    return false;
}

fn opcodeFromRaw(raw: u4) FrameError!Opcode {
    return switch (raw) {
        0x0 => .continuation,
        0x1 => .text,
        0x2 => .binary,
        0x8 => .close,
        0x9 => .ping,
        0xa => .pong,
        else => error.InvalidOpcode,
    };
}

fn xorMask(dst: []u8, src: []const u8, key: [4]u8) void {
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        dst[i] = src[i] ^ key[i & 3];
    }
}

test "canonical RFC 6455 handshake example" {
    const request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";

    var accept_buf: [ACCEPT_LEN]u8 = undefined;
    const accept = try computeAccept("dGhlIHNhbXBsZSBub25jZQ==", &accept_buf);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);

    var response_buf: [MAX_RESPONSE_LEN]u8 = undefined;
    const response = try buildHandshakeResponse(request, &response_buf);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        response,
    );
}

test "handshake rejects malformed and missing required headers" {
    try std.testing.expectError(error.UnsupportedMethod, parseHandshake(
        "POST /chat HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    ));
    try std.testing.expectError(error.MissingConnection, parseHandshake(
        "GET /chat HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    ));
    try std.testing.expectError(error.InvalidKey, parseHandshake(
        "GET /chat HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: bad-key\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    ));
}

test "known RFC masked frame decodes expected payload" {
    const bytes = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var payload_buf: [32]u8 = undefined;
    const decoded = try decodeFrame(128, .client_to_server, &bytes, &payload_buf);
    try std.testing.expect(decoded.frame.fin);
    try std.testing.expectEqual(Opcode.text, decoded.frame.opcode);
    try std.testing.expect(decoded.frame.masked);
    try std.testing.expectEqualStrings("Hello", decoded.frame.payload);
    try std.testing.expectEqual(bytes.len, decoded.consumed);
}

test "masked and unmasked frames round trip" {
    const client_payload = "PRIVMSG #mizuchi :hello\r\n";
    var encoded_buf: [128]u8 = undefined;
    const encoded = try encodeFrame(128, .{
        .opcode = .text,
        .mask_key = .{ 0x12, 0x34, 0x56, 0x78 },
    }, client_payload, &encoded_buf);

    var payload_buf: [128]u8 = undefined;
    const decoded = try decodeFrame(128, .client_to_server, encoded, &payload_buf);
    try std.testing.expectEqual(Opcode.text, decoded.frame.opcode);
    try std.testing.expectEqualStrings(client_payload, decoded.frame.payload);
    try std.testing.expectEqual(encoded.len, decoded.consumed);

    const server_payload = "PING :mizuchi\r\n";
    const server_encoded = try encodeFrame(128, .{ .opcode = .text }, server_payload, &encoded_buf);
    const server_decoded = try decodeFrame(128, .server_to_client, server_encoded, &.{});
    try std.testing.expect(!server_decoded.frame.masked);
    try std.testing.expectEqualStrings(server_payload, server_decoded.frame.payload);
}

test "extended length frame round trips" {
    var payload: [130]u8 = undefined;
    @memset(&payload, 'a');

    var encoded_buf: [256]u8 = undefined;
    const encoded = try encodeFrame(256, .{
        .opcode = .binary,
        .mask_key = .{ 1, 2, 3, 4 },
    }, &payload, &encoded_buf);
    try std.testing.expectEqual(@as(u8, 126 | 0x80), encoded[1]);

    var payload_buf: [130]u8 = undefined;
    const decoded = try decodeFrame(256, .client_to_server, encoded, &payload_buf);
    try std.testing.expectEqual(Opcode.binary, decoded.frame.opcode);
    try std.testing.expectEqualSlices(u8, &payload, decoded.frame.payload);
}

test "oversize truncated and unmasked client frames are rejected" {
    const unmasked = [_]u8{ 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };
    var payload_buf: [16]u8 = undefined;
    try std.testing.expectError(error.UnmaskedClientFrame, decodeFrame(16, .client_to_server, &unmasked, &payload_buf));

    const truncated = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f };
    try std.testing.expectError(error.Truncated, decodeFrame(16, .client_to_server, &truncated, &payload_buf));

    const oversized = [_]u8{ 0x81, 0x86, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.PayloadTooLarge, decodeFrame(5, .client_to_server, &oversized, &payload_buf));
}

test "invalid control and length encodings are rejected" {
    const fragmented_ping = [_]u8{ 0x09, 0x80, 1, 2, 3, 4 };
    var payload_buf: [16]u8 = undefined;
    try std.testing.expectError(error.FragmentedControlFrame, decodeFrame(16, .client_to_server, &fragmented_ping, &payload_buf));

    const noncanonical = [_]u8{ 0x81, 0xfe, 0x00, 0x7d, 1, 2, 3, 4 };
    try std.testing.expectError(error.NonCanonicalLength, decodeFrame(128, .client_to_server, &noncanonical, &payload_buf));
}

test "irc line helper extracts complete lines only" {
    const first = nextIrcLine("NICK mizuchi\r\nUSER m 0 * :Mizuchi\r\n").?;
    try std.testing.expectEqualStrings("NICK mizuchi", first.line);
    try std.testing.expectEqual(@as(usize, 14), first.consumed);
    try std.testing.expect(nextIrcLine("PRIVMSG #chan :partial") == null);
}
