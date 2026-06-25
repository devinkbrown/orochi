// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.2 handshake message body codecs (RFC 5246): pure byte-slice logic.

const std = @import("std");
const mem = std.mem;

comptime {
    if (@bitSizeOf(usize) != 64) {
        @compileError("tls12_handshake.zig requires a 64-bit target");
    }
}

pub const client_hello_msg_type: u8 = 1;
pub const server_hello_msg_type: u8 = 2;
pub const certificate_msg_type: u8 = 11;
pub const server_hello_done_msg_type: u8 = 14;
pub const finished_msg_type: u8 = 20;

pub const handshake_header_len: usize = 4;
pub const random_len: usize = 32;
pub const finished_verify_data_len: usize = 12;
pub const max_u16: usize = 0xffff;
pub const max_u24: usize = 0x00ff_ffff;
pub const max_session_id_len: usize = 32;

const server_hello_fixed_len: usize = 2 + random_len + 1 + 2 + 1 + 2;

pub const ParseError = error{
    BufferTooShort,
    LengthMismatch,
    EmptyVector,
    OddCipherSuites,
    SessionIdTooLong,
    TrailingBytes,
};

pub const EncodeError = error{
    NoSpaceLeft,
    BodyTooLarge,
    VectorTooLarge,
    EmptyVector,
    OddCipherSuites,
    SessionIdTooLong,
    CertificateTooLarge,
    CertificateListTooLarge,
};

pub const ClientHello = struct {
    client_version: u16,
    random: *const [random_len]u8,
    session_id: []const u8,
    cipher_suites: []const u8,
    compression_methods: []const u8,
    extensions: []const u8,

    pub fn cipherSuiteIterator(self: ClientHello) CipherSuiteIterator {
        return .{ .body = self.cipher_suites };
    }

    pub fn extensionIterator(self: ClientHello) ExtensionIterator {
        return .{ .body = self.extensions };
    }
};

pub const ServerHello = struct {
    server_version: u16,
    random: *const [random_len]u8,
    session_id: []const u8,
    cipher_suite: u16,
    compression: u8,
    extensions: []const u8,

    pub fn extensionIterator(self: ServerHello) ExtensionIterator {
        return .{ .body = self.extensions };
    }
};

pub const HandshakeHeader = struct {
    msg_type: u8,
    length: usize,
    body: []const u8,
};

pub const Extension = struct {
    ext_type: u16,
    data: []const u8,
};

pub const CipherSuiteIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *CipherSuiteIterator) ParseError!?u16 {
        if (self.pos == self.body.len) return null;
        if (self.body.len - self.pos < 2) return error.BufferTooShort;
        const suite = mem.readInt(u16, self.body[self.pos..][0..2], .big);
        self.pos += 2;
        return suite;
    }
};

pub const ExtensionIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *ExtensionIterator) ParseError!?Extension {
        if (self.pos == self.body.len) return null;
        if (self.body.len - self.pos < 4) return error.BufferTooShort;
        const ext_type = mem.readInt(u16, self.body[self.pos..][0..2], .big);
        const data_len = mem.readInt(u16, self.body[self.pos + 2 ..][0..2], .big);
        const data_start = self.pos + 4;
        if (self.body.len - data_start < data_len) return error.BufferTooShort;
        self.pos = data_start + data_len;
        return .{ .ext_type = ext_type, .data = self.body[data_start..self.pos] };
    }
};

pub const CertificateIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *CertificateIterator) ParseError!?[]const u8 {
        if (self.pos == self.body.len) return null;
        if (self.body.len - self.pos < 3) return error.BufferTooShort;
        const cert_len = readU24(self.body[self.pos..][0..3]);
        self.pos += 3;
        if (self.body.len - self.pos < cert_len) return error.BufferTooShort;
        const cert = self.body[self.pos .. self.pos + cert_len];
        self.pos += cert_len;
        return cert;
    }
};

pub fn parseClientHello(body: []const u8) ParseError!ClientHello {
    if (body.len < 2 + random_len + 1) return error.BufferTooShort;
    var off: usize = 0;
    const client_version = mem.readInt(u16, body[off..][0..2], .big);
    off += 2;
    const random = body[off..][0..random_len];
    off += random_len;

    const session_id_len: usize = body[off];
    off += 1;
    if (session_id_len > max_session_id_len) return error.SessionIdTooLong;
    if (body.len - off < session_id_len + 2) return error.BufferTooShort;
    const session_id = body[off .. off + session_id_len];
    off += session_id_len;

    const suites_len = mem.readInt(u16, body[off..][0..2], .big);
    off += 2;
    if (suites_len == 0) return error.EmptyVector;
    if ((suites_len & 1) != 0) return error.OddCipherSuites;
    if (body.len - off < suites_len + 1) return error.BufferTooShort;
    const cipher_suites = body[off .. off + suites_len];
    off += suites_len;

    const compression_len: usize = body[off];
    off += 1;
    if (compression_len == 0) return error.EmptyVector;
    if (body.len - off < compression_len + 2) return error.BufferTooShort;
    const compression_methods = body[off .. off + compression_len];
    off += compression_len;

    const extensions_len = mem.readInt(u16, body[off..][0..2], .big);
    off += 2;
    if (body.len - off < extensions_len) return error.BufferTooShort;
    if (body.len - off != extensions_len) return error.TrailingBytes;
    const extensions = body[off .. off + extensions_len];

    return .{
        .client_version = client_version,
        .random = random,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
        .extensions = extensions,
    };
}

pub fn parseServerHello(body: []const u8) ParseError!ServerHello {
    if (body.len < server_hello_fixed_len) return error.BufferTooShort;
    var off: usize = 0;
    const server_version = mem.readInt(u16, body[off..][0..2], .big);
    off += 2;
    const random = body[off..][0..random_len];
    off += random_len;

    const session_id_len: usize = body[off];
    off += 1;
    if (session_id_len > max_session_id_len) return error.SessionIdTooLong;
    if (body.len - off < session_id_len + 2 + 1 + 2) return error.BufferTooShort;
    const session_id = body[off .. off + session_id_len];
    off += session_id_len;

    const cipher_suite = mem.readInt(u16, body[off..][0..2], .big);
    off += 2;
    const compression = body[off];
    off += 1;

    const extensions_len = mem.readInt(u16, body[off..][0..2], .big);
    off += 2;
    if (body.len - off < extensions_len) return error.BufferTooShort;
    if (body.len - off != extensions_len) return error.TrailingBytes;

    return .{
        .server_version = server_version,
        .random = random,
        .session_id = session_id,
        .cipher_suite = cipher_suite,
        .compression = compression,
        .extensions = body[off .. off + extensions_len],
    };
}

pub fn parseCertificate(body: []const u8) ParseError!CertificateIterator {
    if (body.len < 3) return error.BufferTooShort;
    const list_len = readU24(body[0..3]);
    if (body.len - 3 < list_len) return error.BufferTooShort;
    if (body.len - 3 != list_len) return error.TrailingBytes;
    return .{ .body = body[3 .. 3 + list_len] };
}

pub fn parseServerHelloDone(body: []const u8) ParseError!void {
    if (body.len != 0) return error.TrailingBytes;
}

pub fn parseFinished(body: []const u8) ParseError![]const u8 {
    if (body.len < finished_verify_data_len) return error.BufferTooShort;
    if (body.len != finished_verify_data_len) return error.TrailingBytes;
    return body;
}

pub fn encodeServerHello(
    out: []u8,
    server_version: u16,
    random: *const [random_len]u8,
    session_id: []const u8,
    cipher_suite: u16,
    compression: u8,
    extensions: []const u8,
) EncodeError![]const u8 {
    try checkSessionId(session_id);
    if (extensions.len > max_u16) return error.VectorTooLarge;
    const body_len = 2 + random_len + 1 + session_id.len + 2 + 1 + 2 + extensions.len;
    if (out.len < body_len) return error.NoSpaceLeft;

    var off: usize = 0;
    mem.writeInt(u16, out[off..][0..2], server_version, .big);
    off += 2;
    @memcpy(out[off..][0..random_len], random);
    off += random_len;
    out[off] = @intCast(session_id.len);
    off += 1;
    @memcpy(out[off .. off + session_id.len], session_id);
    off += session_id.len;
    mem.writeInt(u16, out[off..][0..2], cipher_suite, .big);
    off += 2;
    out[off] = compression;
    off += 1;
    mem.writeInt(u16, out[off..][0..2], @intCast(extensions.len), .big);
    off += 2;
    @memcpy(out[off .. off + extensions.len], extensions);
    off += extensions.len;
    return out[0..off];
}

pub fn encodeCertificate(out: []u8, cert_chain: []const []const u8) EncodeError![]const u8 {
    const list_len = try certificateListLen(cert_chain);
    const body_len = 3 + list_len;
    if (body_len > max_u24) return error.BodyTooLarge;
    if (out.len < body_len) return error.NoSpaceLeft;

    var off: usize = 0;
    writeU24(out[off..][0..3], list_len);
    off += 3;
    for (cert_chain) |cert| {
        writeU24(out[off..][0..3], cert.len);
        off += 3;
        @memcpy(out[off .. off + cert.len], cert);
        off += cert.len;
    }
    return out[0..off];
}

pub fn encodeServerHelloDone(out: []u8) EncodeError![]const u8 {
    _ = out;
    return "";
}

pub fn encodeFinished(out: []u8, verify_data: *const [finished_verify_data_len]u8) EncodeError![]const u8 {
    if (out.len < finished_verify_data_len) return error.NoSpaceLeft;
    @memcpy(out[0..finished_verify_data_len], verify_data);
    return out[0..finished_verify_data_len];
}

pub fn wrapHandshake(out: []u8, msg_type: u8, body: []const u8) EncodeError![]const u8 {
    if (body.len > max_u24) return error.BodyTooLarge;
    const total_len = handshake_header_len + body.len;
    if (out.len < total_len) return error.NoSpaceLeft;
    out[0] = msg_type;
    writeU24(out[1..4], body.len);
    @memcpy(out[handshake_header_len..total_len], body);
    return out[0..total_len];
}

pub fn parseHandshakeHeader(bytes: []const u8) ParseError!HandshakeHeader {
    if (bytes.len < handshake_header_len) return error.BufferTooShort;
    const length = readU24(bytes[1..4]);
    if (bytes.len - handshake_header_len < length) return error.BufferTooShort;
    if (bytes.len - handshake_header_len != length) return error.TrailingBytes;
    return .{
        .msg_type = bytes[0],
        .length = length,
        .body = bytes[handshake_header_len .. handshake_header_len + length],
    };
}

fn checkSessionId(session_id: []const u8) EncodeError!void {
    if (session_id.len > max_session_id_len) return error.SessionIdTooLong;
}

fn certificateListLen(cert_chain: []const []const u8) EncodeError!usize {
    var len: usize = 0;
    for (cert_chain) |cert| {
        if (cert.len > max_u24) return error.CertificateTooLarge;
        if (max_u24 - len < 3) return error.CertificateListTooLarge;
        len += 3;
        if (max_u24 - len < cert.len) return error.CertificateListTooLarge;
        len += cert.len;
    }
    return len;
}

fn writeU24(out: []u8, value: usize) void {
    std.debug.assert(out.len == 3);
    std.debug.assert(value <= max_u24);
    out[0] = @intCast((value >> 16) & 0xff);
    out[1] = @intCast((value >> 8) & 0xff);
    out[2] = @intCast(value & 0xff);
}

fn readU24(bytes: []const u8) usize {
    std.debug.assert(bytes.len == 3);
    return (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
}

const testing = std.testing;

test "parseClientHello aliases vectors and iterates suites and extensions" {
    // Arrange.
    const body = [_]u8{
        0x03, 0x03,
    } ++ [_]u8{0xaa} ** random_len ++ [_]u8{
        0x02, 0x11, 0x22,
        0x00, 0x04, 0xc0,
        0x2f, 0x00, 0x9c,
        0x01, 0x00, 0x00,
        0x08, 0x00, 0x0d,
        0x00, 0x04, 0x04,
        0x03, 0x08, 0x04,
    };

    // Act.
    const parsed = try parseClientHello(&body);
    var suites = parsed.cipherSuiteIterator();
    var extensions = parsed.extensionIterator();

    // Assert.
    try testing.expectEqual(@as(u16, 0x0303), parsed.client_version);
    try testing.expect(parsed.random.ptr == body[2..][0..random_len].ptr);
    try testing.expect(parsed.session_id.ptr == body[35..37].ptr);
    try testing.expectEqual(@as(u16, 0xc02f), (try suites.next()).?);
    try testing.expectEqual(@as(u16, 0x009c), (try suites.next()).?);
    try testing.expectEqual(@as(?u16, null), try suites.next());
    const ext = (try extensions.next()).?;
    try testing.expectEqual(@as(u16, 0x000d), ext.ext_type);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x03, 0x08, 0x04 }, ext.data);
    try testing.expectEqual(@as(?Extension, null), try extensions.next());
}

test "encodeServerHello round trips through parser and extension iterator" {
    // Arrange.
    const random = [_]u8{0x5a} ** random_len;
    const session_id = [_]u8{ 1, 2, 3, 4 };
    const extensions = [_]u8{ 0x00, 0x0b, 0x00, 0x01, 0x02 };
    var out: [128]u8 = undefined;

    // Act.
    const encoded = try encodeServerHello(&out, 0x0303, &random, &session_id, 0xc02f, 0, &extensions);
    const parsed = try parseServerHello(encoded);
    var it = parsed.extensionIterator();

    // Assert.
    try testing.expectEqual(@as(u16, 0x0303), parsed.server_version);
    try testing.expectEqualSlices(u8, &random, parsed.random);
    try testing.expectEqualSlices(u8, &session_id, parsed.session_id);
    try testing.expectEqual(@as(u16, 0xc02f), parsed.cipher_suite);
    try testing.expectEqual(@as(u8, 0), parsed.compression);
    const ext = (try it.next()).?;
    try testing.expectEqual(@as(u16, 0x000b), ext.ext_type);
    try testing.expectEqualSlices(u8, &.{0x02}, ext.data);
    try testing.expectEqual(@as(?Extension, null), try it.next());
}

test "encodeCertificate writes known body bytes and parser iterates entries" {
    // Arrange.
    const first = [_]u8{ 0x30, 0x82 };
    const second = [_]u8{0x31};
    const chain = [_][]const u8{ &first, &second };
    var out: [16]u8 = undefined;

    // Act.
    const encoded = try encodeCertificate(&out, &chain);
    var parsed = try parseCertificate(encoded);

    // Assert.
    const expected = [_]u8{
        0x00, 0x00, 0x09,
        0x00, 0x00, 0x02,
        0x30, 0x82, 0x00,
        0x00, 0x01, 0x31,
    };
    try testing.expectEqualSlices(u8, &expected, encoded);
    try testing.expectEqualSlices(u8, &first, (try parsed.next()).?);
    try testing.expectEqualSlices(u8, &second, (try parsed.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try parsed.next());
}

test "server hello done and finished encode known message bodies" {
    // Arrange.
    const verify_data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    var done_out: [1]u8 = undefined;
    var finished_out: [finished_verify_data_len]u8 = undefined;

    // Act.
    const done = try encodeServerHelloDone(&done_out);
    const finished = try encodeFinished(&finished_out, &verify_data);
    const parsed_verify_data = try parseFinished(finished);

    // Assert.
    try testing.expectEqual(@as(usize, 0), done.len);
    try parseServerHelloDone(done);
    try testing.expectEqualSlices(u8, &verify_data, parsed_verify_data);
}

test "wrapHandshake and parseHandshakeHeader round trip known vector" {
    // Arrange.
    const body = [_]u8{ 0x03, 0x03 };
    var out: [8]u8 = undefined;

    // Act.
    const framed = try wrapHandshake(&out, server_hello_done_msg_type, &body);
    const parsed = try parseHandshakeHeader(framed);

    // Assert.
    try testing.expectEqualSlices(u8, &.{ 0x0e, 0x00, 0x00, 0x02, 0x03, 0x03 }, framed);
    try testing.expectEqual(server_hello_done_msg_type, parsed.msg_type);
    try testing.expectEqual(@as(usize, 2), parsed.length);
    try testing.expectEqualSlices(u8, &body, parsed.body);
}

test "parsers reject truncation, trailing bytes, and malformed vector lengths" {
    // Arrange.
    const short_header = [_]u8{ 1, 0, 0 };
    const trailing_header = [_]u8{ 1, 0, 0, 0, 0 };
    const odd_suites = [_]u8{
        0x03, 0x03,
    } ++ [_]u8{0} ** random_len ++ [_]u8{
        0x00, 0x00, 0x01, 0xff, 0x01, 0x00, 0x00, 0x00,
    };
    const long_session = [_]u8{
        0x03, 0x03,
    } ++ [_]u8{0} ** random_len ++ [_]u8{33} ++ [_]u8{0} ** 33;
    const bad_ext = [_]u8{ 0x00, 0x0d, 0x00, 0x04, 0x01 };
    var ext_it = ExtensionIterator{ .body = &bad_ext };

    try testing.expectError(error.BufferTooShort, parseHandshakeHeader(&short_header));
    try testing.expectError(error.TrailingBytes, parseHandshakeHeader(&trailing_header));
    try testing.expectError(error.OddCipherSuites, parseClientHello(&odd_suites));
    try testing.expectError(error.SessionIdTooLong, parseClientHello(&long_session));
    try testing.expectError(error.BufferTooShort, ext_it.next());
    try testing.expectError(error.BufferTooShort, parseCertificate(&.{ 0x00, 0x00 }));
    try testing.expectError(error.BufferTooShort, parseFinished(&.{ 1, 2 }));
    try testing.expectError(error.TrailingBytes, parseServerHelloDone(&.{0}));
}

test "encoders report NoSpaceLeft and oversize inputs" {
    // Arrange.
    const random = [_]u8{0} ** random_len;
    const long_session = [_]u8{0} ** (max_session_id_len + 1);
    const cert = [_]u8{0xaa};
    const chain = [_][]const u8{&cert};
    var short_out: [2]u8 = undefined;
    // 16 MB — heap-allocated so it cannot overflow the test thread's stack.
    const max_cert = try testing.allocator.alloc(u8, max_u24 + 1);
    defer testing.allocator.free(max_cert);

    try testing.expectError(error.NoSpaceLeft, encodeServerHello(&short_out, 0x0303, &random, "", 0x1301, 0, ""));
    try testing.expectError(error.SessionIdTooLong, encodeServerHello(&short_out, 0x0303, &random, &long_session, 0x1301, 0, ""));
    try testing.expectError(error.NoSpaceLeft, encodeCertificate(&short_out, &chain));
    try testing.expectError(error.CertificateTooLarge, encodeCertificate(&short_out, &.{max_cert}));
    try testing.expectError(error.NoSpaceLeft, encodeFinished(&short_out, &([_]u8{0} ** finished_verify_data_len)));
    try testing.expectError(error.NoSpaceLeft, wrapHandshake(&short_out, client_hello_msg_type, &cert));
}
