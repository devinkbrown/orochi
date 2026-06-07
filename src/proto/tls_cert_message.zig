//! TLS 1.3 Certificate and CertificateVerify message codecs.
//!
//! Pure byte-slice codecs: no I/O, no clock, no randomness, and no allocation.

const std = @import("std");
const mem = std.mem;

comptime {
    if (@bitSizeOf(usize) != 64) {
        @compileError("tls_cert_message.zig requires a 64-bit target");
    }
}

pub const certificate_msg_type: u8 = 11;
pub const certificate_verify_msg_type: u8 = 15;
pub const max_u24: usize = 0x00ff_ffff;
pub const max_u16: usize = 0xffff;

const handshake_header_len: usize = 4;
const certificate_list_prefix_len: usize = 1 + 3;
const certificate_entry_overhead: usize = 3 + 2;
const certificate_verify_body_prefix_len: usize = 2 + 2;

const server_context = "TLS 1.3, server CertificateVerify";
const client_context = "TLS 1.3, client CertificateVerify";

pub const EncodeError = error{
    NoSpaceLeft,
    CertificateTooLarge,
    CertificateListTooLarge,
    BodyTooLarge,
    SignatureTooLarge,
};

pub const ParseError = error{
    BufferTooShort,
    TrailingBytes,
};

pub const SignedContentError = error{
    NoSpaceLeft,
};

pub const CertificateVerify = struct {
    scheme: u16,
    signature: []const u8,
};

pub const CertificateIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *CertificateIterator) ParseError!?[]const u8 {
        if (self.pos == self.body.len) return null;
        if (self.body.len - self.pos < certificate_entry_overhead) return error.BufferTooShort;

        const cert_len = readU24(self.body[self.pos..][0..3]);
        self.pos += 3;
        if (self.body.len - self.pos < cert_len) return error.BufferTooShort;
        const cert = self.body[self.pos .. self.pos + cert_len];
        self.pos += cert_len;

        if (self.body.len - self.pos < 2) return error.BufferTooShort;
        const extensions_len = mem.readInt(u16, self.body[self.pos..][0..2], .big);
        self.pos += 2;
        if (self.body.len - self.pos < extensions_len) return error.BufferTooShort;
        self.pos += extensions_len;

        return cert;
    }

    pub fn remaining(self: CertificateIterator) usize {
        return self.body.len - self.pos;
    }
};

pub fn encodeCertificate(out: []u8, cert_der_chain: []const []const u8) EncodeError![]const u8 {
    const list_len = try certificateListLen(cert_der_chain);
    const body_len = certificate_list_prefix_len + list_len;
    if (body_len > max_u24) return error.BodyTooLarge;
    const total_len = handshake_header_len + body_len;
    if (out.len < total_len) return error.NoSpaceLeft;

    var off: usize = 0;
    out[off] = certificate_msg_type;
    off += 1;
    writeU24(out[off..][0..3], body_len);
    off += 3;

    out[off] = 0;
    off += 1;
    writeU24(out[off..][0..3], list_len);
    off += 3;

    for (cert_der_chain) |der| {
        writeU24(out[off..][0..3], der.len);
        off += 3;
        @memcpy(out[off .. off + der.len], der);
        off += der.len;
        mem.writeInt(u16, out[off..][0..2], 0, .big);
        off += 2;
    }

    return out[0..off];
}

pub fn parseCertificate(body: []const u8) ParseError!CertificateIterator {
    if (body.len < 1) return error.BufferTooShort;
    var off: usize = 0;

    const context_len: usize = body[off];
    off += 1;
    if (body.len - off < context_len) return error.BufferTooShort;
    off += context_len;

    if (body.len - off < 3) return error.BufferTooShort;
    const list_len = readU24(body[off..][0..3]);
    off += 3;
    if (body.len - off < list_len) return error.BufferTooShort;
    if (body.len - off != list_len) return error.TrailingBytes;

    return .{ .body = body[off .. off + list_len] };
}

pub fn encodeCertificateVerify(out: []u8, scheme: u16, signature: []const u8) EncodeError![]const u8 {
    if (signature.len > max_u16) return error.SignatureTooLarge;
    const body_len = certificate_verify_body_prefix_len + signature.len;
    if (body_len > max_u24) return error.BodyTooLarge;
    const total_len = handshake_header_len + body_len;
    if (out.len < total_len) return error.NoSpaceLeft;

    var off: usize = 0;
    out[off] = certificate_verify_msg_type;
    off += 1;
    writeU24(out[off..][0..3], body_len);
    off += 3;
    mem.writeInt(u16, out[off..][0..2], scheme, .big);
    off += 2;
    mem.writeInt(u16, out[off..][0..2], @intCast(signature.len), .big);
    off += 2;
    @memcpy(out[off .. off + signature.len], signature);
    off += signature.len;

    return out[0..off];
}

pub fn parseCertificateVerify(body: []const u8) ParseError!CertificateVerify {
    if (body.len < certificate_verify_body_prefix_len) return error.BufferTooShort;

    const scheme = mem.readInt(u16, body[0..2], .big);
    const signature_len = mem.readInt(u16, body[2..4], .big);
    if (body.len - certificate_verify_body_prefix_len < signature_len) return error.BufferTooShort;
    if (body.len - certificate_verify_body_prefix_len != signature_len) return error.TrailingBytes;

    return .{
        .scheme = scheme,
        .signature = body[certificate_verify_body_prefix_len..],
    };
}

pub fn signedContent(out: []u8, transcript_hash: []const u8, is_server: bool) SignedContentError![]const u8 {
    const context = if (is_server) server_context else client_context;
    const total_len = 64 + context.len + 1 + transcript_hash.len;
    if (out.len < total_len) return error.NoSpaceLeft;

    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..context.len], context);
    out[64 + context.len] = 0;
    @memcpy(out[64 + context.len + 1 .. total_len], transcript_hash);

    return out[0..total_len];
}

fn certificateListLen(cert_der_chain: []const []const u8) EncodeError!usize {
    var len: usize = 0;
    for (cert_der_chain) |der| {
        if (der.len > max_u24) return error.CertificateTooLarge;
        if (max_u24 - len < certificate_entry_overhead) return error.CertificateListTooLarge;
        len += certificate_entry_overhead;
        if (max_u24 - len < der.len) return error.CertificateListTooLarge;
        len += der.len;
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

test "encodeCertificate writes known server certificate message bytes" {
    // Arrange.
    const first = [_]u8{ 0x30, 0x82 };
    const second = [_]u8{0x30};
    const chain = [_][]const u8{ &first, &second };
    var out: [32]u8 = undefined;

    // Act.
    const encoded = try encodeCertificate(&out, &chain);

    // Assert.
    const expected = [_]u8{
        0x0b, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x00, 0x0d,
        0x00, 0x00, 0x02, 0x30,
        0x82, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x30, 0x00,
        0x00,
    };
    try testing.expectEqualSlices(u8, &expected, encoded);
}

test "parseCertificate iterates DER slices and skips entry extensions" {
    // Arrange.
    const body = [_]u8{
        0x00, 0x00, 0x00, 0x0f,
        0x00, 0x00, 0x02, 0xaa,
        0xbb, 0x00, 0x02, 0xcc,
        0xdd, 0x00, 0x00, 0x01,
        0xee, 0x00, 0x00,
    };

    // Act.
    var it = try parseCertificate(&body);
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    const end = try it.next();

    // Assert.
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, first);
    try testing.expectEqualSlices(u8, &.{0xee}, second);
    try testing.expectEqual(@as(?[]const u8, null), end);
    try testing.expect(first.ptr == body[7..9].ptr);
    try testing.expect(second.ptr == body[16..17].ptr);
}

test "encodeCertificate and parseCertificate round trip empty and non-empty chains" {
    // Arrange.
    const first = [_]u8{ 0x01, 0x02, 0x03 };
    const second = [_]u8{ 0x04, 0x05 };
    const chain = [_][]const u8{ &first, &second };
    var out: [64]u8 = undefined;

    // Act.
    const encoded = try encodeCertificate(&out, &chain);
    var it = try parseCertificate(encoded[handshake_header_len..]);
    const parsed_first = (try it.next()).?;
    const parsed_second = (try it.next()).?;
    const end = try it.next();

    const empty_encoded = try encodeCertificate(&out, &.{});
    var empty_it = try parseCertificate(empty_encoded[handshake_header_len..]);
    const empty_end = try empty_it.next();

    // Assert.
    try testing.expectEqual(certificate_msg_type, encoded[0]);
    try testing.expectEqualSlices(u8, &first, parsed_first);
    try testing.expectEqualSlices(u8, &second, parsed_second);
    try testing.expectEqual(@as(?[]const u8, null), end);
    try testing.expectEqual(@as(?[]const u8, null), empty_end);
    try testing.expectEqualSlices(u8, &.{ 0x0b, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 }, empty_encoded);
}

test "parseCertificate rejects top-level truncation and trailing bytes" {
    // Arrange.
    const good_body = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const trailing = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0xff };
    const bad_context = [_]u8{ 0x02, 0xaa };
    const bad_list = [_]u8{ 0x00, 0x00, 0x00, 0x01 };

    // Act and assert.
    var len: usize = 0;
    while (len < good_body.len) : (len += 1) {
        try testing.expectError(error.BufferTooShort, parseCertificate(good_body[0..len]));
    }
    try testing.expectError(error.TrailingBytes, parseCertificate(&trailing));
    try testing.expectError(error.BufferTooShort, parseCertificate(&bad_context));
    try testing.expectError(error.BufferTooShort, parseCertificate(&bad_list));
}

test "CertificateIterator rejects truncated entry fields" {
    // Arrange.
    const short_header = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x00 };
    const short_cert = [_]u8{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0xaa };
    const short_ext_len = [_]u8{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0xaa };
    const short_ext = [_]u8{ 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0xaa, 0x00, 0x03, 0xbb };

    // Act and assert.
    var a = try parseCertificate(&short_header);
    try testing.expectError(error.BufferTooShort, a.next());
    var b = try parseCertificate(&short_cert);
    try testing.expectError(error.BufferTooShort, b.next());
    var c = try parseCertificate(&short_ext_len);
    try testing.expectError(error.BufferTooShort, c.next());
    var d = try parseCertificate(&short_ext);
    try testing.expectError(error.BufferTooShort, d.next());
}

test "encodeCertificate reports small output and oversized vectors" {
    // Arrange.
    const cert = [_]u8{ 0x01, 0x02, 0x03 };
    const chain = [_][]const u8{&cert};
    var short_out: [8]u8 = undefined;
    const max_sized_cert = try testing.allocator.alloc(u8, max_u24);
    defer testing.allocator.free(max_sized_cert);
    const too_large_cert = try testing.allocator.alloc(u8, max_u24 + 1);
    defer testing.allocator.free(too_large_cert);
    const max_chain = [_][]const u8{max_sized_cert};
    const too_large_chain = [_][]const u8{too_large_cert};

    // Act and assert.
    try testing.expectError(error.NoSpaceLeft, encodeCertificate(&short_out, &chain));
    try testing.expectError(error.CertificateListTooLarge, encodeCertificate(&short_out, &max_chain));
    try testing.expectError(error.CertificateTooLarge, encodeCertificate(&short_out, &too_large_chain));
}

test "encodeCertificateVerify writes known bytes and parser aliases signature" {
    // Arrange.
    const signature = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var out: [16]u8 = undefined;

    // Act.
    const encoded = try encodeCertificateVerify(&out, 0x0807, &signature);
    const parsed = try parseCertificateVerify(encoded[handshake_header_len..]);

    // Assert.
    const expected = [_]u8{
        0x0f, 0x00, 0x00, 0x08,
        0x08, 0x07, 0x00, 0x04,
        0xde, 0xad, 0xbe, 0xef,
    };
    try testing.expectEqualSlices(u8, &expected, encoded);
    try testing.expectEqual(@as(u16, 0x0807), parsed.scheme);
    try testing.expectEqualSlices(u8, &signature, parsed.signature);
    try testing.expect(parsed.signature.ptr == encoded[8..12].ptr);
}

test "parseCertificateVerify rejects truncation and trailing bytes" {
    // Arrange.
    const good_body = [_]u8{ 0x08, 0x07, 0x00, 0x01, 0xaa };
    const short_sig = [_]u8{ 0x08, 0x07, 0x00, 0x02, 0xaa };
    const trailing = [_]u8{ 0x08, 0x07, 0x00, 0x01, 0xaa, 0xbb };

    // Act and assert.
    var len: usize = 0;
    while (len < good_body.len) : (len += 1) {
        try testing.expectError(error.BufferTooShort, parseCertificateVerify(good_body[0..len]));
    }
    try testing.expectError(error.BufferTooShort, parseCertificateVerify(&short_sig));
    try testing.expectError(error.TrailingBytes, parseCertificateVerify(&trailing));
}

test "encodeCertificateVerify reports small output and oversized signature" {
    // Arrange.
    var short_out: [6]u8 = undefined;
    const signature = [_]u8{ 0xaa, 0xbb, 0xcc };
    const oversized_signature = [_]u8{0xaa} ** (max_u16 + 1);
    var enough: [handshake_header_len + certificate_verify_body_prefix_len]u8 = undefined;

    // Act and assert.
    try testing.expectError(error.NoSpaceLeft, encodeCertificateVerify(&short_out, 0x0807, &signature));
    try testing.expectError(error.SignatureTooLarge, encodeCertificateVerify(&enough, 0x0807, &oversized_signature));
}

test "signedContent builds known server and client inputs" {
    // Arrange.
    const transcript_hash = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    var server_out: [128]u8 = undefined;
    var client_out: [128]u8 = undefined;

    // Act.
    const server = try signedContent(&server_out, &transcript_hash, true);
    const client = try signedContent(&client_out, &transcript_hash, false);

    // Assert.
    try testing.expectEqual(@as(usize, 64 + server_context.len + 1 + transcript_hash.len), server.len);
    try testing.expectEqualSlices(u8, &([_]u8{0x20} ** 64), server[0..64]);
    try testing.expectEqualSlices(u8, server_context, server[64..][0..server_context.len]);
    try testing.expectEqual(@as(u8, 0), server[64 + server_context.len]);
    try testing.expectEqualSlices(u8, &transcript_hash, server[64 + server_context.len + 1 ..]);
    try testing.expectEqualSlices(u8, client_context, client[64..][0..client_context.len]);
}

test "signedContent reports NoSpaceLeft" {
    // Arrange.
    var out: [64]u8 = undefined;

    // Act and assert.
    try testing.expectError(error.NoSpaceLeft, signedContent(&out, "", true));
}
