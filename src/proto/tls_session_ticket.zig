// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 NewSessionTicket message codec (RFC 8446 section 4.6.1).
//!
//! This module is intentionally pure: it performs only byte-slice
//! encode/decode work and has no I/O, clock, or randomness dependencies.

const std = @import("std");
const mem = std.mem;

comptime {
    if (@bitSizeOf(usize) != 64) {
        @compileError("tls_session_ticket.zig requires a 64-bit target");
    }
}

pub const max_ticket_nonce_len: usize = 0xff;
pub const max_ticket_len: usize = 0xffff;
pub const max_extensions_len: usize = 0xffff;

pub const EncodeError = error{
    NoSpaceLeft,
    TicketNonceTooLarge,
    TicketTooLarge,
    ExtensionsTooLarge,
};

pub const ParseError = error{
    BufferTooShort,
    TrailingBytes,
};

/// TLS 1.3 NewSessionTicket message body.
///
/// `ticket_nonce`, `ticket`, and `extensions` are opaque TLS vectors. Values
/// returned by `parse` alias the input byte slice.
pub const NewSessionTicket = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    ticket: []const u8,
    extensions: []const u8,

    pub fn encodedLen(self: NewSessionTicket) EncodeError!usize {
        if (self.ticket_nonce.len > max_ticket_nonce_len) return error.TicketNonceTooLarge;
        if (self.ticket.len > max_ticket_len) return error.TicketTooLarge;
        if (self.extensions.len > max_extensions_len) return error.ExtensionsTooLarge;

        return 4 + 4 +
            1 + self.ticket_nonce.len +
            2 + self.ticket.len +
            2 + self.extensions.len;
    }
};

/// Encode `ticket` into `out` and return the written wire-format slice.
pub fn encode(out: []u8, ticket: NewSessionTicket) EncodeError![]const u8 {
    const total = try ticket.encodedLen();
    if (out.len < total) return error.NoSpaceLeft;

    var off: usize = 0;
    mem.writeInt(u32, out[off..][0..4], ticket.ticket_lifetime, .big);
    off += 4;
    mem.writeInt(u32, out[off..][0..4], ticket.ticket_age_add, .big);
    off += 4;

    out[off] = @intCast(ticket.ticket_nonce.len);
    off += 1;
    @memcpy(out[off .. off + ticket.ticket_nonce.len], ticket.ticket_nonce);
    off += ticket.ticket_nonce.len;

    mem.writeInt(u16, out[off..][0..2], @intCast(ticket.ticket.len), .big);
    off += 2;
    @memcpy(out[off .. off + ticket.ticket.len], ticket.ticket);
    off += ticket.ticket.len;

    mem.writeInt(u16, out[off..][0..2], @intCast(ticket.extensions.len), .big);
    off += 2;
    @memcpy(out[off .. off + ticket.extensions.len], ticket.extensions);
    off += ticket.extensions.len;

    return out[0..off];
}

/// Parse one complete NewSessionTicket message body.
///
/// The returned slices alias `bytes`; no allocation or copying is performed.
pub fn parse(bytes: []const u8) ParseError!NewSessionTicket {
    var off: usize = 0;

    const ticket_lifetime = try readU32(bytes, &off);
    const ticket_age_add = try readU32(bytes, &off);
    const ticket_nonce = try readOpaqueU8(bytes, &off);
    const ticket = try readOpaqueU16(bytes, &off);
    const extensions = try readOpaqueU16(bytes, &off);

    if (off != bytes.len) return error.TrailingBytes;

    return .{
        .ticket_lifetime = ticket_lifetime,
        .ticket_age_add = ticket_age_add,
        .ticket_nonce = ticket_nonce,
        .ticket = ticket,
        .extensions = extensions,
    };
}

/// RFC 8446 obfuscated_ticket_age calculation:
/// (received_age_ms + ticket_age_add) mod 2^32.
pub fn obfuscatedAge(received_age_ms: u64, ticket_age_add: u32) u32 {
    return @as(u32, @truncate(received_age_ms)) +% ticket_age_add;
}

fn readU32(bytes: []const u8, off: *usize) ParseError!u32 {
    if (bytes.len - off.* < 4) return error.BufferTooShort;
    const value = mem.readInt(u32, bytes[off.*..][0..4], .big);
    off.* += 4;
    return value;
}

fn readOpaqueU8(bytes: []const u8, off: *usize) ParseError![]const u8 {
    if (bytes.len - off.* < 1) return error.BufferTooShort;
    const len = bytes[off.*];
    off.* += 1;
    return readOpaqueBody(bytes, off, len);
}

fn readOpaqueU16(bytes: []const u8, off: *usize) ParseError![]const u8 {
    if (bytes.len - off.* < 2) return error.BufferTooShort;
    const len = mem.readInt(u16, bytes[off.*..][0..2], .big);
    off.* += 2;
    return readOpaqueBody(bytes, off, len);
}

fn readOpaqueBody(bytes: []const u8, off: *usize, len: usize) ParseError![]const u8 {
    if (bytes.len - off.* < len) return error.BufferTooShort;
    const body = bytes[off.* .. off.* + len];
    off.* += len;
    return body;
}

const testing = std.testing;

test "encode and parse round trip preserves all NewSessionTicket fields" {
    // Arrange.
    const source = NewSessionTicket{
        .ticket_lifetime = 86_400,
        .ticket_age_add = 0x1020_3040,
        .ticket_nonce = &.{ 0xaa, 0xbb, 0xcc },
        .ticket = &.{ 0x01, 0x02, 0x03, 0x04, 0x05 },
        .extensions = &.{ 0x00, 0x2a, 0x00, 0x01, 0xff },
    };
    var out: [64]u8 = undefined;

    // Act.
    const encoded = try encode(&out, source);
    const parsed = try parse(encoded);

    // Assert.
    const expected = [_]u8{
        0x00, 0x01, 0x51, 0x80,
        0x10, 0x20, 0x30, 0x40,
        0x03, 0xaa, 0xbb, 0xcc,
        0x00, 0x05, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x00,
        0x05, 0x00, 0x2a, 0x00,
        0x01, 0xff,
    };
    try testing.expectEqualSlices(u8, &expected, encoded);
    try testing.expectEqual(@as(u32, 86_400), parsed.ticket_lifetime);
    try testing.expectEqual(@as(u32, 0x1020_3040), parsed.ticket_age_add);
    try testing.expectEqualSlices(u8, source.ticket_nonce, parsed.ticket_nonce);
    try testing.expectEqualSlices(u8, source.ticket, parsed.ticket);
    try testing.expectEqualSlices(u8, source.extensions, parsed.extensions);
    try testing.expect(parsed.ticket_nonce.ptr == encoded[9..12].ptr);
    try testing.expect(parsed.ticket.ptr == encoded[14..19].ptr);
    try testing.expect(parsed.extensions.ptr == encoded[21..26].ptr);
}

test "parse rejects every truncation of a non-empty NewSessionTicket" {
    // Arrange.
    const wire = [_]u8{
        0x00, 0x00, 0x00, 0x3c,
        0xde, 0xad, 0xbe, 0xef,
        0x02, 0x11, 0x22, 0x00,
        0x03, 0x33, 0x44, 0x55,
        0x00, 0x02, 0x66, 0x77,
    };

    // Act and assert.
    var len: usize = 0;
    while (len < wire.len) : (len += 1) {
        try testing.expectError(error.BufferTooShort, parse(wire[0..len]));
    }
}

test "parse accepts empty ticket_nonce and extensions" {
    // Arrange.
    const wire = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x02, 0xaa,
        0xbb, 0x00, 0x00,
    };

    // Act.
    const parsed = try parse(&wire);

    // Assert.
    try testing.expectEqual(@as(u32, 1), parsed.ticket_lifetime);
    try testing.expectEqual(@as(u32, 2), parsed.ticket_age_add);
    try testing.expectEqual(@as(usize, 0), parsed.ticket_nonce.len);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, parsed.ticket);
    try testing.expectEqual(@as(usize, 0), parsed.extensions.len);
}

test "encode writes empty ticket_nonce and extensions with zero lengths" {
    // Arrange.
    const source = NewSessionTicket{
        .ticket_lifetime = 1,
        .ticket_age_add = 2,
        .ticket_nonce = "",
        .ticket = &.{0xab},
        .extensions = "",
    };
    var out: [14]u8 = undefined;

    // Act.
    const encoded = try encode(&out, source);

    // Assert.
    const expected = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x01, 0xab,
        0x00, 0x00,
    };
    try testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode rejects an output buffer without enough space" {
    // Arrange.
    const source = NewSessionTicket{
        .ticket_lifetime = 1,
        .ticket_age_add = 2,
        .ticket_nonce = &.{0x03},
        .ticket = &.{0x04},
        .extensions = "",
    };
    var out: [12]u8 = undefined;

    // Act and assert.
    try testing.expectError(error.NoSpaceLeft, encode(&out, source));
}

test "parse rejects trailing bytes after extensions vector" {
    // Arrange.
    const wire = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x01, 0xaa,
        0x00, 0x00, 0xff,
    };

    // Act and assert.
    try testing.expectError(error.TrailingBytes, parse(&wire));
}

test "obfuscatedAge adds modulo 2 to the 32nd power" {
    // Arrange.
    const received_age_ms: u64 = 0xffff_fff0;
    const ticket_age_add: u32 = 0x30;

    // Act.
    const age = obfuscatedAge(received_age_ms, ticket_age_add);

    // Assert.
    try testing.expectEqual(@as(u32, 0x20), age);
}

test "obfuscatedAge uses low 32 bits of large millisecond ages" {
    // Arrange.
    const received_age_ms: u64 = 0x1_0000_0005;
    const ticket_age_add: u32 = 7;

    // Act.
    const age = obfuscatedAge(received_age_ms, ticket_age_add);

    // Assert.
    try testing.expectEqual(@as(u32, 12), age);
}
