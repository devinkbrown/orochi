//! TLS 1.3 Cookie extension data codec (RFC 8446 section 4.2.2).
//!
//! The extension_data for the cookie extension is a single opaque vector:
//! `{ cookie<0..2^16-1> }`, encoded as a two-byte big-endian length followed
//! by exactly that many cookie bytes.
//!
//! Pure slice codec: no I/O, no clock, no RNG, no allocation. Returned slices
//! alias caller-provided input.

const std = @import("std");
const mem = std.mem;

comptime {
    if (@bitSizeOf(usize) != 64) {
        @compileError("tls_cookie.zig requires a 64-bit target");
    }
}

pub const max_cookie_len: usize = std.math.maxInt(u16);
pub const length_len: usize = 2;

pub const Error = error{
    Truncated,
    TrailingBytes,
    CookieTooLong,
    NoSpaceLeft,
};

/// Parse one TLS 1.3 cookie extension_data block.
///
/// The returned cookie slice aliases `block`.
pub fn parse(block: []const u8) Error![]const u8 {
    if (block.len < length_len) return error.Truncated;

    const cookie_len = mem.readInt(u16, block[0..2], .big);
    const body_start = length_len;
    if (block.len - body_start < cookie_len) return error.Truncated;
    if (block.len - body_start != cookie_len) return error.TrailingBytes;

    return block[body_start .. body_start + cookie_len];
}

/// Build one TLS 1.3 cookie extension_data block into `out`.
///
/// Returns the written wire-format slice, which aliases `out`.
pub fn build(out: []u8, cookie: []const u8) Error![]const u8 {
    if (cookie.len > max_cookie_len) return error.CookieTooLong;

    const needed = length_len + cookie.len;
    if (out.len < needed) return error.NoSpaceLeft;

    mem.writeInt(u16, out[0..2], @intCast(cookie.len), .big);
    @memcpy(out[length_len..needed], cookie);
    return out[0..needed];
}

const testing = std.testing;

test "parse returns cookie from known-answer extension data" {
    // Arrange.
    const block = [_]u8{ 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };

    // Act.
    const cookie = try parse(&block);

    // Assert.
    try testing.expectEqualSlices(u8, "hello", cookie);
    try testing.expect(cookie.ptr == block[2..].ptr);
}

test "build writes known-answer extension data" {
    // Arrange.
    var out: [16]u8 = undefined;

    // Act.
    const block = try build(&out, "hello");

    // Assert.
    const expected = [_]u8{ 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    try testing.expectEqualSlices(u8, &expected, block);
    try testing.expect(block.ptr == out[0..].ptr);
}

test "build and parse round trip empty cookie" {
    // Arrange.
    var out: [2]u8 = undefined;

    // Act.
    const block = try build(&out, "");
    const cookie = try parse(block);

    // Assert.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, block);
    try testing.expectEqual(@as(usize, 0), cookie.len);
    try testing.expect(cookie.ptr == block[2..].ptr);
}

test "build and parse round trip maximum-length cookie" {
    // Arrange.
    var cookie: [max_cookie_len]u8 = undefined;
    for (&cookie, 0..) |*byte, i| {
        byte.* = @intCast(i & 0xff);
    }
    var out: [length_len + max_cookie_len]u8 = undefined;

    // Act.
    const block = try build(&out, &cookie);
    const parsed = try parse(block);

    // Assert.
    try testing.expectEqual(@as(usize, length_len + max_cookie_len), block.len);
    try testing.expectEqual(@as(u8, 0xff), block[0]);
    try testing.expectEqual(@as(u8, 0xff), block[1]);
    try testing.expectEqualSlices(u8, &cookie, parsed);
}

test "parse rejects missing or partial length prefix" {
    // Arrange.
    const empty = [_]u8{};
    const partial = [_]u8{0x00};

    // Act.
    const empty_result = parse(&empty);
    const partial_result = parse(&partial);

    // Assert.
    try testing.expectError(error.Truncated, empty_result);
    try testing.expectError(error.Truncated, partial_result);
}

test "parse rejects truncated cookie body" {
    // Arrange.
    const block = [_]u8{ 0x00, 0x03, 0xaa, 0xbb };

    // Act.
    const result = parse(&block);

    // Assert.
    try testing.expectError(error.Truncated, result);
}

test "parse rejects trailing bytes after declared cookie" {
    // Arrange.
    const block = [_]u8{ 0x00, 0x01, 0xaa, 0xbb };

    // Act.
    const result = parse(&block);

    // Assert.
    try testing.expectError(error.TrailingBytes, result);
}

test "build rejects output buffer with no room for length prefix" {
    // Arrange.
    var out: [1]u8 = undefined;

    // Act.
    const result = build(&out, "");

    // Assert.
    try testing.expectError(error.NoSpaceLeft, result);
}

test "build rejects output buffer too small for cookie body" {
    // Arrange.
    var out: [3]u8 = undefined;

    // Act.
    const result = build(&out, &[_]u8{ 0xaa, 0xbb });

    // Assert.
    try testing.expectError(error.NoSpaceLeft, result);
}

test "build rejects cookie longer than uint16 vector limit" {
    // Arrange.
    var cookie: [max_cookie_len + 1]u8 = undefined;
    var out: [length_len + max_cookie_len]u8 = undefined;

    // Act.
    const result = build(&out, &cookie);

    // Assert.
    try testing.expectError(error.CookieTooLong, result);
}
