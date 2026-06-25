// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone LEB128 varint codec.
//!
//! This module is a self-contained, allocation-free LEB128 (Little Endian Base
//! 128) codec for 64-bit integers. It is intentionally decoupled from any
//! higher-level wire format: the encoders write into a caller-owned buffer and
//! the decoders read from a caller-owned slice, returning the decoded value
//! together with the number of bytes consumed.
//!
//! Two integer flavors are provided:
//!
//!   * Unsigned: `encodeU64` / `decodeU64` emit and parse standard unsigned
//!     LEB128 (7 payload bits per byte, MSB as continuation flag).
//!   * Signed: `encodeI64` / `decodeI64` apply ZigZag mapping so that small
//!     magnitude negatives encode compactly, then reuse the unsigned codec.
//!
//! Hardening guarantees:
//!
//!   * A 64-bit value never occupies more than `max_len` (10) bytes.
//!   * Decoding rejects truncated input (`error.Truncated`) when the buffer
//!     ends mid-varint.
//!   * Decoding rejects overlong encodings (`error.Overflow`) once more than
//!     `max_len` continuation bytes appear, or when the 10th byte carries bits
//!     that would not fit in a `u64`.
//!
//! Unlike the canonical CoilPack primitives, this codec does NOT reject
//! non-minimal (but in-range) encodings; it only guards against truncation and
//! 64-bit overflow. Callers needing canonical-form enforcement should layer
//! that check on top using the returned `len`.

const std = @import("std");

/// Maximum number of bytes any 64-bit LEB128 varint can occupy.
///
/// ceil(64 / 7) == 10. The final byte carries only the top bit of the value.
pub const max_len: usize = 10;

/// Errors produced while decoding a varint.
pub const DecodeError = error{
    /// The input slice ended before a terminating (continuation-clear) byte.
    Truncated,
    /// The encoding exceeds `max_len` bytes or sets bits beyond bit 63.
    Overflow,
};

/// Result of a successful decode: the recovered value and the byte count read.
pub const Decoded = struct {
    /// The decoded unsigned value.
    value: u64,
    /// Number of bytes consumed from the input slice.
    len: usize,
};

/// Result of a successful signed decode: the recovered value and bytes read.
pub const DecodedSigned = struct {
    /// The decoded signed value (after ZigZag inverse mapping).
    value: i64,
    /// Number of bytes consumed from the input slice.
    len: usize,
};

/// Returns the number of bytes the unsigned LEB128 encoding of `value` needs.
///
/// Always between 1 and `max_len` inclusive.
pub fn encodedLenU64(value: u64) usize {
    var remaining = value;
    var len: usize = 1;
    while (remaining >= 0x80) : (len += 1) {
        remaining >>= 7;
    }
    return len;
}

/// Encodes `value` as unsigned LEB128 into the front of `buf`.
///
/// Returns the slice of `buf` that holds the encoding. Fails with
/// `error.BufferTooSmall` if `buf` cannot hold the full varint; in that case
/// `buf` may have been partially written and must be treated as undefined.
pub fn encodeU64(value: u64, buf: []u8) error{BufferTooSmall}![]u8 {
    var remaining = value;
    var pos: usize = 0;
    while (remaining >= 0x80) {
        if (pos >= buf.len) return error.BufferTooSmall;
        buf[pos] = @as(u8, @intCast(remaining & 0x7f)) | 0x80;
        pos += 1;
        remaining >>= 7;
    }
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = @intCast(remaining);
    pos += 1;
    return buf[0..pos];
}

/// Decodes an unsigned LEB128 varint from the front of `buf`.
///
/// Returns the value and the number of bytes consumed. Trailing bytes after the
/// terminating byte are ignored (the caller can advance by `Decoded.len`).
pub fn decodeU64(buf: []const u8) DecodeError!Decoded {
    var value: u64 = 0;
    var i: usize = 0;
    while (i < max_len) : (i += 1) {
        if (i >= buf.len) return error.Truncated;
        const byte = buf[i];
        const payload: u64 = byte & 0x7f;

        // The 10th byte (index 9) may contribute only the single top bit of a
        // u64; any larger payload would overflow 64 bits.
        if (i == max_len - 1 and payload > 1) return error.Overflow;

        value |= payload << @as(u6, @intCast(i * 7));

        if ((byte & 0x80) == 0) {
            return .{ .value = value, .len = i + 1 };
        }
    }
    // All `max_len` bytes had the continuation bit set: the varint is overlong.
    return error.Overflow;
}

/// Returns the number of bytes the signed (ZigZag) encoding of `value` needs.
pub fn encodedLenI64(value: i64) usize {
    return encodedLenU64(zigzagEncode(value));
}

/// Encodes `value` as ZigZag + unsigned LEB128 into the front of `buf`.
///
/// Returns the slice of `buf` holding the encoding. See `encodeU64` for the
/// `error.BufferTooSmall` contract.
pub fn encodeI64(value: i64, buf: []u8) error{BufferTooSmall}![]u8 {
    return encodeU64(zigzagEncode(value), buf);
}

/// Decodes a ZigZag + unsigned LEB128 varint from the front of `buf`.
pub fn decodeI64(buf: []const u8) DecodeError!DecodedSigned {
    const decoded = try decodeU64(buf);
    return .{ .value = zigzagDecode(decoded.value), .len = decoded.len };
}

/// Maps a signed integer to an unsigned one so small magnitudes stay small:
/// 0 -> 0, -1 -> 1, 1 -> 2, -2 -> 3, ...
pub fn zigzagEncode(value: i64) u64 {
    return (@as(u64, @bitCast(value)) << 1) ^ @as(u64, @bitCast(value >> 63));
}

/// Inverse of `zigzagEncode`.
pub fn zigzagDecode(value: u64) i64 {
    return @bitCast((value >> 1) ^ (0 -% (value & 1)));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "encodedLenU64 matches known boundaries" {
    try testing.expectEqual(@as(usize, 1), encodedLenU64(0));
    try testing.expectEqual(@as(usize, 1), encodedLenU64(0x7f));
    try testing.expectEqual(@as(usize, 2), encodedLenU64(0x80));
    try testing.expectEqual(@as(usize, 2), encodedLenU64(0x3fff));
    try testing.expectEqual(@as(usize, 3), encodedLenU64(0x4000));
    try testing.expectEqual(@as(usize, max_len), encodedLenU64(std.math.maxInt(u64)));
}

test "unsigned round-trips at canonical boundaries" {
    const values = [_]u64{
        0,
        1,
        2,
        0x7f,
        0x80,
        0x81,
        0x3fff,
        0x4000,
        0xffff,
        0x1_0000,
        0xffff_ffff,
        0x1_0000_0000,
        std.math.maxInt(u64),
    };

    for (values) |value| {
        var buf: [max_len]u8 = undefined;
        const encoded = try encodeU64(value, &buf);
        try testing.expectEqual(encodedLenU64(value), encoded.len);

        const decoded = try decodeU64(encoded);
        try testing.expectEqual(value, decoded.value);
        try testing.expectEqual(encoded.len, decoded.len);
    }
}

test "encodeU64 produces expected bytes for 0 127 128 300" {
    var buf: [max_len]u8 = undefined;

    try testing.expectEqualSlices(u8, &.{0x00}, try encodeU64(0, &buf));
    try testing.expectEqualSlices(u8, &.{0x7f}, try encodeU64(127, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, try encodeU64(128, &buf));
    try testing.expectEqualSlices(u8, &.{ 0xac, 0x02 }, try encodeU64(300, &buf));
}

test "maxInt(u64) occupies exactly max_len bytes" {
    var buf: [max_len]u8 = undefined;
    const encoded = try encodeU64(std.math.maxInt(u64), &buf);
    try testing.expectEqual(@as(usize, max_len), encoded.len);
    try testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 },
        encoded,
    );

    const decoded = try decodeU64(encoded);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), decoded.value);
    try testing.expectEqual(@as(usize, max_len), decoded.len);
}

test "decodeU64 ignores trailing bytes and reports consumed length" {
    // 300 encodes to {0xac, 0x02}; extra bytes must be left untouched.
    const buf = [_]u8{ 0xac, 0x02, 0xde, 0xad };
    const decoded = try decodeU64(&buf);
    try testing.expectEqual(@as(u64, 300), decoded.value);
    try testing.expectEqual(@as(usize, 2), decoded.len);
}

test "decodeU64 rejects truncated input" {
    // Empty buffer.
    try testing.expectError(error.Truncated, decodeU64(&.{}));
    // Single continuation byte with nothing following.
    try testing.expectError(error.Truncated, decodeU64(&.{0x80}));
    // Several continuation bytes, still no terminator.
    try testing.expectError(error.Truncated, decodeU64(&.{ 0x80, 0x80, 0x80 }));
}

test "decodeU64 rejects overlong encodings" {
    // 10 continuation bytes then a terminator with a high payload: the 10th
    // byte carries more than the single permissible top bit.
    const overflow_high = [_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 };
    try testing.expectError(error.Overflow, decodeU64(&overflow_high));

    // 10 continuation bytes with no terminator at all: exceeds max_len.
    const all_continuations = [_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
    try testing.expectError(error.Overflow, decodeU64(&all_continuations));
}

test "decodeU64 accepts boundary 10-byte encoding of maxInt" {
    // The 10th byte's payload is exactly 1, which is permitted.
    const at_limit = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    const decoded = try decodeU64(&at_limit);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), decoded.value);
    try testing.expectEqual(@as(usize, max_len), decoded.len);
}

test "encodeU64 rejects buffers that are too small" {
    var empty: [0]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeU64(1, &empty));

    // 300 needs two bytes; a single-byte buffer must fail.
    var one: [1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeU64(300, &one));

    // maxInt needs max_len bytes; max_len - 1 must fail.
    var short: [max_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeU64(std.math.maxInt(u64), &short));
}

test "zigzag mapping matches the canonical small-magnitude ordering" {
    try testing.expectEqual(@as(u64, 0), zigzagEncode(0));
    try testing.expectEqual(@as(u64, 1), zigzagEncode(-1));
    try testing.expectEqual(@as(u64, 2), zigzagEncode(1));
    try testing.expectEqual(@as(u64, 3), zigzagEncode(-2));
    try testing.expectEqual(@as(u64, 4), zigzagEncode(2));

    try testing.expectEqual(@as(i64, 0), zigzagDecode(0));
    try testing.expectEqual(@as(i64, -1), zigzagDecode(1));
    try testing.expectEqual(@as(i64, 1), zigzagDecode(2));
    try testing.expectEqual(@as(i64, -2), zigzagDecode(3));
    try testing.expectEqual(@as(i64, 2), zigzagDecode(4));
}

test "signed round-trips across positives negatives and extremes" {
    const values = [_]i64{
        0,
        1,
        -1,
        63,
        -64,
        127,
        -128,
        128,
        -129,
        std.math.maxInt(i32),
        std.math.minInt(i32),
        std.math.maxInt(i64),
        std.math.minInt(i64),
    };

    for (values) |value| {
        var buf: [max_len]u8 = undefined;
        const encoded = try encodeI64(value, &buf);
        try testing.expectEqual(encodedLenI64(value), encoded.len);

        const decoded = try decodeI64(encoded);
        try testing.expectEqual(value, decoded.value);
        try testing.expectEqual(encoded.len, decoded.len);
    }
}

test "small negatives encode compactly via zigzag" {
    var buf: [max_len]u8 = undefined;
    // -1 -> zigzag 1 -> single byte 0x01.
    try testing.expectEqualSlices(u8, &.{0x01}, try encodeI64(-1, &buf));
    // -64 -> zigzag 127 -> single byte 0x7f.
    try testing.expectEqualSlices(u8, &.{0x7f}, try encodeI64(-64, &buf));
}

test "minInt(i64) encodes to max_len bytes and round-trips" {
    var buf: [max_len]u8 = undefined;
    const encoded = try encodeI64(std.math.minInt(i64), &buf);
    try testing.expectEqual(@as(usize, max_len), encoded.len);

    const decoded = try decodeI64(encoded);
    try testing.expectEqual(@as(i64, std.math.minInt(i64)), decoded.value);
}

test "decodeI64 propagates truncation and overflow errors" {
    try testing.expectError(error.Truncated, decodeI64(&.{0x80}));

    const overflow = [_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 };
    try testing.expectError(error.Overflow, decodeI64(&overflow));
}
