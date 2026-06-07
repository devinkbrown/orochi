const std = @import("std");
const testing = std.testing;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("asn1_bitstring requires a 64-bit target");
}

pub const tag_bit_string: u8 = 0x03;

pub const EncodeError = error{
    InvalidBitString,
    LengthTooLarge,
    NoSpaceLeft,
};

pub const ParseError = error{
    InvalidBitString,
    Truncated,
};

pub const Parsed = struct {
    unused_bits: u3,
    bytes: []const u8,
};

/// Return the full DER TLV length for a BIT STRING carrying `bytes_len` bytes.
pub fn encodedLen(bytes_len: usize) EncodeError!usize {
    const content_len = std.math.add(usize, bytes_len, 1) catch return error.LengthTooLarge;
    const header_len = std.math.add(usize, 1, lengthFieldLen(content_len)) catch return error.LengthTooLarge;
    return std.math.add(usize, header_len, content_len) catch return error.LengthTooLarge;
}

/// Encode a DER BIT STRING TLV into `out`.
pub fn encode(out: []u8, bytes: []const u8, unused_bits: u3) EncodeError![]u8 {
    try validateContent(bytes, unused_bits);

    const total_len = try encodedLen(bytes.len);
    if (out.len < total_len) return error.NoSpaceLeft;

    var cursor: usize = 0;
    out[cursor] = tag_bit_string;
    cursor += 1;
    cursor += try writeLength(out[cursor..], bytes.len + 1);
    out[cursor] = @as(u8, unused_bits);
    cursor += 1;
    @memcpy(out[cursor..][0..bytes.len], bytes);
    cursor += bytes.len;

    return out[0..cursor];
}

/// Encode a DER BIT STRING TLV for byte-aligned data.
pub fn encodeBytes(out: []u8, bytes: []const u8) EncodeError![]u8 {
    return encode(out, bytes, 0);
}

/// Parse the content bytes of a DER BIT STRING TLV.
pub fn parse(der_tlv_content: []const u8) ParseError!Parsed {
    if (der_tlv_content.len == 0) return error.Truncated;

    const unused_bits = der_tlv_content[0];
    if (unused_bits > 7) return error.InvalidBitString;

    const bytes = der_tlv_content[1..];
    try validateContent(bytes, @as(u3, @intCast(unused_bits)));

    return .{
        .unused_bits = @as(u3, @intCast(unused_bits)),
        .bytes = bytes,
    };
}

fn validateContent(bytes: []const u8, unused_bits: u3) error{InvalidBitString}!void {
    if (unused_bits == 0) return;
    if (bytes.len == 0) return error.InvalidBitString;

    const unused_mask = (@as(u8, 1) << unused_bits) - 1;
    if ((bytes[bytes.len - 1] & unused_mask) != 0) return error.InvalidBitString;
}

fn lengthFieldLen(len: usize) usize {
    if (len < 0x80) return 1;

    var octets: usize = 0;
    var n = len;
    while (n != 0) : (n >>= 8) {
        octets += 1;
    }
    return 1 + octets;
}

fn writeLength(out: []u8, len: usize) error{NoSpaceLeft}!usize {
    if (len < 0x80) {
        if (out.len < 1) return error.NoSpaceLeft;
        out[0] = @as(u8, @intCast(len));
        return 1;
    }

    const field_len = lengthFieldLen(len);
    if (out.len < field_len) return error.NoSpaceLeft;

    const octets = field_len - 1;
    out[0] = 0x80 | @as(u8, @intCast(octets));
    for (0..octets) |i| {
        const shift: u6 = @intCast((octets - 1 - i) * 8);
        out[1 + i] = @truncate(len >> shift);
    }
    return field_len;
}

test "encodeBytes writes known DER BIT STRING for byte-aligned data" {
    // Arrange
    const input = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const expected = [_]u8{ 0x03, 0x05, 0x00, 0xde, 0xad, 0xbe, 0xef };
    var out: [expected.len]u8 = undefined;

    // Act
    const encoded = try encodeBytes(&out, &input);

    // Assert
    try testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode writes known DER BIT STRING with unused tail bits" {
    // Arrange
    const input = [_]u8{ 0xf0, 0x80 };
    const expected = [_]u8{ 0x03, 0x03, 0x07, 0xf0, 0x80 };
    var out: [expected.len]u8 = undefined;

    // Act
    const encoded = try encode(&out, &input, 7);

    // Assert
    try testing.expectEqualSlices(u8, &expected, encoded);
}

test "encode and parse round-trip byte-aligned content" {
    // Arrange
    const input = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var out: [16]u8 = undefined;

    // Act
    const encoded = try encodeBytes(&out, &input);
    const parsed = try parse(encoded[2..]);

    // Assert
    try testing.expectEqual(@as(u3, 0), parsed.unused_bits);
    try testing.expectEqualSlices(u8, &input, parsed.bytes);
}

test "encode and parse round-trip non-byte-aligned content" {
    // Arrange
    const input = [_]u8{0xa8};
    var out: [8]u8 = undefined;

    // Act
    const encoded = try encode(&out, &input, 3);
    const parsed = try parse(encoded[2..]);

    // Assert
    try testing.expectEqual(@as(u3, 3), parsed.unused_bits);
    try testing.expectEqualSlices(u8, &input, parsed.bytes);
}

test "encode writes short-form length at the DER boundary" {
    // Arrange
    const input = [_]u8{0xaa} ** 126;
    var out: [129]u8 = undefined;

    // Act
    const encoded = try encodeBytes(&out, &input);

    // Assert
    try testing.expectEqual(@as(usize, 129), encoded.len);
    try testing.expectEqual(@as(u8, 0x03), encoded[0]);
    try testing.expectEqual(@as(u8, 0x7f), encoded[1]);
    try testing.expectEqual(@as(u8, 0x00), encoded[2]);
    try testing.expectEqualSlices(u8, &input, encoded[3..]);
}

test "encode writes long-form length after the DER short-form boundary" {
    // Arrange
    const input = [_]u8{0xbb} ** 127;
    var out: [131]u8 = undefined;

    // Act
    const encoded = try encodeBytes(&out, &input);

    // Assert
    try testing.expectEqual(@as(usize, 131), encoded.len);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x81, 0x80, 0x00 }, encoded[0..4]);
    try testing.expectEqualSlices(u8, &input, encoded[4..]);
}

test "encode rejects output buffer truncation" {
    // Arrange
    const input = [_]u8{ 0x01, 0x02, 0x03 };
    var out: [5]u8 = undefined;

    // Act
    const result = encodeBytes(&out, &input);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "encode rejects nonzero unused bits without payload bytes" {
    // Arrange
    const input = [_]u8{};
    var out: [4]u8 = undefined;

    // Act
    const result = encode(&out, &input, 1);

    // Assert
    try testing.expectError(error.InvalidBitString, result);
}

test "encode rejects nonzero padding bits in final byte" {
    // Arrange
    const input = [_]u8{0x03};
    var out: [4]u8 = undefined;

    // Act
    const result = encode(&out, &input, 2);

    // Assert
    try testing.expectError(error.InvalidBitString, result);
}

test "encodedLen rejects oversized byte lengths" {
    // Arrange
    const too_large_for_content = std.math.maxInt(usize);
    const too_large_for_tlv = std.math.maxInt(usize) - 1;

    // Act
    const content_result = encodedLen(too_large_for_content);
    const tlv_result = encodedLen(too_large_for_tlv);

    // Assert
    try testing.expectError(error.LengthTooLarge, content_result);
    try testing.expectError(error.LengthTooLarge, tlv_result);
}

test "parse accepts valid content and returns payload slice" {
    // Arrange
    const content = [_]u8{ 0x04, 0xf0 };

    // Act
    const parsed = try parse(&content);

    // Assert
    try testing.expectEqual(@as(u3, 4), parsed.unused_bits);
    try testing.expectEqualSlices(u8, content[1..], parsed.bytes);
}

test "parse rejects truncated content" {
    // Arrange
    const content = [_]u8{};

    // Act
    const result = parse(&content);

    // Assert
    try testing.expectError(error.Truncated, result);
}

test "parse rejects unused-bit count above seven" {
    // Arrange
    const content = [_]u8{ 0x08, 0x00 };

    // Act
    const result = parse(&content);

    // Assert
    try testing.expectError(error.InvalidBitString, result);
}

test "parse rejects unused bits without payload bytes" {
    // Arrange
    const content = [_]u8{0x01};

    // Act
    const result = parse(&content);

    // Assert
    try testing.expectError(error.InvalidBitString, result);
}

test "parse rejects nonzero padding bits in final byte" {
    // Arrange
    const content = [_]u8{ 0x02, 0x03 };

    // Act
    const result = parse(&content);

    // Assert
    try testing.expectError(error.InvalidBitString, result);
}
