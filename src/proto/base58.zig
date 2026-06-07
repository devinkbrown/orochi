//! Bitcoin-alphabet Base58 helpers for compact key and id display.
//!
//! The API is allocation-free: callers provide every output buffer and receive
//! the populated prefix back. Leading zero bytes are represented as leading
//! `1` characters, and leading `1` characters decode back to zero bytes.

const std = @import("std");

pub const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub const Error = error{
    NoSpaceLeft,
    InvalidCharacter,
};

/// Encode `bytes` into Bitcoin-alphabet Base58 using caller-owned storage.
pub fn encode(out: []u8, bytes: []const u8) Error![]const u8 {
    var zeroes: usize = 0;
    while (zeroes < bytes.len and bytes[zeroes] == 0) : (zeroes += 1) {}

    var digit_count: usize = 0;
    for (bytes[zeroes..]) |byte| {
        var carry: u32 = byte;
        var index: usize = 0;
        while (index < digit_count) : (index += 1) {
            carry += @as(u32, out[index]) << 8;
            out[index] = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            if (digit_count >= out.len) return error.NoSpaceLeft;
            out[digit_count] = @intCast(carry % 58);
            digit_count += 1;
            carry /= 58;
        }
    }

    const total = zeroes + digit_count;
    if (out.len < total) return error.NoSpaceLeft;

    reverse(out[0..digit_count]);

    var index = digit_count;
    while (index > 0) {
        index -= 1;
        out[zeroes + index] = alphabet[out[index]];
    }

    @memset(out[0..zeroes], '1');
    return out[0..total];
}

/// Decode Bitcoin-alphabet Base58 into caller-owned storage.
pub fn decode(out: []u8, text: []const u8) Error![]const u8 {
    for (text) |char| {
        _ = decodeValue(char) orelse return error.InvalidCharacter;
    }

    var zeroes: usize = 0;
    while (zeroes < text.len and text[zeroes] == '1') : (zeroes += 1) {}

    var byte_count: usize = 0;
    for (text[zeroes..]) |char| {
        var carry: u32 = decodeValue(char).?;
        var index: usize = 0;
        while (index < byte_count) : (index += 1) {
            carry += @as(u32, out[index]) * 58;
            out[index] = @intCast(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0) {
            if (byte_count >= out.len) return error.NoSpaceLeft;
            out[byte_count] = @intCast(carry & 0xff);
            byte_count += 1;
            carry >>= 8;
        }
    }

    const total = zeroes + byte_count;
    if (out.len < total) return error.NoSpaceLeft;

    reverse(out[0..byte_count]);

    var index = byte_count;
    while (index > 0) {
        index -= 1;
        out[zeroes + index] = out[index];
    }

    @memset(out[0..zeroes], 0);
    return out[0..total];
}

fn decodeValue(char: u8) ?u8 {
    return switch (char) {
        '1'...'9' => char - '1',
        'A'...'H' => 9 + char - 'A',
        'J'...'N' => 17 + char - 'J',
        'P'...'Z' => 22 + char - 'P',
        'a'...'k' => 33 + char - 'a',
        'm'...'z' => 44 + char - 'm',
        else => null,
    };
}

fn reverse(buf: []u8) void {
    var left: usize = 0;
    var right = buf.len;
    while (left < right) {
        right -= 1;
        if (left >= right) break;
        std.mem.swap(u8, &buf[left], &buf[right]);
        left += 1;
    }
}

test "known vectors" {
    var enc: [32]u8 = undefined;
    var dec: [32]u8 = undefined;

    try std.testing.expectEqualStrings("", try encode(&enc, ""));
    try std.testing.expectEqualStrings("1", try encode(&enc, &.{0}));
    try std.testing.expectEqualStrings("Cn8eVZg", try encode(&enc, "hello"));

    const round_trip = try decode(&dec, try encode(&enc, "hello"));
    try std.testing.expectEqualSlices(u8, "hello", round_trip);
}

test "leading zero bytes are preserved" {
    var enc: [32]u8 = undefined;
    var dec: [32]u8 = undefined;
    const input = [_]u8{ 0, 0, 1, 2, 3 };

    const text = try encode(&enc, &input);
    try std.testing.expectEqual(@as(u8, '1'), text[0]);
    try std.testing.expectEqual(@as(u8, '1'), text[1]);

    const bytes = try decode(&dec, text);
    try std.testing.expectEqualSlices(u8, &input, bytes);
}

test "decode rejects invalid characters" {
    var out: [8]u8 = undefined;

    try std.testing.expectError(error.InvalidCharacter, decode(&out, "0"));
    try std.testing.expectError(error.InvalidCharacter, decode(&out, "O"));
    try std.testing.expectError(error.InvalidCharacter, decode(&out, "I"));
    try std.testing.expectError(error.InvalidCharacter, decode(&out, "l"));
}

test "encode reports buffer too small" {
    var out: [1]u8 = undefined;

    try std.testing.expectError(error.NoSpaceLeft, encode(&out, "hello"));
}

test "decode reports buffer too small" {
    var out: [1]u8 = undefined;

    try std.testing.expectError(error.NoSpaceLeft, decode(&out, "Cn8eVZg"));
}
