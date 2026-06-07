//! Canonical LEB128 variable-length integer codec for compact wire fields.

const std = @import("std");

pub const max_len = 10;

pub const DecodeError = error{
    Truncated,
    Overlong,
};

pub const DecodedU = struct {
    value: u64,
    len: usize,
};

pub const DecodedI = struct {
    value: i64,
    len: usize,
};

pub fn encodeU(out: []u8, value: u64) usize {
    var remaining = value;
    var index: usize = 0;

    while (remaining >= 0x80) {
        out[index] = @as(u8, @intCast(remaining & 0x7f)) | 0x80;
        remaining >>= 7;
        index += 1;
    }

    out[index] = @as(u8, @intCast(remaining));
    return index + 1;
}

pub fn decodeU(bytes: []const u8) DecodeError!DecodedU {
    var value: u64 = 0;
    var shift: u6 = 0;

    for (bytes, 0..) |byte, index| {
        if (index >= max_len) return DecodeError.Overlong;

        const payload = byte & 0x7f;
        if (index == max_len - 1 and (payload > 1 or (byte & 0x80) != 0)) {
            return DecodeError.Overlong;
        }

        value |= @as(u64, payload) << shift;

        if ((byte & 0x80) == 0) {
            const len = index + 1;
            if (len != encodedLenU(value)) return DecodeError.Overlong;
            return .{ .value = value, .len = len };
        }

        shift += 7;
    }

    return DecodeError.Truncated;
}

pub fn encodeI(out: []u8, value: i64) usize {
    return encodeU(out, zigZagEncode(value));
}

pub fn decodeI(bytes: []const u8) DecodeError!DecodedI {
    const decoded = try decodeU(bytes);
    return .{
        .value = zigZagDecode(decoded.value),
        .len = decoded.len,
    };
}

pub fn zigZagEncode(value: i64) u64 {
    const bits: u64 = @bitCast(value);
    const sign: u64 = @bitCast(value >> 63);
    return (bits << 1) ^ sign;
}

pub fn zigZagDecode(value: u64) i64 {
    const mask: u64 = 0 -% (value & 1);
    return @bitCast((value >> 1) ^ mask);
}

fn encodedLenU(value: u64) usize {
    var remaining = value;
    var len: usize = 1;

    while (remaining >= 0x80) {
        remaining >>= 7;
        len += 1;
    }

    return len;
}

fn expectRoundTripU(value: u64) !void {
    var buffer: [max_len]u8 = undefined;
    const len = encodeU(&buffer, value);
    try std.testing.expectEqual(encodedLenU(value), len);

    const decoded = try decodeU(buffer[0..len]);
    try std.testing.expectEqual(value, decoded.value);
    try std.testing.expectEqual(len, decoded.len);
}

fn expectRoundTripI(value: i64) !void {
    var buffer: [max_len]u8 = undefined;
    const len = encodeI(&buffer, value);

    const decoded = try decodeI(buffer[0..len]);
    try std.testing.expectEqual(value, decoded.value);
    try std.testing.expectEqual(len, decoded.len);
}

test "unsigned round trips across length boundaries" {
    const values = [_]u64{
        0,
        1,
        126,
        127,
        128,
        129,
        16_383,
        16_384,
        std.math.maxInt(u64),
    };

    for (values) |value| {
        try expectRoundTripU(value);
    }
}

test "zigzag signed round trips" {
    const values = [_]i64{
        0,
        -1,
        1,
        -2,
        2,
        -64,
        63,
        -65,
        std.math.minInt(i64),
        std.math.maxInt(i64),
    };

    for (values) |value| {
        try expectRoundTripI(value);
    }
}

test "truncated input errors" {
    try std.testing.expectError(DecodeError.Truncated, decodeU(&.{}));
    try std.testing.expectError(DecodeError.Truncated, decodeU(&.{0x80}));
    try std.testing.expectError(DecodeError.Truncated, decodeU(&.{ 0x80, 0x80 }));
    try std.testing.expectError(DecodeError.Truncated, decodeI(&.{ 0x81, 0x80 }));
}

test "overlong input rejected" {
    try std.testing.expectError(DecodeError.Overlong, decodeU(&.{ 0x80, 0x00 }));
    try std.testing.expectError(DecodeError.Overlong, decodeU(&.{ 0x81, 0x00 }));
    try std.testing.expectError(DecodeError.Overlong, decodeU(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 }));
    try std.testing.expectError(DecodeError.Overlong, decodeU(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }));
}
