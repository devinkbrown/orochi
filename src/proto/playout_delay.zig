const std = @import("std");

pub const Error = error{
    Truncated,
    OutOfRange,
    BufferTooSmall,
};

pub const Delay = struct {
    min_ms: u32,
    max_ms: u32,
};

const wire_len: usize = 3;
const unit_ms: u32 = 10;
const max_delay_ms: u32 = 0x0fff * unit_ms;

pub fn encode(d: Delay, out: []u8) Error![]const u8 {
    if (out.len < wire_len) return error.BufferTooSmall;

    const min_units = try toUnits(d.min_ms);
    const max_units = try toUnits(d.max_ms);
    if (min_units > max_units) return error.OutOfRange;

    out[0] = @intCast(min_units >> 4);
    out[1] = @intCast(((min_units & 0x0f) << 4) | (max_units >> 8));
    out[2] = @intCast(max_units & 0xff);

    return out[0..wire_len];
}

pub fn decode(bytes: []const u8) Error!Delay {
    if (bytes.len < wire_len) return error.Truncated;

    const min_units: u32 = (@as(u32, bytes[0]) << 4) | (@as(u32, bytes[1]) >> 4);
    const max_units: u32 = ((@as(u32, bytes[1]) & 0x0f) << 8) | @as(u32, bytes[2]);

    return .{
        .min_ms = min_units * unit_ms,
        .max_ms = max_units * unit_ms,
    };
}

fn toUnits(ms: u32) Error!u32 {
    if (ms > max_delay_ms) return error.OutOfRange;
    if (ms % unit_ms != 0) return error.OutOfRange;
    return ms / unit_ms;
}

test "encode and decode round trips" {
    const cases = [_]Delay{
        .{ .min_ms = 0, .max_ms = 0 },
        .{ .min_ms = 100, .max_ms = 1000 },
        .{ .min_ms = 10, .max_ms = 40950 },
        .{ .min_ms = 40950, .max_ms = 40950 },
    };

    for (cases) |case| {
        var buf: [wire_len]u8 = undefined;
        const encoded = try encode(case, &buf);
        try std.testing.expectEqual(@as(usize, wire_len), encoded.len);
        try std.testing.expectEqualSlices(u8, buf[0..], encoded);
        try std.testing.expectEqual(case, try decode(encoded));
    }
}

test "known wire encoding" {
    var buf: [wire_len]u8 = undefined;

    const encoded = try encode(.{ .min_ms = 100, .max_ms = 1000 }, &buf);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0xa0, 0x64 }, encoded);
    try std.testing.expectEqual(Delay{ .min_ms = 100, .max_ms = 1000 }, try decode(&.{ 0x00, 0xa0, 0x64 }));
}

test "encode rejects out of range values" {
    var buf: [wire_len]u8 = undefined;

    try std.testing.expectError(error.OutOfRange, encode(.{ .min_ms = 1000, .max_ms = 100 }, &buf));
    try std.testing.expectError(error.OutOfRange, encode(.{ .min_ms = 0, .max_ms = 40960 }, &buf));
    try std.testing.expectError(error.OutOfRange, encode(.{ .min_ms = 5, .max_ms = 10 }, &buf));
}

test "encode reports small output buffer" {
    var buf: [wire_len - 1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encode(.{ .min_ms = 0, .max_ms = 0 }, &buf));
}

test "decode reports truncated input" {
    try std.testing.expectError(error.Truncated, decode(&.{}));
    try std.testing.expectError(error.Truncated, decode(&.{ 0x00 }));
    try std.testing.expectError(error.Truncated, decode(&.{ 0x00, 0x00 }));
}
