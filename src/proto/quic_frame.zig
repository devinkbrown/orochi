const std = @import("std");

pub const WireError = error{
    BufferTooShort,
    InvalidVarInt,
    NonCanonicalVarInt,
    InvalidFrame,
    UnknownFrameType,
    TrailingBytes,
    InvalidPacketNumberLength,
};

pub const DecodedVarInt = struct {
    value: u64,
    len: usize,
};

pub const AckRange = struct {
    gap: u64,
    len: u64,
};

pub const AckFrame = struct {
    largest: u64,
    delay: u64 = 0,
    first_range: u64 = 0,
    ranges: []const AckRange = &.{},
};

pub const CryptoFrame = struct {
    offset: u64,
    len: u64,
    data: []const u8,
};

pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64 = 0,
    fin: bool = false,
    len: u64,
    data: []const u8,
};

pub const DatagramFrame = struct {
    len: u64,
    data: []const u8,
};

pub const ConnectionCloseFrame = struct {
    error_code: u64,
    reason_len: u64,
    reason: []const u8,
};

pub const Frame = union(enum) {
    PADDING: void,
    PING: void,
    ACK: AckFrame,
    CRYPTO: CryptoFrame,
    STREAM: StreamFrame,
    DATAGRAM: DatagramFrame,
    CONNECTION_CLOSE: ConnectionCloseFrame,
};

pub const DecodedFrame = struct {
    frame: Frame,
    len: usize,
};

pub const DecodedFrames = struct {
    allocator: std.mem.Allocator,
    frames: []Frame,

    pub fn deinit(self: *DecodedFrames) void {
        for (self.frames) |frame| freeFrame(self.allocator, frame);
        self.allocator.free(self.frames);
        self.* = .{ .allocator = self.allocator, .frames = &.{} };
    }
};

pub const max_varint: u64 = (1 << 62) - 1;

pub fn varIntLen(value: u64) WireError!usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= max_varint) return 8;
    return WireError.InvalidVarInt;
}

pub fn encodeVarInt(value: u64, out: []u8) WireError!usize {
    const len = try varIntLen(value);
    if (out.len < len) return WireError.BufferTooShort;

    switch (len) {
        1 => out[0] = @as(u8, @intCast(value)),
        2 => {
            const v = value | 0x4000;
            out[0] = @as(u8, @intCast(v >> 8));
            out[1] = @as(u8, @intCast(v & 0xff));
        },
        4 => {
            const v = value | 0x80000000;
            out[0] = @as(u8, @intCast(v >> 24));
            out[1] = @as(u8, @intCast((v >> 16) & 0xff));
            out[2] = @as(u8, @intCast((v >> 8) & 0xff));
            out[3] = @as(u8, @intCast(v & 0xff));
        },
        8 => {
            const v = value | 0xc000000000000000;
            out[0] = @as(u8, @intCast(v >> 56));
            out[1] = @as(u8, @intCast((v >> 48) & 0xff));
            out[2] = @as(u8, @intCast((v >> 40) & 0xff));
            out[3] = @as(u8, @intCast((v >> 32) & 0xff));
            out[4] = @as(u8, @intCast((v >> 24) & 0xff));
            out[5] = @as(u8, @intCast((v >> 16) & 0xff));
            out[6] = @as(u8, @intCast((v >> 8) & 0xff));
            out[7] = @as(u8, @intCast(v & 0xff));
        },
        else => unreachable,
    }

    return len;
}

pub fn appendVarInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var buf: [8]u8 = undefined;
    const len = try encodeVarInt(value, &buf);
    try out.appendSlice(allocator, buf[0..len]);
}

pub fn decodeVarInt(input: []const u8) WireError!DecodedVarInt {
    if (input.len == 0) return WireError.BufferTooShort;

    const tag = input[0] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (input.len < len) return WireError.BufferTooShort;

    var value: u64 = input[0] & 0x3f;
    for (input[1..len]) |byte| value = (value << 8) | byte;

    if ((try varIntLen(value)) != len) return WireError.NonCanonicalVarInt;
    return .{ .value = value, .len = len };
}

pub fn encodeFrame(out: *std.ArrayList(u8), allocator: std.mem.Allocator, frame: Frame) !void {
    switch (frame) {
        .PADDING => try out.append(allocator, 0x00),
        .PING => try out.append(allocator, 0x01),
        .ACK => |ack| {
            try out.append(allocator, 0x02);
            try appendVarInt(out, allocator, ack.largest);
            try appendVarInt(out, allocator, ack.delay);
            try appendVarInt(out, allocator, ack.ranges.len);
            try appendVarInt(out, allocator, ack.first_range);
            for (ack.ranges) |range| {
                try appendVarInt(out, allocator, range.gap);
                try appendVarInt(out, allocator, range.len);
            }
        },
        .CRYPTO => |crypto| {
            try ensureLenMatches(crypto.len, crypto.data);
            try out.append(allocator, 0x06);
            try appendVarInt(out, allocator, crypto.offset);
            try appendVarInt(out, allocator, crypto.len);
            try out.appendSlice(allocator, crypto.data);
        },
        .STREAM => |stream| {
            try ensureLenMatches(stream.len, stream.data);
            var ty: u8 = 0x08 | 0x02;
            if (stream.offset != 0) ty |= 0x04;
            if (stream.fin) ty |= 0x01;
            try out.append(allocator, ty);
            try appendVarInt(out, allocator, stream.stream_id);
            if (stream.offset != 0) try appendVarInt(out, allocator, stream.offset);
            try appendVarInt(out, allocator, stream.len);
            try out.appendSlice(allocator, stream.data);
        },
        .DATAGRAM => |datagram| {
            try ensureLenMatches(datagram.len, datagram.data);
            try out.append(allocator, 0x31);
            try appendVarInt(out, allocator, datagram.len);
            try out.appendSlice(allocator, datagram.data);
        },
        .CONNECTION_CLOSE => |close| {
            try ensureLenMatches(close.reason_len, close.reason);
            try out.append(allocator, 0x1c);
            try appendVarInt(out, allocator, close.error_code);
            try appendVarInt(out, allocator, 0);
            try appendVarInt(out, allocator, close.reason_len);
            try out.appendSlice(allocator, close.reason);
        },
    }
}

pub fn encodeFrames(allocator: std.mem.Allocator, frames: []const Frame) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (frames) |frame| try encodeFrame(&out, allocator, frame);
    return out.toOwnedSlice(allocator);
}

pub fn decodeFrame(allocator: std.mem.Allocator, input: []const u8) !DecodedFrame {
    if (input.len == 0) return WireError.BufferTooShort;

    const ty = input[0];
    var pos: usize = 1;

    switch (ty) {
        0x00 => return .{ .frame = .{ .PADDING = {} }, .len = 1 },
        0x01 => return .{ .frame = .{ .PING = {} }, .len = 1 },
        0x02 => {
            const largest = try takeVarInt(input, &pos);
            const delay = try takeVarInt(input, &pos);
            const range_count = try takeVarInt(input, &pos);
            const first_range = try takeVarInt(input, &pos);

            // Each ACK range needs >= 2 bytes on the wire (gap + len varints).
            // Reject a count that cannot possibly fit the remaining input so a
            // tiny packet cannot trigger a huge allocation.
            if (range_count > (input.len - pos) / 2) return WireError.InvalidFrame;
            const ranges = try allocator.alloc(AckRange, @intCast(range_count));
            errdefer allocator.free(ranges);
            for (ranges) |*range| {
                range.* = .{
                    .gap = try takeVarInt(input, &pos),
                    .len = try takeVarInt(input, &pos),
                };
            }

            return .{
                .frame = .{ .ACK = .{
                    .largest = largest,
                    .delay = delay,
                    .first_range = first_range,
                    .ranges = ranges,
                } },
                .len = pos,
            };
        },
        0x06 => {
            const offset = try takeVarInt(input, &pos);
            const len = try takeVarInt(input, &pos);
            const data = try takeBytes(input, &pos, len);
            return .{
                .frame = .{ .CRYPTO = .{ .offset = offset, .len = len, .data = data } },
                .len = pos,
            };
        },
        0x1c => {
            const error_code = try takeVarInt(input, &pos);
            _ = try takeVarInt(input, &pos);
            const reason_len = try takeVarInt(input, &pos);
            const reason = try takeBytes(input, &pos, reason_len);
            return .{
                .frame = .{ .CONNECTION_CLOSE = .{
                    .error_code = error_code,
                    .reason_len = reason_len,
                    .reason = reason,
                } },
                .len = pos,
            };
        },
        0x30, 0x31 => {
            const has_len = (ty & 0x01) != 0;
            const len = if (has_len) try takeVarInt(input, &pos) else input.len - pos;
            const data = try takeBytes(input, &pos, len);
            return .{
                .frame = .{ .DATAGRAM = .{ .len = len, .data = data } },
                .len = pos,
            };
        },
        else => {
            if ((ty & 0xf8) == 0x08) {
                const has_fin = (ty & 0x01) != 0;
                const has_len = (ty & 0x02) != 0;
                const has_offset = (ty & 0x04) != 0;
                const stream_id = try takeVarInt(input, &pos);
                const offset = if (has_offset) try takeVarInt(input, &pos) else 0;
                const len = if (has_len) try takeVarInt(input, &pos) else input.len - pos;
                const data = try takeBytes(input, &pos, len);
                return .{
                    .frame = .{ .STREAM = .{
                        .stream_id = stream_id,
                        .offset = offset,
                        .fin = has_fin,
                        .len = len,
                        .data = data,
                    } },
                    .len = pos,
                };
            }
            return WireError.UnknownFrameType;
        },
    }
}

pub fn decodeFrameExact(allocator: std.mem.Allocator, input: []const u8) !Frame {
    const decoded = try decodeFrame(allocator, input);
    errdefer freeFrame(allocator, decoded.frame);
    if (decoded.len != input.len) return WireError.TrailingBytes;
    return decoded.frame;
}

pub fn decodeFrames(allocator: std.mem.Allocator, payload: []const u8) !DecodedFrames {
    var frames: std.ArrayList(Frame) = .empty;
    errdefer {
        for (frames.items) |frame| freeFrame(allocator, frame);
        frames.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos < payload.len) {
        const decoded = try decodeFrame(allocator, payload[pos..]);
        errdefer freeFrame(allocator, decoded.frame);
        if (decoded.len == 0) return WireError.InvalidFrame;
        try frames.append(allocator, decoded.frame);
        pos += decoded.len;
    }

    return .{
        .allocator = allocator,
        .frames = try frames.toOwnedSlice(allocator),
    };
}

pub fn freeFrame(allocator: std.mem.Allocator, frame: Frame) void {
    switch (frame) {
        .ACK => |ack| allocator.free(ack.ranges),
        else => {},
    }
}

pub fn packetNumberLen(full_pn: u64, largest_acked: ?u64) WireError!usize {
    if (full_pn > max_varint) return WireError.InvalidFrame;
    const gap = if (largest_acked) |largest| blk: {
        if (full_pn <= largest) break :blk 1;
        break :blk full_pn - largest;
    } else full_pn;

    if (gap <= 0x80) return 1;
    if (gap <= 0x8000) return 2;
    if (gap <= 0x800000) return 3;
    return 4;
}

pub fn truncatePacketNumber(full_pn: u64, len: usize) WireError!u64 {
    try checkPacketNumberLen(len);
    const bits: u6 = @intCast(len * 8);
    const mask = (@as(u64, 1) << bits) - 1;
    return full_pn & mask;
}

pub fn encodePacketNumber(full_pn: u64, len: usize, out: []u8) WireError!usize {
    try checkPacketNumberLen(len);
    if (out.len < len) return WireError.BufferTooShort;
    const truncated = try truncatePacketNumber(full_pn, len);
    for (0..len) |i| {
        const shift: u6 = @intCast((len - 1 - i) * 8);
        out[i] = @as(u8, @intCast((truncated >> shift) & 0xff));
    }
    return len;
}

pub fn decodePacketNumber(truncated: u64, len: usize, largest_pn: u64) WireError!u64 {
    try checkPacketNumberLen(len);
    const bits: u6 = @intCast(len * 8);
    const pn_win = @as(u64, 1) << bits;
    if (truncated >= pn_win) return WireError.InvalidFrame;

    const expected = largest_pn + 1;
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;
    var candidate = (expected & ~pn_mask) | truncated;

    if (candidate + pn_hwin <= expected and candidate <= max_varint - pn_win) {
        candidate += pn_win;
    } else if (candidate > expected + pn_hwin and candidate >= pn_win) {
        candidate -= pn_win;
    }

    return candidate;
}

fn ensureLenMatches(len: u64, data: []const u8) WireError!void {
    if (len != data.len) return WireError.InvalidFrame;
}

fn takeVarInt(input: []const u8, pos: *usize) WireError!u64 {
    const decoded = try decodeVarInt(input[pos.*..]);
    pos.* += decoded.len;
    return decoded.value;
}

fn takeBytes(input: []const u8, pos: *usize, len: u64) WireError![]const u8 {
    if (len > std.math.maxInt(usize)) return WireError.InvalidFrame;
    const n: usize = @intCast(len);
    if (input.len - pos.* < n) return WireError.BufferTooShort;
    defer pos.* += n;
    return input[pos.*..][0..n];
}

fn checkPacketNumberLen(len: usize) WireError!void {
    if (len < 1 or len > 4) return WireError.InvalidPacketNumberLength;
}

fn expectFrameEqual(expected: Frame, actual: Frame) !void {
    switch (expected) {
        .PADDING => try std.testing.expect(actual == .PADDING),
        .PING => try std.testing.expect(actual == .PING),
        .ACK => |e| {
            const a = actual.ACK;
            try std.testing.expectEqual(e.largest, a.largest);
            try std.testing.expectEqual(e.delay, a.delay);
            try std.testing.expectEqual(e.first_range, a.first_range);
            try std.testing.expectEqualSlices(AckRange, e.ranges, a.ranges);
        },
        .CRYPTO => |e| {
            const a = actual.CRYPTO;
            try std.testing.expectEqual(e.offset, a.offset);
            try std.testing.expectEqual(e.len, a.len);
            try std.testing.expectEqualSlices(u8, e.data, a.data);
        },
        .STREAM => |e| {
            const a = actual.STREAM;
            try std.testing.expectEqual(e.stream_id, a.stream_id);
            try std.testing.expectEqual(e.offset, a.offset);
            try std.testing.expectEqual(e.fin, a.fin);
            try std.testing.expectEqual(e.len, a.len);
            try std.testing.expectEqualSlices(u8, e.data, a.data);
        },
        .DATAGRAM => |e| {
            const a = actual.DATAGRAM;
            try std.testing.expectEqual(e.len, a.len);
            try std.testing.expectEqualSlices(u8, e.data, a.data);
        },
        .CONNECTION_CLOSE => |e| {
            const a = actual.CONNECTION_CLOSE;
            try std.testing.expectEqual(e.error_code, a.error_code);
            try std.testing.expectEqual(e.reason_len, a.reason_len);
            try std.testing.expectEqualSlices(u8, e.reason, a.reason);
        },
    }
}

test "varint round-trip for all four lengths" {
    const cases = [_]struct {
        value: u64,
        len: usize,
    }{
        .{ .value = 37, .len = 1 },
        .{ .value = 15293, .len = 2 },
        .{ .value = 494878333, .len = 4 },
        .{ .value = 151288809941952652, .len = 8 },
    };

    for (cases) |case| {
        var buf: [8]u8 = undefined;
        const encoded_len = try encodeVarInt(case.value, &buf);
        try std.testing.expectEqual(case.len, encoded_len);
        const decoded = try decodeVarInt(buf[0..encoded_len]);
        try std.testing.expectEqual(case.value, decoded.value);
        try std.testing.expectEqual(case.len, decoded.len);
    }
}

test "varint rejects non-minimal encodings" {
    try std.testing.expectError(WireError.NonCanonicalVarInt, decodeVarInt(&.{ 0x40, 0x25 }));
    try std.testing.expectError(WireError.NonCanonicalVarInt, decodeVarInt(&.{ 0x80, 0x00, 0x3f, 0xff }));
    try std.testing.expectError(WireError.NonCanonicalVarInt, decodeVarInt(&.{ 0xc0, 0x00, 0x00, 0x00, 0x3f, 0xff, 0xff, 0xff }));
}

test "padding frame round-trip" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .PADDING = {} };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    var decoded = try decodeFrames(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), decoded.frames.len);
    try expectFrameEqual(frame, decoded.frames[0]);
}

test "ping frame round-trip" {
    const allocator = std.testing.allocator;
    const frame = Frame{ .PING = {} };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "ack frame round-trip" {
    const allocator = std.testing.allocator;
    const ranges = [_]AckRange{
        .{ .gap = 0, .len = 3 },
        .{ .gap = 2, .len = 7 },
    };
    const frame = Frame{ .ACK = .{
        .largest = 100,
        .delay = 25,
        .first_range = 8,
        .ranges = &ranges,
    } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "crypto frame round-trip" {
    const allocator = std.testing.allocator;
    const data = "crypto bytes";
    const frame = Frame{ .CRYPTO = .{ .offset = 64, .len = data.len, .data = data } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
    try std.testing.expect(@intFromPtr(decoded.CRYPTO.data.ptr) >= @intFromPtr(encoded.ptr));
}

test "stream frame round-trip" {
    const allocator = std.testing.allocator;
    const data = "stream payload";
    const frame = Frame{ .STREAM = .{
        .stream_id = 9,
        .offset = 1024,
        .fin = true,
        .len = data.len,
        .data = data,
    } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "datagram frame round-trip" {
    const allocator = std.testing.allocator;
    const data = "datagram payload";
    const frame = Frame{ .DATAGRAM = .{ .len = data.len, .data = data } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "connection close frame round-trip" {
    const allocator = std.testing.allocator;
    const reason = "done";
    const frame = Frame{ .CONNECTION_CLOSE = .{
        .error_code = 0x10,
        .reason_len = reason.len,
        .reason = reason,
    } };
    const encoded = try encodeFrames(allocator, &.{frame});
    defer allocator.free(encoded);

    const decoded = try decodeFrameExact(allocator, encoded);
    defer freeFrame(allocator, decoded);
    try expectFrameEqual(frame, decoded);
}

test "multi-frame payload round-trip" {
    const allocator = std.testing.allocator;
    const crypto_data = "hello";
    const stream_data = "world";
    const frames = [_]Frame{
        .{ .PADDING = {} },
        .{ .PING = {} },
        .{ .CRYPTO = .{ .offset = 0, .len = crypto_data.len, .data = crypto_data } },
        .{ .STREAM = .{ .stream_id = 1, .offset = 0, .fin = false, .len = stream_data.len, .data = stream_data } },
    };
    const encoded = try encodeFrames(allocator, &frames);
    defer allocator.free(encoded);

    var decoded = try decodeFrames(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(frames.len, decoded.frames.len);
    for (frames, decoded.frames) |expected, actual| try expectFrameEqual(expected, actual);
}

test "decode rejects truncation and trailing bytes" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(WireError.BufferTooShort, decodeFrame(allocator, &.{0x06}));
    try std.testing.expectError(WireError.BufferTooShort, decodeFrame(allocator, &.{ 0x31, 0x05, 0xaa }));
    try std.testing.expectError(WireError.TrailingBytes, decodeFrameExact(allocator, &.{ 0x01, 0x00 }));
}

test "packet number truncation encoding and reconstruction" {
    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), try packetNumberLen(0xabe8bc, 0xabe700));
    try std.testing.expectEqual(@as(u64, 0xe8bc), try truncatePacketNumber(0xabe8bc, 2));
    try std.testing.expectEqual(@as(usize, 2), try encodePacketNumber(0xabe8bc, 2, &buf));
    try std.testing.expectEqualSlices(u8, &.{ 0xe8, 0xbc }, buf[0..2]);
    try std.testing.expectEqual(@as(u64, 0xabe8bc), try decodePacketNumber(0xe8bc, 2, 0xabe700));
    try std.testing.expectError(WireError.InvalidPacketNumberLength, encodePacketNumber(1, 0, &buf));
}
