// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebTransport-over-HTTP/3 framing helpers.
//!
//! This module intentionally covers framing only: QUIC-style variable-length
//! integers, HTTP Capsule type-length-value records, WebTransport datagram
//! prefixes, and the small stream signal prefixes used to bind streams to a
//! session. Decoded payload slices borrow from the input buffer.

const std = @import("std");

pub const max_varint: u64 = (@as(u64, 1) << 62) - 1;

pub const FormatError = error{
    Truncated,
    TrailingBytes,
    NonCanonicalVarint,
    VarintTooLarge,
    CapsuleLengthOverflow,
    InvalidSessionId,
};

pub const CapsuleType = struct {
    pub const datagram: u64 = 0x00;
    pub const close_webtransport_session: u64 = 0x2843;
    pub const drain_webtransport_session: u64 = 0x78ae;
};

pub const StreamType = struct {
    pub const webtransport_bidirectional: u64 = 0x41;
    pub const webtransport_unidirectional: u64 = 0x54;
};

pub const KnownStreamSignal = enum {
    bidirectional,
    unidirectional,
};

pub const Varint = struct {
    value: u64,
    len: usize,
};

pub const Capsule = struct {
    capsule_type: u64,
    value: []const u8,
};

pub const Datagram = struct {
    quarter_stream_id: u64,
    payload: []const u8,
};

pub const SessionId = struct {
    stream_id: u64,

    pub fn initClientBidirectional(stream_id: u64) FormatError!SessionId {
        if (stream_id > max_varint or (stream_id & 0x03) != 0) {
            return FormatError.InvalidSessionId;
        }
        return .{ .stream_id = stream_id };
    }

    pub fn fromQuarterStreamId(quarter_stream_id: u64) FormatError!SessionId {
        if (quarter_stream_id > (max_varint >> 2)) return FormatError.InvalidSessionId;
        return .{ .stream_id = quarter_stream_id << 2 };
    }

    pub fn quarterStreamId(self: SessionId) u64 {
        return self.stream_id >> 2;
    }
};

pub const StreamSignal = struct {
    stream_type: u64,
    session_id: SessionId,

    pub fn knownKind(self: StreamSignal) ?KnownStreamSignal {
        return switch (self.stream_type) {
            StreamType.webtransport_bidirectional => .bidirectional,
            StreamType.webtransport_unidirectional => .unidirectional,
            else => null,
        };
    }
};

pub fn varintEncodedLen(value: u64) FormatError!usize {
    if (value <= 63) return 1;
    if (value <= 16_383) return 2;
    if (value <= 1_073_741_823) return 4;
    if (value <= max_varint) return 8;
    return FormatError.VarintTooLarge;
}

pub fn encodeVarint(value: u64, buffer: *[8]u8) FormatError![]const u8 {
    const len = try varintEncodedLen(value);
    const marker: u8 = switch (len) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        else => unreachable,
    };

    for (buffer[0..len], 0..) |*byte, i| {
        const shift: u6 = @intCast((len - 1 - i) * 8);
        byte.* = @intCast((value >> shift) & 0xff);
    }
    buffer[0] = (buffer[0] & 0x3f) | marker;
    return buffer[0..len];
}

pub fn decodeVarint(input: []const u8) FormatError!Varint {
    if (input.len == 0) return FormatError.Truncated;

    const len: usize = switch (input[0] >> 6) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (input.len < len) return FormatError.Truncated;

    var value: u64 = input[0] & 0x3f;
    for (input[1..len]) |byte| {
        value = (value << 8) | byte;
    }

    if ((try varintEncodedLen(value)) != len) return FormatError.NonCanonicalVarint;
    return .{ .value = value, .len = len };
}

pub fn decodeVarintComplete(input: []const u8) FormatError!u64 {
    const decoded = try decodeVarint(input);
    if (decoded.len != input.len) return FormatError.TrailingBytes;
    return decoded.value;
}

pub fn encodeCapsule(
    allocator: std.mem.Allocator,
    capsule_type: u64,
    value: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendVarint(allocator, &out, capsule_type);
    try appendVarint(allocator, &out, try usizeToVarint(value.len));
    try out.appendSlice(allocator, value);
    return try out.toOwnedSlice(allocator);
}

pub fn decodeCapsule(input: []const u8) FormatError!Capsule {
    var reader = Reader{ .input = input };
    const capsule = try reader.readCapsule();
    if (reader.pos != input.len) return FormatError.TrailingBytes;
    return capsule;
}

pub fn decodeCapsules(allocator: std.mem.Allocator, input: []const u8) ![]Capsule {
    var reader = Reader{ .input = input };
    var capsules: std.ArrayList(Capsule) = .empty;
    errdefer capsules.deinit(allocator);

    while (reader.pos < input.len) {
        try capsules.append(allocator, try reader.readCapsule());
    }

    return try capsules.toOwnedSlice(allocator);
}

pub fn encodeDatagram(
    allocator: std.mem.Allocator,
    quarter_stream_id: u64,
    payload: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendVarint(allocator, &out, quarter_stream_id);
    try out.appendSlice(allocator, payload);
    return try out.toOwnedSlice(allocator);
}

pub fn encodeSessionDatagram(
    allocator: std.mem.Allocator,
    session_id: SessionId,
    payload: []const u8,
) ![]u8 {
    return encodeDatagram(allocator, session_id.quarterStreamId(), payload);
}

pub fn decodeDatagram(input: []const u8) FormatError!Datagram {
    var reader = Reader{ .input = input };
    const quarter_stream_id = try reader.readVarint();
    return .{
        .quarter_stream_id = quarter_stream_id,
        .payload = input[reader.pos..],
    };
}

pub fn decodeSessionDatagram(input: []const u8) FormatError!struct {
    session_id: SessionId,
    payload: []const u8,
} {
    const datagram = try decodeDatagram(input);
    return .{
        .session_id = try SessionId.fromQuarterStreamId(datagram.quarter_stream_id),
        .payload = datagram.payload,
    };
}

pub fn encodeStreamSignal(
    allocator: std.mem.Allocator,
    stream_type: u64,
    session_id: SessionId,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendVarint(allocator, &out, stream_type);
    try appendVarint(allocator, &out, session_id.stream_id);
    return try out.toOwnedSlice(allocator);
}

pub fn decodeStreamSignal(input: []const u8) FormatError!StreamSignal {
    var reader = Reader{ .input = input };
    const stream_type = try reader.readVarint();
    const session_id = try SessionId.initClientBidirectional(try reader.readVarint());
    if (reader.pos != input.len) return FormatError.TrailingBytes;
    return .{ .stream_type = stream_type, .session_id = session_id };
}

fn appendVarint(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    value: u64,
) !void {
    var buffer: [8]u8 = undefined;
    try out.appendSlice(allocator, try encodeVarint(value, &buffer));
}

fn usizeToVarint(value: usize) FormatError!u64 {
    const narrowed = std.math.cast(u64, value) orelse return FormatError.VarintTooLarge;
    if (narrowed > max_varint) return FormatError.VarintTooLarge;
    return narrowed;
}

const Reader = struct {
    input: []const u8,
    pos: usize = 0,

    fn readVarint(self: *Reader) FormatError!u64 {
        const decoded = try decodeVarint(self.input[self.pos..]);
        self.pos += decoded.len;
        return decoded.value;
    }

    fn readCapsule(self: *Reader) FormatError!Capsule {
        const capsule_type = try self.readVarint();
        const length_u64 = try self.readVarint();
        const length = std.math.cast(usize, length_u64) orelse {
            return FormatError.CapsuleLengthOverflow;
        };
        if (length > self.input.len - self.pos) return FormatError.Truncated;

        const start = self.pos;
        self.pos += length;
        return .{
            .capsule_type = capsule_type,
            .value = self.input[start..self.pos],
        };
    }
};

test "QUIC varint canonical encoding is deterministic" {
    const cases = [_]struct {
        value: u64,
        encoded: []const u8,
    }{
        .{ .value = 0, .encoded = &[_]u8{0x00} },
        .{ .value = 63, .encoded = &[_]u8{0x3f} },
        .{ .value = 64, .encoded = &[_]u8{ 0x40, 0x40 } },
        .{ .value = 15_277, .encoded = &[_]u8{ 0x7b, 0xad } },
        .{ .value = 16_383, .encoded = &[_]u8{ 0x7f, 0xff } },
        .{ .value = 16_384, .encoded = &[_]u8{ 0x80, 0x00, 0x40, 0x00 } },
        .{ .value = 1_073_741_823, .encoded = &[_]u8{ 0xbf, 0xff, 0xff, 0xff } },
        .{ .value = 1_073_741_824, .encoded = &[_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 } },
        .{ .value = max_varint, .encoded = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    };

    for (cases) |case| {
        var buffer: [8]u8 = undefined;
        const encoded = try encodeVarint(case.value, &buffer);
        try std.testing.expectEqualSlices(u8, case.encoded, encoded);

        const decoded = try decodeVarint(encoded);
        try std.testing.expectEqual(case.value, decoded.value);
        try std.testing.expectEqual(case.encoded.len, decoded.len);
    }
}

test "QUIC varint rejects non-minimal and oversized forms" {
    try std.testing.expectError(FormatError.NonCanonicalVarint, decodeVarint(&[_]u8{ 0x40, 0x00 }));
    try std.testing.expectError(FormatError.NonCanonicalVarint, decodeVarint(&[_]u8{ 0x40, 0x3f }));
    try std.testing.expectError(FormatError.NonCanonicalVarint, decodeVarint(&[_]u8{ 0x80, 0x00, 0x00, 0x01 }));
    try std.testing.expectError(
        FormatError.NonCanonicalVarint,
        decodeVarint(&[_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }),
    );
    try std.testing.expectError(FormatError.VarintTooLarge, varintEncodedLen(max_varint + 1));
}

test "QUIC varint reports truncation and trailing bytes" {
    try std.testing.expectError(FormatError.Truncated, decodeVarint(&[_]u8{}));
    try std.testing.expectError(FormatError.Truncated, decodeVarint(&[_]u8{0x40}));
    try std.testing.expectError(FormatError.Truncated, decodeVarint(&[_]u8{ 0x80, 0x00, 0x00 }));
    try std.testing.expectError(FormatError.Truncated, decodeVarint(&[_]u8{ 0xc0, 0x00, 0x00, 0x00 }));
    try std.testing.expectError(FormatError.TrailingBytes, decodeVarintComplete(&[_]u8{ 0x01, 0x00 }));
}

test "HTTP capsules round-trip individual records and sequences" {
    const allocator = std.testing.allocator;

    const encoded = try encodeCapsule(allocator, CapsuleType.close_webtransport_session, "closed");
    defer allocator.free(encoded);

    const capsule = try decodeCapsule(encoded);
    try std.testing.expectEqual(CapsuleType.close_webtransport_session, capsule.capsule_type);
    try std.testing.expectEqualSlices(u8, "closed", capsule.value);

    var sequence: std.ArrayList(u8) = .empty;
    defer sequence.deinit(allocator);

    const datagram = try encodeCapsule(allocator, CapsuleType.datagram, &[_]u8{ 0x01, 0x02 });
    defer allocator.free(datagram);
    try sequence.appendSlice(allocator, datagram);

    const close = try encodeCapsule(allocator, CapsuleType.close_webtransport_session, "bye");
    defer allocator.free(close);
    try sequence.appendSlice(allocator, close);

    const drain = try encodeCapsule(allocator, CapsuleType.drain_webtransport_session, "");
    defer allocator.free(drain);
    try sequence.appendSlice(allocator, drain);

    const decoded = try decodeCapsules(allocator, sequence.items);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    try std.testing.expectEqual(CapsuleType.datagram, decoded[0].capsule_type);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02 }, decoded[0].value);
    try std.testing.expectEqual(CapsuleType.close_webtransport_session, decoded[1].capsule_type);
    try std.testing.expectEqualSlices(u8, "bye", decoded[1].value);
    try std.testing.expectEqual(CapsuleType.drain_webtransport_session, decoded[2].capsule_type);
    try std.testing.expectEqualSlices(u8, "", decoded[2].value);
}

test "HTTP capsules reject malformed lengths and trailing records" {
    try std.testing.expectError(FormatError.Truncated, decodeCapsule(&[_]u8{ 0x00, 0x03, 0xaa, 0xbb }));
    try std.testing.expectError(FormatError.TrailingBytes, decodeCapsule(&[_]u8{ 0x00, 0x00, 0x00, 0x00 }));
    try std.testing.expectError(FormatError.NonCanonicalVarint, decodeCapsule(&[_]u8{ 0x40, 0x00, 0x00 }));
    try std.testing.expectError(FormatError.Truncated, decodeCapsules(std.testing.allocator, &[_]u8{ 0x00, 0x02, 0x01 }));
}

test "WebTransport datagram framing round-trips quarter-stream id and payload" {
    const allocator = std.testing.allocator;

    const payload = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const encoded = try encodeDatagram(allocator, 64, &payload);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x40, 0x40, 0xde, 0xad, 0xbe, 0xef }, encoded);

    const decoded = try decodeDatagram(encoded);
    try std.testing.expectEqual(@as(u64, 64), decoded.quarter_stream_id);
    try std.testing.expectEqualSlices(u8, &payload, decoded.payload);

    const empty = try encodeDatagram(allocator, 0, "");
    defer allocator.free(empty);
    const empty_decoded = try decodeDatagram(empty);
    try std.testing.expectEqual(@as(u64, 0), empty_decoded.quarter_stream_id);
    try std.testing.expectEqualSlices(u8, "", empty_decoded.payload);
}

test "Session id model maps to and from quarter-stream ids" {
    const session = try SessionId.initClientBidirectional(12);
    try std.testing.expectEqual(@as(u64, 3), session.quarterStreamId());

    const same = try SessionId.fromQuarterStreamId(3);
    try std.testing.expectEqual(@as(u64, 12), same.stream_id);

    try std.testing.expectError(FormatError.InvalidSessionId, SessionId.initClientBidirectional(1));
    try std.testing.expectError(FormatError.InvalidSessionId, SessionId.initClientBidirectional(max_varint));
    try std.testing.expectError(FormatError.InvalidSessionId, SessionId.fromQuarterStreamId((max_varint >> 2) + 1));
}

test "Session datagram framing round-trips through the session model" {
    const allocator = std.testing.allocator;
    const session = try SessionId.initClientBidirectional(8);

    const encoded = try encodeSessionDatagram(allocator, session, "wt");
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 'w', 't' }, encoded);

    const decoded = try decodeSessionDatagram(encoded);
    try std.testing.expectEqual(session.stream_id, decoded.session_id.stream_id);
    try std.testing.expectEqualSlices(u8, "wt", decoded.payload);
}

test "Stream signal framing encodes and decodes known stream types" {
    const allocator = std.testing.allocator;
    const session = try SessionId.initClientBidirectional(4);

    const uni = try encodeStreamSignal(allocator, StreamType.webtransport_unidirectional, session);
    defer allocator.free(uni);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x40, 0x54, 0x04 }, uni);

    const decoded_uni = try decodeStreamSignal(uni);
    try std.testing.expectEqual(KnownStreamSignal.unidirectional, decoded_uni.knownKind().?);
    try std.testing.expectEqual(session.stream_id, decoded_uni.session_id.stream_id);

    const bidi = try encodeStreamSignal(allocator, StreamType.webtransport_bidirectional, session);
    defer allocator.free(bidi);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x40, 0x41, 0x04 }, bidi);

    const decoded_bidi = try decodeStreamSignal(bidi);
    try std.testing.expectEqual(KnownStreamSignal.bidirectional, decoded_bidi.knownKind().?);
    try std.testing.expectEqual(session.stream_id, decoded_bidi.session_id.stream_id);
}

test "Stream signal framing rejects truncation trailing bytes and invalid sessions" {
    try std.testing.expectError(FormatError.Truncated, decodeStreamSignal(&[_]u8{0x54}));
    try std.testing.expectError(FormatError.TrailingBytes, decodeStreamSignal(&[_]u8{ 0x40, 0x54, 0x04, 0x00 }));
    try std.testing.expectError(FormatError.InvalidSessionId, decodeStreamSignal(&[_]u8{ 0x40, 0x54, 0x01 }));
    try std.testing.expectError(FormatError.NonCanonicalVarint, decodeStreamSignal(&[_]u8{ 0x40, 0x54, 0x40, 0x04 }));
}
