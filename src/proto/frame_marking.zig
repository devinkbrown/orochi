//! draft-ietf-avtext-framemarking RTP frame-marking extension value codec.
//!
//! This module encodes and decodes only the header-extension value bytes. The
//! generic RFC 8285 one-byte/two-byte extension element framing lives in
//! `rtp_ext.zig`.
const std = @import("std");

pub const Marking = struct {
    start: bool,
    end: bool,
    independent: bool,
    discardable: bool,
    base_sync: bool,
    tid: u3,
    lid: u8 = 0,
    tl0picidx: u8 = 0,
    extended: bool = false,
};

pub const Error = error{ Truncated, BufferTooSmall };

const common_len: usize = 1;
const extended_len: usize = 3;

const start_mask: u8 = 0x80;
const end_mask: u8 = 0x40;
const independent_mask: u8 = 0x20;
const discardable_mask: u8 = 0x10;
const base_sync_mask: u8 = 0x08;
const tid_mask: u8 = 0x07;

pub fn encode(m: Marking, out: []u8) Error![]const u8 {
    const needed: usize = if (m.extended) extended_len else common_len;
    if (out.len < needed) return error.BufferTooSmall;

    out[0] = encodeByte0(m);
    if (m.extended) {
        out[1] = m.lid;
        out[2] = m.tl0picidx;
    }

    return out[0..needed];
}

pub fn decode(bytes: []const u8) Error!Marking {
    if (bytes.len == 0) return error.Truncated;
    if (bytes.len == common_len) return decodeByte0(bytes[0], false, 0, 0);
    if (bytes.len < extended_len) return error.Truncated;
    return decodeByte0(bytes[0], true, bytes[1], bytes[2]);
}

pub fn isKeyframe(m: Marking) bool {
    return m.independent and m.start;
}

fn encodeByte0(m: Marking) u8 {
    return (if (m.start) start_mask else 0) |
        (if (m.end) end_mask else 0) |
        (if (m.independent) independent_mask else 0) |
        (if (m.discardable) discardable_mask else 0) |
        (if (m.base_sync) base_sync_mask else 0) |
        @as(u8, m.tid);
}

fn decodeByte0(byte: u8, extended: bool, lid: u8, tl0picidx: u8) Marking {
    return .{
        .start = (byte & start_mask) != 0,
        .end = (byte & end_mask) != 0,
        .independent = (byte & independent_mask) != 0,
        .discardable = (byte & discardable_mask) != 0,
        .base_sync = (byte & base_sync_mask) != 0,
        .tid = @intCast(byte & tid_mask),
        .lid = lid,
        .tl0picidx = tl0picidx,
        .extended = extended,
    };
}

test "1-byte round-trip preserving all flags and tid" {
    const want = Marking{
        .start = true,
        .end = true,
        .independent = false,
        .discardable = true,
        .base_sync = true,
        .tid = 5,
    };

    var buf: [extended_len]u8 = undefined;
    const encoded = try encode(want, &buf);
    try std.testing.expectEqual(@as(usize, common_len), encoded.len);

    const got = try decode(encoded);
    try std.testing.expectEqual(want, got);
}

test "3-byte extended round-trip with lid and tl0picidx" {
    const want = Marking{
        .start = true,
        .end = false,
        .independent = true,
        .discardable = false,
        .base_sync = true,
        .tid = 3,
        .lid = 0x42,
        .tl0picidx = 0xa7,
        .extended = true,
    };

    var buf: [extended_len]u8 = undefined;
    const encoded = try encode(want, &buf);
    try std.testing.expectEqualSlices(u8, &.{ 0xab, 0x42, 0xa7 }, encoded);

    const got = try decode(encoded);
    try std.testing.expectEqual(want, got);
}

test "known marking has exact byte0 bit layout" {
    const m = Marking{
        .start = true,
        .end = false,
        .independent = true,
        .discardable = true,
        .base_sync = false,
        .tid = 6,
    };

    var buf: [common_len]u8 = undefined;
    const encoded = try encode(m, &buf);
    try std.testing.expectEqualSlices(u8, &.{0xb6}, encoded);
    try std.testing.expectEqual(m, try decode(&.{0xb6}));
}

test "decode reports Truncated on empty input" {
    try std.testing.expectError(error.Truncated, decode(&.{}));
}

test "isKeyframe requires independent start of frame" {
    try std.testing.expect(isKeyframe(.{
        .start = true,
        .end = false,
        .independent = true,
        .discardable = false,
        .base_sync = false,
        .tid = 0,
    }));
    try std.testing.expect(!isKeyframe(.{
        .start = false,
        .end = true,
        .independent = true,
        .discardable = false,
        .base_sync = false,
        .tid = 0,
    }));
    try std.testing.expect(!isKeyframe(.{
        .start = true,
        .end = false,
        .independent = false,
        .discardable = false,
        .base_sync = false,
        .tid = 0,
    }));
}
