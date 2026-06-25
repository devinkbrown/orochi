// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const max_frame_bytes: usize = 1275;
pub const max_packet_duration_us: u32 = 120_000;

pub const Mode = enum {
    silk,
    hybrid,
    celt,
};

pub const Bandwidth = enum {
    narrowband,
    mediumband,
    wideband,
    superwideband,
    fullband,
};

pub const Toc = struct {
    byte: u8,
    config: u8,
    stereo: bool,
    frame_count_code: u2,
    mode: Mode,
    bandwidth: Bandwidth,
    samples_per_frame: u16,
    frame_duration_us: u32,
};

pub const Frame = struct {
    data: []const u8,
};

pub const Packet = struct {
    toc: Toc,
    nb_frames: usize,
    samples_per_frame: u16,
    mode: Mode,
    bandwidth: Bandwidth,
    code3_vbr: ?bool,
    padding_len: usize,
    frames: []Frame,

    pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
        allocator.free(self.frames);
        self.* = .{
            .toc = self.toc,
            .nb_frames = 0,
            .samples_per_frame = 0,
            .mode = self.mode,
            .bandwidth = self.bandwidth,
            .code3_vbr = null,
            .padding_len = 0,
            .frames = &.{},
        };
    }
};

pub const ParseError = error{
    EmptyPacket,
    Code1UnevenPayload,
    TruncatedLength,
    FrameTooLarge,
    FrameLengthExceedsPacket,
    Code3Truncated,
    InvalidFrameCount,
    InvalidPadding,
    InvalidCBRLength,
} || std.mem.Allocator.Error;

const ConfigInfo = struct {
    mode: Mode,
    bandwidth: Bandwidth,
    samples_per_frame: u16,
    frame_duration_us: u32,
};

pub fn parseToc(byte: u8) Toc {
    const config = byte >> 3;
    const info = configInfo(config);
    return .{
        .byte = byte,
        .config = config,
        .stereo = (byte & 0x04) != 0,
        .frame_count_code = @intCast(byte & 0x03),
        .mode = info.mode,
        .bandwidth = info.bandwidth,
        .samples_per_frame = info.samples_per_frame,
        .frame_duration_us = info.frame_duration_us,
    };
}

pub fn parsePacket(allocator: std.mem.Allocator, packet: []const u8) ParseError!Packet {
    if (packet.len == 0) return error.EmptyPacket;

    const toc = parseToc(packet[0]);
    var frames: std.ArrayList(Frame) = .empty;
    errdefer frames.deinit(allocator);

    var padding_len: usize = 0;
    const code3_vbr: ?bool = switch (toc.frame_count_code) {
        0 => blk: {
            try appendFrame(allocator, &frames, packet[1..]);
            break :blk null;
        },
        1 => blk: {
            const payload_len = packet.len - 1;
            if (payload_len % 2 != 0) return error.Code1UnevenPayload;
            const frame_len = payload_len / 2;
            try appendFrame(allocator, &frames, packet[1 .. 1 + frame_len]);
            try appendFrame(allocator, &frames, packet[1 + frame_len ..]);
            break :blk null;
        },
        2 => blk: {
            var offset: usize = 1;
            const first_len = try readFrameLength(packet, &offset, packet.len);
            if (first_len > packet.len - offset) return error.FrameLengthExceedsPacket;
            try appendFrame(allocator, &frames, packet[offset .. offset + first_len]);
            offset += first_len;
            try appendFrame(allocator, &frames, packet[offset..]);
            break :blk null;
        },
        3 => blk: {
            const vbr = try parseCode3(allocator, packet, toc, &frames, &padding_len);
            break :blk vbr;
        },
    };

    const owned = try frames.toOwnedSlice(allocator);
    return .{
        .toc = toc,
        .nb_frames = owned.len,
        .samples_per_frame = toc.samples_per_frame,
        .mode = toc.mode,
        .bandwidth = toc.bandwidth,
        .code3_vbr = code3_vbr,
        .padding_len = padding_len,
        .frames = owned,
    };
}

fn parseCode3(
    allocator: std.mem.Allocator,
    packet: []const u8,
    toc: Toc,
    frames: *std.ArrayList(Frame),
    padding_len: *usize,
) ParseError!bool {
    if (packet.len < 2) return error.Code3Truncated;

    const count_byte = packet[1];
    const vbr = (count_byte & 0x80) != 0;
    const has_padding = (count_byte & 0x40) != 0;
    const frame_count: usize = count_byte & 0x3f;
    if (frame_count == 0) return error.InvalidFrameCount;
    if (@as(u64, frame_count) * toc.frame_duration_us > max_packet_duration_us) {
        return error.InvalidFrameCount;
    }

    var offset: usize = 2;
    var frame_end = packet.len;
    if (has_padding) {
        padding_len.* = try readPaddingLength(packet, &offset);
        if (padding_len.* > packet.len - offset) return error.InvalidPadding;
        frame_end = packet.len - padding_len.*;
    }

    if (vbr) {
        try parseCode3Vbr(allocator, packet, frame_count, offset, frame_end, frames);
    } else {
        try parseCode3Cbr(allocator, packet, frame_count, offset, frame_end, frames);
    }
    return vbr;
}

fn parseCode3Cbr(
    allocator: std.mem.Allocator,
    packet: []const u8,
    frame_count: usize,
    offset: usize,
    frame_end: usize,
    frames: *std.ArrayList(Frame),
) ParseError!void {
    if (frame_end < offset) return error.InvalidPadding;
    const remaining = frame_end - offset;
    if (remaining % frame_count != 0) return error.InvalidCBRLength;

    const frame_len = remaining / frame_count;
    if (frame_len > max_frame_bytes) return error.FrameTooLarge;

    var cursor = offset;
    var i: usize = 0;
    while (i < frame_count) : (i += 1) {
        try appendFrame(allocator, frames, packet[cursor .. cursor + frame_len]);
        cursor += frame_len;
    }
}

fn parseCode3Vbr(
    allocator: std.mem.Allocator,
    packet: []const u8,
    frame_count: usize,
    offset: usize,
    frame_end: usize,
    frames: *std.ArrayList(Frame),
) ParseError!void {
    if (frame_end < offset) return error.InvalidPadding;

    var lengths: std.ArrayList(usize) = .empty;
    defer lengths.deinit(allocator);

    var cursor = offset;
    var total_explicit: usize = 0;
    var i: usize = 0;
    while (i + 1 < frame_count) : (i += 1) {
        const len = try readFrameLength(packet, &cursor, frame_end);
        try lengths.append(allocator, len);
        total_explicit += len;
    }

    if (total_explicit > frame_end - cursor) return error.FrameLengthExceedsPacket;

    var data_cursor = cursor;
    for (lengths.items) |len| {
        try appendFrame(allocator, frames, packet[data_cursor .. data_cursor + len]);
        data_cursor += len;
    }
    try appendFrame(allocator, frames, packet[data_cursor..frame_end]);
}

fn readFrameLength(packet: []const u8, offset: *usize, end: usize) ParseError!usize {
    if (offset.* >= end) return error.TruncatedLength;
    const first = packet[offset.*];
    offset.* += 1;
    if (first < 252) return first;

    if (offset.* >= end) return error.TruncatedLength;
    const second = packet[offset.*];
    offset.* += 1;
    return @as(usize, second) * 4 + first;
}

fn readPaddingLength(packet: []const u8, offset: *usize) ParseError!usize {
    var padding_len: usize = 0;
    while (true) {
        if (offset.* >= packet.len) return error.Code3Truncated;
        const byte = packet[offset.*];
        offset.* += 1;
        if (byte == 255) {
            padding_len += 254;
        } else {
            padding_len += byte;
            return padding_len;
        }
    }
}

fn appendFrame(
    allocator: std.mem.Allocator,
    frames: *std.ArrayList(Frame),
    data: []const u8,
) ParseError!void {
    if (data.len > max_frame_bytes) return error.FrameTooLarge;
    try frames.append(allocator, .{ .data = data });
}

fn configInfo(config: u8) ConfigInfo {
    if (config <= 11) {
        const group = config / 4;
        const frame_index = config % 4;
        return .{
            .mode = .silk,
            .bandwidth = switch (group) {
                0 => .narrowband,
                1 => .mediumband,
                else => .wideband,
            },
            .samples_per_frame = switch (frame_index) {
                0 => 480,
                1 => 960,
                2 => 1920,
                else => 2880,
            },
            .frame_duration_us = switch (frame_index) {
                0 => 10_000,
                1 => 20_000,
                2 => 40_000,
                else => 60_000,
            },
        };
    }

    if (config <= 15) {
        const frame_index = config % 2;
        return .{
            .mode = .hybrid,
            .bandwidth = if (config <= 13) .superwideband else .fullband,
            .samples_per_frame = if (frame_index == 0) 480 else 960,
            .frame_duration_us = if (frame_index == 0) 10_000 else 20_000,
        };
    }

    const group = (config - 16) / 4;
    const frame_index = (config - 16) % 4;
    return .{
        .mode = .celt,
        .bandwidth = switch (group) {
            0 => .narrowband,
            1 => .wideband,
            2 => .superwideband,
            else => .fullband,
        },
        .samples_per_frame = switch (frame_index) {
            0 => 120,
            1 => 240,
            2 => 480,
            else => 960,
        },
        .frame_duration_us = switch (frame_index) {
            0 => 2_500,
            1 => 5_000,
            2 => 10_000,
            else => 20_000,
        },
    };
}

fn tocByte(config: u8, stereo: bool, code: u2) u8 {
    return (config << 3) | (if (stereo) @as(u8, 0x04) else 0) | code;
}

test "parse TOC byte exposes config stereo frame count and config metadata" {
    const toc = parseToc(tocByte(31, true, 3));
    try std.testing.expectEqual(@as(u8, 31), toc.config);
    try std.testing.expect(toc.stereo);
    try std.testing.expectEqual(@as(u2, 3), toc.frame_count_code);
    try std.testing.expectEqual(Mode.celt, toc.mode);
    try std.testing.expectEqual(Bandwidth.fullband, toc.bandwidth);
    try std.testing.expectEqual(@as(u16, 960), toc.samples_per_frame);
    try std.testing.expectEqual(@as(u32, 20_000), toc.frame_duration_us);
}

test "configuration table reports samples bandwidth and mode" {
    const cases = [_]struct {
        config: u8,
        mode: Mode,
        bandwidth: Bandwidth,
        samples: u16,
        duration_us: u32,
    }{
        .{ .config = 0, .mode = .silk, .bandwidth = .narrowband, .samples = 480, .duration_us = 10_000 },
        .{ .config = 3, .mode = .silk, .bandwidth = .narrowband, .samples = 2880, .duration_us = 60_000 },
        .{ .config = 5, .mode = .silk, .bandwidth = .mediumband, .samples = 960, .duration_us = 20_000 },
        .{ .config = 10, .mode = .silk, .bandwidth = .wideband, .samples = 1920, .duration_us = 40_000 },
        .{ .config = 12, .mode = .hybrid, .bandwidth = .superwideband, .samples = 480, .duration_us = 10_000 },
        .{ .config = 15, .mode = .hybrid, .bandwidth = .fullband, .samples = 960, .duration_us = 20_000 },
        .{ .config = 16, .mode = .celt, .bandwidth = .narrowband, .samples = 120, .duration_us = 2_500 },
        .{ .config = 21, .mode = .celt, .bandwidth = .wideband, .samples = 240, .duration_us = 5_000 },
        .{ .config = 26, .mode = .celt, .bandwidth = .superwideband, .samples = 480, .duration_us = 10_000 },
        .{ .config = 31, .mode = .celt, .bandwidth = .fullband, .samples = 960, .duration_us = 20_000 },
    };

    for (cases) |case| {
        const toc = parseToc(tocByte(case.config, false, 0));
        try std.testing.expectEqual(case.mode, toc.mode);
        try std.testing.expectEqual(case.bandwidth, toc.bandwidth);
        try std.testing.expectEqual(case.samples, toc.samples_per_frame);
        try std.testing.expectEqual(case.duration_us, toc.frame_duration_us);
    }
}

test "code 0 parses one frame from remaining payload" {
    const packet = [_]u8{ tocByte(0, false, 0), 0xaa, 0xbb, 0xcc };

    var parsed = try parsePacket(std.testing.allocator, &packet);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.nb_frames);
    try std.testing.expectEqual(@as(u16, 480), parsed.samples_per_frame);
    try std.testing.expectEqual(Mode.silk, parsed.mode);
    try std.testing.expectEqual(Bandwidth.narrowband, parsed.bandwidth);
    try std.testing.expectEqualSlices(u8, packet[1..], parsed.frames[0].data);
}

test "code 1 parses two equal-size frames" {
    const packet = [_]u8{ tocByte(20, true, 1), 1, 2, 3, 4 };

    var parsed = try parsePacket(std.testing.allocator, &packet);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.nb_frames);
    try std.testing.expectEqual(@as(u16, 120), parsed.toc.samples_per_frame);
    try std.testing.expect(parsed.toc.stereo);
    try std.testing.expectEqualSlices(u8, packet[1..3], parsed.frames[0].data);
    try std.testing.expectEqualSlices(u8, packet[3..5], parsed.frames[1].data);
}

test "code 2 parses two unequal frames with one-byte length" {
    const packet = [_]u8{ tocByte(24, false, 2), 3, 0x10, 0x11, 0x12, 0x20, 0x21 };

    var parsed = try parsePacket(std.testing.allocator, &packet);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.nb_frames);
    try std.testing.expectEqualSlices(u8, packet[2..5], parsed.frames[0].data);
    try std.testing.expectEqualSlices(u8, packet[5..], parsed.frames[1].data);
}

test "code 2 parses a two-byte frame length" {
    var packet: [1 + 2 + 253 + 2]u8 = undefined;
    packet[0] = tocByte(16, false, 2);
    packet[1] = 253;
    packet[2] = 0;
    @memset(packet[3..256], 0x55);
    packet[256] = 0x77;
    packet[257] = 0x88;

    var parsed = try parsePacket(std.testing.allocator, &packet);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.nb_frames);
    try std.testing.expectEqual(@as(usize, 253), parsed.frames[0].data.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.frames[1].data.len);
}

test "code 3 CBR parses signaled number of equal frames" {
    const packet = [_]u8{ tocByte(16, false, 3), 3, 1, 2, 3, 4, 5, 6 };

    var parsed = try parsePacket(std.testing.allocator, &packet);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), parsed.nb_frames);
    try std.testing.expectEqual(false, parsed.code3_vbr.?);
    try std.testing.expectEqualSlices(u8, packet[2..4], parsed.frames[0].data);
    try std.testing.expectEqualSlices(u8, packet[4..6], parsed.frames[1].data);
    try std.testing.expectEqualSlices(u8, packet[6..8], parsed.frames[2].data);
}

test "code 3 VBR parses explicit lengths and implicit final frame" {
    const packet = [_]u8{
        tocByte(17, false, 3), 0x80 | 3, 2,    1,
        0xaa,                  0xbb,     0xcc, 0xdd,
        0xee,                  0xff,
    };

    var parsed = try parsePacket(std.testing.allocator, &packet);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), parsed.nb_frames);
    try std.testing.expectEqual(true, parsed.code3_vbr.?);
    try std.testing.expectEqualSlices(u8, packet[4..6], parsed.frames[0].data);
    try std.testing.expectEqualSlices(u8, packet[6..7], parsed.frames[1].data);
    try std.testing.expectEqualSlices(u8, packet[7..10], parsed.frames[2].data);
}

test "code 3 CBR parses optional padding and ignores padding bytes" {
    const packet = [_]u8{ tocByte(18, false, 3), 0x40 | 2, 2, 1, 2, 3, 4, 0x99, 0x88 };

    var parsed = try parsePacket(std.testing.allocator, &packet);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.nb_frames);
    try std.testing.expectEqual(@as(usize, 2), parsed.padding_len);
    try std.testing.expectEqual(false, parsed.code3_vbr.?);
    try std.testing.expectEqualSlices(u8, packet[3..5], parsed.frames[0].data);
    try std.testing.expectEqualSlices(u8, packet[5..7], parsed.frames[1].data);
}

test "malformed packets violating RFC requirements are rejected" {
    const code1_odd = [_]u8{ tocByte(0, false, 1), 0xaa };
    try std.testing.expectError(error.Code1UnevenPayload, parsePacket(std.testing.allocator, &code1_odd));

    const code2_overrun = [_]u8{ tocByte(0, false, 2), 3, 0xaa };
    try std.testing.expectError(error.FrameLengthExceedsPacket, parsePacket(std.testing.allocator, &code2_overrun));

    const too_many_frames = [_]u8{ tocByte(16, false, 3), 49 };
    try std.testing.expectError(error.InvalidFrameCount, parsePacket(std.testing.allocator, &too_many_frames));

    const cbr_not_multiple = [_]u8{ tocByte(16, false, 3), 2, 1, 2, 3 };
    try std.testing.expectError(error.InvalidCBRLength, parsePacket(std.testing.allocator, &cbr_not_multiple));

    const padding_overrun = [_]u8{ tocByte(16, false, 3), 0x40 | 1, 4, 1, 2 };
    try std.testing.expectError(error.InvalidPadding, parsePacket(std.testing.allocator, &padding_overrun));
}

test "truncated headers are rejected" {
    const empty = [_]u8{};
    try std.testing.expectError(error.EmptyPacket, parsePacket(std.testing.allocator, &empty));

    const code2_missing_second_length_byte = [_]u8{ tocByte(0, false, 2), 252 };
    try std.testing.expectError(error.TruncatedLength, parsePacket(std.testing.allocator, &code2_missing_second_length_byte));

    const code3_missing_frame_count = [_]u8{tocByte(16, false, 3)};
    try std.testing.expectError(error.Code3Truncated, parsePacket(std.testing.allocator, &code3_missing_frame_count));

    const code3_padding_chain_truncated = [_]u8{ tocByte(16, false, 3), 0x40 | 1, 255 };
    try std.testing.expectError(error.Code3Truncated, parsePacket(std.testing.allocator, &code3_padding_chain_truncated));
}

test "implicit frame lengths above 1275 bytes are rejected" {
    var code0: [1 + max_frame_bytes + 1]u8 = undefined;
    code0[0] = tocByte(16, false, 0);
    @memset(code0[1..], 0);
    try std.testing.expectError(error.FrameTooLarge, parsePacket(std.testing.allocator, &code0));

    var code1: [1 + 2 * (max_frame_bytes + 1)]u8 = undefined;
    code1[0] = tocByte(16, false, 1);
    @memset(code1[1..], 0);
    try std.testing.expectError(error.FrameTooLarge, parsePacket(std.testing.allocator, &code1));
}
