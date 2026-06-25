// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const Error = error{ Truncated, BadFormat, BufferTooSmall, TooMany };

const fmt_remb: u8 = 15;
const pt_psfb: u8 = 206;
const remb_tag = "REMB";
const fixed_packet_len: usize = 20;
const max_mantissa: u64 = (1 << 18) - 1;

pub const Parsed = struct {
    sender_ssrc: u32,
    bitrate_bps: u64,
    ssrcs: []const u32,
};

pub fn build(sender_ssrc: u32, bitrate_bps: u64, ssrcs: []const u32, out: []u8) Error![]const u8 {
    if (ssrcs.len > std.math.maxInt(u8)) return Error.TooMany;

    const packet_len = fixed_packet_len + ssrcs.len * 4;
    if (out.len < packet_len) return Error.BufferTooSmall;

    var exp: u6 = 0;
    while ((bitrate_bps >> exp) > max_mantissa) : (exp += 1) {}
    const mantissa = bitrate_bps >> exp;

    out[0] = 0x80 | fmt_remb;
    out[1] = pt_psfb;
    std.mem.writeInt(u16, out[2..4], @intCast(packet_len / 4 - 1), .big);
    std.mem.writeInt(u32, out[4..8], sender_ssrc, .big);
    std.mem.writeInt(u32, out[8..12], 0, .big);
    @memcpy(out[12..16], remb_tag);
    out[16] = @intCast(ssrcs.len);

    const mantissa_u32: u32 = @intCast(mantissa);
    out[17] = (@as(u8, exp) << 2) | @as(u8, @intCast((mantissa_u32 >> 16) & 0x03));
    std.mem.writeInt(u16, out[18..20], @intCast(mantissa_u32 & 0xffff), .big);

    var cursor: usize = fixed_packet_len;
    for (ssrcs) |ssrc| {
        std.mem.writeInt(u32, out[cursor..][0..4], ssrc, .big);
        cursor += 4;
    }

    return out[0..packet_len];
}

pub fn parse(bytes: []const u8, ssrc_out: []u32) Error!Parsed {
    if (bytes.len < 4) return Error.Truncated;

    const version = bytes[0] >> 6;
    const fmt = bytes[0] & 0x1f;
    if (version != 2 or fmt != fmt_remb or bytes[1] != pt_psfb) return Error.BadFormat;

    const words_minus_one = std.mem.readInt(u16, bytes[2..4], .big);
    const packet_len = (@as(usize, words_minus_one) + 1) * 4;
    if (bytes.len < packet_len) return Error.Truncated;
    if (bytes.len != packet_len or packet_len < fixed_packet_len) return Error.BadFormat;

    if (!std.mem.eql(u8, bytes[12..16], remb_tag)) return Error.BadFormat;

    const count: usize = bytes[16];
    const expected_len = fixed_packet_len + count * 4;
    if (packet_len != expected_len) return Error.BadFormat;
    if (count > ssrc_out.len) return Error.TooMany;

    const exp: u6 = @intCast(bytes[17] >> 2);
    const mantissa_high = @as(u32, bytes[17] & 0x03) << 16;
    const mantissa_low = std.mem.readInt(u16, bytes[18..20], .big);
    const mantissa = mantissa_high | mantissa_low;

    var cursor: usize = fixed_packet_len;
    for (ssrc_out[0..count]) |*ssrc| {
        ssrc.* = std.mem.readInt(u32, bytes[cursor..][0..4], .big);
        cursor += 4;
    }

    return .{
        .sender_ssrc = std.mem.readInt(u32, bytes[4..8], .big),
        .bitrate_bps = @as(u64, mantissa) << exp,
        .ssrcs = ssrc_out[0..count],
    };
}

test "build and parse REMB packet" {
    var buf: [28]u8 = undefined;
    const ssrcs = [_]u32{ 0x11223344, 0xaabbccdd };

    const packet = try build(0x01020304, 2_500_000, &ssrcs, &buf);
    try std.testing.expectEqual(@as(usize, 28), packet.len);
    try std.testing.expectEqual(@as(u8, 0x8f), packet[0]);
    try std.testing.expectEqual(pt_psfb, packet[1]);
    try std.testing.expectEqualSlices(u8, remb_tag, packet[12..16]);

    var parsed_ssrcs: [2]u32 = undefined;
    const parsed = try parse(packet, &parsed_ssrcs);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.sender_ssrc);
    try std.testing.expectEqualSlices(u32, &ssrcs, parsed.ssrcs);

    const exp: u6 = @intCast(packet[17] >> 2);
    const mantissa = (@as(u32, packet[17] & 0x03) << 16) | std.mem.readInt(u16, packet[18..20], .big);
    try std.testing.expectEqual(@as(u64, mantissa) << exp, parsed.bitrate_bps);
    try std.testing.expect(parsed.bitrate_bps <= 2_500_000);
}

test "parse rejects truncated packet" {
    var buf: [24]u8 = undefined;
    const packet = try build(0x01020304, 2_500_000, &.{0x11223344}, &buf);

    var parsed_ssrcs: [1]u32 = undefined;
    try std.testing.expectError(Error.Truncated, parse(packet[0 .. packet.len - 1], &parsed_ssrcs));
}

test "parse rejects non-REMB tag" {
    var buf: [24]u8 = undefined;
    const packet = try build(0x01020304, 2_500_000, &.{0x11223344}, &buf);
    buf[12] = 'X';

    var parsed_ssrcs: [1]u32 = undefined;
    try std.testing.expectError(Error.BadFormat, parse(packet, &parsed_ssrcs));
}
