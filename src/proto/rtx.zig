// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RTP Retransmission payload format (RTX), RFC 4588.
const std = @import("std");
const rtp_profile = @import("rtp_profile.zig");

pub const Error = error{ Truncated, BufferTooSmall };

const osn_len: usize = 2;
const endian = .big;

pub fn wrap(
    original_rtp: []const u8,
    rtx_ssrc: u32,
    rtx_seq: u16,
    rtx_pt: u7,
    out: []u8,
) Error![]const u8 {
    if (original_rtp.len < rtp_profile.header_len) return error.Truncated;

    const original = decodeHeader(original_rtp);
    const original_payload = original_rtp[rtp_profile.header_len..];
    const total = rtp_profile.header_len + osn_len + original_payload.len;
    if (out.len < total) return error.BufferTooSmall;

    _ = encodeHeader(.{
        .marker = original.marker,
        .payload_type = rtx_pt,
        .sequence = rtx_seq,
        .timestamp = original.timestamp,
        .ssrc = rtx_ssrc,
    }, out[0..rtp_profile.header_len]);

    std.mem.writeInt(u16, out[rtp_profile.header_len .. rtp_profile.header_len + osn_len], original.sequence, endian);
    @memcpy(out[rtp_profile.header_len + osn_len .. total], original_payload);
    return out[0..total];
}

pub fn unwrap(
    rtx_packet: []const u8,
    original_ssrc: u32,
    original_pt: u7,
    out: []u8,
) Error![]const u8 {
    if (rtx_packet.len < rtp_profile.header_len + osn_len) return error.Truncated;

    const rtx = decodeHeader(rtx_packet);
    const osn = std.mem.readInt(u16, rtx_packet[rtp_profile.header_len .. rtp_profile.header_len + osn_len], endian);
    const original_payload = rtx_packet[rtp_profile.header_len + osn_len ..];
    const total = rtp_profile.header_len + original_payload.len;
    if (out.len < total) return error.BufferTooSmall;

    _ = encodeHeader(.{
        .marker = rtx.marker,
        .payload_type = original_pt,
        .sequence = osn,
        .timestamp = rtx.timestamp,
        .ssrc = original_ssrc,
    }, out[0..rtp_profile.header_len]);

    @memcpy(out[rtp_profile.header_len..total], original_payload);
    return out[0..total];
}

fn decodeHeader(input: []const u8) rtp_profile.Header {
    return (rtp_profile.decodeHeader(input) catch unreachable).header;
}

fn encodeHeader(header: rtp_profile.Header, out: []u8) []const u8 {
    return rtp_profile.encodeHeader(header, out) catch unreachable;
}

test "wrap and unwrap RTX packet" {
    var original_buf: [rtp_profile.header_len + 5]u8 = undefined;
    const original_payload = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01 };
    const original_rtp = try rtp_profile.encodePacket(.{
        .header = .{
            .marker = true,
            .payload_type = 96,
            .sequence = 1000,
            .timestamp = 0x11223344,
            .ssrc = 0x0000aaaa,
        },
        .payload = &original_payload,
    }, &original_buf);

    var rtx_buf: [rtp_profile.header_len + osn_len + original_payload.len]u8 = undefined;
    const rtx_packet = try wrap(original_rtp, 0x0000bbbb, 5, 97, &rtx_buf);

    const rtx_header = (try rtp_profile.decodeHeader(rtx_packet)).header;
    try std.testing.expectEqual(@as(u7, 97), rtx_header.payload_type);
    try std.testing.expectEqual(@as(u16, 5), rtx_header.sequence);
    try std.testing.expectEqual(@as(u32, 0x11223344), rtx_header.timestamp);
    try std.testing.expectEqual(@as(u32, 0x0000bbbb), rtx_header.ssrc);
    try std.testing.expect(rtx_header.marker);
    try std.testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, rtx_packet[rtp_profile.header_len .. rtp_profile.header_len + osn_len], endian));
    try std.testing.expectEqualSlices(u8, &original_payload, rtx_packet[rtp_profile.header_len + osn_len ..]);

    var recovered_buf: [rtp_profile.header_len + original_payload.len]u8 = undefined;
    const recovered = try unwrap(rtx_packet, 0x0000aaaa, 96, &recovered_buf);

    const recovered_header = (try rtp_profile.decodeHeader(recovered)).header;
    try std.testing.expectEqual(@as(u7, 96), recovered_header.payload_type);
    try std.testing.expectEqual(@as(u16, 1000), recovered_header.sequence);
    try std.testing.expectEqual(@as(u32, 0x11223344), recovered_header.timestamp);
    try std.testing.expectEqual(@as(u32, 0x0000aaaa), recovered_header.ssrc);
    try std.testing.expect(recovered_header.marker);
    try std.testing.expectEqualSlices(u8, original_rtp[rtp_profile.header_len..], recovered[rtp_profile.header_len..]);
    try std.testing.expectEqualSlices(u8, original_rtp, recovered);
}

test "short input is truncated" {
    var out: [rtp_profile.header_len + osn_len]u8 = undefined;

    try std.testing.expectError(error.Truncated, wrap(&.{0x80}, 0x0000bbbb, 5, 97, &out));
    try std.testing.expectError(error.Truncated, unwrap(&.{0x80}, 0x0000aaaa, 96, &out));
}
