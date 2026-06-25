// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CHANNEL_MODE_FLAGS frame payload codec (S2S channel flag propagation).
//!
//! Carries one convergent aggregate fact for a channel's boolean MODE flags:
//! on `origin_node`, `channel` has `flags` as of `hlc`. The receiver applies it
//! last-writer-wins by `hlc` and locally diffs the aggregate before emitting IRC
//! MODE lines. Compact fixed binary layout (little-endian):
//!
//!   flags:u16 | origin_node:u64 | hlc:u64 | chan_len:u16 | chan...
//!
//! Bounded by the channel-name limit; decode borrows the input (no allocation).
const std = @import("std");

pub const max_channel_len = 128;
pub const max_flag_bits: u16 = 0x3fff; // i,m,n,t,s,C,T,N,g,S,M,W,O,A
const fixed_prefix = 2 + 8 + 8;

pub const Error = error{
    Truncated,
    NameTooLong,
    InvalidFlags,
    TrailingBytes,
};

pub const ChannelModeFlagsEvent = struct {
    flags: u16,
    origin_node: u64,
    hlc: u64,
    channel: []const u8, // borrows the encode buffer (encode) / input (decode)
};

pub fn encodedLen(ev: ChannelModeFlagsEvent) Error!usize {
    if (ev.channel.len > max_channel_len) return error.NameTooLong;
    if ((ev.flags & ~max_flag_bits) != 0) return error.InvalidFlags;
    return fixed_prefix + 2 + ev.channel.len;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: ChannelModeFlagsEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    std.mem.writeInt(u16, out[i..][0..2], ev.flags, .little);
    i += 2;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.channel.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.channel.len], ev.channel);
    i += ev.channel.len;
    return out[0..i];
}

/// Decode from `bytes`; the returned `channel` borrows `bytes`.
pub fn decode(bytes: []const u8) Error!ChannelModeFlagsEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;
    var i: usize = 0;
    const flags = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if ((flags & ~max_flag_bits) != 0) return error.InvalidFlags;
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;

    const chan_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (chan_len > max_channel_len) return error.NameTooLong;
    if (bytes.len < i + chan_len) return error.Truncated;
    const channel = bytes[i .. i + chan_len];
    i += chan_len;

    if (i != bytes.len) return error.TrailingBytes;
    return .{
        .flags = flags,
        .origin_node = origin_node,
        .hlc = hlc,
        .channel = channel,
    };
}

const testing = std.testing;

test "channel mode flags event round-trips" {
    const ev = ChannelModeFlagsEvent{
        .flags = 0b10_1010_0101_0011,
        .origin_node = 0xCAFE_BABE,
        .hlc = 42,
        .channel = "#chat",
    };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(@as(u16, 0b10_1010_0101_0011), got.flags);
    try testing.expectEqual(@as(u64, 0xCAFE_BABE), got.origin_node);
    try testing.expectEqual(@as(u64, 42), got.hlc);
    try testing.expectEqualStrings("#chat", got.channel);
}

test "channel mode flags event rejects truncated and trailing input" {
    const ev = ChannelModeFlagsEvent{ .flags = 3, .origin_node = 1, .hlc = 2, .channel = "#c" };
    var buf: [128]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));
    try testing.expectError(error.Truncated, decode(wire[0..3]));

    var padded: [129]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "channel mode flags event validates bounds" {
    const big = "#" ++ ("x" ** max_channel_len);
    try testing.expectError(error.NameTooLong, encodedLen(.{ .flags = 0, .origin_node = 1, .hlc = 1, .channel = big }));
    try testing.expectError(error.InvalidFlags, encodedLen(.{ .flags = max_flag_bits + 1, .origin_node = 1, .hlc = 1, .channel = "#c" }));

    var buf: [fixed_prefix + 2 + 2]u8 = undefined;
    _ = try encode(.{ .flags = 0, .origin_node = 1, .hlc = 1, .channel = "#c" }, &buf);
    std.mem.writeInt(u16, buf[0..2], max_flag_bits + 1, .little);
    try testing.expectError(error.InvalidFlags, decode(&buf));
}
