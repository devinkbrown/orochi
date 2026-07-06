// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOPIC frame payload codec (S2S channel-topic propagation).
//!
//! Carries one last-writer-wins channel topic fact: `present` distinguishes a
//! set topic from a cleared one, `hlc` orders writes, and `setter`/`set_at`
//! preserve the IRC topic metadata surfaced by RPL_TOPIC / RPL_TOPICWHOTIME.
//! Decode borrows the input and allocates nothing.
const std = @import("std");

pub const max_channel_len = 128;
pub const max_topic_len = 512;
pub const max_setter_len = 256;
const fixed_prefix = 1 + 8 + 8 + 8; // present, origin_node, hlc, set_at

pub const Error = error{
    Truncated,
    FieldTooLong,
    TrailingBytes,
};

pub const TopicEvent = struct {
    present: bool,
    origin_node: u64,
    hlc: u64,
    set_at: i64,
    channel: []const u8,
    topic: []const u8,
    setter: []const u8,
};

pub fn encodedLen(ev: TopicEvent) Error!usize {
    if (ev.channel.len > max_channel_len or ev.topic.len > max_topic_len or ev.setter.len > max_setter_len) {
        return error.FieldTooLong;
    }
    return fixed_prefix + 2 + ev.channel.len + 2 + ev.topic.len + 2 + ev.setter.len;
}

pub fn encode(ev: TopicEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;

    var i: usize = 0;
    out[i] = @intFromBool(ev.present);
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    std.mem.writeInt(i64, out[i..][0..8], ev.set_at, .little);
    i += 8;

    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.channel.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.channel.len], ev.channel);
    i += ev.channel.len;

    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.topic.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.topic.len], ev.topic);
    i += ev.topic.len;

    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.setter.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.setter.len], ev.setter);
    i += ev.setter.len;

    return out[0..i];
}

fn validateNoLineBreak(bytes: []const u8) Error!void {
    for (bytes) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return error.FieldTooLong;
    }
}

pub fn decode(bytes: []const u8) Error!TopicEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;

    var i: usize = 0;
    const present = bytes[i] != 0;
    i += 1;
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const set_at = std.mem.readInt(i64, bytes[i..][0..8], .little);
    i += 8;

    const channel_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (channel_len > max_channel_len) return error.FieldTooLong;
    if (bytes.len < i + channel_len + 2) return error.Truncated;
    const channel = bytes[i .. i + channel_len];
    i += channel_len;

    const topic_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (topic_len > max_topic_len) return error.FieldTooLong;
    if (bytes.len < i + topic_len + 2) return error.Truncated;
    const topic = bytes[i .. i + topic_len];
    i += topic_len;

    const setter_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (setter_len > max_setter_len) return error.FieldTooLong;
    if (bytes.len < i + setter_len) return error.Truncated;
    const setter = bytes[i .. i + setter_len];
    i += setter_len;

    if (i != bytes.len) return error.TrailingBytes;
    try validateNoLineBreak(topic);
    try validateNoLineBreak(setter);
    return .{
        .present = present,
        .origin_node = origin_node,
        .hlc = hlc,
        .set_at = set_at,
        .channel = channel,
        .topic = topic,
        .setter = setter,
    };
}

const testing = std.testing;

test "topic event round-trips a set topic" {
    const ev = TopicEvent{
        .present = true,
        .origin_node = 42,
        .hlc = 99,
        .set_at = 1_781_234_567,
        .channel = "#ops",
        .topic = "welcome to the mesh",
        .setter = "Oper!user@host",
    };
    var buf: [1024]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expect(got.present);
    try testing.expectEqual(@as(u64, 42), got.origin_node);
    try testing.expectEqual(@as(u64, 99), got.hlc);
    try testing.expectEqual(@as(i64, 1_781_234_567), got.set_at);
    try testing.expectEqualStrings("#ops", got.channel);
    try testing.expectEqualStrings("welcome to the mesh", got.topic);
    try testing.expectEqualStrings("Oper!user@host", got.setter);
}

test "topic event round-trips a cleared topic" {
    const ev = TopicEvent{
        .present = false,
        .origin_node = 7,
        .hlc = 8,
        .set_at = 9,
        .channel = "#i",
        .topic = "",
        .setter = "services",
    };
    var buf: [256]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expect(!got.present);
    try testing.expectEqualStrings("", got.topic);
    try testing.expectEqualStrings("services", got.setter);
}

test "topic event rejects malformed input" {
    const ev = TopicEvent{ .present = true, .origin_node = 1, .hlc = 2, .set_at = 3, .channel = "#c", .topic = "t", .setter = "s" };
    var buf: [128]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));

    var padded: [129]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xaa;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "topic event enforces bounds" {
    const big = &@as([(max_topic_len + 1)]u8, @splat('x'));
    const ev = TopicEvent{ .present = true, .origin_node = 1, .hlc = 1, .set_at = 1, .channel = "#c", .topic = big, .setter = "s" };
    try testing.expectError(error.FieldTooLong, encodedLen(ev));
}
