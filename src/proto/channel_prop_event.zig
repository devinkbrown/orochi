//! CHANNEL_PROP frame payload codec (S2S IRCX channel PROP convergence).
//!
//! Carries one last-writer-wins channel property fact between mesh peers:
//! key `key` on channel `channel` is present with `value`/`owner` as of `hlc`,
//! or absent when `present` is false. Decode borrows the input and allocates
//! nothing; all fields are bounded to IRCX-compatible limits.
const std = @import("std");

pub const max_channel_len = 128;
pub const max_key_len = 64;
pub const max_value_len = 512;
pub const max_owner_len = 128;

const fixed_prefix = 1 + 8;

pub const Error = error{
    Truncated,
    FieldTooLong,
    TrailingBytes,
};

pub const ChannelPropEvent = struct {
    present: bool,
    hlc: u64,
    channel: []const u8,
    key: []const u8,
    value: []const u8,
    owner: []const u8,
};

pub fn encodedLen(ev: ChannelPropEvent) Error!usize {
    if (ev.channel.len > max_channel_len or
        ev.key.len > max_key_len or
        ev.value.len > max_value_len or
        ev.owner.len > max_owner_len)
    {
        return error.FieldTooLong;
    }
    return fixed_prefix + 2 + ev.channel.len + 2 + ev.key.len + 2 + ev.value.len + 2 + ev.owner.len;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: ChannelPropEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = @intFromBool(ev.present);
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    i = writeField(out, i, ev.channel);
    i = writeField(out, i, ev.key);
    i = writeField(out, i, ev.value);
    i = writeField(out, i, ev.owner);
    return out[0..i];
}

fn writeField(out: []u8, i_in: usize, bytes: []const u8) usize {
    var i = i_in;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(bytes.len), .little);
    i += 2;
    @memcpy(out[i..][0..bytes.len], bytes);
    return i + bytes.len;
}

/// Decode from `bytes`; returned slices borrow `bytes`.
pub fn decode(bytes: []const u8) Error!ChannelPropEvent {
    if (bytes.len < fixed_prefix + 8) return error.Truncated;
    var i: usize = 0;
    const present = bytes[i] != 0;
    i += 1;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;

    const channel = try readField(bytes, &i, max_channel_len);
    const key = try readField(bytes, &i, max_key_len);
    const value = try readField(bytes, &i, max_value_len);
    const owner = try readField(bytes, &i, max_owner_len);
    if (i != bytes.len) return error.TrailingBytes;

    return .{
        .present = present,
        .hlc = hlc,
        .channel = channel,
        .key = key,
        .value = value,
        .owner = owner,
    };
}

fn readField(bytes: []const u8, i: *usize, max_len: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max_len) return error.FieldTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const field = bytes[i.* .. i.* + len];
    i.* += len;
    return field;
}

const testing = std.testing;

test "channel prop event set round-trips" {
    const ev = ChannelPropEvent{
        .present = true,
        .hlc = 12345,
        .channel = "#chat",
        .key = "TOPIC",
        .value = "hello mesh",
        .owner = "alice",
    };
    var buf: [800]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expect(got.present);
    try testing.expectEqual(@as(u64, 12345), got.hlc);
    try testing.expectEqualStrings("#chat", got.channel);
    try testing.expectEqualStrings("TOPIC", got.key);
    try testing.expectEqualStrings("hello mesh", got.value);
    try testing.expectEqualStrings("alice", got.owner);
}

test "channel prop delete round-trips" {
    const ev = ChannelPropEvent{ .present = false, .hlc = 9, .channel = "#chat", .key = "TOPIC", .value = "", .owner = "alice" };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expect(!got.present);
    try testing.expectEqualStrings("", got.value);
}

test "channel prop codec rejects truncated and trailing input" {
    const ev = ChannelPropEvent{ .present = true, .hlc = 1, .channel = "#c", .key = "K", .value = "V", .owner = "o" };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));

    var padded: [257]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "channel prop codec rejects oversized fields" {
    const big = "x" ** (max_value_len + 1);
    const ev = ChannelPropEvent{ .present = true, .hlc = 1, .channel = "#c", .key = "K", .value = big, .owner = "o" };
    try testing.expectError(error.FieldTooLong, encodedLen(ev));
}
