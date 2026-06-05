//! MEMBERSHIP frame payload codec (S2S remote-member propagation, #6 live).
//!
//! Carries one convergent membership fact between mesh peers: "on `origin_node`,
//! nick `nick` is present in `channel` with `status`, as of `hlc`" (or, when
//! `present` is false, has left). The route table applies these last-writer-wins
//! by `hlc` (see route_table.applyMembership), so out-of-order delivery still
//! converges. Compact fixed binary layout (little-endian):
//!
//!   present:u8 | status:u8 | origin_node:u64 | hlc:u64 |
//!   chan_len:u16 | chan… | nick_len:u16 | nick…
//!
//! Bounded by the channel/nick name limits so a hostile peer cannot pin large
//! buffers; decode borrows the input (no allocation).
const std = @import("std");

pub const max_channel_len = 128;
pub const max_nick_len = 64;
const fixed_prefix = 1 + 1 + 8 + 8; // present, status, origin_node, hlc

pub const Error = error{
    Truncated,
    NameTooLong,
    TrailingBytes,
};

pub const MembershipEvent = struct {
    present: bool,
    status: u4,
    origin_node: u64,
    hlc: u64,
    channel: []const u8, // borrows the encode buffer (encode) / input (decode)
    nick: []const u8,
};

pub fn encodedLen(ev: MembershipEvent) Error!usize {
    if (ev.channel.len > max_channel_len or ev.nick.len > max_nick_len) return error.NameTooLong;
    return fixed_prefix + 2 + ev.channel.len + 2 + ev.nick.len;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: MembershipEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = @intFromBool(ev.present);
    i += 1;
    out[i] = ev.status;
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.channel.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.channel.len], ev.channel);
    i += ev.channel.len;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.nick.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.nick.len], ev.nick);
    i += ev.nick.len;
    return out[0..i];
}

/// Decode from `bytes`; the returned `channel`/`nick` borrow `bytes`.
pub fn decode(bytes: []const u8) Error!MembershipEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;
    var i: usize = 0;
    const present = bytes[i] != 0;
    i += 1;
    const status_raw = bytes[i];
    i += 1;
    if (status_raw > 0x0f) return error.NameTooLong; // status is a u4
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;

    const chan_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (chan_len > max_channel_len) return error.NameTooLong;
    if (bytes.len < i + chan_len + 2) return error.Truncated;
    const channel = bytes[i .. i + chan_len];
    i += chan_len;

    const nick_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (nick_len > max_nick_len) return error.NameTooLong;
    if (bytes.len < i + nick_len) return error.Truncated;
    const nick = bytes[i .. i + nick_len];
    i += nick_len;

    if (i != bytes.len) return error.TrailingBytes;
    return .{
        .present = present,
        .status = @intCast(status_raw),
        .origin_node = origin_node,
        .hlc = hlc,
        .channel = channel,
        .nick = nick,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "membership event round-trips" {
    const ev = MembershipEvent{
        .present = true,
        .status = 0b0100,
        .origin_node = 0xDEADBEEFCAFE,
        .hlc = 12345,
        .channel = "#chat",
        .nick = "alice",
    };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(true, got.present);
    try testing.expectEqual(@as(u4, 0b0100), got.status);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFE), got.origin_node);
    try testing.expectEqual(@as(u64, 12345), got.hlc);
    try testing.expectEqualStrings("#chat", got.channel);
    try testing.expectEqualStrings("alice", got.nick);
}

test "a part event (present=false) round-trips" {
    const ev = MembershipEvent{ .present = false, .status = 0, .origin_node = 7, .hlc = 9, .channel = "&local", .nick = "bob" };
    var buf: [128]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqual(false, got.present);
    try testing.expectEqualStrings("&local", got.channel);
}

test "truncated input is rejected" {
    const ev = MembershipEvent{ .present = true, .status = 1, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n" };
    var buf: [128]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));
    try testing.expectError(error.Truncated, decode(wire[0..3]));
}

test "trailing bytes are rejected" {
    const ev = MembershipEvent{ .present = true, .status = 1, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n" };
    var buf: [128]u8 = undefined;
    const wire = try encode(ev, &buf);
    var padded: [129]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "over-long names are rejected by encode and decode" {
    const big = "#" ++ ("x" ** max_channel_len);
    const ev = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = big, .nick = "n" };
    try testing.expectError(error.NameTooLong, encodedLen(ev));
}
