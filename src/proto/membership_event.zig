//! MEMBERSHIP frame payload codec (S2S remote-member propagation, #6 live).
//!
//! Carries one convergent membership fact between mesh peers: "on `origin_node`,
//! nick `nick` is present in `channel` with `status`, as of `hlc`" (or, when
//! `present` is false, has left). The route table applies these last-writer-wins
//! by `hlc` (see route_table.applyMembership), so out-of-order delivery still
//! converges. Alongside the membership fact the event carries the member's
//! visible identity (username, realname, cloaked/visible host) so remote peers
//! can render the real `user@host` in NAMES/JOIN/WHOIS instead of a
//! `mesh@<server>` placeholder. Compact fixed binary layout (little-endian):
//!
//!   present:u8 | status:u8 | origin_node:u64 | hlc:u64 |
//!   chan_len:u16 | chan… | nick_len:u16 | nick… |
//!   user_len:u16 | user… | real_len:u16 | real… | host_len:u16 | host…
//!
//! Bounded by the per-field limits so a hostile peer cannot pin large buffers;
//! decode borrows the input (no allocation). Identity fields may be empty
//! (e.g. on a part event); consumers substitute their placeholder fallbacks.
const std = @import("std");

pub const max_channel_len = 128;
pub const max_nick_len = 64;
pub const max_username_len = 32;
pub const max_realname_len = 256;
pub const max_host_len = 255;
const fixed_prefix = 1 + 1 + 8 + 8; // present, status, origin_node, hlc

/// Upper bound on one encoded event (all fields at their limits) — size the
/// stack encode buffer with this.
pub const max_encoded_len = fixed_prefix +
    2 + max_channel_len +
    2 + max_nick_len +
    2 + max_username_len +
    2 + max_realname_len +
    2 + max_host_len;

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
    /// The member's username (USER ident) as its home node sees it ("" = unknown).
    username: []const u8 = "",
    /// The member's realname (GECOS) ("" = unknown).
    realname: []const u8 = "",
    /// The member's VISIBLE host — cloak/vhost when set ("" = unknown).
    host: []const u8 = "",
};

pub fn encodedLen(ev: MembershipEvent) Error!usize {
    if (ev.channel.len > max_channel_len or ev.nick.len > max_nick_len) return error.NameTooLong;
    if (ev.username.len > max_username_len) return error.NameTooLong;
    if (ev.realname.len > max_realname_len) return error.NameTooLong;
    if (ev.host.len > max_host_len) return error.NameTooLong;
    return fixed_prefix +
        2 + ev.channel.len +
        2 + ev.nick.len +
        2 + ev.username.len +
        2 + ev.realname.len +
        2 + ev.host.len;
}

fn putBytes16(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
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
    putBytes16(out, &i, ev.channel);
    putBytes16(out, &i, ev.nick);
    putBytes16(out, &i, ev.username);
    putBytes16(out, &i, ev.realname);
    putBytes16(out, &i, ev.host);
    return out[0..i];
}

fn takeBytes16(bytes: []const u8, i: *usize, max_len: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max_len) return error.NameTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const out = bytes[i.* .. i.* + len];
    i.* += len;
    return out;
}

/// Decode from `bytes`; the returned string fields borrow `bytes`.
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

    const channel = try takeBytes16(bytes, &i, max_channel_len);
    const nick = try takeBytes16(bytes, &i, max_nick_len);
    const username = try takeBytes16(bytes, &i, max_username_len);
    const realname = try takeBytes16(bytes, &i, max_realname_len);
    const host = try takeBytes16(bytes, &i, max_host_len);

    if (i != bytes.len) return error.TrailingBytes;
    return .{
        .present = present,
        .status = @intCast(status_raw),
        .origin_node = origin_node,
        .hlc = hlc,
        .channel = channel,
        .nick = nick,
        .username = username,
        .realname = realname,
        .host = host,
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
        .username = "alice",
        .realname = "Alice Liddell",
        .host = "cloak-1a2b3c.users.orochi",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(true, got.present);
    try testing.expectEqual(@as(u4, 0b0100), got.status);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFE), got.origin_node);
    try testing.expectEqual(@as(u64, 12345), got.hlc);
    try testing.expectEqualStrings("#chat", got.channel);
    try testing.expectEqualStrings("alice", got.nick);
    try testing.expectEqualStrings("alice", got.username);
    try testing.expectEqualStrings("Alice Liddell", got.realname);
    try testing.expectEqualStrings("cloak-1a2b3c.users.orochi", got.host);
}

test "empty identity fields round-trip (legacy placeholder producers)" {
    const ev = MembershipEvent{
        .present = true,
        .status = 0,
        .origin_node = 3,
        .hlc = 7,
        .channel = "#c",
        .nick = "n",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqualStrings("", got.username);
    try testing.expectEqualStrings("", got.realname);
    try testing.expectEqualStrings("", got.host);
}

test "a part event (present=false) round-trips" {
    const ev = MembershipEvent{ .present = false, .status = 0, .origin_node = 7, .hlc = 9, .channel = "&local", .nick = "bob" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqual(false, got.present);
    try testing.expectEqualStrings("&local", got.channel);
}

test "truncated input is rejected" {
    const ev = MembershipEvent{ .present = true, .status = 1, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .username = "u", .realname = "r", .host = "h" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    // Cut anywhere — every prefix shorter than the full event must be rejected.
    var cut: usize = 0;
    while (cut < wire.len) : (cut += 1) {
        try testing.expectError(error.Truncated, decode(wire[0..cut]));
    }
}

test "trailing bytes are rejected" {
    const ev = MembershipEvent{ .present = true, .status = 1, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var padded: [max_encoded_len + 1]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "over-long names are rejected by encode and decode" {
    const big = "#" ++ ("x" ** max_channel_len);
    const ev = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = big, .nick = "n" };
    try testing.expectError(error.NameTooLong, encodedLen(ev));

    const big_user = "u" ** (max_username_len + 1);
    const ev2 = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .username = big_user };
    try testing.expectError(error.NameTooLong, encodedLen(ev2));

    const big_real = "r" ** (max_realname_len + 1);
    const ev3 = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .realname = big_real };
    try testing.expectError(error.NameTooLong, encodedLen(ev3));

    const big_host = "h" ** (max_host_len + 1);
    const ev4 = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .host = big_host };
    try testing.expectError(error.NameTooLong, encodedLen(ev4));
}

test "decode rejects an over-long identity length prefix" {
    // Build a valid event, then corrupt the username length to exceed the cap.
    const ev = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .username = "u" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var corrupt: [max_encoded_len]u8 = undefined;
    @memcpy(corrupt[0..wire.len], wire);
    // username length lives right after chan(2+2) + nick(2+1) past the fixed prefix.
    const user_len_off = 18 + 2 + 2 + 2 + 1;
    std.mem.writeInt(u16, corrupt[user_len_off..][0..2], max_username_len + 1, .little);
    try testing.expectError(error.NameTooLong, decode(corrupt[0..wire.len]));
}
