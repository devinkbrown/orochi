//! NICKCHANGE frame payload codec (S2S nick-change propagation).
//!
//! Carries one nick change for a remote user: the old and new nick plus the
//! user's real identity (username/realname/visible-host), so the receiving node
//! can rename the user in its route table + channel rosters and surface a live
//! `:old!user@host NICK new` line to local members of shared channels. `hlc`
//! orders concurrent renames. Decode borrows the input and allocates nothing.
const std = @import("std");

pub const max_nick_len = 64;
pub const max_user_len = 32;
pub const max_real_len = 256;
pub const max_host_len = 255;
const fixed_prefix = 8 + 8; // origin_node, hlc

pub const Error = error{
    Truncated,
    FieldTooLong,
    TrailingBytes,
};

pub const NickEvent = struct {
    origin_node: u64,
    hlc: u64,
    old_nick: []const u8,
    new_nick: []const u8,
    username: []const u8,
    realname: []const u8,
    host: []const u8,
};

pub fn encodedLen(ev: NickEvent) Error!usize {
    if (ev.old_nick.len > max_nick_len or ev.new_nick.len > max_nick_len or
        ev.username.len > max_user_len or ev.realname.len > max_real_len or
        ev.host.len > max_host_len)
    {
        return error.FieldTooLong;
    }
    return fixed_prefix + 2 + ev.old_nick.len + 2 + ev.new_nick.len +
        2 + ev.username.len + 2 + ev.realname.len + 2 + ev.host.len;
}

fn putBytes16(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

pub fn encode(ev: NickEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;

    var i: usize = 0;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    putBytes16(out, &i, ev.old_nick);
    putBytes16(out, &i, ev.new_nick);
    putBytes16(out, &i, ev.username);
    putBytes16(out, &i, ev.realname);
    putBytes16(out, &i, ev.host);
    return out[0..i];
}

fn takeBytes16(bytes: []const u8, i: *usize, max: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max) return error.FieldTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const out = bytes[i.* .. i.* + len];
    i.* += len;
    return out;
}

pub fn decode(bytes: []const u8) Error!NickEvent {
    if (bytes.len < fixed_prefix) return error.Truncated;

    var i: usize = 0;
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;

    const old_nick = try takeBytes16(bytes, &i, max_nick_len);
    const new_nick = try takeBytes16(bytes, &i, max_nick_len);
    const username = try takeBytes16(bytes, &i, max_user_len);
    const realname = try takeBytes16(bytes, &i, max_real_len);
    const host = try takeBytes16(bytes, &i, max_host_len);

    if (i != bytes.len) return error.TrailingBytes;
    return .{
        .origin_node = origin_node,
        .hlc = hlc,
        .old_nick = old_nick,
        .new_nick = new_nick,
        .username = username,
        .realname = realname,
        .host = host,
    };
}

const testing = std.testing;

test "nick event round-trips with identity" {
    const ev = NickEvent{
        .origin_node = 42,
        .hlc = 99,
        .old_nick = "Guest8192",
        .new_nick = "kain",
        .username = "kain",
        .realname = "Devin",
        .host = "cloak-abc.users.test",
    };
    var buf: [1024]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(@as(u64, 42), got.origin_node);
    try testing.expectEqual(@as(u64, 99), got.hlc);
    try testing.expectEqualStrings("Guest8192", got.old_nick);
    try testing.expectEqualStrings("kain", got.new_nick);
    try testing.expectEqualStrings("kain", got.username);
    try testing.expectEqualStrings("Devin", got.realname);
    try testing.expectEqualStrings("cloak-abc.users.test", got.host);
}

test "nick event round-trips with empty identity" {
    const ev = NickEvent{
        .origin_node = 1,
        .hlc = 2,
        .old_nick = "a",
        .new_nick = "b",
        .username = "",
        .realname = "",
        .host = "",
    };
    var buf: [256]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expectEqualStrings("a", got.old_nick);
    try testing.expectEqualStrings("b", got.new_nick);
    try testing.expectEqualStrings("", got.host);
}

test "nick event rejects malformed input" {
    const ev = NickEvent{ .origin_node = 1, .hlc = 2, .old_nick = "old", .new_nick = "new", .username = "u", .realname = "r", .host = "h" };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));

    var padded: [257]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xaa;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "nick event enforces bounds" {
    const big = "x" ** (max_nick_len + 1);
    const ev = NickEvent{ .origin_node = 1, .hlc = 1, .old_nick = big, .new_nick = "b", .username = "", .realname = "", .host = "" };
    try testing.expectError(error.FieldTooLong, encodedLen(ev));
}
