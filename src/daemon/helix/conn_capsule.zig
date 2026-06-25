// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for a single IRC connection's resumable state.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to serialize each
//! client before `execve` and restore it in the successor process. The codec is
//! pure and std-only: it never allocates. Decoded string slices borrow the
//! input buffer, so the caller must keep that buffer alive for as long as the
//! returned `ConnCapsule` is used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1) fd_index(u32) caps(u128, 16 bytes) flags(1)
//!   nick:     u16 len + bytes
//!   user:     u16 len + bytes
//!   realname: u16 len + bytes
//!   host:     u16 len + bytes
//!   account:  u16 len + bytes   (len == 0xFFFF means null)
//!
//! `fd_index` is the index into the array of fds passed out-of-band via
//! SCM_RIGHTS, NOT the fd number itself.

const std = @import("std");

/// File magic identifying a connection capsule record.
pub const magic = [_]u8{ 'H', 'C', 'A', 'P' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Sentinel length value indicating a null optional string.
const null_len: u16 = 0xFFFF;

/// Maximum encodable string length. 0xFFFF is reserved as the null sentinel.
const max_str_len: usize = 0xFFFE;

/// Connection-level boolean state, packed into a single byte.
pub const Flags = packed struct(u8) {
    registered: bool = false,
    is_tls: bool = false,
    ircx: bool = false,
    _pad: u5 = 0,
};

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read,
    /// or the output buffer was too small to hold the record.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// A field exceeded the maximum encodable length, or the output buffer
    /// could not hold the record.
    TooLong,
};

/// Resumable state for a single IRC connection.
pub const ConnCapsule = struct {
    fd_index: u32,
    caps: u128,
    flags: Flags,
    nick: []const u8,
    user: []const u8,
    realname: []const u8,
    host: []const u8,
    account: ?[]const u8,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooLong` if `out` is too small or any string exceeds the
    /// maximum encodable length (0xFFFE bytes).
    pub fn encode(self: ConnCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);
        // fd_index(u32 BE)
        try writeU32(out, &pos, self.fd_index);
        // caps(u128 BE, 16 bytes)
        try writeU128(out, &pos, self.caps);
        // flags(1)
        try writeByte(out, &pos, @as(u8, @bitCast(self.flags)));

        // Required strings.
        try writeStr(out, &pos, self.nick);
        try writeStr(out, &pos, self.user);
        try writeStr(out, &pos, self.realname);
        try writeStr(out, &pos, self.host);

        // Optional account: 0xFFFF length means null.
        if (self.account) |acct| {
            try writeStr(out, &pos, acct);
        } else {
            try writeU16(out, &pos, null_len);
        }

        return out[0..pos];
    }

    /// Parse a `ConnCapsule` from `bytes`. Returned string slices borrow
    /// `bytes`, which must outlive the result.
    pub fn decode(bytes: []const u8) Error!ConnCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const fd_index = try readU32(bytes, &pos);
        const caps = try readU128(bytes, &pos);
        const flags: Flags = @bitCast(try readByte(bytes, &pos));

        const nick = try readStr(bytes, &pos);
        const user = try readStr(bytes, &pos);
        const realname = try readStr(bytes, &pos);
        const host = try readStr(bytes, &pos);

        const account = try readOptStr(bytes, &pos);

        return .{
            .fd_index = fd_index,
            .caps = caps,
            .flags = flags,
            .nick = nick,
            .user = user,
            .realname = realname,
            .host = host,
            .account = account,
        };
    }
};

// --- encode helpers ---------------------------------------------------------

fn writeBytes(out: []u8, pos: *usize, src: []const u8) Error!void {
    if (pos.* + src.len > out.len) return error.TooLong;
    @memcpy(out[pos.* .. pos.* + src.len], src);
    pos.* += src.len;
}

fn writeByte(out: []u8, pos: *usize, val: u8) Error!void {
    if (pos.* + 1 > out.len) return error.TooLong;
    out[pos.*] = val;
    pos.* += 1;
}

fn writeU16(out: []u8, pos: *usize, val: u16) Error!void {
    if (pos.* + 2 > out.len) return error.TooLong;
    std.mem.writeInt(u16, out[pos.*..][0..2], val, .big);
    pos.* += 2;
}

fn writeU32(out: []u8, pos: *usize, val: u32) Error!void {
    if (pos.* + 4 > out.len) return error.TooLong;
    std.mem.writeInt(u32, out[pos.*..][0..4], val, .big);
    pos.* += 4;
}

fn writeU128(out: []u8, pos: *usize, val: u128) Error!void {
    if (pos.* + 16 > out.len) return error.TooLong;
    std.mem.writeInt(u128, out[pos.*..][0..16], val, .big);
    pos.* += 16;
}

fn writeStr(out: []u8, pos: *usize, str: []const u8) Error!void {
    if (str.len > max_str_len) return error.TooLong;
    try writeU16(out, pos, @intCast(str.len));
    try writeBytes(out, pos, str);
}

// --- decode helpers ---------------------------------------------------------

fn readBytes(bytes: []const u8, pos: *usize, n: usize) Error![]const u8 {
    if (pos.* + n > bytes.len) return error.Truncated;
    const slice = bytes[pos.* .. pos.* + n];
    pos.* += n;
    return slice;
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    if (pos.* + 1 > bytes.len) return error.Truncated;
    const val = bytes[pos.*];
    pos.* += 1;
    return val;
}

fn readU16(bytes: []const u8, pos: *usize) Error!u16 {
    if (pos.* + 2 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u16, bytes[pos.*..][0..2], .big);
    pos.* += 2;
    return val;
}

fn readU32(bytes: []const u8, pos: *usize) Error!u32 {
    if (pos.* + 4 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u32, bytes[pos.*..][0..4], .big);
    pos.* += 4;
    return val;
}

fn readU128(bytes: []const u8, pos: *usize) Error!u128 {
    if (pos.* + 16 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u128, bytes[pos.*..][0..16], .big);
    pos.* += 16;
    return val;
}

fn readStr(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16(bytes, pos);
    return readBytes(bytes, pos, len);
}

fn readOptStr(bytes: []const u8, pos: *usize) Error!?[]const u8 {
    const len = try readU16(bytes, pos);
    if (len == null_len) return null;
    return try readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip with non-null account and high caps bits" {
    const original = ConnCapsule{
        .fd_index = 0xDEAD_BEEF,
        .caps = (@as(u128, 1) << 127) | (@as(u128, 1) << 64) | 0x1234,
        .flags = .{ .registered = true, .is_tls = true, .ircx = true },
        .nick = "Orochi",
        .user = "ident",
        .realname = "Real Name Here",
        .host = "host.example.org",
        .account = "registered-account",
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try ConnCapsule.decode(wire);

    try std.testing.expectEqual(original.fd_index, decoded.fd_index);
    try std.testing.expectEqual(original.caps, decoded.caps);
    try std.testing.expectEqual(
        @as(u8, @bitCast(original.flags)),
        @as(u8, @bitCast(decoded.flags)),
    );
    try std.testing.expect(decoded.flags.registered);
    try std.testing.expect(decoded.flags.is_tls);
    try std.testing.expect(decoded.flags.ircx);
    try std.testing.expectEqualStrings(original.nick, decoded.nick);
    try std.testing.expectEqualStrings(original.user, decoded.user);
    try std.testing.expectEqualStrings(original.realname, decoded.realname);
    try std.testing.expectEqualStrings(original.host, decoded.host);
    try std.testing.expect(decoded.account != null);
    try std.testing.expectEqualStrings(original.account.?, decoded.account.?);
}

test "round-trip with null account" {
    const original = ConnCapsule{
        .fd_index = 7,
        .caps = 0,
        .flags = .{},
        .nick = "guest",
        .user = "u",
        .realname = "",
        .host = "h",
        .account = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try ConnCapsule.decode(wire);

    try std.testing.expectEqual(original.fd_index, decoded.fd_index);
    try std.testing.expectEqual(original.caps, decoded.caps);
    try std.testing.expectEqual(@as(u8, 0), @as(u8, @bitCast(decoded.flags)));
    try std.testing.expectEqualStrings(original.nick, decoded.nick);
    try std.testing.expectEqualStrings("", decoded.realname);
    try std.testing.expect(decoded.account == null);
}

test "decode returns Truncated on a cut buffer" {
    const original = ConnCapsule{
        .fd_index = 1,
        .caps = 42,
        .flags = .{ .registered = true },
        .nick = "abc",
        .user = "def",
        .realname = "ghi",
        .host = "jkl",
        .account = "mno",
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    // Cut just before the end so a string read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, ConnCapsule.decode(cut));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, ConnCapsule.decode(wire[0..0]));
}

test "decode returns BadMagic on corrupted magic" {
    const original = ConnCapsule{
        .fd_index = 1,
        .caps = 0,
        .flags = .{},
        .nick = "a",
        .user = "b",
        .realname = "c",
        .host = "d",
        .account = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    try std.testing.expectError(error.BadMagic, ConnCapsule.decode(corrupted[0..wire.len]));
}

test "decode returns BadVersion on a future version" {
    const original = ConnCapsule{
        .fd_index = 1,
        .caps = 0,
        .flags = .{},
        .nick = "a",
        .user = "b",
        .realname = "c",
        .host = "d",
        .account = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    try std.testing.expectError(error.BadVersion, ConnCapsule.decode(bumped[0..wire.len]));
}

test "encode returns TooLong when output buffer is too small" {
    const original = ConnCapsule{
        .fd_index = 1,
        .caps = 0,
        .flags = .{},
        .nick = "this-is-a-fairly-long-nickname",
        .user = "user",
        .realname = "real name",
        .host = "host.example.org",
        .account = "account",
    };

    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.TooLong, original.encode(&tiny));
}
