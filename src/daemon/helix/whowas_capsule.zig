// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for the WHOWAS history ring.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to migrate the ring
//! of recently-disconnected nick records across the `execve` boundary. The
//! codec is pure and std-only: it never allocates. Decoded string slices borrow
//! the input buffer, so the caller must keep that buffer alive for as long as
//! the returned `WhowasCapsule` (and the records it points at) is used.
//!
//! Records are ordered newest-first, matching the natural traversal order of
//! the WHOWAS ring.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1) record_count(u16)
//!   then `record_count` records, each:
//!     nick:       u16 len + bytes
//!     user:       u16 len + bytes
//!     host:       u16 len + bytes
//!     realname:   u16 len + bytes
//!     signoff_ms: i64

const std = @import("std");

/// File magic identifying a WHOWAS capsule record stream.
pub const magic = [_]u8{ 'H', 'W', 'W', 'S' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length (u16 length prefix).
const max_str_len: usize = 0xFFFF;

/// A single WHOWAS history entry: a snapshot of a client at signoff time.
pub const Record = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    realname: []const u8,
    signoff_ms: i64,
};

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read,
    /// or the output buffer was too small to hold the data.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// The encoded record count exceeded the caller-provided output slice.
    TooMany,
};

/// The migrated WHOWAS ring: an ordered (newest-first) slice of records.
pub const WhowasCapsule = struct {
    records: []const Record,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.Truncated` if `out` is too small to hold the data.
    pub fn encode(self: WhowasCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);
        // record_count(u16 BE)
        if (self.records.len > 0xFFFF) return error.TooMany;
        try writeU16(out, &pos, @intCast(self.records.len));

        for (self.records) |rec| {
            try writeStr(out, &pos, rec.nick);
            try writeStr(out, &pos, rec.user);
            try writeStr(out, &pos, rec.host);
            try writeStr(out, &pos, rec.realname);
            try writeI64(out, &pos, rec.signoff_ms);
        }

        return out[0..pos];
    }

    /// Parse a `WhowasCapsule` from `bytes`, writing decoded records into
    /// `records_out`. Returned string slices borrow `bytes`, which must
    /// outlive the result.
    ///
    /// Returns `error.TooMany` if the encoded count exceeds `records_out.len`.
    pub fn decode(bytes: []const u8, records_out: []Record) Error!WhowasCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const count = try readU16(bytes, &pos);
        if (count > records_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const nick = try readStr(bytes, &pos);
            const user = try readStr(bytes, &pos);
            const host = try readStr(bytes, &pos);
            const realname = try readStr(bytes, &pos);
            const signoff_ms = try readI64(bytes, &pos);
            records_out[i] = .{
                .nick = nick,
                .user = user,
                .host = host,
                .realname = realname,
                .signoff_ms = signoff_ms,
            };
        }

        return .{ .records = records_out[0..count] };
    }
};

// --- encode helpers ---------------------------------------------------------

fn writeBytes(out: []u8, pos: *usize, src: []const u8) Error!void {
    if (pos.* + src.len > out.len) return error.Truncated;
    @memcpy(out[pos.* .. pos.* + src.len], src);
    pos.* += src.len;
}

fn writeByte(out: []u8, pos: *usize, val: u8) Error!void {
    if (pos.* + 1 > out.len) return error.Truncated;
    out[pos.*] = val;
    pos.* += 1;
}

fn writeU16(out: []u8, pos: *usize, val: u16) Error!void {
    if (pos.* + 2 > out.len) return error.Truncated;
    std.mem.writeInt(u16, out[pos.*..][0..2], val, .big);
    pos.* += 2;
}

fn writeI64(out: []u8, pos: *usize, val: i64) Error!void {
    if (pos.* + 8 > out.len) return error.Truncated;
    std.mem.writeInt(i64, out[pos.*..][0..8], val, .big);
    pos.* += 8;
}

fn writeStr(out: []u8, pos: *usize, str: []const u8) Error!void {
    if (str.len > max_str_len) return error.Truncated;
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

fn readI64(bytes: []const u8, pos: *usize) Error!i64 {
    if (pos.* + 8 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(i64, bytes[pos.*..][0..8], .big);
    pos.* += 8;
    return val;
}

fn readStr(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16(bytes, pos);
    return readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip three records" {
    const records = [_]Record{
        .{
            .nick = "Orochi",
            .user = "ident",
            .host = "host.example.org",
            .realname = "Real Name Here",
            .signoff_ms = 1_700_000_000_123,
        },
        .{
            .nick = "guest42",
            .user = "u",
            .host = "10.0.0.1",
            .realname = "",
            .signoff_ms = -9_223_372_036_854,
        },
        .{
            .nick = "OldNick",
            .user = "legacy",
            .host = "cloaked.users.example",
            .realname = "An older session",
            .signoff_ms = 42,
        },
    };

    const original = WhowasCapsule{ .records = &records };

    var buf: [1024]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8]Record = undefined;
    const decoded = try WhowasCapsule.decode(wire, &out);

    try std.testing.expectEqual(@as(usize, 3), decoded.records.len);
    for (records, decoded.records) |exp, got| {
        try std.testing.expectEqualStrings(exp.nick, got.nick);
        try std.testing.expectEqualStrings(exp.user, got.user);
        try std.testing.expectEqualStrings(exp.host, got.host);
        try std.testing.expectEqualStrings(exp.realname, got.realname);
        try std.testing.expectEqual(exp.signoff_ms, got.signoff_ms);
    }
    // The empty-realname record round-trips as empty.
    try std.testing.expectEqualStrings("", decoded.records[1].realname);
}

test "round-trip zero records" {
    const original = WhowasCapsule{ .records = &[_]Record{} };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Record = undefined;
    const decoded = try WhowasCapsule.decode(wire, &out);

    try std.testing.expectEqual(@as(usize, 0), decoded.records.len);
}

test "decode returns Truncated on a cut buffer" {
    const records = [_]Record{
        .{ .nick = "abc", .user = "def", .host = "ghi", .realname = "jkl", .signoff_ms = 7 },
    };
    const original = WhowasCapsule{ .records = &records };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Record = undefined;

    // Cut just before the end so the trailing i64 read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, WhowasCapsule.decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, WhowasCapsule.decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const records = [_]Record{
        .{ .nick = "a", .user = "b", .host = "c", .realname = "d", .signoff_ms = 1 },
    };
    const original = WhowasCapsule{ .records = &records };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [4]Record = undefined;
    try std.testing.expectError(error.BadMagic, WhowasCapsule.decode(corrupted[0..wire.len], &out));
}

test "decode returns BadVersion on a future version" {
    const records = [_]Record{
        .{ .nick = "a", .user = "b", .host = "c", .realname = "d", .signoff_ms = 1 },
    };
    const original = WhowasCapsule{ .records = &records };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [4]Record = undefined;
    try std.testing.expectError(error.BadVersion, WhowasCapsule.decode(bumped[0..wire.len], &out));
}

test "decode returns TooMany when output slice is too small" {
    const records = [_]Record{
        .{ .nick = "n1", .user = "u1", .host = "h1", .realname = "r1", .signoff_ms = 1 },
        .{ .nick = "n2", .user = "u2", .host = "h2", .realname = "r2", .signoff_ms = 2 },
        .{ .nick = "n3", .user = "u3", .host = "h3", .realname = "r3", .signoff_ms = 3 },
    };
    const original = WhowasCapsule{ .records = &records };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [2]Record = undefined; // smaller than the 3 encoded records
    try std.testing.expectError(error.TooMany, WhowasCapsule.decode(wire, &out));
}
