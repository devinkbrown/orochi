//! Allocation-free wire codec for a single channel's resumable world state.
//!
//! Companion to `conn_capsule.zig`: where that codec serializes per-connection
//! state, this one serializes one CHANNEL's resumable state so the Helix
//! in-process upgrade (UPGRADE command) can recreate channels in the successor
//! process after `execve`. The codec is pure and std-only: it never allocates.
//! Decoded string slices borrow the input buffer, and the returned `members`
//! slice borrows a caller-supplied buffer; both must outlive the result.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   name:         u16 len + bytes
//!   topic:        u16 len + bytes   (len == 0 means none)
//!   topic_setter: u16 len + bytes   (len == 0 means none)
//!   topic_ts(i64) created_unix(i64) oid(u64) modes(u32)
//!   key:          u16 len + bytes   (len == 0xFFFF means null)
//!   limit(u32)                       (0 means none)
//!   member_count(u16)
//!   for each member: u16 nick-len + nick + u8 status
//!
//! `oid` is the channel's object id; `modes` is an opaque packed flags word
//! supplied by the caller; `status` is an opaque prefix/rank byte per member.

const std = @import("std");

/// File magic identifying a world (channel) capsule record.
pub const magic = [_]u8{ 'H', 'W', 'C', 'P' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Sentinel length value indicating a null optional string.
const null_len: u16 = 0xFFFF;

/// Maximum encodable string length. 0xFFFF is reserved as the null sentinel.
const max_str_len: usize = 0xFFFE;

/// A single channel member: a nick plus an opaque prefix/rank status byte.
pub const Member = struct {
    nick: []const u8,
    status: u8,
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
    /// A field exceeded the maximum encodable length, the output buffer could
    /// not hold the record, or the decoded member count exceeded the supplied
    /// `members_out` buffer.
    TooLong,
};

/// Resumable state for a single channel.
pub const WorldCapsule = struct {
    name: []const u8,
    topic: []const u8,
    topic_setter: []const u8,
    topic_ts: i64,
    created_unix: i64,
    oid: u64,
    modes: u32,
    key: ?[]const u8,
    limit: u32,
    members: []const Member,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooLong` if `out` is too small, any string exceeds the
    /// maximum encodable length (0xFFFE bytes), or there are more than 0xFFFF
    /// members.
    pub fn encode(self: WorldCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // name + topic + setter (empty topic/setter encode as length 0).
        try writeStr(out, &pos, self.name);
        try writeStr(out, &pos, self.topic);
        try writeStr(out, &pos, self.topic_setter);

        // Fixed numeric fields.
        try writeI64(out, &pos, self.topic_ts);
        try writeI64(out, &pos, self.created_unix);
        try writeU64(out, &pos, self.oid);
        try writeU32(out, &pos, self.modes);

        // Optional key: 0xFFFF length means null.
        if (self.key) |k| {
            try writeStr(out, &pos, k);
        } else {
            try writeU16(out, &pos, null_len);
        }

        // limit(u32 BE)
        try writeU32(out, &pos, self.limit);

        // Members: u16 count followed by each (u16 nick-len + nick + u8 status).
        if (self.members.len > 0xFFFF) return error.TooLong;
        try writeU16(out, &pos, @intCast(self.members.len));
        for (self.members) |m| {
            try writeStr(out, &pos, m.nick);
            try writeByte(out, &pos, m.status);
        }

        return out[0..pos];
    }

    /// Parse a `WorldCapsule` from `bytes`. Returned string slices borrow
    /// `bytes`, and the returned `members` slice borrows `members_out`; both
    /// must outlive the result.
    ///
    /// Returns `error.TooLong` if the decoded member count exceeds
    /// `members_out.len`.
    pub fn decode(bytes: []const u8, members_out: []Member) Error!WorldCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const name = try readStr(bytes, &pos);
        const topic = try readStr(bytes, &pos);
        const topic_setter = try readStr(bytes, &pos);

        const topic_ts = try readI64(bytes, &pos);
        const created_unix = try readI64(bytes, &pos);
        const oid = try readU64(bytes, &pos);
        const modes = try readU32(bytes, &pos);

        const key = try readOptStr(bytes, &pos);
        const limit = try readU32(bytes, &pos);

        const count = try readU16(bytes, &pos);
        if (count > members_out.len) return error.TooLong;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const nick = try readStr(bytes, &pos);
            const status = try readByte(bytes, &pos);
            members_out[i] = .{ .nick = nick, .status = status };
        }

        return .{
            .name = name,
            .topic = topic,
            .topic_setter = topic_setter,
            .topic_ts = topic_ts,
            .created_unix = created_unix,
            .oid = oid,
            .modes = modes,
            .key = key,
            .limit = limit,
            .members = members_out[0..count],
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

fn writeU64(out: []u8, pos: *usize, val: u64) Error!void {
    if (pos.* + 8 > out.len) return error.TooLong;
    std.mem.writeInt(u64, out[pos.*..][0..8], val, .big);
    pos.* += 8;
}

fn writeI64(out: []u8, pos: *usize, val: i64) Error!void {
    if (pos.* + 8 > out.len) return error.TooLong;
    std.mem.writeInt(i64, out[pos.*..][0..8], val, .big);
    pos.* += 8;
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

fn readU64(bytes: []const u8, pos: *usize) Error!u64 {
    if (pos.* + 8 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u64, bytes[pos.*..][0..8], .big);
    pos.* += 8;
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

fn readOptStr(bytes: []const u8, pos: *usize) Error!?[]const u8 {
    const len = try readU16(bytes, pos);
    if (len == null_len) return null;
    return try readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip with non-null key, members, and topic" {
    const members = [_]Member{
        .{ .nick = "founder", .status = 0x80 },
        .{ .nick = "op", .status = 0x40 },
        .{ .nick = "voiced", .status = 0x01 },
        .{ .nick = "regular", .status = 0x00 },
    };

    const original = WorldCapsule{
        .name = "#mizuchi",
        .topic = "Welcome to the deep",
        .topic_setter = "Suimyaku!user@host",
        .topic_ts = 1_700_000_000,
        .created_unix = 1_600_000_000,
        .oid = 0xDEAD_BEEF_CAFE_F00D,
        .modes = 0x1234_5678,
        .key = "s3cr3t",
        .limit = 256,
        .members = &members,
    };

    var buf: [1024]u8 = undefined;
    const wire = try original.encode(&buf);

    var members_out: [16]Member = undefined;
    const decoded = try WorldCapsule.decode(wire, &members_out);

    try std.testing.expectEqualStrings(original.name, decoded.name);
    try std.testing.expectEqualStrings(original.topic, decoded.topic);
    try std.testing.expectEqualStrings(original.topic_setter, decoded.topic_setter);
    try std.testing.expectEqual(original.topic_ts, decoded.topic_ts);
    try std.testing.expectEqual(original.created_unix, decoded.created_unix);
    try std.testing.expectEqual(original.oid, decoded.oid);
    try std.testing.expectEqual(original.modes, decoded.modes);
    try std.testing.expect(decoded.key != null);
    try std.testing.expectEqualStrings(original.key.?, decoded.key.?);
    try std.testing.expectEqual(original.limit, decoded.limit);

    try std.testing.expectEqual(members.len, decoded.members.len);
    for (members, decoded.members) |want, got| {
        try std.testing.expectEqualStrings(want.nick, got.nick);
        try std.testing.expectEqual(want.status, got.status);
    }
}

test "round-trip with null key and zero members" {
    const original = WorldCapsule{
        .name = "#empty",
        .topic = "",
        .topic_setter = "",
        .topic_ts = 0,
        .created_unix = 1_650_000_000,
        .oid = 1,
        .modes = 0,
        .key = null,
        .limit = 0,
        .members = &[_]Member{},
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var members_out: [4]Member = undefined;
    const decoded = try WorldCapsule.decode(wire, &members_out);

    try std.testing.expectEqualStrings(original.name, decoded.name);
    try std.testing.expectEqualStrings("", decoded.topic);
    try std.testing.expectEqualStrings("", decoded.topic_setter);
    try std.testing.expectEqual(original.topic_ts, decoded.topic_ts);
    try std.testing.expectEqual(original.created_unix, decoded.created_unix);
    try std.testing.expectEqual(original.oid, decoded.oid);
    try std.testing.expectEqual(@as(u32, 0), decoded.modes);
    try std.testing.expect(decoded.key == null);
    try std.testing.expectEqual(@as(u32, 0), decoded.limit);
    try std.testing.expectEqual(@as(usize, 0), decoded.members.len);
}

test "decode returns Truncated on a cut buffer" {
    const members = [_]Member{
        .{ .nick = "a", .status = 1 },
        .{ .nick = "b", .status = 2 },
    };
    const original = WorldCapsule{
        .name = "#cut",
        .topic = "topic",
        .topic_setter = "setter",
        .topic_ts = 99,
        .created_unix = 100,
        .oid = 7,
        .modes = 3,
        .key = "key",
        .limit = 10,
        .members = &members,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var members_out: [8]Member = undefined;

    // Cut just before the end so a member read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, WorldCapsule.decode(cut, &members_out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, WorldCapsule.decode(wire[0..0], &members_out));
}

test "decode returns BadMagic on corrupted magic" {
    const original = WorldCapsule{
        .name = "#m",
        .topic = "",
        .topic_setter = "",
        .topic_ts = 0,
        .created_unix = 0,
        .oid = 0,
        .modes = 0,
        .key = null,
        .limit = 0,
        .members = &[_]Member{},
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var members_out: [4]Member = undefined;
    try std.testing.expectError(error.BadMagic, WorldCapsule.decode(corrupted[0..wire.len], &members_out));
}

test "decode returns BadVersion on a future version" {
    const original = WorldCapsule{
        .name = "#m",
        .topic = "",
        .topic_setter = "",
        .topic_ts = 0,
        .created_unix = 0,
        .oid = 0,
        .modes = 0,
        .key = null,
        .limit = 0,
        .members = &[_]Member{},
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var members_out: [4]Member = undefined;
    try std.testing.expectError(error.BadVersion, WorldCapsule.decode(bumped[0..wire.len], &members_out));
}

test "decode returns TooLong when members_out is too small" {
    const members = [_]Member{
        .{ .nick = "one", .status = 1 },
        .{ .nick = "two", .status = 2 },
        .{ .nick = "three", .status = 3 },
    };
    const original = WorldCapsule{
        .name = "#crowd",
        .topic = "",
        .topic_setter = "",
        .topic_ts = 0,
        .created_unix = 0,
        .oid = 0,
        .modes = 0,
        .key = null,
        .limit = 0,
        .members = &members,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    // Buffer can hold only 2 of the 3 encoded members.
    var members_out: [2]Member = undefined;
    try std.testing.expectError(error.TooLong, WorldCapsule.decode(wire, &members_out));
}

test "encode returns TooLong when output buffer is too small" {
    const original = WorldCapsule{
        .name = "#a-fairly-long-channel-name-here",
        .topic = "a topic that takes up some space",
        .topic_setter = "setter!ident@host.example.org",
        .topic_ts = 1,
        .created_unix = 2,
        .oid = 3,
        .modes = 4,
        .key = "key",
        .limit = 5,
        .members = &[_]Member{},
    };

    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.TooLong, original.encode(&tiny));
}
