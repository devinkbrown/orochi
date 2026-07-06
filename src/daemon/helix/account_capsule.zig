// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for a single registered account's stored record.
//!
//! Companion to `conn_capsule.zig` and `world_capsule.zig`: where those codecs
//! serialize per-connection and per-channel state, this one serializes ONE
//! registered account's durable record so the Helix in-process upgrade (UPGRADE
//! command) can carry the account store across `execve` into the successor
//! process. The codec is pure and std-only: it never allocates. Decoded slices
//! borrow the input buffer, which must outlive the returned `AccountCapsule`.
//!
//! The durable subset mirrors `services.zig`'s `AccountRecord` (account name,
//! PBKDF2-HMAC-SHA256 salt + hash, and an opaque flags word) plus transfer
//! metadata supplied by the caller: the PBKDF2 iteration count (which lives in
//! `Services.Config.pbkdf2_rounds`, not the record), a registration timestamp,
//! and an optional vhost. `pass_hash` and `salt` carry RAW bytes — the on-disk
//! record stores them hex-encoded, but the wire form is binary.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   account:   u16 len + bytes
//!   pass_hash: u16 len + bytes
//!   salt:      u16 len + bytes
//!   iterations(u32) registered_unix(i64) flags(u8)
//!   vhost:     u16 len + bytes   (len == 0xFFFF means null)
//!
//! `flags` is an opaque bitset supplied by the caller (e.g. verified). The
//! services-layer flags are u32; the durable bitset carried here is the u8
//! subset the upgrade path migrates.

const std = @import("std");

/// File magic identifying an account capsule record.
pub const magic = [_]u8{ 'H', 'A', 'C', 'P' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Sentinel length value indicating a null optional string.
const null_len: u16 = 0xFFFF;

/// Maximum encodable string length. 0xFFFF is reserved as the null sentinel.
const max_str_len: usize = 0xFFFE;

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

/// Durable, migratable state for a single registered account.
pub const AccountCapsule = struct {
    account: []const u8,
    pass_hash: []const u8,
    salt: []const u8,
    iterations: u32,
    registered_unix: i64,
    flags: u8,
    vhost: ?[]const u8,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooLong` if `out` is too small or any byte field exceeds
    /// the maximum encodable length (0xFFFE bytes).
    pub fn encode(self: AccountCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // Required length-prefixed byte fields.
        try writeStr(out, &pos, self.account);
        try writeStr(out, &pos, self.pass_hash);
        try writeStr(out, &pos, self.salt);

        // Fixed numeric fields.
        try writeU32(out, &pos, self.iterations);
        try writeI64(out, &pos, self.registered_unix);
        try writeByte(out, &pos, self.flags);

        // Optional vhost: 0xFFFF length means null.
        if (self.vhost) |v| {
            try writeStr(out, &pos, v);
        } else {
            try writeU16(out, &pos, null_len);
        }

        return out[0..pos];
    }

    /// Parse an `AccountCapsule` from `bytes`. Returned slices borrow `bytes`,
    /// which must outlive the result.
    pub fn decode(bytes: []const u8) Error!AccountCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const account = try readStr(bytes, &pos);
        const pass_hash = try readStr(bytes, &pos);
        const salt = try readStr(bytes, &pos);

        const iterations = try readU32(bytes, &pos);
        const registered_unix = try readI64(bytes, &pos);
        const flags = try readByte(bytes, &pos);

        const vhost = try readOptStr(bytes, &pos);

        return .{
            .account = account,
            .pass_hash = pass_hash,
            .salt = salt,
            .iterations = iterations,
            .registered_unix = registered_unix,
            .flags = flags,
            .vhost = vhost,
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

test "round-trip with non-null vhost and realistic hash/salt" {
    // Realistic 32-byte PBKDF2-HMAC-SHA256 hash and 16-byte salt.
    const hash = [_]u8{
        0x9b, 0x71, 0xd2, 0x24, 0xbd, 0x62, 0xf3, 0x78,
        0x5d, 0x96, 0xd4, 0x6a, 0xd3, 0xea, 0x3d, 0x73,
        0x31, 0x9b, 0xfb, 0xc2, 0x89, 0x0c, 0xaa, 0xda,
        0xe2, 0xdf, 0xf7, 0x25, 0x19, 0x67, 0x3c, 0xa7,
    };
    const salt = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    const original = AccountCapsule{
        .account = "Suimyaku",
        .pass_hash = &hash,
        .salt = &salt,
        .iterations = 100_000,
        .registered_unix = 1_700_000_000,
        .flags = 0b0000_0001, // e.g. verified
        .vhost = "deep.example.org",
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try AccountCapsule.decode(wire);

    try std.testing.expectEqualStrings(original.account, decoded.account);
    try std.testing.expectEqualSlices(u8, original.pass_hash, decoded.pass_hash);
    try std.testing.expectEqualSlices(u8, original.salt, decoded.salt);
    try std.testing.expectEqual(original.iterations, decoded.iterations);
    try std.testing.expectEqual(original.registered_unix, decoded.registered_unix);
    try std.testing.expectEqual(original.flags, decoded.flags);
    try std.testing.expect(decoded.vhost != null);
    try std.testing.expectEqualStrings(original.vhost.?, decoded.vhost.?);
}

test "round-trip with null vhost" {
    const hash = @as([32]u8, @splat(0xAB));
    const salt = @as([16]u8, @splat(0xCD));

    const original = AccountCapsule{
        .account = "guest-acct",
        .pass_hash = &hash,
        .salt = &salt,
        .iterations = 50_000,
        .registered_unix = 1_600_000_000,
        .flags = 0,
        .vhost = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try AccountCapsule.decode(wire);

    try std.testing.expectEqualStrings(original.account, decoded.account);
    try std.testing.expectEqualSlices(u8, original.pass_hash, decoded.pass_hash);
    try std.testing.expectEqualSlices(u8, original.salt, decoded.salt);
    try std.testing.expectEqual(original.iterations, decoded.iterations);
    try std.testing.expectEqual(original.registered_unix, decoded.registered_unix);
    try std.testing.expectEqual(@as(u8, 0), decoded.flags);
    try std.testing.expect(decoded.vhost == null);
}

test "decode returns Truncated on a cut buffer" {
    const original = AccountCapsule{
        .account = "acct",
        .pass_hash = "hashbytes",
        .salt = "saltbytes",
        .iterations = 1000,
        .registered_unix = 12345,
        .flags = 1,
        .vhost = "host.example.org",
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    // Cut just before the end so the vhost read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, AccountCapsule.decode(cut));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, AccountCapsule.decode(wire[0..0]));
}

test "decode returns BadMagic on corrupted magic" {
    const original = AccountCapsule{
        .account = "a",
        .pass_hash = "h",
        .salt = "s",
        .iterations = 1,
        .registered_unix = 0,
        .flags = 0,
        .vhost = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    try std.testing.expectError(error.BadMagic, AccountCapsule.decode(corrupted[0..wire.len]));
}

test "decode returns BadVersion on a future version" {
    const original = AccountCapsule{
        .account = "a",
        .pass_hash = "h",
        .salt = "s",
        .iterations = 1,
        .registered_unix = 0,
        .flags = 0,
        .vhost = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    try std.testing.expectError(error.BadVersion, AccountCapsule.decode(bumped[0..wire.len]));
}

test "encode returns TooLong when output buffer is too small" {
    const original = AccountCapsule{
        .account = "a-fairly-long-account-name",
        .pass_hash = "a-long-stand-in-for-raw-hash-bytes",
        .salt = "raw-salt-bytes-here",
        .iterations = 100_000,
        .registered_unix = 1_700_000_000,
        .flags = 1,
        .vhost = "vhost.example.org",
    };

    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.TooLong, original.encode(&tiny));
}
