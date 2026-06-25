// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for per-IP rate-limit / reputation / clone-count
//! state.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to migrate abuse
//! controls across a restart so that they do not reset. Without this, an
//! attacker could ride a restart to wipe accumulated penalty and clone counts
//! and then reconnect-storm the successor process. The codec is pure and
//! std-only: it never allocates. Decoded `ip` slices borrow the input buffer,
//! so the caller must keep that buffer alive for as long as the returned
//! `RateLimitCapsule` is used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1) entry_count(u32)
//!   per entry:
//!     ip:           u16 len + bytes   (raw address bytes, 4 or 16)
//!     reputation:   i32
//!     clone_count:  u32
//!     last_seen_ms: i64

const std = @import("std");

/// File magic identifying a rate-limit capsule record.
pub const magic = [_]u8{ 'H', 'R', 'L', 'M' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length (the u16 length prefix's full range).
const max_str_len: usize = 0xFFFF;

/// Per-IP rate-limit / reputation state for a single address.
pub const IpState = struct {
    /// Raw address bytes (4 for IPv4, 16 for IPv6).
    ip: []const u8,
    /// Accumulated reputation score (positive = penalty, negative = reward).
    reputation: i32,
    /// Number of concurrent clones tracked for this address.
    clone_count: u32,
    /// Timestamp this address was last seen, in milliseconds.
    last_seen_ms: i64,
};

/// A collection of per-IP states migrated across a Helix upgrade.
pub const RateLimitCapsule = struct {
    entries: []const IpState,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.Truncated` if `out` is too small. Returns
    /// `error.TooMany` if any `ip` field exceeds the maximum encodable length.
    pub fn encode(self: RateLimitCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        try writeBytes(out, &pos, &magic);
        try writeByte(out, &pos, version);
        try writeU32(out, &pos, @intCast(self.entries.len));

        for (self.entries) |entry| {
            try writeStr(out, &pos, entry.ip);
            try writeI32(out, &pos, entry.reputation);
            try writeU32(out, &pos, entry.clone_count);
            try writeI64(out, &pos, entry.last_seen_ms);
        }

        return out[0..pos];
    }

    /// Parse a `RateLimitCapsule` from `bytes`, writing each decoded entry into
    /// `entries_out`. Returned `ip` slices borrow `bytes`, which must outlive
    /// the result.
    ///
    /// Returns `error.TooMany` if the encoded entry count exceeds the capacity
    /// of `entries_out`.
    pub fn decode(bytes: []const u8, entries_out: []IpState) Error!RateLimitCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const entry_count = try readU32(bytes, &pos);
        if (entry_count > entries_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < entry_count) : (i += 1) {
            const ip = try readStr(bytes, &pos);
            const reputation = try readI32(bytes, &pos);
            const clone_count = try readU32(bytes, &pos);
            const last_seen_ms = try readI64(bytes, &pos);
            entries_out[i] = .{
                .ip = ip,
                .reputation = reputation,
                .clone_count = clone_count,
                .last_seen_ms = last_seen_ms,
            };
        }

        return .{ .entries = entries_out[0..entry_count] };
    }
};

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read, or the
    /// output buffer was too small to hold the record.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// The encoded entry count exceeded the supplied output capacity, or a
    /// field exceeded the maximum encodable length.
    TooMany,
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

fn writeU32(out: []u8, pos: *usize, val: u32) Error!void {
    if (pos.* + 4 > out.len) return error.Truncated;
    std.mem.writeInt(u32, out[pos.*..][0..4], val, .big);
    pos.* += 4;
}

fn writeI32(out: []u8, pos: *usize, val: i32) Error!void {
    if (pos.* + 4 > out.len) return error.Truncated;
    std.mem.writeInt(i32, out[pos.*..][0..4], val, .big);
    pos.* += 4;
}

fn writeI64(out: []u8, pos: *usize, val: i64) Error!void {
    if (pos.* + 8 > out.len) return error.Truncated;
    std.mem.writeInt(i64, out[pos.*..][0..8], val, .big);
    pos.* += 8;
}

fn writeStr(out: []u8, pos: *usize, str: []const u8) Error!void {
    if (str.len > max_str_len) return error.TooMany;
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

fn readI32(bytes: []const u8, pos: *usize) Error!i32 {
    if (pos.* + 4 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(i32, bytes[pos.*..][0..4], .big);
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

// --- tests ------------------------------------------------------------------

test "round-trip three entries with mixed IP widths" {
    const ipv4 = [_]u8{ 192, 0, 2, 1 };
    const ipv6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const ipv4b = [_]u8{ 203, 0, 113, 9 };

    const original = [_]IpState{
        .{ .ip = &ipv4, .reputation = 42, .clone_count = 3, .last_seen_ms = 1_000 },
        .{ .ip = &ipv6, .reputation = -17, .clone_count = 0, .last_seen_ms = 9_999_999 },
        .{ .ip = &ipv4b, .reputation = -1, .clone_count = 128, .last_seen_ms = -5 },
    };

    var buf: [512]u8 = undefined;
    const wire = try (RateLimitCapsule{ .entries = &original }).encode(&buf);

    var slots: [8]IpState = undefined;
    const decoded = try RateLimitCapsule.decode(wire, &slots);

    try std.testing.expectEqual(@as(usize, 3), decoded.entries.len);

    try std.testing.expectEqualSlices(u8, &ipv4, decoded.entries[0].ip);
    try std.testing.expectEqual(@as(i32, 42), decoded.entries[0].reputation);
    try std.testing.expectEqual(@as(u32, 3), decoded.entries[0].clone_count);
    try std.testing.expectEqual(@as(i64, 1_000), decoded.entries[0].last_seen_ms);

    try std.testing.expectEqualSlices(u8, &ipv6, decoded.entries[1].ip);
    try std.testing.expectEqual(@as(usize, 16), decoded.entries[1].ip.len);
    try std.testing.expectEqual(@as(i32, -17), decoded.entries[1].reputation);
    try std.testing.expectEqual(@as(u32, 0), decoded.entries[1].clone_count);
    try std.testing.expectEqual(@as(i64, 9_999_999), decoded.entries[1].last_seen_ms);

    try std.testing.expectEqualSlices(u8, &ipv4b, decoded.entries[2].ip);
    try std.testing.expectEqual(@as(i32, -1), decoded.entries[2].reputation);
    try std.testing.expectEqual(@as(u32, 128), decoded.entries[2].clone_count);
    try std.testing.expectEqual(@as(i64, -5), decoded.entries[2].last_seen_ms);
}

test "round-trip with zero entries" {
    const empty = [_]IpState{};

    var buf: [64]u8 = undefined;
    const wire = try (RateLimitCapsule{ .entries = &empty }).encode(&buf);

    var slots: [4]IpState = undefined;
    const decoded = try RateLimitCapsule.decode(wire, &slots);
    try std.testing.expectEqual(@as(usize, 0), decoded.entries.len);
}

test "decode returns Truncated on a cut buffer" {
    const ip = [_]u8{ 10, 0, 0, 1 };
    const original = [_]IpState{
        .{ .ip = &ip, .reputation = 5, .clone_count = 1, .last_seen_ms = 123 },
    };

    var buf: [128]u8 = undefined;
    const wire = try (RateLimitCapsule{ .entries = &original }).encode(&buf);

    var slots: [4]IpState = undefined;

    // Cut just before the end so a field read runs past the buffer.
    try std.testing.expectError(
        error.Truncated,
        RateLimitCapsule.decode(wire[0 .. wire.len - 2], &slots),
    );

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(
        error.Truncated,
        RateLimitCapsule.decode(wire[0..0], &slots),
    );
}

test "decode returns BadMagic on corrupted magic" {
    const ip = [_]u8{ 10, 0, 0, 1 };
    const original = [_]IpState{
        .{ .ip = &ip, .reputation = 0, .clone_count = 0, .last_seen_ms = 0 },
    };

    var buf: [128]u8 = undefined;
    const wire = try (RateLimitCapsule{ .entries = &original }).encode(&buf);

    var corrupted: [128]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF;

    var slots: [4]IpState = undefined;
    try std.testing.expectError(
        error.BadMagic,
        RateLimitCapsule.decode(corrupted[0..wire.len], &slots),
    );
}

test "decode returns BadVersion on a future version" {
    const ip = [_]u8{ 10, 0, 0, 1 };
    const original = [_]IpState{
        .{ .ip = &ip, .reputation = 0, .clone_count = 0, .last_seen_ms = 0 },
    };

    var buf: [128]u8 = undefined;
    const wire = try (RateLimitCapsule{ .entries = &original }).encode(&buf);

    var bumped: [128]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1;

    var slots: [4]IpState = undefined;
    try std.testing.expectError(
        error.BadVersion,
        RateLimitCapsule.decode(bumped[0..wire.len], &slots),
    );
}

test "decode returns TooMany when output capacity is exceeded" {
    const ip = [_]u8{ 10, 0, 0, 1 };
    const original = [_]IpState{
        .{ .ip = &ip, .reputation = 1, .clone_count = 1, .last_seen_ms = 1 },
        .{ .ip = &ip, .reputation = 2, .clone_count = 2, .last_seen_ms = 2 },
        .{ .ip = &ip, .reputation = 3, .clone_count = 3, .last_seen_ms = 3 },
    };

    var buf: [256]u8 = undefined;
    const wire = try (RateLimitCapsule{ .entries = &original }).encode(&buf);

    var slots: [2]IpState = undefined;
    try std.testing.expectError(
        error.TooMany,
        RateLimitCapsule.decode(wire, &slots),
    );
}
