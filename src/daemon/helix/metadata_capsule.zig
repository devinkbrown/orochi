// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for one target's IRCv3 METADATA key/value pairs.
//!
//! Companion to `conn_capsule.zig`. Used by the Helix in-process upgrade
//! (UPGRADE command) to migrate the METADATA store for a single target — a
//! client (nick) or a channel — across the `execve` boundary. The codec is
//! pure and std-only: it never allocates. Decoded string slices borrow the
//! input buffer, so the caller must keep that buffer alive for as long as the
//! returned `MetadataCapsule` (and its `pairs`) is used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   target:     u16 len + bytes
//!   pair_count: u16
//!   for each pair:
//!     key:        u16 len + bytes
//!     value:      u16 len + bytes
//!     visibility: u8           (opaque flags byte, e.g. public/private)

const std = @import("std");

/// File magic identifying a metadata capsule record.
pub const magic = [_]u8{ 'H', 'M', 'D', 'T' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length. The full u16 range is usable here; there
/// is no null sentinel because keys, values, and the target are never null.
const max_str_len: usize = 0xFFFF;

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
    /// The encoded pair count exceeded the caller-provided output slice.
    TooMany,
};

/// A single METADATA key/value pair plus its opaque visibility flags byte.
pub const Pair = struct {
    key: []const u8,
    value: []const u8,
    visibility: u8,
};

/// Migratable METADATA store for one target (a nick or channel name).
pub const MetadataCapsule = struct {
    target: []const u8,
    pairs: []const Pair,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooLong` if `out` is too small, if any string exceeds the
    /// maximum encodable length (0xFFFF bytes), or if there are more than
    /// 0xFFFF pairs.
    pub fn encode(self: MetadataCapsule, out: []u8) Error![]const u8 {
        if (self.pairs.len > 0xFFFF) return error.TooLong;

        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // target string.
        try writeStr(out, &pos, self.target);

        // pair_count(u16 BE)
        try writeU16(out, &pos, @intCast(self.pairs.len));

        for (self.pairs) |pair| {
            try writeStr(out, &pos, pair.key);
            try writeStr(out, &pos, pair.value);
            try writeByte(out, &pos, pair.visibility);
        }

        return out[0..pos];
    }

    /// Parse a `MetadataCapsule` from `bytes`. Decoded pairs are written into
    /// `pairs_out`; the returned capsule's `pairs` field borrows that slice.
    /// All string slices borrow `bytes`, which must outlive the result.
    ///
    /// Returns `error.TooMany` if the encoded pair count exceeds
    /// `pairs_out.len`.
    pub fn decode(bytes: []const u8, pairs_out: []Pair) Error!MetadataCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const target = try readStr(bytes, &pos);

        const count = try readU16(bytes, &pos);
        if (count > pairs_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const key = try readStr(bytes, &pos);
            const value = try readStr(bytes, &pos);
            const visibility = try readByte(bytes, &pos);
            pairs_out[i] = .{ .key = key, .value = value, .visibility = visibility };
        }

        return .{
            .target = target,
            .pairs = pairs_out[0..count],
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

fn readStr(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16(bytes, pos);
    return readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip a channel target with three metadata pairs" {
    const pairs = [_]Pair{
        .{ .key = "url", .value = "https://example.org", .visibility = 0 },
        .{ .key = "topic-setter", .value = "Onyx", .visibility = 1 },
        .{ .key = "secret", .value = "", .visibility = 0xFF },
    };
    const original = MetadataCapsule{
        .target = "#channel",
        .pairs = &pairs,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out_pairs: [8]Pair = undefined;
    const decoded = try MetadataCapsule.decode(wire, &out_pairs);

    try std.testing.expectEqualStrings(original.target, decoded.target);
    try std.testing.expectEqual(@as(usize, 3), decoded.pairs.len);

    for (pairs, decoded.pairs) |want, got| {
        try std.testing.expectEqualStrings(want.key, got.key);
        try std.testing.expectEqualStrings(want.value, got.value);
        try std.testing.expectEqual(want.visibility, got.visibility);
    }

    // The empty value round-trips correctly.
    try std.testing.expectEqualStrings("", decoded.pairs[2].value);
    try std.testing.expectEqual(@as(u8, 0xFF), decoded.pairs[2].visibility);
}

test "round-trip with zero pairs" {
    const no_pairs = [_]Pair{};
    const original = MetadataCapsule{
        .target = "nick",
        .pairs = &no_pairs,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out_pairs: [4]Pair = undefined;
    const decoded = try MetadataCapsule.decode(wire, &out_pairs);

    try std.testing.expectEqualStrings("nick", decoded.target);
    try std.testing.expectEqual(@as(usize, 0), decoded.pairs.len);
}

test "decode returns Truncated on a cut buffer" {
    const pairs = [_]Pair{
        .{ .key = "k1", .value = "v1", .visibility = 0 },
        .{ .key = "k2", .value = "v2", .visibility = 1 },
    };
    const original = MetadataCapsule{ .target = "#c", .pairs = &pairs };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out_pairs: [8]Pair = undefined;

    // Cut just before the end so a read runs past the buffer.
    const cut = wire[0 .. wire.len - 1];
    try std.testing.expectError(error.Truncated, MetadataCapsule.decode(cut, &out_pairs));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, MetadataCapsule.decode(wire[0..0], &out_pairs));
}

test "decode returns BadMagic on corrupted magic" {
    const pairs = [_]Pair{.{ .key = "k", .value = "v", .visibility = 0 }};
    const original = MetadataCapsule{ .target = "#c", .pairs = &pairs };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out_pairs: [4]Pair = undefined;
    try std.testing.expectError(
        error.BadMagic,
        MetadataCapsule.decode(corrupted[0..wire.len], &out_pairs),
    );
}

test "decode returns BadVersion on a future version" {
    const pairs = [_]Pair{.{ .key = "k", .value = "v", .visibility = 0 }};
    const original = MetadataCapsule{ .target = "#c", .pairs = &pairs };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out_pairs: [4]Pair = undefined;
    try std.testing.expectError(
        error.BadVersion,
        MetadataCapsule.decode(bumped[0..wire.len], &out_pairs),
    );
}

test "decode returns TooMany when pairs_out is too small" {
    const pairs = [_]Pair{
        .{ .key = "k1", .value = "v1", .visibility = 0 },
        .{ .key = "k2", .value = "v2", .visibility = 0 },
        .{ .key = "k3", .value = "v3", .visibility = 0 },
    };
    const original = MetadataCapsule{ .target = "#c", .pairs = &pairs };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out_pairs: [2]Pair = undefined;
    try std.testing.expectError(error.TooMany, MetadataCapsule.decode(wire, &out_pairs));
}
