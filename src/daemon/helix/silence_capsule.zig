//! Allocation-free wire codec for a single client's SILENCE list.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to migrate each
//! client's server-side ignore masks (the SILENCE command / RPL_SILELIST)
//! before `execve` and restore them in the successor process. The codec is
//! pure and std-only: it never allocates. Decoded mask slices borrow the input
//! buffer, so the caller must keep that buffer alive for as long as the
//! returned `SilenceCapsule` is used.
//!
//! Silence masks are stored per client as `nick!user@host` strings.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1) client_id(u64) mask_count(u16)
//!   each mask: u16 len + bytes
//!
//! Decode borrows into the caller-supplied `masks_out` buffer. If the record
//! holds more masks than `masks_out` can hold, decode returns `error.TooMany`.

const std = @import("std");

/// File magic identifying a silence capsule record.
pub const magic = [_]u8{ 'H', 'S', 'I', 'L' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable mask length.
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
    /// The record holds more masks than the caller-supplied buffer can hold.
    TooMany,
};

/// A client's resumable SILENCE list.
pub const SilenceCapsule = struct {
    client_id: u64,
    masks: []const []const u8,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.Truncated` if `out` is too small to hold the record.
    /// Returns `error.TooMany` if the mask count exceeds the wire limit.
    pub fn encode(self: SilenceCapsule, out: []u8) Error![]const u8 {
        if (self.masks.len > std.math.maxInt(u16)) return error.TooMany;

        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);
        // client_id(u64 BE)
        try writeU64(out, &pos, self.client_id);
        // mask_count(u16 BE)
        try writeU16(out, &pos, @intCast(self.masks.len));

        // each mask: u16 len + bytes
        for (self.masks) |mask| {
            try writeStr(out, &pos, mask);
        }

        return out[0..pos];
    }

    /// Parse a `SilenceCapsule` from `bytes`. Decoded mask slices borrow
    /// `bytes`, which must outlive the result, and are written into
    /// `masks_out`. Returns `error.TooMany` if the record holds more masks
    /// than `masks_out` can hold.
    pub fn decode(bytes: []const u8, masks_out: [][]const u8) Error!SilenceCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const client_id = try readU64(bytes, &pos);
        const mask_count = try readU16(bytes, &pos);
        if (mask_count > masks_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < mask_count) : (i += 1) {
            masks_out[i] = try readStr(bytes, &pos);
        }

        return .{
            .client_id = client_id,
            .masks = masks_out[0..mask_count],
        };
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

fn writeU64(out: []u8, pos: *usize, val: u64) Error!void {
    if (pos.* + 8 > out.len) return error.Truncated;
    std.mem.writeInt(u64, out[pos.*..][0..8], val, .big);
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

fn readU64(bytes: []const u8, pos: *usize) Error!u64 {
    if (pos.* + 8 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u64, bytes[pos.*..][0..8], .big);
    pos.* += 8;
    return val;
}

fn readStr(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16(bytes, pos);
    return readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip with three silence masks" {
    const masks = [_][]const u8{
        "spammer!*@*",
        "troll!~user@bad.example.org",
        "*!*@1.2.3.4",
    };
    const original = SilenceCapsule{
        .client_id = 0xDEAD_BEEF_CAFE_1234,
        .masks = &masks,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out_masks: [8][]const u8 = undefined;
    const decoded = try SilenceCapsule.decode(wire, &out_masks);

    try std.testing.expectEqual(original.client_id, decoded.client_id);
    try std.testing.expectEqual(@as(usize, 3), decoded.masks.len);
    try std.testing.expectEqualStrings(masks[0], decoded.masks[0]);
    try std.testing.expectEqualStrings(masks[1], decoded.masks[1]);
    try std.testing.expectEqualStrings(masks[2], decoded.masks[2]);
}

test "round-trip with zero masks" {
    const masks = [_][]const u8{};
    const original = SilenceCapsule{
        .client_id = 42,
        .masks = &masks,
    };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var out_masks: [4][]const u8 = undefined;
    const decoded = try SilenceCapsule.decode(wire, &out_masks);

    try std.testing.expectEqual(@as(u64, 42), decoded.client_id);
    try std.testing.expectEqual(@as(usize, 0), decoded.masks.len);
}

test "decode returns Truncated on a cut buffer" {
    const masks = [_][]const u8{ "a!b@c", "d!e@f" };
    const original = SilenceCapsule{
        .client_id = 1,
        .masks = &masks,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out_masks: [8][]const u8 = undefined;

    // Cut just before the end so a mask read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, SilenceCapsule.decode(cut, &out_masks));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, SilenceCapsule.decode(wire[0..0], &out_masks));
}

test "decode returns BadMagic on corrupted magic" {
    const masks = [_][]const u8{"x!y@z"};
    const original = SilenceCapsule{
        .client_id = 1,
        .masks = &masks,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out_masks: [8][]const u8 = undefined;
    try std.testing.expectError(error.BadMagic, SilenceCapsule.decode(corrupted[0..wire.len], &out_masks));
}

test "decode returns BadVersion on a future version" {
    const masks = [_][]const u8{"x!y@z"};
    const original = SilenceCapsule{
        .client_id = 1,
        .masks = &masks,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out_masks: [8][]const u8 = undefined;
    try std.testing.expectError(error.BadVersion, SilenceCapsule.decode(bumped[0..wire.len], &out_masks));
}

test "decode returns TooMany when masks_out is too small" {
    const masks = [_][]const u8{ "a!b@c", "d!e@f", "g!h@i" };
    const original = SilenceCapsule{
        .client_id = 1,
        .masks = &masks,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    // Only room for 2 masks, but the record holds 3.
    var out_masks: [2][]const u8 = undefined;
    try std.testing.expectError(error.TooMany, SilenceCapsule.decode(wire, &out_masks));
}
