//! Allocation-free wire codec for a client's AWAY status across a Helix upgrade.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to migrate each
//! account/session's away state so a reattaching or migrated client keeps its
//! away message. The codec is pure and std-only: it never allocates. The
//! decoded message slice borrows the input buffer, so the caller must keep that
//! buffer alive for as long as the returned `AwayCapsule` is used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1) client_id(u64) since_ms(i64)
//!   message: u16 len + bytes   (len == 0xFFFF means null / not away)

const std = @import("std");

/// File magic identifying an away capsule record.
pub const magic = [_]u8{ 'H', 'A', 'W', 'Y' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Sentinel length value indicating a null optional string (not away).
const null_len: u16 = 0xFFFF;

/// Maximum encodable string length. 0xFFFF is reserved as the null sentinel.
const max_str_len: usize = 0xFFFE;

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// A field exceeded the maximum encodable length, or the output buffer
    /// could not hold the record.
    TooLong,
};

/// Resumable AWAY state for a single account/session.
pub const AwayCapsule = struct {
    client_id: u64,
    since_ms: i64,
    /// The away message, or null when the client is not away.
    message: ?[]const u8,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooLong` if `out` is too small or the message exceeds the
    /// maximum encodable length (0xFFFE bytes).
    pub fn encode(self: AwayCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);
        // client_id(u64 BE)
        try writeU64(out, &pos, self.client_id);
        // since_ms(i64 BE)
        try writeI64(out, &pos, self.since_ms);

        // Optional message: 0xFFFF length means null (not away).
        if (self.message) |msg| {
            try writeStr(out, &pos, msg);
        } else {
            try writeU16(out, &pos, null_len);
        }

        return out[0..pos];
    }

    /// Parse an `AwayCapsule` from `bytes`. The returned message slice borrows
    /// `bytes`, which must outlive the result.
    pub fn decode(bytes: []const u8) Error!AwayCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const client_id = try readU64(bytes, &pos);
        const since_ms = try readI64(bytes, &pos);

        const message = try readOptStr(bytes, &pos);

        return .{
            .client_id = client_id,
            .since_ms = since_ms,
            .message = message,
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

fn readOptStr(bytes: []const u8, pos: *usize) Error!?[]const u8 {
    const len = try readU16(bytes, pos);
    if (len == null_len) return null;
    return try readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip with non-null away message" {
    const original = AwayCapsule{
        .client_id = 0xDEAD_BEEF_CAFE_1234,
        .since_ms = 1_717_000_000_123,
        .message = "gone fishing, back later",
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try AwayCapsule.decode(wire);

    try std.testing.expectEqual(original.client_id, decoded.client_id);
    try std.testing.expectEqual(original.since_ms, decoded.since_ms);
    try std.testing.expect(decoded.message != null);
    try std.testing.expectEqualStrings(original.message.?, decoded.message.?);
}

test "round-trip with null message (not away)" {
    const original = AwayCapsule{
        .client_id = 7,
        .since_ms = 0,
        .message = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try AwayCapsule.decode(wire);

    try std.testing.expectEqual(original.client_id, decoded.client_id);
    try std.testing.expectEqual(original.since_ms, decoded.since_ms);
    try std.testing.expect(decoded.message == null);
}

test "round-trip with negative since_ms and empty message" {
    const original = AwayCapsule{
        .client_id = 0,
        .since_ms = -1_234_567,
        .message = "",
    };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try AwayCapsule.decode(wire);

    try std.testing.expectEqual(original.since_ms, decoded.since_ms);
    try std.testing.expect(decoded.message != null);
    try std.testing.expectEqualStrings("", decoded.message.?);
}

test "decode returns Truncated on a cut buffer" {
    const original = AwayCapsule{
        .client_id = 1,
        .since_ms = 42,
        .message = "afk",
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    // Cut just before the end so the message read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, AwayCapsule.decode(cut));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, AwayCapsule.decode(wire[0..0]));
}

test "decode returns BadMagic on corrupted magic" {
    const original = AwayCapsule{
        .client_id = 1,
        .since_ms = 0,
        .message = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    try std.testing.expectError(error.BadMagic, AwayCapsule.decode(corrupted[0..wire.len]));
}

test "decode returns BadVersion on a future version" {
    const original = AwayCapsule{
        .client_id = 1,
        .since_ms = 0,
        .message = null,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    try std.testing.expectError(error.BadVersion, AwayCapsule.decode(bumped[0..wire.len]));
}

test "encode returns TooLong when output buffer is too small" {
    const original = AwayCapsule{
        .client_id = 1,
        .since_ms = 0,
        .message = "this-message-will-not-fit-in-a-tiny-buffer",
    };

    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.TooLong, original.encode(&tiny));
}
