//! Allocation-free wire codec for one account's IRCv3 read-marker state.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to migrate
//! draft/read-marker state (`draft/read-marker`: per-account, per-target
//! last-read position) across the binary swap, so a reattaching client's read
//! position survives the upgrade. The codec is pure and std-only: it never
//! allocates. Decoded string slices borrow the input buffer, so the caller
//! must keep that buffer alive for as long as the returned
//! `ReadMarkerCapsule` is used.
//!
//! Conceptually this mirrors `proto/read_marker_store.zig`, which keys markers
//! by `owner` (the account) plus `target` (a channel or nick), with the stored
//! value being a `Timestamp`. This capsule groups one owner's markers into a
//! single record and additionally carries an optional `msgid` so a marker may
//! be timestamp-only or carry a message id.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   account:      u16 len + bytes
//!   marker_count: u16
//!   repeated marker_count times:
//!     target:       u16 len + bytes
//!     timestamp_ms: i64
//!     msgid:        u16 len + bytes   (len == 0 means timestamp-only)

const std = @import("std");

/// File magic identifying a read-marker capsule record.
pub const magic = [_]u8{ 'H', 'R', 'D', 'M' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length and marker count. Both fields are u16.
const max_str_len: usize = 0xFFFF;
const max_marker_count: usize = 0xFFFF;

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read,
    /// or the output buffer was too small to hold the record.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// A field exceeded the maximum encodable length, the marker count
    /// exceeded the encodable maximum, or the output buffer could not hold
    /// the record.
    TooLong,
    /// The decode output slice could not hold every marker in the record.
    TooMany,
};

/// One read-marker entry for a single target.
///
/// `target` is a channel or nick. `timestamp_ms` is the last-read time in
/// milliseconds since the Unix epoch. `msgid` is empty when the marker is
/// timestamp-only.
pub const Marker = struct {
    target: []const u8,
    timestamp_ms: i64,
    msgid: []const u8,
};

/// Resumable read-marker state for a single account.
pub const ReadMarkerCapsule = struct {
    account: []const u8,
    markers: []const Marker,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooLong` if `out` is too small, any string exceeds the
    /// maximum encodable length (0xFFFF bytes), or the marker count exceeds
    /// the encodable maximum (0xFFFF).
    pub fn encode(self: ReadMarkerCapsule, out: []u8) Error![]const u8 {
        if (self.markers.len > max_marker_count) return error.TooLong;

        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // account(u16 len + bytes)
        try writeStr(out, &pos, self.account);

        // marker_count(u16 BE)
        try writeU16(out, &pos, @intCast(self.markers.len));

        for (self.markers) |marker| {
            try writeStr(out, &pos, marker.target);
            try writeI64(out, &pos, marker.timestamp_ms);
            try writeStr(out, &pos, marker.msgid);
        }

        return out[0..pos];
    }

    /// Parse a `ReadMarkerCapsule` from `bytes`, writing the decoded markers
    /// into `markers_out`. Returned string slices borrow `bytes`, which must
    /// outlive the result.
    ///
    /// Returns `error.TooMany` if the record holds more markers than
    /// `markers_out` can hold.
    pub fn decode(bytes: []const u8, markers_out: []Marker) Error!ReadMarkerCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const account = try readStr(bytes, &pos);

        const marker_count = try readU16(bytes, &pos);
        if (marker_count > markers_out.len) return error.TooMany;

        var index: usize = 0;
        while (index < marker_count) : (index += 1) {
            const target = try readStr(bytes, &pos);
            const timestamp_ms = try readI64(bytes, &pos);
            const msgid = try readStr(bytes, &pos);
            markers_out[index] = .{
                .target = target,
                .timestamp_ms = timestamp_ms,
                .msgid = msgid,
            };
        }

        return .{
            .account = account,
            .markers = markers_out[0..marker_count],
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

test "round-trip account with three markers" {
    const markers = [_]Marker{
        .{ .target = "#mizuchi", .timestamp_ms = 1_717_000_000_000, .msgid = "" },
        .{ .target = "#helix", .timestamp_ms = 1_717_000_500_123, .msgid = "abc123def456" },
        .{ .target = "Suzuki", .timestamp_ms = 1_717_001_000_999, .msgid = "" },
    };
    const original = ReadMarkerCapsule{
        .account = "registered-account",
        .markers = &markers,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8]Marker = undefined;
    const decoded = try ReadMarkerCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings(original.account, decoded.account);
    try std.testing.expectEqual(@as(usize, 3), decoded.markers.len);

    try std.testing.expectEqualStrings("#mizuchi", decoded.markers[0].target);
    try std.testing.expectEqual(@as(i64, 1_717_000_000_000), decoded.markers[0].timestamp_ms);
    try std.testing.expectEqualStrings("", decoded.markers[0].msgid);

    try std.testing.expectEqualStrings("#helix", decoded.markers[1].target);
    try std.testing.expectEqual(@as(i64, 1_717_000_500_123), decoded.markers[1].timestamp_ms);
    try std.testing.expectEqualStrings("abc123def456", decoded.markers[1].msgid);

    try std.testing.expectEqualStrings("Suzuki", decoded.markers[2].target);
    try std.testing.expectEqual(@as(i64, 1_717_001_000_999), decoded.markers[2].timestamp_ms);
    try std.testing.expectEqualStrings("", decoded.markers[2].msgid);
}

test "round-trip with zero markers" {
    const original = ReadMarkerCapsule{
        .account = "lonely-account",
        .markers = &.{},
    };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Marker = undefined;
    const decoded = try ReadMarkerCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings(original.account, decoded.account);
    try std.testing.expectEqual(@as(usize, 0), decoded.markers.len);
}

test "decode returns Truncated on a cut buffer" {
    const markers = [_]Marker{
        .{ .target = "#chan", .timestamp_ms = 42, .msgid = "id" },
    };
    const original = ReadMarkerCapsule{
        .account = "acct",
        .markers = &markers,
    };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Marker = undefined;

    // Cut just before the end so a string read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, ReadMarkerCapsule.decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, ReadMarkerCapsule.decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const original = ReadMarkerCapsule{
        .account = "acct",
        .markers = &.{},
    };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [128]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [4]Marker = undefined;
    try std.testing.expectError(error.BadMagic, ReadMarkerCapsule.decode(corrupted[0..wire.len], &out));
}

test "decode returns BadVersion on a future version" {
    const original = ReadMarkerCapsule{
        .account = "acct",
        .markers = &.{},
    };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [128]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [4]Marker = undefined;
    try std.testing.expectError(error.BadVersion, ReadMarkerCapsule.decode(bumped[0..wire.len], &out));
}

test "decode returns TooMany when markers_out is too small" {
    const markers = [_]Marker{
        .{ .target = "#a", .timestamp_ms = 1, .msgid = "" },
        .{ .target = "#b", .timestamp_ms = 2, .msgid = "" },
        .{ .target = "#c", .timestamp_ms = 3, .msgid = "" },
    };
    const original = ReadMarkerCapsule{
        .account = "acct",
        .markers = &markers,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [2]Marker = undefined; // too small for three markers
    try std.testing.expectError(error.TooMany, ReadMarkerCapsule.decode(wire, &out));
}
