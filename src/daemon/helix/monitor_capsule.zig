//! Allocation-free wire codec for a single client's IRCv3 MONITOR watch list.
//!
//! Companion to `conn_capsule.zig`. Used by the Helix in-process upgrade
//! (UPGRADE command) to serialize each client's monitored-nick set before
//! `execve` and restore it in the successor process, so contact-notification
//! state survives an in-place upgrade. The codec is pure and std-only: it never
//! allocates. Decoded target slices borrow the input buffer, so the caller must
//! keep that buffer alive for as long as the returned `MonitorCapsule` is used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1) client_id(u64) target_count(u16)
//!   each target: u16 len + bytes
//!
//! `client_id` ties the watch list back to a connection (the same id space as
//! `MonitorStore.ClientId`); `targets` are the monitored nicks.

const std = @import("std");

/// File magic identifying a monitor capsule record.
pub const magic = [_]u8{ 'H', 'M', 'O', 'N' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length and target count.
const max_str_len: usize = 0xFFFF;
const max_count: usize = 0xFFFF;

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read,
    /// or the output buffer was too small to hold the record.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// More targets than the caller-provided output slice (decode) or than the
    /// wire format can represent (encode) could hold.
    TooMany,
};

/// A single client's resumable MONITOR watch list.
pub const MonitorCapsule = struct {
    client_id: u64,
    targets: []const []const u8,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooMany` if the target list or any single target exceeds
    /// what the wire format can represent, or `error.Truncated` if `out` is too
    /// small to hold the record.
    pub fn encode(self: MonitorCapsule, out: []u8) Error![]const u8 {
        if (self.targets.len > max_count) return error.TooMany;

        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);
        // client_id(u64 BE)
        try writeU64(out, &pos, self.client_id);
        // target_count(u16 BE)
        try writeU16(out, &pos, @intCast(self.targets.len));

        // Each target: u16 len + bytes.
        for (self.targets) |target| {
            try writeStr(out, &pos, target);
        }

        return out[0..pos];
    }

    /// Parse a `MonitorCapsule` from `bytes`, filling `targets_out` with
    /// borrowing slices into `bytes`. `bytes` must outlive the result.
    ///
    /// Returns `error.TooMany` if the encoded target count exceeds
    /// `targets_out.len`.
    pub fn decode(bytes: []const u8, targets_out: [][]const u8) Error!MonitorCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const client_id = try readU64(bytes, &pos);
        const count = try readU16(bytes, &pos);
        if (count > targets_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < count) : (i += 1) {
            targets_out[i] = try readStr(bytes, &pos);
        }

        return .{
            .client_id = client_id,
            .targets = targets_out[0..count],
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

test "round-trip a client_id with three monitored nicks" {
    const targets = [_][]const u8{ "Alice", "Bob", "Charlie" };
    const original = MonitorCapsule{
        .client_id = 0xDEAD_BEEF_CAFE_F00D,
        .targets = &targets,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8][]const u8 = undefined;
    const decoded = try MonitorCapsule.decode(wire, &out);

    try std.testing.expectEqual(original.client_id, decoded.client_id);
    try std.testing.expectEqual(@as(usize, 3), decoded.targets.len);
    try std.testing.expectEqualStrings("Alice", decoded.targets[0]);
    try std.testing.expectEqualStrings("Bob", decoded.targets[1]);
    try std.testing.expectEqualStrings("Charlie", decoded.targets[2]);
}

test "round-trip with zero targets" {
    const original = MonitorCapsule{
        .client_id = 7,
        .targets = &[_][]const u8{},
    };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4][]const u8 = undefined;
    const decoded = try MonitorCapsule.decode(wire, &out);

    try std.testing.expectEqual(@as(u64, 7), decoded.client_id);
    try std.testing.expectEqual(@as(usize, 0), decoded.targets.len);
}

test "decode returns Truncated on a cut buffer" {
    const targets = [_][]const u8{ "abc", "def" };
    const original = MonitorCapsule{ .client_id = 1, .targets = &targets };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8][]const u8 = undefined;

    // Cut just before the end so a target read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, MonitorCapsule.decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, MonitorCapsule.decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const targets = [_][]const u8{"a"};
    const original = MonitorCapsule{ .client_id = 1, .targets = &targets };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [8][]const u8 = undefined;
    try std.testing.expectError(error.BadMagic, MonitorCapsule.decode(corrupted[0..wire.len], &out));
}

test "decode returns BadVersion on a future version" {
    const targets = [_][]const u8{"a"};
    const original = MonitorCapsule{ .client_id = 1, .targets = &targets };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [8][]const u8 = undefined;
    try std.testing.expectError(error.BadVersion, MonitorCapsule.decode(bumped[0..wire.len], &out));
}

test "decode returns TooMany when targets_out is too small" {
    const targets = [_][]const u8{ "one", "two", "three" };
    const original = MonitorCapsule{ .client_id = 99, .targets = &targets };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [2][]const u8 = undefined; // smaller than the 3 encoded targets
    try std.testing.expectError(error.TooMany, MonitorCapsule.decode(wire, &out));
}
