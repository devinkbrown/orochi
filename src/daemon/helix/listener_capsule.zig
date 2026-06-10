//! Allocation-free wire codec for the global Helix upgrade server header.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to serialize the
//! singleton, process-wide resume state the successor process needs before it
//! rebuilds any connections: node id, config epoch, config file path, server
//! start time, and the fd indices of the inherited listener sockets (the IRC
//! listener, the S2S listener, and the media UDP socket) within the array of
//! fds passed out-of-band via SCM_RIGHTS.
//!
//! The codec is pure and std-only: it never allocates. The decoded
//! `config_path` slice borrows the input buffer, so the caller must keep that
//! buffer alive for as long as the returned `ListenerCapsule` is used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   node_id(u64) epoch(u64) started_unix(i64)
//!   irc_listener_fd_index(i32) s2s_listener_fd_index(i32) media_fd_index(i32)
//!   config_path: u16 len + bytes   (len == 0xFFFF means null)
//!
//! Each fd index is the index into the array of fds passed out-of-band via
//! SCM_RIGHTS, NOT the fd number itself. A value of -1 means "no such
//! listener".

const std = @import("std");

/// File magic identifying a listener (global server header) capsule record.
pub const magic = [_]u8{ 'H', 'L', 'S', 'N' };

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

/// Process-wide resume state carried across a Helix upgrade.
pub const ListenerCapsule = struct {
    node_id: u64,
    epoch: u64,
    started_unix: i64,
    config_path: ?[]const u8,
    /// Index of the inherited IRC listener fd, or -1 if none.
    irc_listener_fd_index: i32,
    /// Index of the inherited S2S listener fd, or -1 if none.
    s2s_listener_fd_index: i32,
    /// Index of the inherited media UDP socket fd, or -1 if none.
    media_fd_index: i32,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooLong` if `out` is too small or `config_path` exceeds
    /// the maximum encodable length (0xFFFE bytes).
    pub fn encode(self: ListenerCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);
        // node_id(u64 BE)
        try writeU64(out, &pos, self.node_id);
        // epoch(u64 BE)
        try writeU64(out, &pos, self.epoch);
        // started_unix(i64 BE)
        try writeI64(out, &pos, self.started_unix);
        // fd indices (i32 BE each)
        try writeI32(out, &pos, self.irc_listener_fd_index);
        try writeI32(out, &pos, self.s2s_listener_fd_index);
        try writeI32(out, &pos, self.media_fd_index);

        // Optional config_path: 0xFFFF length means null.
        if (self.config_path) |path| {
            try writeStr(out, &pos, path);
        } else {
            try writeU16(out, &pos, null_len);
        }

        return out[0..pos];
    }

    /// Parse a `ListenerCapsule` from `bytes`. The returned `config_path`
    /// slice borrows `bytes`, which must outlive the result.
    pub fn decode(bytes: []const u8) Error!ListenerCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const node_id = try readU64(bytes, &pos);
        const epoch = try readU64(bytes, &pos);
        const started_unix = try readI64(bytes, &pos);

        const irc_listener_fd_index = try readI32(bytes, &pos);
        const s2s_listener_fd_index = try readI32(bytes, &pos);
        const media_fd_index = try readI32(bytes, &pos);

        const config_path = try readOptStr(bytes, &pos);

        return .{
            .node_id = node_id,
            .epoch = epoch,
            .started_unix = started_unix,
            .config_path = config_path,
            .irc_listener_fd_index = irc_listener_fd_index,
            .s2s_listener_fd_index = s2s_listener_fd_index,
            .media_fd_index = media_fd_index,
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

fn writeI32(out: []u8, pos: *usize, val: i32) Error!void {
    if (pos.* + 4 > out.len) return error.TooLong;
    std.mem.writeInt(i32, out[pos.*..][0..4], val, .big);
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

fn readI32(bytes: []const u8, pos: *usize) Error!i32 {
    if (pos.* + 4 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(i32, bytes[pos.*..][0..4], .big);
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

fn readOptStr(bytes: []const u8, pos: *usize) Error!?[]const u8 {
    const len = try readU16(bytes, pos);
    if (len == null_len) return null;
    return try readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip with non-null config_path and distinct fd indices" {
    const original = ListenerCapsule{
        .node_id = 0xDEAD_BEEF_CAFE_F00D,
        .epoch = 0x0102_0304_0506_0708,
        .started_unix = 1_700_000_000,
        .config_path = "/etc/orochi/orochi.conf",
        .irc_listener_fd_index = 3,
        .s2s_listener_fd_index = 7,
        .media_fd_index = 11,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try ListenerCapsule.decode(wire);

    try std.testing.expectEqual(original.node_id, decoded.node_id);
    try std.testing.expectEqual(original.epoch, decoded.epoch);
    try std.testing.expectEqual(original.started_unix, decoded.started_unix);
    try std.testing.expectEqual(original.irc_listener_fd_index, decoded.irc_listener_fd_index);
    try std.testing.expectEqual(original.s2s_listener_fd_index, decoded.s2s_listener_fd_index);
    try std.testing.expectEqual(original.media_fd_index, decoded.media_fd_index);
    try std.testing.expect(decoded.config_path != null);
    try std.testing.expectEqualStrings(original.config_path.?, decoded.config_path.?);
}

test "round-trip with null config_path and all fd indices -1" {
    const original = ListenerCapsule{
        .node_id = 1,
        .epoch = 0,
        .started_unix = -5,
        .config_path = null,
        .irc_listener_fd_index = -1,
        .s2s_listener_fd_index = -1,
        .media_fd_index = -1,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);
    const decoded = try ListenerCapsule.decode(wire);

    try std.testing.expectEqual(original.node_id, decoded.node_id);
    try std.testing.expectEqual(original.epoch, decoded.epoch);
    try std.testing.expectEqual(original.started_unix, decoded.started_unix);
    try std.testing.expectEqual(@as(i32, -1), decoded.irc_listener_fd_index);
    try std.testing.expectEqual(@as(i32, -1), decoded.s2s_listener_fd_index);
    try std.testing.expectEqual(@as(i32, -1), decoded.media_fd_index);
    try std.testing.expect(decoded.config_path == null);
}

test "decode returns Truncated on a cut buffer" {
    const original = ListenerCapsule{
        .node_id = 42,
        .epoch = 9,
        .started_unix = 123,
        .config_path = "/tmp/x.conf",
        .irc_listener_fd_index = 0,
        .s2s_listener_fd_index = 1,
        .media_fd_index = 2,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    // Cut just before the end so the config_path read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, ListenerCapsule.decode(cut));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, ListenerCapsule.decode(wire[0..0]));
}

test "decode returns BadMagic on corrupted magic" {
    const original = ListenerCapsule{
        .node_id = 1,
        .epoch = 0,
        .started_unix = 0,
        .config_path = null,
        .irc_listener_fd_index = -1,
        .s2s_listener_fd_index = -1,
        .media_fd_index = -1,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    try std.testing.expectError(error.BadMagic, ListenerCapsule.decode(corrupted[0..wire.len]));
}

test "decode returns BadVersion on a future version" {
    const original = ListenerCapsule{
        .node_id = 1,
        .epoch = 0,
        .started_unix = 0,
        .config_path = null,
        .irc_listener_fd_index = -1,
        .s2s_listener_fd_index = -1,
        .media_fd_index = -1,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    try std.testing.expectError(error.BadVersion, ListenerCapsule.decode(bumped[0..wire.len]));
}

test "encode returns TooLong when output buffer is too small" {
    const original = ListenerCapsule{
        .node_id = 0xFFFF_FFFF_FFFF_FFFF,
        .epoch = 1,
        .started_unix = 1,
        .config_path = "/a/fairly/long/path/to/the/configuration/file.conf",
        .irc_listener_fd_index = 1,
        .s2s_listener_fd_index = 2,
        .media_fd_index = 3,
    };

    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.TooLong, original.encode(&tiny));
}
