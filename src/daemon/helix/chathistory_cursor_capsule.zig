//! Allocation-free wire codec for a session's CHATHISTORY replay cursors.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to migrate the
//! per-target last-delivered replay position of a session before `execve` and
//! restore it in the successor process, so reattach can rewind/replay from the
//! correct point. A CHATHISTORY position is referenced by its IRC msgid (see
//! `MessageRef.msgid` in `src/proto/chathistory.zig`) and/or its timestamp
//! (the wall-clock millisecond derived from the entry's `Hlc`).
//!
//! The codec is pure and std-only: it never allocates. Decoded string slices
//! borrow the input buffer, so the caller must keep that buffer alive for as
//! long as the returned capsule is used. The cursor array is written into a
//! caller-provided `cursors_out` slice; nothing is heap-allocated.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   account:      u16 len + bytes
//!   cursor_count: u16 BE
//!   each cursor:
//!     target:     u16 len + bytes
//!     last_msgid: u16 len + bytes
//!     last_ts_ms: i64 BE

const std = @import("std");

/// File magic identifying a CHATHISTORY cursor capsule record.
pub const magic = [_]u8{ 'H', 'C', 'H', 'C' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length.
const max_str_len: usize = 0xFFFF;

/// One per-target replay cursor: the last-delivered history position for a
/// single channel or nick target.
pub const Cursor = struct {
    /// Channel or nick the cursor tracks. Borrows the input buffer on decode.
    target: []const u8,
    /// IRC msgid of the last delivered message. May be empty when the position
    /// is only timestamp-addressed. Borrows the input buffer on decode.
    last_msgid: []const u8,
    /// Wall-clock millisecond timestamp of the last delivered message.
    last_ts_ms: i64,
};

/// Resumable CHATHISTORY replay state for a single session.
pub const ChatHistoryCursorCapsule = struct {
    account: []const u8,
    cursors: []const Cursor,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.Truncated` if `out` is too small. Returns
    /// `error.TooMany` if there are more cursors than fit in a u16 count.
    pub fn encode(self: ChatHistoryCursorCapsule, out: []u8) Error![]const u8 {
        if (self.cursors.len > std.math.maxInt(u16)) return error.TooMany;

        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // account
        try writeStr(out, &pos, self.account);

        // cursor_count(u16 BE)
        try writeU16(out, &pos, @intCast(self.cursors.len));

        for (self.cursors) |cursor| {
            try writeStr(out, &pos, cursor.target);
            try writeStr(out, &pos, cursor.last_msgid);
            try writeI64(out, &pos, cursor.last_ts_ms);
        }

        return out[0..pos];
    }

    /// Parse a `ChatHistoryCursorCapsule` from `bytes`. Decoded cursors are
    /// written into `cursors_out`; their string slices borrow `bytes`, which
    /// must outlive the result.
    ///
    /// Returns `error.TooMany` if the record holds more cursors than
    /// `cursors_out` can store.
    pub fn decode(bytes: []const u8, cursors_out: []Cursor) Error!ChatHistoryCursorCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const account = try readStr(bytes, &pos);

        const count = try readU16(bytes, &pos);
        if (count > cursors_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const target = try readStr(bytes, &pos);
            const last_msgid = try readStr(bytes, &pos);
            const last_ts_ms = try readI64(bytes, &pos);
            cursors_out[i] = .{
                .target = target,
                .last_msgid = last_msgid,
                .last_ts_ms = last_ts_ms,
            };
        }

        return .{
            .account = account,
            .cursors = cursors_out[0..count],
        };
    }
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
    /// More cursors than can be encoded in a u16 count, or more cursors than
    /// the caller's `cursors_out` slice can hold.
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

test "round-trip an account with three cursors" {
    const cursors = [_]Cursor{
        .{ .target = "#zig", .last_msgid = "msg-abc-001", .last_ts_ms = 1_700_000_000_000 },
        .{ .target = "#orochi", .last_msgid = "msg-def-777", .last_ts_ms = -42 },
        .{ .target = "alice", .last_msgid = "", .last_ts_ms = 9_223_372_036_854_775_807 },
    };
    const original = ChatHistoryCursorCapsule{
        .account = "registered-account",
        .cursors = &cursors,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8]Cursor = undefined;
    const decoded = try ChatHistoryCursorCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings(original.account, decoded.account);
    try std.testing.expectEqual(@as(usize, 3), decoded.cursors.len);

    try std.testing.expectEqualStrings("#zig", decoded.cursors[0].target);
    try std.testing.expectEqualStrings("msg-abc-001", decoded.cursors[0].last_msgid);
    try std.testing.expectEqual(@as(i64, 1_700_000_000_000), decoded.cursors[0].last_ts_ms);

    try std.testing.expectEqualStrings("#orochi", decoded.cursors[1].target);
    try std.testing.expectEqualStrings("msg-def-777", decoded.cursors[1].last_msgid);
    try std.testing.expectEqual(@as(i64, -42), decoded.cursors[1].last_ts_ms);

    try std.testing.expectEqualStrings("alice", decoded.cursors[2].target);
    try std.testing.expectEqualStrings("", decoded.cursors[2].last_msgid);
    try std.testing.expectEqual(
        @as(i64, 9_223_372_036_854_775_807),
        decoded.cursors[2].last_ts_ms,
    );
}

test "round-trip with zero cursors" {
    const original = ChatHistoryCursorCapsule{
        .account = "lonely",
        .cursors = &.{},
    };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Cursor = undefined;
    const decoded = try ChatHistoryCursorCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings("lonely", decoded.account);
    try std.testing.expectEqual(@as(usize, 0), decoded.cursors.len);
}

test "decode returns Truncated on a cut buffer" {
    const cursors = [_]Cursor{
        .{ .target = "#zig", .last_msgid = "m1", .last_ts_ms = 100 },
    };
    const original = ChatHistoryCursorCapsule{
        .account = "acct",
        .cursors = &cursors,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Cursor = undefined;

    // Cut just before the end so the trailing i64 read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, ChatHistoryCursorCapsule.decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, ChatHistoryCursorCapsule.decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const cursors = [_]Cursor{
        .{ .target = "#zig", .last_msgid = "m1", .last_ts_ms = 1 },
    };
    const original = ChatHistoryCursorCapsule{
        .account = "acct",
        .cursors = &cursors,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [4]Cursor = undefined;
    try std.testing.expectError(
        error.BadMagic,
        ChatHistoryCursorCapsule.decode(corrupted[0..wire.len], &out),
    );
}

test "decode returns BadVersion on a future version" {
    const cursors = [_]Cursor{
        .{ .target = "#zig", .last_msgid = "m1", .last_ts_ms = 1 },
    };
    const original = ChatHistoryCursorCapsule{
        .account = "acct",
        .cursors = &cursors,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [4]Cursor = undefined;
    try std.testing.expectError(
        error.BadVersion,
        ChatHistoryCursorCapsule.decode(bumped[0..wire.len], &out),
    );
}

test "decode returns TooMany when cursors_out is too small" {
    const cursors = [_]Cursor{
        .{ .target = "#a", .last_msgid = "m1", .last_ts_ms = 1 },
        .{ .target = "#b", .last_msgid = "m2", .last_ts_ms = 2 },
        .{ .target = "#c", .last_msgid = "m3", .last_ts_ms = 3 },
    };
    const original = ChatHistoryCursorCapsule{
        .account = "acct",
        .cursors = &cursors,
    };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [2]Cursor = undefined; // too small for 3 cursors
    try std.testing.expectError(error.TooMany, ChatHistoryCursorCapsule.decode(wire, &out));
}
