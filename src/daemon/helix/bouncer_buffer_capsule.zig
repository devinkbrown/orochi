// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for a detached session's BOUNCER backlog.
//!
//! When an account's session goes detached (`sessions.zig`: `Session.attached
//! == false`), inbound traffic addressed to that account is buffered as raw IRC
//! lines and replayed when the client reattaches. This codec serializes that
//! per-account backlog so a Helix in-process upgrade (UPGRADE command) can carry
//! it across the binary swap without losing any buffered line.
//!
//! Durable subset mapped from `sessions.zig`:
//!   * `account` — the account name, the durable identity used as the
//!     `SessionStore.accounts` StringHashMap key (owned per account). This is
//!     what keys the bouncer fan-out / backlog.
//!   * `lines` — the buffered raw IRC lines retained while the session is
//!     detached, each stamped with `ts_ms` (an `i64` epoch-millis timestamp,
//!     mirroring `Session.signon_ms: i64`) for ordered replay.
//!
//! The codec is pure and std-only: it never allocates. Decoded `line` slices
//! borrow the input buffer, so the caller must keep that buffer alive for as
//! long as the returned `BouncerBufferCapsule` (and its lines) are used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   account:    u16 len + bytes
//!   line_count: u32
//!   repeated line_count times:
//!     ts_ms: i64
//!     line:  u16 len + bytes

const std = @import("std");

/// File magic identifying a bouncer-buffer capsule record.
pub const magic = [_]u8{ 'H', 'B', 'U', 'F' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length (account name or a buffered line).
const max_str_len: usize = 0xFFFF;

/// A single raw IRC line buffered for replay, with its arrival timestamp.
pub const BufferedLine = struct {
    ts_ms: i64,
    line: []const u8,
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
    /// The decoded line count exceeded the caller-supplied output slice.
    TooMany,
};

/// A detached session's per-account buffered backlog.
pub const BouncerBufferCapsule = struct {
    account: []const u8,
    lines: []const BufferedLine,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.Truncated` if `out` is too small to hold the record.
    pub fn encode(self: BouncerBufferCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // account: u16 len + bytes
        try writeStr(out, &pos, self.account);

        // line_count: u32 BE (a backlog can be large)
        try writeU32(out, &pos, @intCast(self.lines.len));

        // each line: ts_ms(i64 BE) + line(u16 len + bytes)
        for (self.lines) |bl| {
            try writeI64(out, &pos, bl.ts_ms);
            try writeStr(out, &pos, bl.line);
        }

        return out[0..pos];
    }

    /// Parse a `BouncerBufferCapsule` from `bytes`, writing the decoded
    /// `BufferedLine` entries into `lines_out` and borrowing slices from `bytes`
    /// (which must outlive the result).
    ///
    /// Returns `error.TooMany` if the encoded line count exceeds
    /// `lines_out.len`.
    pub fn decode(bytes: []const u8, lines_out: []BufferedLine) Error!BouncerBufferCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const account = try readStr(bytes, &pos);

        const count = try readU32(bytes, &pos);
        if (count > lines_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const ts_ms = try readI64(bytes, &pos);
            const line = try readStr(bytes, &pos);
            lines_out[i] = .{ .ts_ms = ts_ms, .line = line };
        }

        return .{ .account = account, .lines = lines_out[0..count] };
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

fn writeU32(out: []u8, pos: *usize, val: u32) Error!void {
    if (pos.* + 4 > out.len) return error.Truncated;
    std.mem.writeInt(u32, out[pos.*..][0..4], val, .big);
    pos.* += 4;
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

// --- tests ------------------------------------------------------------------

test "round-trip an account with three buffered lines" {
    const lines = [_]BufferedLine{
        .{ .ts_ms = 1_700_000_000_000, .line = ":nick!u@h PRIVMSG #chan :hello" },
        .{ .ts_ms = 1_700_000_000_500, .line = "" }, // empty line
        .{ .ts_ms = -42, .line = ":srv NOTICE * :back from the past" },
    };
    const original = BouncerBufferCapsule{
        .account = "alice",
        .lines = &lines,
    };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8]BufferedLine = undefined;
    const decoded = try BouncerBufferCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings("alice", decoded.account);
    try std.testing.expectEqual(@as(usize, 3), decoded.lines.len);

    try std.testing.expectEqual(@as(i64, 1_700_000_000_000), decoded.lines[0].ts_ms);
    try std.testing.expectEqualStrings(lines[0].line, decoded.lines[0].line);

    try std.testing.expectEqual(@as(i64, 1_700_000_000_500), decoded.lines[1].ts_ms);
    try std.testing.expectEqualStrings("", decoded.lines[1].line);

    try std.testing.expectEqual(@as(i64, -42), decoded.lines[2].ts_ms);
    try std.testing.expectEqualStrings(lines[2].line, decoded.lines[2].line);
}

test "round-trip with zero buffered lines" {
    const original = BouncerBufferCapsule{
        .account = "bob",
        .lines = &.{},
    };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]BufferedLine = undefined;
    const decoded = try BouncerBufferCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings("bob", decoded.account);
    try std.testing.expectEqual(@as(usize, 0), decoded.lines.len);
}

test "decode returns Truncated on a cut buffer" {
    const lines = [_]BufferedLine{
        .{ .ts_ms = 1, .line = "PING :a" },
        .{ .ts_ms = 2, .line = "PING :b" },
    };
    const original = BouncerBufferCapsule{ .account = "carol", .lines = &lines };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]BufferedLine = undefined;

    // Cut just before the end so the last line read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, BouncerBufferCapsule.decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, BouncerBufferCapsule.decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const original = BouncerBufferCapsule{ .account = "dave", .lines = &.{} };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [128]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [4]BufferedLine = undefined;
    try std.testing.expectError(error.BadMagic, BouncerBufferCapsule.decode(corrupted[0..wire.len], &out));
}

test "decode returns BadVersion on a future version" {
    const original = BouncerBufferCapsule{ .account = "erin", .lines = &.{} };

    var buf: [128]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [128]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [4]BufferedLine = undefined;
    try std.testing.expectError(error.BadVersion, BouncerBufferCapsule.decode(bumped[0..wire.len], &out));
}

test "decode returns TooMany when lines_out is too small" {
    const lines = [_]BufferedLine{
        .{ .ts_ms = 1, .line = "a" },
        .{ .ts_ms = 2, .line = "b" },
        .{ .ts_ms = 3, .line = "c" },
    };
    const original = BouncerBufferCapsule{ .account = "frank", .lines = &lines };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [2]BufferedLine = undefined; // smaller than the 3 encoded lines
    try std.testing.expectError(error.TooMany, BouncerBufferCapsule.decode(wire, &out));
}
