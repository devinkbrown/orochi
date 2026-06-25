// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for an account's queued Tegami (offline/MEMO)
//! messages.
//!
//! Used by the Helix in-process upgrade (UPGRADE command) to serialize each
//! account's pending offline mailbox before `execve` and restore it in the
//! successor process, so messages left for an offline account survive a
//! restart. The codec is pure and std-only: it never allocates. Decoded string
//! slices borrow the input buffer, so the caller must keep that buffer alive for
//! as long as the returned `TegamiCapsule` (and its `Memo` slice) is used.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   account:    u16 len + bytes
//!   memo_count: u16
//!   for each memo:
//!     from:    u16 len + bytes
//!     text:    u16 len + bytes
//!     sent_ms: i64 (8 bytes)
//!
//! Mirrors the per-account fields in `daemon/tegami.zig` (`Message`).

const std = @import("std");

/// File magic identifying a Tegami capsule record.
pub const magic = [_]u8{ 'H', 'T', 'G', 'M' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length.
const max_str_len: usize = 0xFFFF;

/// One queued offline message. String fields borrow the decode input buffer.
pub const Memo = struct {
    from: []const u8,
    text: []const u8,
    sent_ms: i64,
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
    /// The record declares more memos than the caller's `memos_out` slice can
    /// hold.
    TooMany,
};

/// An account's full set of queued offline messages.
pub const TegamiCapsule = struct {
    account: []const u8,
    memos: []const Memo,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.Truncated` if `out` is too small to hold the record.
    pub fn encode(self: TegamiCapsule, out: []u8) Error![]const u8 {
        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // account: u16 len + bytes
        try writeStr(out, &pos, self.account);

        // memo_count(u16 BE)
        try writeU16(out, &pos, @intCast(self.memos.len));

        for (self.memos) |memo| {
            try writeStr(out, &pos, memo.from);
            try writeStr(out, &pos, memo.text);
            try writeI64(out, &pos, memo.sent_ms);
        }

        return out[0..pos];
    }

    /// Parse a `TegamiCapsule` from `bytes`, writing decoded memos into
    /// `memos_out`. Returned string slices borrow `bytes`, which must outlive
    /// the result. Returns `error.TooMany` if the record holds more memos than
    /// `memos_out.len`.
    pub fn decode(bytes: []const u8, memos_out: []Memo) Error!TegamiCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const account = try readStr(bytes, &pos);

        const memo_count = try readU16(bytes, &pos);
        if (memo_count > memos_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < memo_count) : (i += 1) {
            const from = try readStr(bytes, &pos);
            const text = try readStr(bytes, &pos);
            const sent_ms = try readI64(bytes, &pos);
            memos_out[i] = .{ .from = from, .text = text, .sent_ms = sent_ms };
        }

        return .{ .account = account, .memos = memos_out[0..memo_count] };
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

test "round-trip an account with three memos" {
    const memos = [_]Memo{
        .{ .from = "bob", .text = "hi alice", .sent_ms = 1000 },
        .{ .from = "carol", .text = "", .sent_ms = -42 }, // empty text
        .{ .from = "dave", .text = "see you at 5", .sent_ms = 9_223_372_036_854 },
    };
    const original = TegamiCapsule{ .account = "alice", .memos = &memos };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8]Memo = undefined;
    const decoded = try TegamiCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings("alice", decoded.account);
    try std.testing.expectEqual(@as(usize, 3), decoded.memos.len);

    try std.testing.expectEqualStrings("bob", decoded.memos[0].from);
    try std.testing.expectEqualStrings("hi alice", decoded.memos[0].text);
    try std.testing.expectEqual(@as(i64, 1000), decoded.memos[0].sent_ms);

    try std.testing.expectEqualStrings("carol", decoded.memos[1].from);
    try std.testing.expectEqualStrings("", decoded.memos[1].text);
    try std.testing.expectEqual(@as(i64, -42), decoded.memos[1].sent_ms);

    try std.testing.expectEqualStrings("dave", decoded.memos[2].from);
    try std.testing.expectEqualStrings("see you at 5", decoded.memos[2].text);
    try std.testing.expectEqual(@as(i64, 9_223_372_036_854), decoded.memos[2].sent_ms);
}

test "round-trip an account with zero memos" {
    const original = TegamiCapsule{ .account = "loner", .memos = &.{} };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Memo = undefined;
    const decoded = try TegamiCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings("loner", decoded.account);
    try std.testing.expectEqual(@as(usize, 0), decoded.memos.len);
}

test "decode returns Truncated on a cut buffer" {
    const memos = [_]Memo{
        .{ .from = "bob", .text = "hello", .sent_ms = 5 },
    };
    const original = TegamiCapsule{ .account = "alice", .memos = &memos };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]Memo = undefined;

    // Cut into the middle of the last memo so a read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, TegamiCapsule.decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, TegamiCapsule.decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const original = TegamiCapsule{ .account = "alice", .memos = &.{} };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [64]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [4]Memo = undefined;
    try std.testing.expectError(error.BadMagic, TegamiCapsule.decode(corrupted[0..wire.len], &out));
}

test "decode returns BadVersion on a future version" {
    const original = TegamiCapsule{ .account = "alice", .memos = &.{} };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [64]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [4]Memo = undefined;
    try std.testing.expectError(error.BadVersion, TegamiCapsule.decode(bumped[0..wire.len], &out));
}

test "decode returns TooMany when memos exceed the output slice" {
    const memos = [_]Memo{
        .{ .from = "a", .text = "1", .sent_ms = 1 },
        .{ .from = "b", .text = "2", .sent_ms = 2 },
        .{ .from = "c", .text = "3", .sent_ms = 3 },
    };
    const original = TegamiCapsule{ .account = "alice", .memos = &memos };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [2]Memo = undefined; // too small for 3 memos
    try std.testing.expectError(error.TooMany, TegamiCapsule.decode(wire, &out));
}
