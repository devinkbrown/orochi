// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for a single account's multi-session record.
//!
//! Companion to `conn_capsule.zig`: where that carries one live socket's
//! resumable state, this carries the ACCOUNT-level session registry record so
//! that detached / bouncer sessions survive an in-place Helix upgrade. The real
//! registry is `sessions.zig`'s `SessionStore` (account -> set of `Session`),
//! and this codec serializes the durable subset of each session.
//!
//! The codec is pure and std-only: it never allocates. Decoded string slices
//! borrow the input buffer, and the decoded session array borrows a caller-
//! supplied `sessions_out` buffer, so both must outlive the returned capsule.
//!
//! Mapping to `sessions.zig`:
//!   - `account`         <- the `SessionStore.accounts` map key
//!   - `SessionEntry.token`       <- `Session.token` ([16]u8, carried as bytes)
//!   - `SessionEntry.signon_unix` <- `Session.signon_ms`
//!   - `SessionEntry.detached`    <- `!Session.attached`
//!   - `SessionEntry.client`      <- `Session.client` (ClientId / u64)
//! `Session.token` is a fixed [16]u8 in the store; here it is carried as a
//! length-prefixed byte string so the wire format stays uniform with
//! conn_capsule and tolerant of a future variable-width token.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   account:       u16 len + bytes
//!   session_count: u16
//!   each session:  token(u16 len + bytes) client(u64) signon_unix(i64) detached(u8)

const std = @import("std");

/// File magic identifying a session capsule record.
pub const magic = [_]u8{ 'H', 'S', 'S', 'N' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length (token / account).
const max_str_len: usize = 0xFFFF;

/// Maximum encodable session count (u16 on the wire).
const max_sessions: usize = 0xFFFF;

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read,
    /// or the output buffer was too small to hold the record.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// The decoded session count exceeded the caller-supplied output slice,
    /// or a field exceeded its maximum encodable length on encode.
    TooMany,
};

/// Durable per-session state. Maps to a `sessions.zig` `Session`:
///   token       <- Session.token  (carried as raw bytes)
///   signon_unix <- Session.signon_ms
///   detached    <- !Session.attached
///   client      <- Session.client (ClientId)
pub const SessionEntry = struct {
    token: []const u8,
    signon_unix: i64,
    detached: bool,
    client: u64 = 0,
};

/// One account's full session record, ready to migrate across an upgrade.
pub const SessionCapsule = struct {
    account: []const u8,
    sessions: []const SessionEntry,

    /// Serialize `self` into `out`. Returns the written prefix of `out`.
    ///
    /// Returns `error.TooMany` if `out` is too small, the account or a token
    /// exceeds the maximum encodable length, or there are more than 0xFFFF
    /// sessions.
    pub fn encode(self: SessionCapsule, out: []u8) Error![]const u8 {
        if (self.sessions.len > max_sessions) return error.TooMany;

        var pos: usize = 0;

        // magic(4)
        try writeBytes(out, &pos, &magic);
        // version(1)
        try writeByte(out, &pos, version);

        // account: u16 len + bytes
        try writeStr(out, &pos, self.account);

        // session_count(u16)
        try writeU16(out, &pos, @intCast(self.sessions.len));

        for (self.sessions) |entry| {
            // token: u16 len + bytes
            try writeStr(out, &pos, entry.token);
            // client(u64 BE)
            try writeU64(out, &pos, entry.client);
            // signon_unix(i64 BE)
            try writeI64(out, &pos, entry.signon_unix);
            // detached(u8)
            try writeByte(out, &pos, @intFromBool(entry.detached));
        }

        return out[0..pos];
    }

    /// Parse a `SessionCapsule` from `bytes`. The decoded sessions are written
    /// into `sessions_out` and the returned capsule's `sessions` slice borrows
    /// it; string slices (account, token) borrow `bytes`. Both buffers must
    /// outlive the result.
    ///
    /// Returns `error.TooMany` if the encoded session count exceeds
    /// `sessions_out.len`.
    pub fn decode(bytes: []const u8, sessions_out: []SessionEntry) Error!SessionCapsule {
        var pos: usize = 0;

        const got_magic = try readBytes(bytes, &pos, magic.len);
        if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

        const got_version = try readByte(bytes, &pos);
        if (got_version != version) return error.BadVersion;

        const account = try readStr(bytes, &pos);

        const count = try readU16(bytes, &pos);
        if (count > sessions_out.len) return error.TooMany;

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const token = try readStr(bytes, &pos);
            const client = try readU64(bytes, &pos);
            const signon_unix = try readI64(bytes, &pos);
            const detached = (try readByte(bytes, &pos)) != 0;
            sessions_out[i] = .{
                .token = token,
                .signon_unix = signon_unix,
                .detached = detached,
                .client = client,
            };
        }

        return .{ .account = account, .sessions = sessions_out[0..count] };
    }
};

// --- encode helpers ---------------------------------------------------------

fn writeBytes(out: []u8, pos: *usize, src: []const u8) Error!void {
    if (pos.* + src.len > out.len) return error.TooMany;
    @memcpy(out[pos.* .. pos.* + src.len], src);
    pos.* += src.len;
}

fn writeByte(out: []u8, pos: *usize, val: u8) Error!void {
    if (pos.* + 1 > out.len) return error.TooMany;
    out[pos.*] = val;
    pos.* += 1;
}

fn writeU16(out: []u8, pos: *usize, val: u16) Error!void {
    if (pos.* + 2 > out.len) return error.TooMany;
    std.mem.writeInt(u16, out[pos.*..][0..2], val, .big);
    pos.* += 2;
}

fn writeU64(out: []u8, pos: *usize, val: u64) Error!void {
    if (pos.* + 8 > out.len) return error.TooMany;
    std.mem.writeInt(u64, out[pos.*..][0..8], val, .big);
    pos.* += 8;
}

fn writeI64(out: []u8, pos: *usize, val: i64) Error!void {
    if (pos.* + 8 > out.len) return error.TooMany;
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

fn readStr(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16(bytes, pos);
    return readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip an account with two sessions (one detached, one attached)" {
    const sessions = [_]SessionEntry{
        .{ .token = "tok-attached-0001", .signon_unix = 1_700_000_000, .detached = false, .client = 42 },
        .{ .token = "tok-detached-0002", .signon_unix = 1_700_009_999, .detached = true, .client = 99 },
    };
    const original = SessionCapsule{ .account = "alice", .sessions = &sessions };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [8]SessionEntry = undefined;
    const decoded = try SessionCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings("alice", decoded.account);
    try std.testing.expectEqual(@as(usize, 2), decoded.sessions.len);

    try std.testing.expectEqualStrings(sessions[0].token, decoded.sessions[0].token);
    try std.testing.expectEqual(sessions[0].signon_unix, decoded.sessions[0].signon_unix);
    try std.testing.expectEqual(false, decoded.sessions[0].detached);
    try std.testing.expectEqual(@as(u64, 42), decoded.sessions[0].client);

    try std.testing.expectEqualStrings(sessions[1].token, decoded.sessions[1].token);
    try std.testing.expectEqual(sessions[1].signon_unix, decoded.sessions[1].signon_unix);
    try std.testing.expectEqual(true, decoded.sessions[1].detached);
    try std.testing.expectEqual(@as(u64, 99), decoded.sessions[1].client);
}

test "round-trip an account with zero sessions" {
    const original = SessionCapsule{ .account = "ghost", .sessions = &.{} };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]SessionEntry = undefined;
    const decoded = try SessionCapsule.decode(wire, &out);

    try std.testing.expectEqualStrings("ghost", decoded.account);
    try std.testing.expectEqual(@as(usize, 0), decoded.sessions.len);
}

test "decode returns Truncated on a cut buffer" {
    const sessions = [_]SessionEntry{
        .{ .token = "abcdefghijklmnop", .signon_unix = 5, .detached = false, .client = 1 },
    };
    const original = SessionCapsule{ .account = "bob", .sessions = &sessions };

    var buf: [256]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [4]SessionEntry = undefined;

    // Cut just before the end so a session field read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, SessionCapsule.decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, SessionCapsule.decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const original = SessionCapsule{ .account = "a", .sessions = &.{} };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var corrupted: [64]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [4]SessionEntry = undefined;
    try std.testing.expectError(error.BadMagic, SessionCapsule.decode(corrupted[0..wire.len], &out));
}

test "decode returns BadVersion on a future version" {
    const original = SessionCapsule{ .account = "a", .sessions = &.{} };

    var buf: [64]u8 = undefined;
    const wire = try original.encode(&buf);

    var bumped: [64]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [4]SessionEntry = undefined;
    try std.testing.expectError(error.BadVersion, SessionCapsule.decode(bumped[0..wire.len], &out));
}

test "decode returns TooMany when sessions_out is too small" {
    const sessions = [_]SessionEntry{
        .{ .token = "one", .signon_unix = 1, .detached = false, .client = 1 },
        .{ .token = "two", .signon_unix = 2, .detached = true, .client = 2 },
        .{ .token = "three", .signon_unix = 3, .detached = false, .client = 3 },
    };
    const original = SessionCapsule{ .account = "carol", .sessions = &sessions };

    var buf: [512]u8 = undefined;
    const wire = try original.encode(&buf);

    var out: [2]SessionEntry = undefined; // too small for 3 sessions
    try std.testing.expectError(error.TooMany, SessionCapsule.decode(wire, &out));
}
