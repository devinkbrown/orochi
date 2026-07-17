// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-global TLS session-ticket key(s) carried across a Helix UPGRADE.
//!
//! Unlike the per-client capsules (keyed by socket fd), this is a SINGLETON: the
//! daemon emits exactly one, holding the current ticket key and — after a REHASH
//! rotation (`rotateTicketKey`) — the previous key that
//! `tls_resumption.openTicketWithRotation` still accepts for one more window.
//!
//! Without it, the successor mints a fresh random ticket key at boot, so every
//! resumption ticket the predecessor issued becomes undecryptable across the
//! upgrade and each resuming client falls back to a full handshake. Carrying the
//! key(s) lets a client that reconnects right after an upgrade still resume on
//! its pre-upgrade ticket. (Connections that stay open ride their own
//! per-conn `.tls_session` capsule and are unaffected either way.)
//!
//! The key is a secret; it rides the same sealed handoff arena (a memfd inherited
//! across execve) that already carries per-connection TLS traffic secrets, so it
//! never touches disk or the wire.
//!
//! Wire format (little-endian): [u8 version][current: key_len][u8 has_prev][prev: key_len?]
const std = @import("std");
const tls_resumption = @import("../../crypto/tls_resumption.zig");

pub const Error = error{ Truncated, BadVersion, InvalidBoolean, TrailingBytes };

/// Wire version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// TicketKey is a fixed byte array (`[ChaCha20Poly1305.key_length]u8`), so its
/// `@sizeOf` is its length.
const key_len = @sizeOf(tls_resumption.TicketKey);

/// A plain view of the carried ticket key(s).
pub const Snapshot = struct {
    /// The key new tickets are sealed with (and tried first on open).
    current: tls_resumption.TicketKey,
    /// The key retired by the most recent REHASH rotation, still accepted for
    /// tickets in flight. Null before the first rotation.
    previous: ?tls_resumption.TicketKey = null,
};

/// Encode `snap` into a freshly-allocated buffer the caller owns.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, version);
    try out.appendSlice(allocator, &snap.current);
    if (snap.previous) |prev| {
        try out.append(allocator, 1);
        try out.appendSlice(allocator, &prev);
    } else {
        try out.append(allocator, 0);
    }
    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot. A truncated or wrong-version payload is rejected so the
/// caller keeps its freshly-minted boot key rather than adopting garbage.
pub fn decode(bytes: []const u8) Error!Snapshot {
    if (bytes.len < 2 + key_len) return error.Truncated; // version + current + has_prev
    if (bytes[0] != version) return error.BadVersion;
    var snap = Snapshot{ .current = undefined };
    @memcpy(&snap.current, bytes[1 .. 1 + key_len]);
    if (bytes[1 + key_len] != 0) {
        if (bytes.len < 2 + 2 * key_len) return error.Truncated;
        var prev: tls_resumption.TicketKey = undefined;
        @memcpy(&prev, bytes[2 + key_len .. 2 + 2 * key_len]);
        snap.previous = prev;
    }
    return snap;
}

/// Decode only the unique current v1 representation emitted by `encode`.
/// The legacy `decode` remains tolerant for explicit old callers; authoritative
/// Helix adoption must use this entry point so a noncanonical previous-key
/// marker or unauthenticated trailing bytes cannot select ambiguous state.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    const marker_index = 1 + key_len;
    if (bytes.len <= marker_index) return error.Truncated;
    if (bytes[0] != version) return error.BadVersion;
    const expected_len: usize = switch (bytes[marker_index]) {
        0 => marker_index + 1,
        1 => marker_index + 1 + key_len,
        else => return error.InvalidBoolean,
    };
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    return decode(bytes);
}

const testing = std.testing;

test "ticket-key capsule round-trips a current-only key" {
    const a = testing.allocator;
    const cur = @as([key_len]u8, @splat(0xAB));
    const bytes = try encode(a, .{ .current = cur });
    defer a.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, &cur, &got.current);
    try testing.expect(got.previous == null);
}

test "ticket-key capsule round-trips current + previous (post-rotation)" {
    const a = testing.allocator;
    const cur = @as([key_len]u8, @splat(0x11));
    const prev = @as([key_len]u8, @splat(0x22));
    const bytes = try encode(a, .{ .current = cur, .previous = prev });
    defer a.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, &cur, &got.current);
    try testing.expect(got.previous != null);
    try testing.expectEqualSlices(u8, &prev, &got.previous.?);
}

test "ticket-key capsule decode rejects truncation and a bad version" {
    try testing.expectError(error.Truncated, decode(&[_]u8{1}));
    const short = [_]u8{1} ++ @as([10]u8, @splat(0));
    try testing.expectError(error.Truncated, decode(&short));
    const bad = [_]u8{9} ++ @as([(1 + key_len)]u8, @splat(0));
    try testing.expectError(error.BadVersion, decode(&bad));
}

test "ticket-key decodeCurrent rejects every prefix nonboolean marker and trailing data" {
    const allocator = testing.allocator;
    const cur = @as([key_len]u8, @splat(0x31));
    const prev = @as([key_len]u8, @splat(0x42));
    const wire = try encode(allocator, .{ .current = cur, .previous = prev });
    defer allocator.free(wire);

    for (0..wire.len) |end| {
        try testing.expectError(error.Truncated, decodeCurrent(wire[0..end]));
    }
    const got = try decodeCurrent(wire);
    try testing.expectEqualSlices(u8, &cur, &got.current);
    try testing.expectEqualSlices(u8, &prev, &got.previous.?);

    const malformed = try allocator.dupe(u8, wire);
    defer allocator.free(malformed);
    malformed[1 + key_len] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(malformed));

    const trailing = try allocator.alloc(u8, wire.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(trailing));
}

test "ticket-key decodeCurrent is allocation-free" {
    const fn_info = @typeInfo(@TypeOf(decodeCurrent)).@"fn";
    comptime {
        const return_type = fn_info.return_type orelse @compileError("decodeCurrent must return a value");
        const decode_errors = @typeInfo(return_type).error_union.error_set;
        for (@typeInfo(decode_errors).error_set.error_names.?) |name| {
            if (std.mem.eql(u8, name, "OutOfMemory"))
                @compileError("decodeCurrent must remain allocation-free");
        }
    }
    const wire = [_]u8{version} ++ @as([key_len]u8, @splat(0xA5)) ++ [_]u8{0};
    try testing.expect((try decodeCurrent(&wire)).previous == null);
}
