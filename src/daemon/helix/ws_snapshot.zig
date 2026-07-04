// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client WebSocket resume marker — carried across a Helix UPGRADE so an
//! ESTABLISHED wss browser client (Ruri and friends) keeps its socket instead
//! of being dropped and forced to reconnect on every hot upgrade.
//!
//! A wss client is layered TLS-then-WebSocket. The TLS crypto state rides its
//! own `.tls_session` capsule (see tls_snapshot.zig); THIS capsule carries the
//! thin WebSocket-adapter state that pairs with it. `fd` is the join key back to
//! the matching `.clients` session snapshot and `.tls_session`.
//!
//! DELIBERATELY MINIMAL. The predecessor only seals this capsule when the WS
//! adapter is at a CLEAN framing boundary: handshake complete (phase = open),
//! no partially-received inbound frame in the deframer, and no partially-built
//! outbound line in the tx accumulator. At such a boundary the successor can
//! rebuild a FRESH, empty deframer/tx and resume framing with no lost bytes, so
//! there is nothing to serialize but the identity + phase. When the adapter is
//! mid-frame at the upgrade instant the predecessor does NOT carry the client at
//! all — it falls back to the historical behavior (socket closes at execve, the
//! browser reconnects against the still-bound listener), which is always safe.
//!
//! Wire format (all integers little-endian):
//!   [i32 fd][u8 flags]        flags bit0 = phase_open (required to adopt)
const std = @import("std");

pub const Error = error{ Truncated, TooLong };

/// flags bit0: the carried adapter had completed its HTTP Upgrade (phase=open).
/// A capsule without it is ignored on adopt (a handshake-phase WS is never
/// carried; it reconnects). Reserved higher bits stay zero for forward capsules.
pub const flag_phase_open: u8 = 1 << 0;

/// A plain view of one carried WebSocket adapter.
pub const Snapshot = struct {
    /// The client's socket fd (inherited across execve) — joins this WS marker
    /// to its `.clients` session snapshot and `.tls_session` capsule.
    fd: i32 = -1,
    /// The adapter had finished its Upgrade handshake and was framing IRC lines.
    /// Only an open adapter is ever sealed (and only from a clean boundary).
    phase_open: bool = true,
};

/// Encode `snap` into a freshly-allocated buffer the caller owns.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var le: [4]u8 = undefined;
    std.mem.writeInt(i32, &le, snap.fd, .little);
    try out.appendSlice(allocator, &le);
    try out.append(allocator, if (snap.phase_open) flag_phase_open else 0);
    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot.
pub fn decode(bytes: []const u8) Error!Snapshot {
    if (bytes.len < 5) return error.Truncated;
    const fd = std.mem.readInt(i32, bytes[0..4], .little);
    const flags = bytes[4];
    return .{ .fd = fd, .phase_open = (flags & flag_phase_open) != 0 };
}

const testing = std.testing;

test "ws snapshot round-trips fd + open phase" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 31, .phase_open = true });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqual(@as(i32, 31), got.fd);
    try testing.expect(got.phase_open);
}

test "ws snapshot carries a not-open marker distinctly" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 7, .phase_open = false });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqual(@as(i32, 7), got.fd);
    try testing.expect(!got.phase_open);
}

test "decode rejects truncation" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0, 0 }));
}
