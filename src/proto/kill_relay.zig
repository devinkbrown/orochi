// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! KILL frame payload codec (cross-mesh operator KILL).
//!
//! Carries one targeted KILL between mesh peers: "on `origin_server`, operator
//! `killer` (a full `nick!user@host` mask, or `SYSTEM` for an anonymized
//! override) killed the user `target` with this `reason`". The killer's node has
//! already enforced operator authority (`client_kill` privilege); the frame is
//! signed by that node's Tsumugi identity, so the owning node honors it and
//! disconnects its local `target`. Unlike the convergent facts, a KILL is a
//! one-shot COMMAND — peers do not store it.
//!
//! Compact fixed binary layout (little-endian), each field length-prefixed:
//!
//!   origin_len:u16 | origin… | killer_len:u16 | killer…
//!     | target_len:u16 | target… | reason_len:u16 | reason…
//!
//! Bounded per-field so a hostile peer cannot pin large buffers; decode borrows
//! the input (no allocation).
const std = @import("std");

pub const max_name_len = 128; // origin server, killer mask, target nick
pub const max_reason_len = 400;

/// Upper bound on one encoded KILL (all fields at their limits).
pub const max_encoded_len = (2 + max_name_len) * 3 + 2 + max_reason_len;

pub const Error = error{
    Truncated,
    FieldTooLong,
    EmptyField,
    BadField,
    TrailingBytes,
};

pub const KillRelay = struct {
    /// Server name where the KILL was issued (rendered as the kill source).
    origin_server: []const u8,
    /// Full `nick!user@host` mask of the killer, or `SYSTEM` for an override.
    killer: []const u8,
    /// Nick of the user to disconnect on the receiving (owning) node.
    target: []const u8,
    /// Human-readable kill reason (already control-byte sanitized by the origin).
    reason: []const u8,
};

pub fn encodedLen(ev: KillRelay) Error!usize {
    if (ev.origin_server.len > max_name_len) return error.FieldTooLong;
    if (ev.killer.len > max_name_len) return error.FieldTooLong;
    if (ev.target.len > max_name_len) return error.FieldTooLong;
    if (ev.reason.len > max_reason_len) return error.FieldTooLong;
    return 2 + ev.origin_server.len + 2 + ev.killer.len + 2 + ev.target.len + 2 + ev.reason.len;
}

fn putBytes16(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: KillRelay, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    putBytes16(out, &i, ev.origin_server);
    putBytes16(out, &i, ev.killer);
    putBytes16(out, &i, ev.target);
    putBytes16(out, &i, ev.reason);
    return out[0..i];
}

fn takeBytes16(bytes: []const u8, i: *usize, max: usize) Error![]const u8 {
    if (i.* + 2 > bytes.len) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max) return error.FieldTooLong;
    if (i.* + len > bytes.len) return error.Truncated;
    const out = bytes[i.*..][0..len];
    i.* += len;
    return out;
}

/// A token field (server/killer/target) must be a non-empty single atom: no
/// spaces or control bytes (so it can never break the wire framing). `killer`
/// may be a `nick!user@host` mask, which contains none of those.
fn validateAtom(text: []const u8) Error!void {
    if (text.len == 0) return error.EmptyField;
    for (text) |b| {
        if (b <= 0x20 or b == 0x7f) return error.BadField;
    }
}

/// The reason may carry spaces but never control bytes.
fn validateReason(text: []const u8) Error!void {
    for (text) |b| {
        if (b < 0x20 or b == 0x7f) return error.BadField;
    }
}

/// Decode one KILL payload. Borrows `bytes`; validates every field.
pub fn decode(bytes: []const u8) Error!KillRelay {
    var i: usize = 0;
    const origin = try takeBytes16(bytes, &i, max_name_len);
    const killer = try takeBytes16(bytes, &i, max_name_len);
    const target = try takeBytes16(bytes, &i, max_name_len);
    const reason = try takeBytes16(bytes, &i, max_reason_len);
    if (i != bytes.len) return error.TrailingBytes;
    try validateAtom(origin);
    try validateAtom(killer);
    try validateAtom(target);
    try validateReason(reason);
    return .{ .origin_server = origin, .killer = killer, .target = target, .reason = reason };
}

const testing = std.testing;

test "encode/decode round-trips a KILL relay" {
    const ev = KillRelay{
        .origin_server = "orochi.local",
        .killer = "kain!~k@admin.example",
        .target = "spammer",
        .reason = "flooding the network",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqualStrings(ev.origin_server, got.origin_server);
    try testing.expectEqualStrings(ev.killer, got.killer);
    try testing.expectEqualStrings(ev.target, got.target);
    try testing.expectEqualStrings(ev.reason, got.reason);
}

test "decode rejects truncated, trailing, empty, and control-byte payloads" {
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(.{ .origin_server = "s", .killer = "k", .target = "t", .reason = "r" }, &buf);
    // Truncated.
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));
    // Trailing bytes.
    var extended: [64]u8 = undefined;
    @memcpy(extended[0..wire.len], wire);
    extended[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decode(extended[0 .. wire.len + 1]));
    // Empty target atom is rejected.
    try testing.expectError(error.EmptyField, decode(try encode(.{ .origin_server = "s", .killer = "k", .target = "", .reason = "r" }, &buf)));
    // A control byte in an atom field is rejected.
    try testing.expectError(error.BadField, decode(try encode(.{ .origin_server = "s", .killer = "k\x07x", .target = "t", .reason = "r" }, &buf)));
}

test "encode enforces field bounds" {
    var buf: [max_encoded_len]u8 = undefined;
    const long_name = &@as([(max_name_len + 1)]u8, @splat('x'));
    try testing.expectError(error.FieldTooLong, encode(.{ .origin_server = long_name, .killer = "k", .target = "t", .reason = "r" }, &buf));
}
