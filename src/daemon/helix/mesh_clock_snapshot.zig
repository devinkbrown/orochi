// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-global mesh-clock state carried across a Helix UPGRADE.
//!
//! Stable mesh event identity is the authenticated `(origin_node, hlc)` pair.
//! Re-execing with a fresh `MeshClock` can therefore reuse an identity when the
//! successor starts in the same wall-clock millisecond, or can regress for much
//! longer after a wall-clock step-back. This fixed-size snapshot preserves the
//! predecessor's complete HLC high-water mark so a successor's first stamp is
//! strictly newer even when its process-local sequence counter restarts.
//!
//! Only `last_stamp` is serialized. `last_physical` is redundant state and is
//! always reconstructed as `MeshClock.physicalOf(last_stamp)` on decode. That
//! makes an inconsistent pair unrepresentable in the handoff payload.
//!
//! Wire format (all integers little-endian):
//!   [magic "MHLC"][u8 version=1][u64 last_stamp]
//!
//! The codec is allocation-free and fixed-size. Short, wrong-magic, unsupported,
//! and trailing payloads fail closed rather than partially restoring clock state.
const std = @import("std");
const mesh_clock = @import("../../substrate/suimyaku/mesh_clock.zig");

pub const Error = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    TrailingBytes,
};

/// Wire version. Bump on any incompatible payload change.
pub const version: u8 = 1;
pub const magic = [_]u8{ 'M', 'H', 'L', 'C' };
pub const encoded_len: usize = magic.len + 1 + @sizeOf(u64);

/// Capture one process-global mesh clock into a fixed-size Helix payload.
/// `last_physical` is deliberately omitted; `decode` derives it canonically.
pub fn encode(clock: mesh_clock.MeshClock) [encoded_len]u8 {
    var out: [encoded_len]u8 = undefined;
    @memcpy(out[0..magic.len], &magic);
    out[magic.len] = version;
    std.mem.writeInt(u64, out[magic.len + 1 ..][0..8], clock.last_stamp, .little);
    return out;
}

/// Decode and restore a process-global mesh clock. The returned clock always
/// satisfies `last_physical == MeshClock.physicalOf(last_stamp)`; the redundant
/// physical high-water mark is never trusted from handoff bytes.
pub fn decode(bytes: []const u8) Error!mesh_clock.MeshClock {
    if (bytes.len < encoded_len) return error.Truncated;
    if (bytes.len > encoded_len) return error.TrailingBytes;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;

    const last_stamp = std.mem.readInt(u64, bytes[magic.len + 1 ..][0..8], .little);
    return .{
        .last_physical = mesh_clock.MeshClock.physicalOf(last_stamp),
        .last_stamp = last_stamp,
    };
}

const testing = std.testing;

test "mesh clock snapshot round-trips the complete HLC high-water mark" {
    var predecessor: mesh_clock.MeshClock = .{};
    const last = predecessor.stamp(1_700_000_000_000, 40_000);

    const wire = encode(predecessor);
    const successor = try decode(&wire);
    try testing.expectEqual(last, successor.last_stamp);
    try testing.expectEqual(mesh_clock.MeshClock.physicalOf(last), successor.last_physical);
}

test "mesh clock snapshot canonicalizes redundant physical state" {
    // Even an inconsistent in-memory source cannot put an inconsistent
    // last_physical value on the wire: only last_stamp is authoritative.
    const stamp: u64 = (123_456 << mesh_clock.seq_bits) | 77;
    const wire = encode(.{ .last_physical = 999_999, .last_stamp = stamp });
    const restored = try decode(&wire);
    try testing.expectEqual(stamp, restored.last_stamp);
    try testing.expectEqual(@as(u64, 123_456), restored.last_physical);
}

test "mesh clock snapshot restores advancement after sequence reset and wall-clock step-back" {
    const wall_ms: u64 = 1_700_000_000_000;
    var predecessor: mesh_clock.MeshClock = .{};
    const before = predecessor.stamp(wall_ms, 60_000);

    const wire = encode(predecessor);
    var successor = try decode(&wire);
    // Models a successor whose process-local sequence restarted and whose wall
    // clock is behind the predecessor after an NTP correction.
    const after = successor.stamp(wall_ms - 10_000, 1);
    try testing.expect(after > before);
}

test "mesh clock snapshot preserves zero and maximum boundary stamps" {
    inline for (.{ @as(u64, 0), std.math.maxInt(u64) }) |last_stamp| {
        const wire = encode(.{ .last_stamp = last_stamp });
        try testing.expectEqual(encoded_len, wire.len);
        const restored = try decode(&wire);
        try testing.expectEqual(last_stamp, restored.last_stamp);
        try testing.expectEqual(mesh_clock.MeshClock.physicalOf(last_stamp), restored.last_physical);
    }
}

test "mesh clock snapshot has deterministic little-endian wire encoding" {
    const wire = encode(.{ .last_stamp = 0x0102_0304_0506_0708 });
    try testing.expectEqualSlices(u8, "MHLC\x01\x08\x07\x06\x05\x04\x03\x02\x01", &wire);
}

test "mesh clock snapshot rejects every truncation" {
    const wire = encode(.{ .last_stamp = 7 });
    var n: usize = 0;
    while (n < encoded_len) : (n += 1) {
        try testing.expectError(error.Truncated, decode(wire[0..n]));
    }
}

test "mesh clock snapshot rejects bad magic too-new versions and trailing bytes" {
    var bad_magic = encode(.{ .last_stamp = 7 });
    bad_magic[0] = 'X';
    try testing.expectError(error.BadMagic, decode(&bad_magic));

    var too_new = encode(.{ .last_stamp = 7 });
    too_new[magic.len] = version + 1;
    try testing.expectError(error.UnsupportedVersion, decode(&too_new));

    const trailing = encode(.{ .last_stamp = 7 }) ++ [_]u8{0};
    try testing.expectError(error.TrailingBytes, decode(&trailing));
}
