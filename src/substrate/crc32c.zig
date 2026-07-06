// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CRC32C (Castagnoli) checksum for frame integrity checks.
//!
//! Implements the CRC-32/ISCSI variant: polynomial 0x1EDC6F41, used here in its
//! reflected form 0x82F63B78 with reflected input/output and an initial/final
//! XOR value of 0xFFFFFFFF. This is the same CRC32C used by iSCSI, SCTP, ext4,
//! Btrfs, and many wire framing protocols.
//!
//! Two interfaces are provided:
//!   - `crc32c(bytes)`: one-shot convenience over a byte slice.
//!   - `Hasher`: streaming computation via `init`/`update`/`final`.
//!
//! The lookup table is generated at comptime, so there is no runtime init cost
//! and the table lives in read-only data.

const std = @import("std");

/// Reflected Castagnoli polynomial (bit-reversed 0x1EDC6F41).
const POLY: u32 = 0x82F63B78;

/// Value used to seed the register and to XOR the final result.
const XOR_MASK: u32 = 0xFFFFFFFF;

/// Comptime-generated 256-entry byte lookup table for the reflected polynomial.
const table = buildTable();

fn buildTable() [256]u32 {
    @setEvalBranchQuota(20000);
    var t: [256]u32 = undefined;
    var n: usize = 0;
    while (n < 256) : (n += 1) {
        var crc: u32 = @intCast(n);
        var k: usize = 0;
        while (k < 8) : (k += 1) {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
        t[n] = crc;
    }
    return t;
}

/// Streaming CRC32C computation.
///
/// Usage:
/// ```
/// var h = Hasher.init();
/// h.update("123");
/// h.update("456789");
/// const sum = h.final();
/// ```
pub const Hasher = struct {
    /// Running CRC register (stored pre-final-XOR / inverted form).
    state: u32,

    /// Create a fresh hasher seeded with the standard initial value.
    pub fn init() Hasher {
        return .{ .state = XOR_MASK };
    }

    /// Feed a slice of bytes into the running checksum.
    pub fn update(self: *Hasher, bytes: []const u8) void {
        var crc = self.state;
        for (bytes) |b| {
            const idx: u8 = @truncate(crc ^ b);
            crc = (crc >> 8) ^ table[idx];
        }
        self.state = crc;
    }

    /// Produce the finalized checksum. Non-destructive: the hasher may continue
    /// to be `update`d afterward and `final` called again.
    pub fn final(self: *const Hasher) u32 {
        return self.state ^ XOR_MASK;
    }
};

/// One-shot CRC32C over a byte slice.
pub fn crc32c(bytes: []const u8) u32 {
    var h = Hasher.init();
    h.update(bytes);
    return h.final();
}

const testing = std.testing;

test "empty input is zero" {
    try testing.expectEqual(@as(u32, 0), crc32c(""));
}

test "canonical check vector 123456789" {
    try testing.expectEqual(@as(u32, 0xE3069283), crc32c("123456789"));
}

test "single byte" {
    // CRC32C of a single 0x00 byte.
    try testing.expectEqual(@as(u32, 0x527D5351), crc32c(&[_]u8{0x00}));
}

test "streaming matches one-shot" {
    const data = "The quick brown fox jumps over the lazy dog";
    const oneshot = crc32c(data);

    var h = Hasher.init();
    h.update(data[0..10]);
    h.update(data[10..20]);
    h.update(data[20..]);
    try testing.expectEqual(oneshot, h.final());
}

test "streaming byte-by-byte matches one-shot" {
    const data = "123456789";
    var h = Hasher.init();
    for (data) |b| {
        h.update(&[_]u8{b});
    }
    try testing.expectEqual(@as(u32, 0xE3069283), h.final());
}

test "final is non-destructive and resumable" {
    var h = Hasher.init();
    h.update("12345");
    const partial = h.final();
    h.update("6789");
    try testing.expectEqual(@as(u32, 0xE3069283), h.final());
    // The earlier partial result must equal a fresh one-shot of the prefix.
    try testing.expectEqual(crc32c("12345"), partial);
}

test "matches std.hash.crc Crc32Iscsi" {
    const data = "orochi frame integrity";
    const Crc32Iscsi = std.hash.crc.@"CRC-32/ISCSI";
    try testing.expectEqual(Crc32Iscsi.hash(data), crc32c(data));
}

test "comptime evaluation" {
    const sum = comptime crc32c("123456789");
    try testing.expectEqual(@as(u32, 0xE3069283), sum);
}
