// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Snowflake: distributed, roughly-time-ordered 64-bit unique identifiers.
//!
//! Layout (most-significant bit first):
//!
//!     63                                    22    21      12 11        0
//!     +--------------------------------------+------+--------+---------+
//!     | 41-bit milliseconds since epoch      | unused | node  |  seq   |
//!     +--------------------------------------+--------+-------+---------+
//!       (bit 63 is always 0 so ids are positive when read as i64)
//!
//! - 42 bits of millisecond timestamp (relative to a configurable epoch). Only
//!   41 of those bits are usable while keeping the high bit clear, which still
//!   covers ~69 years from the chosen epoch.
//! - 12-bit node id (up to 4096 generators in a mesh).
//! - 10-bit per-millisecond sequence (up to 1024 ids per node per ms).
//!
//! `Generator.next` is strictly monotonic for a single generator: ids minted
//! later never compare less than ids minted earlier, even if the supplied clock
//! moves backwards or stalls. When the 10-bit sequence overflows within one
//! millisecond, the generator deterministically advances its internal clock to
//! the next millisecond instead of sleeping, so it never blocks.

const std = @import("std");

const testing = std.testing;

/// Bit widths of each field.
pub const timestamp_bits: u6 = 42;
pub const node_bits: u6 = 12;
pub const seq_bits: u6 = 10;

/// Bit offsets (shift amounts) of each field within the 64-bit id.
pub const seq_shift: u6 = 0;
pub const node_shift: u6 = seq_bits;
pub const timestamp_shift: u6 = seq_bits + node_bits;

/// Inclusive maximum values for each field.
pub const max_node: u12 = std.math.maxInt(u12);
pub const max_seq: u10 = std.math.maxInt(u10);
pub const max_timestamp: u64 = (@as(u64, 1) << timestamp_bits) - 1;

const node_mask: u64 = @as(u64, max_node);
const seq_mask: u64 = @as(u64, max_seq);
const timestamp_mask: u64 = max_timestamp;

/// A per-node snowflake id generator.
///
/// One `Generator` is intended to be owned by a single logical worker / node.
/// It is not internally synchronized; callers that share one across threads
/// must provide their own mutual exclusion.
pub const Generator = struct {
    node: u12,
    epoch_ms: i64,
    last_ms: i64,
    seq: u10,

    /// Create a generator for `node` measuring time relative to `epoch_ms`
    /// (a Unix-millisecond timestamp). `last_ms` starts below any real time so
    /// the very first `next` is accepted as-is.
    pub fn init(node: u12, epoch_ms: i64) Generator {
        return .{
            .node = node,
            .epoch_ms = epoch_ms,
            .last_ms = std.math.minInt(i64),
            .seq = 0,
        };
    }

    /// Mint the next id given the current wall-clock `now_ms` (Unix ms).
    ///
    /// Guarantees, in order of precedence:
    ///   1. Strictly monotonic output for this generator.
    ///   2. Multiple calls within the same millisecond differ only in `seq`.
    ///   3. On `seq` overflow the internal clock advances by 1ms (no sleep).
    ///   4. A clock that moves backwards is clamped to the last observed ms.
    pub fn next(self: *Generator, now_ms: i64) u64 {
        // Never travel backwards: clamp a regressed clock to the last value.
        var current = if (now_ms > self.last_ms) now_ms else self.last_ms;

        if (current == self.last_ms) {
            // Same millisecond as the previous id: bump the sequence.
            if (self.seq == max_seq) {
                // Sequence exhausted for this ms — deterministically roll over
                // into the next millisecond rather than blocking.
                current += 1;
                self.seq = 0;
            } else {
                self.seq += 1;
            }
        } else {
            // A fresh, strictly-newer millisecond: restart the sequence.
            self.seq = 0;
        }

        self.last_ms = current;
        return compose(current - self.epoch_ms, self.node, self.seq);
    }

    /// Reconstruct the Unix-millisecond timestamp encoded in `id`.
    pub fn timestampOf(self: Generator, id: u64) i64 {
        return timestampOfEpoch(id, self.epoch_ms);
    }

    /// Extract the node id encoded in `id`.
    pub fn nodeOf(self: Generator, id: u64) u12 {
        _ = self;
        return decodeNode(id);
    }

    /// Extract the per-ms sequence encoded in `id`.
    pub fn seqOf(self: Generator, id: u64) u10 {
        _ = self;
        return decodeSeq(id);
    }
};

/// Assemble a raw id from already-relative timestamp, node, and sequence.
fn compose(relative_ms: i64, node: u12, seq: u10) u64 {
    std.debug.assert(relative_ms >= 0);
    const ts: u64 = @as(u64, @intCast(relative_ms)) & timestamp_mask;
    return (ts << timestamp_shift) |
        (@as(u64, node) << node_shift) |
        (@as(u64, seq) << seq_shift);
}

/// Decode the raw (epoch-relative) millisecond field of `id`.
pub fn relativeTimestampOf(id: u64) u64 {
    return (id >> timestamp_shift) & timestamp_mask;
}

/// Decode the absolute Unix-millisecond timestamp of `id` given `epoch_ms`.
pub fn timestampOfEpoch(id: u64, epoch_ms: i64) i64 {
    return @as(i64, @intCast(relativeTimestampOf(id))) + epoch_ms;
}

/// Decode the node id of `id`.
pub fn decodeNode(id: u64) u12 {
    return @intCast((id >> node_shift) & node_mask);
}

/// Decode the per-ms sequence of `id`.
pub fn decodeSeq(id: u64) u10 {
    return @intCast((id >> seq_shift) & seq_mask);
}

test "field layout never overlaps and stays within 64 bits" {
    const total: u32 = @as(u32, timestamp_bits) + node_bits + seq_bits;
    try testing.expectEqual(@as(u32, 64), total);
    try testing.expectEqual(timestamp_shift, node_shift + node_bits);
    try testing.expectEqual(node_shift, seq_shift + seq_bits);
}

test "monotonic across stalled, advancing, and regressed clocks" {
    var gen = Generator.init(7, 1_700_000_000_000);
    var prev: u64 = 0;
    // Stalled clock: every call shares one ms.
    for (0..50) |_| {
        const id = gen.next(1_700_000_000_500);
        try testing.expect(id > prev);
        prev = id;
    }
    // Advancing clock.
    for (1..50) |i| {
        const id = gen.next(1_700_000_000_500 + @as(i64, @intCast(i)));
        try testing.expect(id > prev);
        prev = id;
    }
    // Regressed clock must not produce a smaller id.
    const id = gen.next(1_000_000_000_000);
    try testing.expect(id > prev);
}

test "same millisecond ids differ only by sequence" {
    const epoch: i64 = 1_700_000_000_000;
    var gen = Generator.init(3, epoch);
    const a = gen.next(epoch + 42);
    const b = gen.next(epoch + 42);
    const c = gen.next(epoch + 42);
    try testing.expectEqual(@as(u10, 0), decodeSeq(a));
    try testing.expectEqual(@as(u10, 1), decodeSeq(b));
    try testing.expectEqual(@as(u10, 2), decodeSeq(c));
    // Identical timestamp + node, so only the sequence bits change.
    try testing.expectEqual(relativeTimestampOf(a), relativeTimestampOf(c));
    try testing.expectEqual(decodeNode(a), decodeNode(c));
}

test "decode round-trips timestamp, node, and sequence" {
    const epoch: i64 = 1_600_000_000_000;
    const node: u12 = 2025;
    var gen = Generator.init(node, epoch);
    const now: i64 = epoch + 123_456;
    const id = gen.next(now);
    try testing.expectEqual(now, gen.timestampOf(id));
    try testing.expectEqual(now, timestampOfEpoch(id, epoch));
    try testing.expectEqual(node, gen.nodeOf(id));
    try testing.expectEqual(@as(u10, 0), gen.seqOf(id));
}

test "sequence overflow advances the millisecond deterministically" {
    const epoch: i64 = 1_700_000_000_000;
    var gen = Generator.init(1, epoch);
    const fixed = epoch + 10;
    // Drain the full 1024-id budget for this ms (seq 0..1023).
    var last: u64 = 0;
    for (0..@as(usize, max_seq) + 1) |i| {
        last = gen.next(fixed);
        try testing.expectEqual(@as(u10, @intCast(i)), decodeSeq(last));
        try testing.expectEqual(fixed, gen.timestampOf(last));
    }
    // The 1025th call overflows: clock rolls to the next ms, seq resets to 0.
    const overflow = gen.next(fixed);
    try testing.expectEqual(@as(u10, 0), decodeSeq(overflow));
    try testing.expectEqual(fixed + 1, gen.timestampOf(overflow));
    try testing.expect(overflow > last);
}

test "node bits are isolated from timestamp and sequence" {
    const epoch: i64 = 0;
    var gen = Generator.init(max_node, epoch);
    const id = gen.next(epoch + 999);
    try testing.expectEqual(max_node, decodeNode(id));
    try testing.expectEqual(@as(i64, 999), gen.timestampOf(id));
}
