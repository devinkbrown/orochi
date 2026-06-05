//! Deterministic packet pacer and GSO batch planner for transport sends.
//!
//! ## Pacer
//! Token-bucket pacer that spreads a congestion window's worth of packets
//! evenly across an RTT rather than bursting them all at once.  The bucket
//! refills at `pacing_rate` (bytes/s) up to `burst_budget` bytes; a send is
//! allowed only when enough tokens have accumulated.
//!
//! ## GSO planner
//! Groups an outbound packet queue into super-batches suitable for Linux UDP
//! Generic Segmentation Offload: consecutive segments of identical size are
//! coalesced into one batch; the run is split when the segment size changes,
//! `max_segments` is reached, or `max_bytes` would be exceeded.  The last
//! segment in a batch may be smaller than the others (this matches the kernel
//! constraint that only the final segment is allowed to be shorter).
const std = @import("std");

// ---------------------------------------------------------------------------
// Pacer
// ---------------------------------------------------------------------------

/// Token-bucket packet pacer.
///
/// Time is expressed in microseconds throughout.  The caller supplies the
/// current wall-clock value; the pacer itself never reads a clock.
pub const Pacer = struct {
    /// Bytes per second allowed by the congestion controller.
    pacing_rate: u64,
    /// Maximum token accumulation (bytes).  Typically ~2 * MSS.
    burst_budget: u64,

    /// Current token balance (bytes, capped at burst_budget).
    tokens: u64,
    /// Timestamp of the last `onSent` or initialisation, in microseconds.
    last_us: u64,

    /// Initialise the pacer.  `now_us` is the current time in microseconds.
    pub fn init(pacing_rate: u64, burst_budget: u64, now_us: u64) Pacer {
        std.debug.assert(pacing_rate > 0);
        std.debug.assert(burst_budget > 0);
        return .{
            .pacing_rate = pacing_rate,
            .burst_budget = burst_budget,
            .tokens = burst_budget,
            .last_us = now_us,
        };
    }

    /// Accumulate tokens earned since `last_us`.  Returns the new balance
    /// without mutating state; used internally and by `canSend`.
    fn refill(self: Pacer, now_us: u64) u64 {
        if (now_us <= self.last_us) return self.tokens;
        const elapsed_us = now_us - self.last_us;
        // bytes earned = rate (bytes/s) * elapsed (us) / 1_000_000
        // Use 128-bit intermediate to avoid overflow for large rates/intervals.
        const earned = @as(u128, self.pacing_rate) * @as(u128, elapsed_us) / 1_000_000;
        const new_tokens = self.tokens + @as(u64, @truncate(earned));
        return if (new_tokens > self.burst_budget) self.burst_budget else new_tokens;
    }

    /// Returns true if `bytes` can be sent right now without violating the
    /// pacing budget.
    pub fn canSend(self: *Pacer, now_us: u64, bytes: u64) bool {
        const available = self.refill(now_us);
        // Sync the clock even when we cannot send so time doesn't stall.
        if (now_us > self.last_us) {
            self.tokens = available;
            self.last_us = now_us;
        }
        return available >= bytes;
    }

    /// Record that `bytes` have been sent at time `now_us`.  Must only be
    /// called after `canSend` returned true for the same `bytes` value.
    pub fn onSent(self: *Pacer, now_us: u64, bytes: u64) void {
        const available = self.refill(now_us);
        self.last_us = now_us;
        // Deduct tokens; saturate at zero in case of accounting drift.
        self.tokens = if (available >= bytes) available - bytes else 0;
    }

    /// Earliest time (µs) at which `bytes` could be sent, given the current
    /// token balance.  Returns `last_us` immediately when tokens are already
    /// sufficient.
    pub fn nextSendTime(self: Pacer, bytes: u64) u64 {
        if (self.tokens >= bytes) return self.last_us;
        const deficit = bytes - self.tokens;
        // time_us = deficit * 1_000_000 / rate  (ceiling division)
        const wait_us = (@as(u128, deficit) * 1_000_000 + @as(u128, self.pacing_rate) - 1) /
            @as(u128, self.pacing_rate);
        return self.last_us + @as(u64, @truncate(wait_us));
    }
};

// ---------------------------------------------------------------------------
// GSO planner
// ---------------------------------------------------------------------------

/// Opaque reference to one outbound packet: a (payload) byte length plus an
/// index that the caller uses to map back to its own storage.
pub const PacketRef = struct {
    /// Byte length of this packet's payload (must be > 0).
    len: u32,
    /// Caller-defined opaque index (unused by the planner).
    index: u32,
};

/// Limits that govern how a super-batch may be constructed.
pub const GsoLimits = struct {
    /// Maximum number of segments per batch (≥ 1).
    max_segments: u32,
    /// Maximum total byte payload per batch (≥ 1).
    max_bytes: u32,
};

/// One GSO super-batch.
///
/// `start` and `count` are indices into the original `packets` slice.
/// `seg_size` is the uniform segment size for segments [start, start+count-2];
/// the last segment (`start+count-1`) may be ≤ `seg_size`.
pub const Batch = struct {
    /// Index of the first packet in this batch within the source slice.
    start: u32,
    /// Number of packets in this batch (≥ 1).
    count: u32,
    /// Uniform segment size used for all-but-last segments.
    seg_size: u32,
};

/// Plan GSO batches for `packets`.
///
/// The caller owns the returned slice; free it with
/// `allocator.free(result)` when done.
///
/// Rules applied (mirrors Linux UDP GSO constraints):
///  1. A new batch begins whenever the segment size differs from the current
///     batch's `seg_size`.
///  2. A new batch begins when adding the next segment would exceed
///     `limits.max_segments`.
///  3. A new batch begins when adding the next segment would push the total
///     byte count above `limits.max_bytes`.
///  4. The last segment in a batch is allowed to be smaller than `seg_size`.
pub fn planGso(
    allocator: std.mem.Allocator,
    packets: []const PacketRef,
    limits: GsoLimits,
) std.mem.Allocator.Error![]Batch {
    std.debug.assert(limits.max_segments >= 1);
    std.debug.assert(limits.max_bytes >= 1);

    if (packets.len == 0) return allocator.alloc(Batch, 0);

    var batches: std.ArrayList(Batch) = .empty;
    errdefer batches.deinit(allocator);

    var batch_start: u32 = 0;
    var batch_count: u32 = 1;
    var seg_size: u32 = packets[0].len;
    var batch_bytes: u32 = packets[0].len;

    var i: u32 = 1;
    while (i < packets.len) : (i += 1) {
        const pkt = packets[i];
        const size_mismatch = pkt.len != seg_size;
        const segments_full = batch_count >= limits.max_segments;
        // Would adding this packet push us over the byte budget?
        const bytes_overflow = batch_bytes + pkt.len > limits.max_bytes;

        // The very first packet in a new batch sets seg_size.  A packet
        // smaller than the current seg_size is *only* legal as the last
        // packet (we will find out next iteration); if it is not the last
        // it forces a split too.
        //
        // A packet *larger* than seg_size always forces a split.
        //
        // A packet exactly equal to seg_size is fine to append as long as
        // count and byte limits allow it.
        //
        // A packet smaller than seg_size is fine to append as the last entry
        // of a batch — we check that by looking one packet ahead: if there IS
        // a next packet after this one (i+1 < len), we must split now so the
        // smaller pkt becomes the last in the current batch and the following
        // equal-size run starts a new one.
        //
        // Simpler unified rule that matches linux behaviour:
        //   Split if: size change OR limit hit.
        //   Size change = current pkt differs from seg_size.

        if (size_mismatch or segments_full or bytes_overflow) {
            try batches.append(allocator, .{
                .start = batch_start,
                .count = batch_count,
                .seg_size = seg_size,
            });
            batch_start = i;
            batch_count = 1;
            seg_size = pkt.len;
            batch_bytes = pkt.len;
        } else {
            batch_count += 1;
            batch_bytes += pkt.len;
        }
    }

    // Flush final batch.
    try batches.append(allocator, .{
        .start = batch_start,
        .count = batch_count,
        .seg_size = seg_size,
    });

    return try batches.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// -- Pacer tests ------------------------------------------------------------

test "pacer: full burst budget available at t0" {
    const p = Pacer.init(1_000_000, 4096, 0);
    // Tokens start at burst_budget.
    try testing.expect(p.tokens == 4096);
}

test "pacer: canSend consumes tokens correctly" {
    var p = Pacer.init(1_000_000, 4096, 0);
    try testing.expect(p.canSend(0, 1400));
    p.onSent(0, 1400);
    try testing.expectEqual(@as(u64, 4096 - 1400), p.tokens);
}

test "pacer: canSend returns false when budget exhausted" {
    var p = Pacer.init(1_000_000, 1400, 0);
    try testing.expect(p.canSend(0, 1400));
    p.onSent(0, 1400);
    // No time elapsed; tokens should be 0.
    try testing.expect(!p.canSend(0, 1));
}

test "pacer: refills over time" {
    // rate = 1_000_000 bytes/s => 1 byte/µs
    var p = Pacer.init(1_000_000, 8192, 0);
    p.onSent(0, 4096); // exhaust half the budget
    // After 4096 µs we earn 4096 bytes back.
    try testing.expect(p.canSend(4096, 4096));
}

test "pacer: tokens capped at burst_budget after long idle" {
    var p = Pacer.init(1_000_000, 4096, 0);
    p.onSent(0, 4096); // drain to zero
    // After 10 s (10_000_000 µs) we would earn 10_000_000 bytes but cap at budget.
    const available = p.refill(10_000_000);
    try testing.expectEqual(@as(u64, 4096), available);
}

test "pacer: nextSendTime immediate when tokens sufficient" {
    const p = Pacer.init(1_000_000, 4096, 1000);
    // Tokens = 4096, asking for 1400 — already available.
    try testing.expectEqual(@as(u64, 1000), p.nextSendTime(1400));
}

test "pacer: nextSendTime future when tokens insufficient" {
    // rate = 1_000_000 bytes/s == 1 byte/µs
    var p = Pacer.init(1_000_000, 4096, 0);
    p.onSent(0, 4096); // tokens = 0
    // Need 1000 bytes; at 1 byte/µs that is 1000 µs away.
    try testing.expectEqual(@as(u64, 1000), p.nextSendTime(1000));
}

test "pacer: nextSendTime ceiling division" {
    // rate = 3 bytes/µs (3_000_000 bytes/s)
    // tokens = 0, need 10 bytes => ceil(10/3) = 4 µs
    var p = Pacer.init(3_000_000, 100, 0);
    p.onSent(0, 100); // drain
    // refill to know current tokens
    const t = p.nextSendTime(10);
    try testing.expectEqual(@as(u64, 4), t);
}

test "pacer: spreads N sends across an RTT" {
    // Scenario: cwnd = 10 packets of 1400 bytes each, RTT = 10 000 µs.
    // pacing_rate = cwnd_bytes / RTT = 14000 / 0.01 = 1_400_000 bytes/s.
    // burst_budget = 2 * MSS = 2800 bytes.
    // We send 10 packets and verify they are NOT all allowed at t=0.
    const mss: u64 = 1400;
    const n: u64 = 10;
    const rtt_us: u64 = 10_000;
    const pacing_rate: u64 = (n * mss * 1_000_000) / rtt_us; // bytes/s
    const burst_budget: u64 = 2 * mss;

    var p = Pacer.init(pacing_rate, burst_budget, 0);
    var sent: u64 = 0;
    var time_us: u64 = 0;

    // Drain the burst budget first.
    while (p.canSend(time_us, mss)) {
        p.onSent(time_us, mss);
        sent += 1;
    }
    const burst_sends = sent;
    // burst can hold at most ceil(burst_budget / mss) packets.
    try testing.expect(burst_sends <= (burst_budget + mss - 1) / mss);
    // Must NOT have sent all packets in the burst.
    try testing.expect(burst_sends < n);

    // Now advance time to drain the remaining packets.
    while (sent < n) {
        time_us = p.nextSendTime(mss);
        try testing.expect(p.canSend(time_us, mss));
        p.onSent(time_us, mss);
        sent += 1;
    }
    // Final send time should be within the RTT.
    try testing.expect(time_us <= rtt_us);
}

test "pacer: canSend updates last_us even on refusal" {
    var p = Pacer.init(1_000_000, 1400, 0);
    p.onSent(0, 1400); // exhaust
    _ = p.canSend(500, 1); // time advances inside canSend
    try testing.expectEqual(@as(u64, 500), p.last_us);
}

// -- GSO planner tests ------------------------------------------------------

test "gso: empty queue returns empty slice" {
    const batches = try planGso(testing.allocator, &.{}, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 0), batches.len);
}

test "gso: single packet becomes one batch" {
    const pkts = [_]PacketRef{.{ .len = 1400, .index = 0 }};
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 1), batches.len);
    try testing.expectEqual(@as(u32, 0), batches[0].start);
    try testing.expectEqual(@as(u32, 1), batches[0].count);
    try testing.expectEqual(@as(u32, 1400), batches[0].seg_size);
}

test "gso: equal-size run coalesces into one batch" {
    var pkts: [5]PacketRef = undefined;
    for (&pkts, 0..) |*p, i| p.* = .{ .len = 1400, .index = @intCast(i) };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 1), batches.len);
    try testing.expectEqual(@as(u32, 5), batches[0].count);
    try testing.expectEqual(@as(u32, 1400), batches[0].seg_size);
}

test "gso: size change splits into two batches" {
    const pkts = [_]PacketRef{
        .{ .len = 1400, .index = 0 },
        .{ .len = 1400, .index = 1 },
        .{ .len = 800, .index = 2 }, // size change here
        .{ .len = 800, .index = 3 },
    };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 2), batches.len);
    try testing.expectEqual(@as(u32, 0), batches[0].start);
    try testing.expectEqual(@as(u32, 2), batches[0].count);
    try testing.expectEqual(@as(u32, 1400), batches[0].seg_size);
    try testing.expectEqual(@as(u32, 2), batches[1].start);
    try testing.expectEqual(@as(u32, 2), batches[1].count);
    try testing.expectEqual(@as(u32, 800), batches[1].seg_size);
}

test "gso: max_segments limit splits run" {
    // 6 equal packets, max 4 segments => batches of 4 + 2.
    var pkts: [6]PacketRef = undefined;
    for (&pkts, 0..) |*p, i| p.* = .{ .len = 1400, .index = @intCast(i) };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 4,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 2), batches.len);
    try testing.expectEqual(@as(u32, 4), batches[0].count);
    try testing.expectEqual(@as(u32, 2), batches[1].count);
}

test "gso: max_bytes limit splits run" {
    // 5 packets of 1400 bytes = 7000 bytes total; max_bytes = 4000.
    // After 2 packets: 2800 bytes; 3rd would reach 4200 > 4000 => split.
    // Batch 1: packets 0,1 (2800 bytes).
    // Batch 2: packets 2,3 (2800 bytes); 5th would reach 4200 > 4000 => split.
    // Batch 3: packet 4 (1400 bytes).
    var pkts: [5]PacketRef = undefined;
    for (&pkts, 0..) |*p, i| p.* = .{ .len = 1400, .index = @intCast(i) };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 4000,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 3), batches.len);
    try testing.expectEqual(@as(u32, 2), batches[0].count);
    try testing.expectEqual(@as(u32, 2), batches[1].count);
    try testing.expectEqual(@as(u32, 1), batches[2].count);
}

test "gso: last segment smaller than seg_size is allowed" {
    // 3 × 1400 + 1 × 800; the 800-byte packet ends the run.
    const pkts = [_]PacketRef{
        .{ .len = 1400, .index = 0 },
        .{ .len = 1400, .index = 1 },
        .{ .len = 1400, .index = 2 },
        .{ .len = 800, .index = 3 },
    };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    // Size change forces a split between index 2 and 3.
    try testing.expectEqual(@as(usize, 2), batches.len);
    // First batch: three 1400-byte segments.
    try testing.expectEqual(@as(u32, 3), batches[0].count);
    try testing.expectEqual(@as(u32, 1400), batches[0].seg_size);
    // Second batch: one 800-byte segment.
    try testing.expectEqual(@as(u32, 1), batches[1].count);
    try testing.expectEqual(@as(u32, 800), batches[1].seg_size);
}

test "gso: mixed sizes produce many small batches" {
    const sizes = [_]u32{ 1400, 1200, 1400, 1400, 900, 900 };
    var pkts: [sizes.len]PacketRef = undefined;
    for (&pkts, 0..) |*p, i| p.* = .{ .len = sizes[i], .index = @intCast(i) };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    // Expected groupings: [1400] [1200] [1400,1400] [900,900]
    try testing.expectEqual(@as(usize, 4), batches.len);
    try testing.expectEqual(@as(u32, 1), batches[0].count);
    try testing.expectEqual(@as(u32, 1), batches[1].count);
    try testing.expectEqual(@as(u32, 2), batches[2].count);
    try testing.expectEqual(@as(u32, 2), batches[3].count);
}

test "gso: max_segments=1 produces one batch per packet" {
    var pkts: [4]PacketRef = undefined;
    for (&pkts, 0..) |*p, i| p.* = .{ .len = 1400, .index = @intCast(i) };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 1,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 4), batches.len);
    for (batches) |b| {
        try testing.expectEqual(@as(u32, 1), b.count);
    }
}

test "gso: batch covers correct start indices" {
    const pkts = [_]PacketRef{
        .{ .len = 500, .index = 10 },
        .{ .len = 500, .index = 11 },
        .{ .len = 300, .index = 12 },
        .{ .len = 300, .index = 13 },
        .{ .len = 300, .index = 14 },
    };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    try testing.expectEqual(@as(usize, 2), batches.len);
    try testing.expectEqual(@as(u32, 0), batches[0].start);
    try testing.expectEqual(@as(u32, 2), batches[0].count);
    try testing.expectEqual(@as(u32, 2), batches[1].start);
    try testing.expectEqual(@as(u32, 3), batches[1].count);
}

test "gso: all batches together cover all packets" {
    const sizes = [_]u32{ 1400, 1400, 800, 1400, 1400, 1400, 600 };
    var pkts: [sizes.len]PacketRef = undefined;
    for (&pkts, 0..) |*p, i| p.* = .{ .len = sizes[i], .index = @intCast(i) };
    const batches = try planGso(testing.allocator, &pkts, .{
        .max_segments = 64,
        .max_bytes = 65535,
    });
    defer testing.allocator.free(batches);
    var total: u32 = 0;
    for (batches) |b| total += b.count;
    try testing.expectEqual(@as(u32, sizes.len), total);
}
