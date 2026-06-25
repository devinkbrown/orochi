// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic Cell Rate Algorithm (GCRA) rate limiter.
//!
//! This is a deterministic virtual-scheduling limiter: callers provide time in
//! microseconds, and the limiter never reads a clock.  Internally, timestamps
//! are represented as `microseconds * rate_per_sec`, which keeps non-integer
//! intervals exact without floating point.

const std = @import("std");

const us_per_sec: u128 = 1_000_000;

fn scaledCost(cost: u64) u128 {
    return @as(u128, cost) * us_per_sec;
}

fn scaledNow(now_us: u64, rate_per_sec: u64) u128 {
    return @as(u128, now_us) * @as(u128, rate_per_sec);
}

fn addSat(a: u128, b: u128) u128 {
    const max = std.math.maxInt(u128);
    if (a > max - b) return max;
    return a + b;
}

fn ceilDivU128ByU64(n: u128, d: u64) u64 {
    std.debug.assert(d > 0);
    if (n == 0) return 0;

    const q = (n - 1) / @as(u128, d) + 1;
    const max = std.math.maxInt(u64);
    if (q > max) return max;
    return @intCast(q);
}

fn addSatU64(a: u64, b: u64) u64 {
    const max = std.math.maxInt(u64);
    if (a > max - b) return max;
    return a + b;
}

/// GCRA rate limiter.
///
/// `rate_per_sec` is the sustained rate in arbitrary cost units per second.
/// `burst` is the maximum immediate cost that may be accepted at one instant.
pub const Gcra = struct {
    rate_per_sec: u64,
    burst: u64,
    tat_scaled: u128,

    /// Create a limiter with an empty theoretical arrival time.
    pub fn init(rate_per_sec: u64, burst: u64) Gcra {
        std.debug.assert(rate_per_sec > 0);
        std.debug.assert(burst > 0);

        return .{
            .rate_per_sec = rate_per_sec,
            .burst = burst,
            .tat_scaled = 0,
        };
    }

    /// Attempt to spend `cost` units at `now_us`.
    ///
    /// On success, this advances the theoretical arrival time (TAT).  On
    /// refusal, state is unchanged.  A zero-cost operation is always accepted
    /// and does not advance TAT.
    pub fn allow(self: *Gcra, now_us: u64, cost: u64) bool {
        if (cost == 0) return true;

        const now_scaled = scaledNow(now_us, self.rate_per_sec);
        const base = @max(self.tat_scaled, now_scaled);
        const projected_tat = addSat(base, scaledCost(cost));
        const allowed_limit = addSat(now_scaled, scaledCost(self.burst));

        if (projected_tat > allowed_limit) return false;

        self.tat_scaled = projected_tat;
        return true;
    }

    /// Microseconds until a cost-1 operation would be accepted.
    pub fn retryAfter(self: Gcra, now_us: u64) u64 {
        return self.retryAfterCost(now_us, 1);
    }

    /// Earliest absolute microsecond timestamp for a cost-1 operation.
    pub fn nextAllowedAt(self: Gcra, now_us: u64) u64 {
        return addSatU64(now_us, self.retryAfter(now_us));
    }

    /// Microseconds until an operation with `cost` would be accepted.
    pub fn retryAfterCost(self: Gcra, now_us: u64, cost: u64) u64 {
        if (cost == 0) return 0;

        const now_scaled = scaledNow(now_us, self.rate_per_sec);
        const base = @max(self.tat_scaled, now_scaled);
        const projected_tat = addSat(base, scaledCost(cost));
        const allowed_limit = addSat(now_scaled, scaledCost(self.burst));

        if (projected_tat <= allowed_limit) return 0;
        return ceilDivU128ByU64(projected_tat - allowed_limit, self.rate_per_sec);
    }
};

test "gcra: steady allowance follows configured rate" {
    var limiter = Gcra.init(2, 1);

    try std.testing.expect(limiter.allow(0, 1));
    try std.testing.expect(!limiter.allow(499_999, 1));
    try std.testing.expectEqual(@as(u64, 1), limiter.retryAfter(499_999));
    try std.testing.expectEqual(@as(u64, 500_000), limiter.nextAllowedAt(499_999));

    try std.testing.expect(limiter.allow(500_000, 1));
    try std.testing.expect(!limiter.allow(999_999, 1));
    try std.testing.expect(limiter.allow(1_000_000, 1));
}

test "gcra: bursts are allowed up to the limit then throttled" {
    var limiter = Gcra.init(100, 3);

    try std.testing.expect(limiter.allow(0, 1));
    try std.testing.expect(limiter.allow(0, 1));
    try std.testing.expect(limiter.allow(0, 1));
    try std.testing.expect(!limiter.allow(0, 1));

    try std.testing.expectEqual(@as(u64, 10_000), limiter.retryAfter(0));
    try std.testing.expect(!limiter.allow(9_999, 1));
    try std.testing.expect(limiter.allow(10_000, 1));
}

test "gcra: retryAfter returns zero when a request can pass now" {
    var limiter = Gcra.init(4, 2);

    try std.testing.expectEqual(@as(u64, 0), limiter.retryAfter(0));
    try std.testing.expect(limiter.allow(0, 1));
    try std.testing.expectEqual(@as(u64, 0), limiter.retryAfter(0));
    try std.testing.expect(limiter.allow(0, 1));

    try std.testing.expectEqual(@as(u64, 250_000), limiter.retryAfter(0));
    try std.testing.expectEqual(@as(u64, 250_000), limiter.nextAllowedAt(0));
    try std.testing.expectEqual(@as(u64, 1), limiter.retryAfter(249_999));
    try std.testing.expectEqual(@as(u64, 0), limiter.retryAfter(250_000));
}

test "gcra: cost greater than one consumes proportional burst budget" {
    var limiter = Gcra.init(10, 5);

    try std.testing.expect(limiter.allow(0, 3));
    try std.testing.expect(limiter.allow(0, 2));
    try std.testing.expect(!limiter.allow(0, 1));
    try std.testing.expectEqual(@as(u64, 100_000), limiter.retryAfter(0));

    try std.testing.expect(limiter.allow(100_000, 1));
    try std.testing.expect(!limiter.allow(100_000, 6));
    try std.testing.expectEqual(@as(u64, 200_000), limiter.retryAfterCost(100_000, 2));
    try std.testing.expect(limiter.allow(300_000, 2));
}

test "gcra: cost larger than burst is refused without mutating state" {
    var limiter = Gcra.init(10, 5);

    try std.testing.expect(!limiter.allow(0, 6));
    try std.testing.expectEqual(@as(u64, 0), limiter.retryAfter(0));

    try std.testing.expect(limiter.allow(0, 5));
    try std.testing.expect(!limiter.allow(0, 1));
}

test "gcra: zero cost is deterministic and does not advance tat" {
    var limiter = Gcra.init(1, 1);

    try std.testing.expect(limiter.allow(0, 0));
    try std.testing.expect(limiter.allow(0, 1));
    try std.testing.expect(limiter.allow(999_999, 0));
    try std.testing.expect(!limiter.allow(999_999, 1));
    try std.testing.expectEqual(@as(u64, 1), limiter.retryAfter(999_999));
}

test "gcra: fractional microsecond intervals use exact scaled arithmetic" {
    var limiter = Gcra.init(3, 1);

    try std.testing.expect(limiter.allow(0, 1));
    try std.testing.expect(!limiter.allow(333_333, 1));
    try std.testing.expectEqual(@as(u64, 1), limiter.retryAfter(333_333));
    try std.testing.expect(limiter.allow(333_334, 1));
}

test "gcra: repeated runs with the same timestamps produce the same results" {
    const times = [_]u64{ 0, 0, 0, 100_000, 199_999, 200_000, 450_000, 500_000 };
    const costs = [_]u64{ 1, 2, 1, 1, 1, 2, 3, 1 };
    var a = Gcra.init(5, 4);
    var b = Gcra.init(5, 4);

    for (times, costs) |now_us, cost| {
        const a_wait = a.retryAfterCost(now_us, cost);
        const b_wait = b.retryAfterCost(now_us, cost);
        try std.testing.expectEqual(a_wait, b_wait);
        try std.testing.expectEqual(a.allow(now_us, cost), b.allow(now_us, cost));
    }

    try std.testing.expectEqual(a.tat_scaled, b.tat_scaled);
}
