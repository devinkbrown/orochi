// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free media send pacer.
//!
//! Callers supply a monotonic microsecond clock. The pacer never reads time
//! itself and keeps all accounting in integer byte budgets.

const std = @import("std");

const us_per_sec: u128 = 1_000_000;

fn ceilDivU128(n: u128, d: u128) u128 {
    std.debug.assert(d > 0);
    if (n == 0) return 0;
    return (n - 1) / d + 1;
}

pub const Pacer = struct {
    target_bps: u64,
    budget_bytes: i64,
    last_us: i64,
    max_burst_bytes: u32,

    pub fn init(target_bps: u64, max_burst_bytes: u32, now_us: i64) Pacer {
        return .{
            .target_bps = target_bps,
            .budget_bytes = max_burst_bytes,
            .last_us = now_us,
            .max_burst_bytes = max_burst_bytes,
        };
    }

    pub fn setTarget(self: *Pacer, bps: u64) void {
        self.target_bps = bps;
    }

    fn byteRate(self: Pacer) u64 {
        return self.target_bps / 8;
    }

    const Refilled = struct {
        budget_bytes: i64,
        last_us: i64,
    };

    fn refilled(self: Pacer, now_us: i64) Refilled {
        if (now_us <= self.last_us) {
            return .{ .budget_bytes = self.budget_bytes, .last_us = self.last_us };
        }

        const elapsed_us: u64 = @intCast(now_us - self.last_us);
        const bytes_per_sec = self.byteRate();
        if (bytes_per_sec == 0) {
            return .{ .budget_bytes = self.budget_bytes, .last_us = self.last_us };
        }

        const added_u128 = (@as(u128, bytes_per_sec) * @as(u128, elapsed_us)) / us_per_sec;
        const added: i128 = @intCast(added_u128);
        const cap: i128 = @intCast(self.max_burst_bytes);
        const next = @as(i128, self.budget_bytes) + added;

        if (next >= cap) {
            return .{ .budget_bytes = @intCast(cap), .last_us = now_us };
        }

        const used_us = (added_u128 * us_per_sec) / @as(u128, bytes_per_sec);
        return .{
            .budget_bytes = @intCast(next),
            .last_us = self.last_us + @as(i64, @intCast(used_us)),
        };
    }

    fn refill(self: *Pacer, now_us: i64) void {
        const next = self.refilled(now_us);
        self.budget_bytes = next.budget_bytes;
        self.last_us = next.last_us;
    }

    /// Refill the bucket up to now and return whether a packet of `size` bytes
    /// may be sent now; if yes, debit it.
    pub fn tryConsume(self: *Pacer, size: u32, now_us: i64) bool {
        self.refill(now_us);
        if (size == 0) return true;
        if (self.budget_bytes <= 0) return false;

        self.budget_bytes -= @intCast(size);
        return true;
    }

    /// Microseconds until `size` bytes could be sent (0 if now).
    pub fn delayUntilUs(self: *const Pacer, size: u32, now_us: i64) i64 {
        if (size == 0) return 0;

        const budget = self.refilled(now_us).budget_bytes;
        if (budget > 0) return 0;

        const bytes_per_sec = self.byteRate();
        if (bytes_per_sec == 0) return std.math.maxInt(i64);

        const deficit: u128 = @intCast(1 - budget);
        const wait_us = ceilDivU128(deficit * us_per_sec, bytes_per_sec);
        if (wait_us > std.math.maxInt(i64)) return std.math.maxInt(i64);
        return @intCast(wait_us);
    }
};

const testing = std.testing;

test "media pacer: initial packet passes then immediate second packet is paced" {
    var pacer = Pacer.init(1_000_000, 600, 0);

    try testing.expect(pacer.tryConsume(1200, 0));
    try testing.expectEqual(@as(i64, -600), pacer.budget_bytes);
    try testing.expect(!pacer.tryConsume(1200, 0));

    const delay_us = pacer.delayUntilUs(1200, 0);
    try testing.expect(delay_us > 0);
    try testing.expect(!pacer.tryConsume(1200, delay_us - 1));
    try testing.expect(pacer.tryConsume(1200, delay_us));
}

test "media pacer: sustained simulated throughput stays near target" {
    var pacer = Pacer.init(1_000_000, 1500, 0);
    var now_us: i64 = 0;
    var sent: u64 = 0;

    while (now_us < 1_000_000) {
        if (pacer.tryConsume(1000, now_us)) {
            sent += 1000;
        } else {
            const delay_us = pacer.delayUntilUs(1000, now_us);
            try testing.expect(delay_us > 0);
            now_us += delay_us;
        }
    }

    const target_bytes_per_sec = 1_000_000 / 8;
    try testing.expect(sent >= target_bytes_per_sec);
    try testing.expect(sent <= target_bytes_per_sec + pacer.max_burst_bytes + 1000);
}

test "media pacer: setTarget changes recovery rate" {
    var pacer = Pacer.init(1_000_000, 600, 0);
    try testing.expect(pacer.tryConsume(1200, 0));

    const one_mbps_delay = pacer.delayUntilUs(1200, 0);
    pacer.setTarget(2_000_000);
    const two_mbps_delay = pacer.delayUntilUs(1200, 0);

    try testing.expect(two_mbps_delay > 0);
    try testing.expect(two_mbps_delay < one_mbps_delay);
    try testing.expect(!pacer.tryConsume(1200, two_mbps_delay - 1));
    try testing.expect(pacer.tryConsume(1200, two_mbps_delay));
}

test "media pacer: refill caps at max burst" {
    var pacer = Pacer.init(1_000_000, 900, 0);

    try testing.expect(pacer.tryConsume(500, 0));
    try testing.expectEqual(@as(i64, 400), pacer.budget_bytes);

    try testing.expect(pacer.tryConsume(100, 1_000_000));
    try testing.expectEqual(@as(i64, 800), pacer.budget_bytes);
}
