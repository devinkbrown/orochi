// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Delay-based bandwidth estimator for Orochi's SFU layer.
//!
//! This module turns transport-wide-congestion-control (TWCC) feedback into a
//! target send bitrate that the SFU uses to drive simulcast layer selection.
//! It is a simplified, Google-congestion-control-style estimator: the caller
//! feeds it already-parsed feedback summaries (how many bytes were delivered
//! over a measured interval, plus a smoothed inter-group delay gradient) and
//! the estimator maintains an AIMD target bitrate.
//!
//! The AIMD controller behaves as follows:
//!   - When the measured delay gradient indicates *overuse* (the one-way delay
//!     trend is rising past a threshold), the link is congesting: enter the
//!     `decreasing` state and multiplicatively back off the target.
//!   - When the link is *underused* (delay flat or falling) and the measured
//!     throughput is close to the current target, the path can carry more:
//!     enter the `increasing` state and additively probe upward.
//!   - Otherwise the estimate is `holding` and left unchanged.
//!
//! Like the rest of the proto layer this module is pure, allocation-free, and
//! std-only. It does not import the twcc modules; it operates purely on the
//! arrival deltas already extracted by the feedback parser. The estimate is
//! always clamped to `[min_bps, max_bps]`.
const std = @import("std");

/// Lower bound on the target bitrate. Below this we stop backing off, so even
/// a badly congested path keeps a usable floor for the lowest simulcast layer.
pub const min_bps: u32 = 30_000;
/// Upper bound on the target bitrate. Probing never grows past this ceiling.
pub const max_bps: u32 = 25_000_000;

/// Delay-gradient threshold, in microseconds, above which the path is treated
/// as overused. A positive gradient means the inter-group one-way delay is
/// trending upward (a queue is building); crossing this triggers back-off.
pub const overuse_gradient_us: i64 = 12_000;

/// Multiplicative decrease factor applied on overuse, expressed as a fraction
/// of 256 so the arithmetic stays integer-only. 218/256 == 0.8515625, i.e. an
/// ~15% reduction per overuse signal.
pub const decrease_num: u64 = 218;
pub const decrease_den: u64 = 256;

/// Largest additive probe step per feedback, in bits-per-second. The actual
/// step is the smaller of this and `target/16`, so probing is gentle near the
/// floor and bounded near the ceiling.
pub const max_additive_step_bps: u32 = 8_000;

/// Fraction of the current target the measured throughput must reach before an
/// additive increase is allowed, expressed over 256. 230/256 == ~0.898: the
/// link must be carrying ~90% of the target for us to probe higher.
pub const use_ratio_num: u64 = 230;
pub const use_ratio_den: u64 = 256;

/// Phase of the AIMD controller after the most recent feedback.
pub const State = enum {
    /// Underused and well-utilized: probing the target upward additively.
    increasing,
    /// Overuse detected: multiplicatively backing the target off.
    decreasing,
    /// Neither condition met: the target is left unchanged.
    holding,
};

/// Delay-based AIMD bandwidth estimator. Allocation-free and copyable.
pub const Estimator = struct {
    /// Current target send bitrate in bits per second, always within bounds.
    target_bps: u32,
    /// Controller phase produced by the most recent `onFeedback` call.
    state: State,
    /// Exponentially smoothed delay gradient (microseconds). Retained so a
    /// single noisy sample does not flip the controller; the smoothed value is
    /// what gates the overuse decision.
    smoothed_gradient_us: i64,
    /// Last measured throughput in bits per second, for observability.
    last_throughput_bps: u32,

    /// EMA weight for the smoothed gradient, over 256. 90/256 == ~0.35 weight
    /// on the freshest sample, the rest carried from history.
    const grad_alpha_num: i64 = 90;
    const grad_alpha_den: i64 = 256;

    /// Create an estimator seeded at `start_bps`, clamped into bounds. The
    /// initial state is `holding` until the first feedback arrives.
    pub fn init(start_bps: u32) Estimator {
        return .{
            .target_bps = clamp(start_bps),
            .state = .holding,
            .smoothed_gradient_us = 0,
            .last_throughput_bps = 0,
        };
    }

    /// Fold one feedback summary into the estimate.
    ///
    /// `delivered_bytes` is the number of payload bytes acknowledged as
    /// delivered over the window. `interval_us` is the length of that window in
    /// microseconds. `delay_gradient_us` is the change in inter-group one-way
    /// delay over the window (positive == queue building, negative == draining).
    pub fn onFeedback(
        self: *Estimator,
        delivered_bytes: u64,
        interval_us: i64,
        delay_gradient_us: i64,
    ) void {
        // Smooth the gradient so a single spike does not dominate the decision.
        self.smoothed_gradient_us = emaGradient(self.smoothed_gradient_us, delay_gradient_us);

        const throughput = throughputBps(delivered_bytes, interval_us);
        self.last_throughput_bps = throughput;

        if (self.smoothed_gradient_us > overuse_gradient_us) {
            // Overuse: a queue is building. Multiplicatively back off.
            self.state = .decreasing;
            const reduced = @as(u64, self.target_bps) * decrease_num / decrease_den;
            self.target_bps = clamp(@intCast(reduced));
            return;
        }

        // Underuse: probe upward only if the link is actually well utilized,
        // otherwise raising the target chases capacity we are not using.
        const utilized_floor = @as(u64, self.target_bps) * use_ratio_num / use_ratio_den;
        if (@as(u64, throughput) >= utilized_floor) {
            self.state = .increasing;
            const step = additiveStep(self.target_bps);
            const grown = @as(u64, self.target_bps) + step;
            self.target_bps = clamp(saturatingU32(grown));
            return;
        }

        // Neither overuse nor a confident increase: leave the target alone.
        self.state = .holding;
    }

    /// Current target send bitrate in bits per second.
    pub fn estimate(self: *const Estimator) u32 {
        return self.target_bps;
    }

    /// Exponential moving average of the delay gradient.
    fn emaGradient(prev: i64, sample: i64) i64 {
        const blended = prev * (grad_alpha_den - grad_alpha_num) + sample * grad_alpha_num;
        return @divTrunc(blended, grad_alpha_den);
    }

    /// Additive probe step: min(max_additive_step_bps, target/16).
    fn additiveStep(target: u32) u32 {
        const proportional = target / 16;
        return @min(max_additive_step_bps, proportional);
    }
};

/// Convert delivered bytes over a window into a throughput in bits per second.
/// A non-positive interval yields zero, which keeps the controller from probing
/// on a degenerate window.
fn throughputBps(delivered_bytes: u64, interval_us: i64) u32 {
    if (interval_us <= 0) return 0;
    const bits = delivered_bytes * 8;
    const bps = bits * 1_000_000 / @as(u64, @intCast(interval_us));
    return saturatingU32(bps);
}

/// Clamp a bitrate into `[min_bps, max_bps]`.
fn clamp(bps: u32) u32 {
    return @min(max_bps, @max(min_bps, bps));
}

/// Narrow a u64 to u32, saturating at the u32 ceiling instead of wrapping.
fn saturatingU32(v: u64) u32 {
    return @intCast(@min(v, @as(u64, std.math.maxInt(u32))));
}

test "init clamps the seed into bounds" {
    try std.testing.expectEqual(min_bps, Estimator.init(0).estimate());
    try std.testing.expectEqual(max_bps, Estimator.init(std.math.maxInt(u32)).estimate());
    try std.testing.expectEqual(@as(u32, 300_000), Estimator.init(300_000).estimate());
    try std.testing.expectEqual(State.holding, Estimator.init(300_000).state);
}

test "repeated underuse grows the target monotonically and caps at max" {
    var est = Estimator.init(300_000);
    var prev = est.estimate();

    // Feed well-utilized, flat-delay windows: throughput matches the target,
    // delay gradient is zero (no queueing). This is the increase regime.
    var i: usize = 0;
    while (i < 5000) : (i += 1) {
        const target = est.estimate();
        // Deliver exactly one second's worth of the current target bitrate.
        const delivered_bytes: u64 = @as(u64, target) / 8;
        est.onFeedback(delivered_bytes, 1_000_000, 0);

        const now = est.estimate();
        if (now < max_bps) {
            // Strictly increasing until we hit the ceiling.
            try std.testing.expect(now > prev);
            try std.testing.expectEqual(State.increasing, est.state);
        } else {
            try std.testing.expect(now >= prev);
        }
        try std.testing.expect(now <= max_bps);
        prev = now;
    }

    // After many probes it must have reached (and held at) the ceiling.
    try std.testing.expectEqual(max_bps, est.estimate());
}

test "an overuse feedback drops the target about 15 percent" {
    var est = Estimator.init(1_000_000);
    const before = est.estimate();

    // A single large positive gradient. Smoothing means one sample may not
    // immediately cross the threshold, so drive a few overuse windows and
    // confirm the target is backing off multiplicatively.
    est.onFeedback(0, 1_000_000, 200_000);
    // First sample is smoothed; keep feeding until the controller reacts.
    var reacted = est.state == .decreasing;
    var j: usize = 0;
    while (!reacted and j < 8) : (j += 1) {
        est.onFeedback(0, 1_000_000, 200_000);
        reacted = est.state == .decreasing;
    }
    try std.testing.expect(reacted);
    try std.testing.expectEqual(State.decreasing, est.state);

    const after = est.estimate();
    try std.testing.expect(after < before);

    // One decrease step is ~15% (factor 218/256). Verify a single decreasing
    // transition from a known value lands in the expected neighborhood.
    var fresh = Estimator.init(1_000_000);
    // Pre-load the smoothed gradient so the very next sample crosses cleanly.
    var k: usize = 0;
    while (k < 20) : (k += 1) {
        fresh.onFeedback(0, 1_000_000, 1_000_000); // huge, saturate the EMA
    }
    // Each step multiplies by ~0.8516; just check the ratio of one step.
    var single = Estimator.init(1_000_000);
    single.smoothed_gradient_us = overuse_gradient_us * 4; // force overuse path
    single.onFeedback(0, 1_000_000, overuse_gradient_us * 4);
    const dropped = single.estimate();
    // Expect roughly 851_562 (1_000_000 * 218/256).
    try std.testing.expect(dropped > 840_000 and dropped < 865_000);
}

test "holding keeps the target stable" {
    var est = Estimator.init(2_000_000);
    const before = est.estimate();

    // Delay flat (no overuse) but throughput far below target: the increase
    // gate is not met and there is no overuse, so the controller holds.
    est.onFeedback(1_000, 1_000_000, 0); // trivially small delivery
    try std.testing.expectEqual(State.holding, est.state);
    try std.testing.expectEqual(before, est.estimate());
}

test "target never leaves the configured bounds" {
    // Hammer with overuse from the floor: must never sink below min_bps.
    var low = Estimator.init(min_bps);
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        low.onFeedback(0, 1_000_000, 1_000_000);
        try std.testing.expect(low.estimate() >= min_bps);
        try std.testing.expect(low.estimate() <= max_bps);
    }
    try std.testing.expectEqual(min_bps, low.estimate());

    // Hammer with strong underuse from near the ceiling: must never exceed max.
    var high = Estimator.init(max_bps - 1);
    var j: usize = 0;
    while (j < 1000) : (j += 1) {
        const t = high.estimate();
        high.onFeedback(@as(u64, t) / 8, 1_000_000, -50_000);
        try std.testing.expect(high.estimate() <= max_bps);
        try std.testing.expect(high.estimate() >= min_bps);
    }
    try std.testing.expectEqual(max_bps, high.estimate());
}

test "negative gradient keeps the path in the increase regime" {
    var est = Estimator.init(500_000);
    const before = est.estimate();
    const target = est.estimate();
    est.onFeedback(@as(u64, target) / 8, 1_000_000, -8_000);
    try std.testing.expectEqual(State.increasing, est.state);
    try std.testing.expect(est.estimate() > before);
}

test "degenerate interval yields zero throughput and holds" {
    var est = Estimator.init(700_000);
    const before = est.estimate();
    est.onFeedback(1_000_000_000, 0, 0); // interval_us <= 0 -> zero throughput
    try std.testing.expectEqual(State.holding, est.state);
    try std.testing.expectEqual(before, est.estimate());
}
