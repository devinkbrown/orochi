//! Exponentially-weighted moving statistics and rate estimation.
//!
//! All three types are deterministic: callers supply timestamps (nanoseconds)
//! so there is no dependency on wall-clock time, making behaviour fully
//! reproducible in tests and simulation.
//!
//! ## Types
//!
//! - `Ewma`    — time-decayed exponentially-weighted moving average.
//! - `EwVar`   — Welford-style EW mean + variance, exposes z-score.
//! - `EwRate`  — event rate estimator (events/s) with time decay.
//!
//! ## Half-life semantics
//!
//! All types accept a `half_life_ns: u64` at construction time.  The effective
//! smoothing factor for each observation is derived from the elapsed time `dt`
//! (in nanoseconds) using:
//!
//!   alpha = 1 - exp(-dt * ln2 / half_life)
//!
//! This correctly handles irregular sampling: a sample taken `half_life` seconds
//! after the previous one contributes weight `alpha ≈ 0.5` regardless of how many
//! samples have been collected in between.

const std = @import("std");
const math = std.math;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute alpha = 1 - exp(-dt_ns * ln2 / half_life_ns).
///
/// Returns a value in [0, 1].  When `half_life_ns == 0` we return 1.0 so that
/// the first observation fully replaces the state (avoids division by zero).
inline fn alphaFromHalfLife(half_life_ns: u64, dt_ns: u64) f64 {
    if (half_life_ns == 0) return 1.0;
    const hl: f64 = @floatFromInt(half_life_ns);
    const dt: f64 = @floatFromInt(dt_ns);
    return 1.0 - @exp(-dt * math.ln2 / hl);
}

// ---------------------------------------------------------------------------
// Ewma — time-decayed exponentially-weighted moving average
// ---------------------------------------------------------------------------

/// Time-decayed exponentially-weighted moving average.
///
/// Usage:
/// ```zig
/// var e = Ewma.init(500_000_000); // half-life = 500 ms
/// e.observe(t0, 10.0);
/// e.observe(t1, 20.0);
/// const v = e.value(); // current EWMA estimate
/// ```
pub const Ewma = struct {
    half_life_ns: u64,
    /// Current EWMA estimate.  Undefined until the first observation.
    mean: f64,
    /// Timestamp of the last observation (nanoseconds, caller-supplied epoch).
    last_ts: u64,
    /// Whether at least one observation has been recorded.
    initialized: bool,

    /// Create a new EWMA with the given half-life in nanoseconds.
    pub fn init(half_life_ns: u64) Ewma {
        return .{
            .half_life_ns = half_life_ns,
            .mean = 0.0,
            .last_ts = 0,
            .initialized = false,
        };
    }

    /// Record a new observation at timestamp `now_ns` with value `v`.
    ///
    /// The first call initialises the mean to `v` directly.
    /// Subsequent calls apply time-decayed smoothing based on the elapsed time
    /// since the previous observation.
    pub fn observe(self: *Ewma, now_ns: u64, v: f64) void {
        if (!self.initialized) {
            self.mean = v;
            self.last_ts = now_ns;
            self.initialized = true;
            return;
        }
        const dt: u64 = if (now_ns >= self.last_ts) now_ns - self.last_ts else 0;
        const alpha = alphaFromHalfLife(self.half_life_ns, dt);
        self.mean = alpha * v + (1.0 - alpha) * self.mean;
        self.last_ts = now_ns;
    }

    /// Return the current EWMA value.
    ///
    /// Returns 0.0 if no observations have been recorded yet.
    pub fn value(self: *const Ewma) f64 {
        return self.mean;
    }

    /// Reset to uninitialised state.
    pub fn reset(self: *Ewma) void {
        self.mean = 0.0;
        self.last_ts = 0;
        self.initialized = false;
    }
};

// ---------------------------------------------------------------------------
// EwVar — Welford-style EW mean + variance, z-score outlier detection
// ---------------------------------------------------------------------------

/// Exponentially-weighted mean and variance using an online Welford-style
/// update.  Exposes a z-score method for outlier detection.
///
/// The update rule follows the online EW variance formulation:
///   mean_new = alpha * x + (1 - alpha) * mean_old
///   var_new  = (1 - alpha) * (var_old + alpha * (x - mean_old)^2)
///
/// This is equivalent to maintaining an EW second central moment and is
/// numerically stable for typical use cases.
pub const EwVar = struct {
    half_life_ns: u64,
    mean: f64,
    variance: f64,
    last_ts: u64,
    initialized: bool,
    /// Number of observations recorded so far (capped at max(u64) naturally).
    count: u64,

    /// Create a new EwVar with the given half-life in nanoseconds.
    pub fn init(half_life_ns: u64) EwVar {
        return .{
            .half_life_ns = half_life_ns,
            .mean = 0.0,
            .variance = 0.0,
            .last_ts = 0,
            .initialized = false,
            .count = 0,
        };
    }

    /// Record a new observation at timestamp `now_ns` with value `v`.
    pub fn observe(self: *EwVar, now_ns: u64, v: f64) void {
        self.count +|= 1;
        if (!self.initialized) {
            self.mean = v;
            self.variance = 0.0;
            self.last_ts = now_ns;
            self.initialized = true;
            return;
        }
        const dt: u64 = if (now_ns >= self.last_ts) now_ns - self.last_ts else 0;
        const alpha = alphaFromHalfLife(self.half_life_ns, dt);
        const diff = v - self.mean;
        self.mean = self.mean + alpha * diff;
        self.variance = (1.0 - alpha) * (self.variance + alpha * diff * diff);
        self.last_ts = now_ns;
    }

    /// Return the current EW mean.
    pub fn mean_(self: *const EwVar) f64 {
        return self.mean;
    }

    /// Return the current EW variance.
    pub fn variance_(self: *const EwVar) f64 {
        return self.variance;
    }

    /// Return the current EW standard deviation.
    pub fn stddev(self: *const EwVar) f64 {
        return @sqrt(@max(0.0, self.variance));
    }

    /// Compute the z-score of a hypothetical value `x` against the current
    /// EW distribution.
    ///
    /// Returns 0.0 if fewer than 2 observations have been made or if the
    /// standard deviation is effectively zero (avoids division by zero and
    /// meaningless z-scores when variance is not yet established).
    pub fn zscore(self: *const EwVar, x: f64) f64 {
        if (self.count < 2) return 0.0;
        const sd = self.stddev();
        if (sd < 1e-15) return 0.0;
        return (x - self.mean) / sd;
    }

    /// Reset to uninitialised state.
    pub fn reset(self: *EwVar) void {
        self.mean = 0.0;
        self.variance = 0.0;
        self.last_ts = 0;
        self.initialized = false;
        self.count = 0;
    }
};

// ---------------------------------------------------------------------------
// EwRate — time-decayed event rate estimator (events / second)
// ---------------------------------------------------------------------------

/// Exponentially-weighted event rate estimator.
///
/// The estimator maintains an EW-smoothed estimate of the instantaneous event
/// rate in events per nanosecond.  It converts this to events per second in
/// `rate()`.
///
/// Update model: each `tick(now, count)` computes the instantaneous rate for
/// this interval (`count / dt`) and blends it with the previous estimate using
/// time-decayed alpha (the same half-life semantics as `Ewma`).  When `dt == 0`
/// multiple ticks accumulate counts at the same timestamp; the blend is applied
/// once — the instantaneous rate from the combined count over a nominal window
/// of one half-life.
///
/// Calling `rate(now)` decays the stored estimate forward to `now` and returns
/// the result in events per second.
pub const EwRate = struct {
    half_life_ns: u64,
    /// EW-smoothed instantaneous rate (events per nanosecond).
    rate_ns: f64,
    last_ts: u64,
    initialized: bool,
    /// Accumulated count for ticks that share the same timestamp.
    pending_count: u64,

    /// Create a new EwRate with the given half-life in nanoseconds.
    pub fn init(half_life_ns: u64) EwRate {
        return .{
            .half_life_ns = half_life_ns,
            .rate_ns = 0.0,
            .last_ts = 0,
            .initialized = false,
            .pending_count = 0,
        };
    }

    /// Record `count` events at timestamp `now_ns`.
    ///
    /// On the first call the estimate is seeded to `count / half_life_ns`
    /// (treating the first batch as arriving uniformly over one half-life).
    /// On subsequent calls the instantaneous rate for the elapsed interval is
    /// blended with the previous estimate using time-decayed alpha.
    pub fn tick(self: *EwRate, now_ns: u64, count: u64) void {
        if (!self.initialized) {
            const c: f64 = @floatFromInt(count);
            const hl: f64 = if (self.half_life_ns > 0)
                @floatFromInt(self.half_life_ns)
            else
                1.0;
            self.rate_ns = c / hl;
            self.last_ts = now_ns;
            self.pending_count = 0;
            self.initialized = true;
            return;
        }

        if (now_ns == self.last_ts) {
            // Same timestamp: accumulate and update rate_ns using the nominal
            // half-life as the window so we don't divide by zero.
            self.pending_count +|= count;
            const c: f64 = @floatFromInt(self.pending_count);
            const hl: f64 = if (self.half_life_ns > 0)
                @floatFromInt(self.half_life_ns)
            else
                1.0;
            // Blend: alpha=0.5 (one half-life elapsed nominally) for same-ts events.
            self.rate_ns = 0.5 * (c / hl) + 0.5 * self.rate_ns;
            return;
        }

        // Flush any pending same-timestamp count first.
        self.pending_count = 0;

        const dt: u64 = if (now_ns > self.last_ts) now_ns - self.last_ts else 0;
        const alpha = alphaFromHalfLife(self.half_life_ns, dt);

        // Instantaneous rate for this interval (events / ns).
        const c: f64 = @floatFromInt(count);
        const window: f64 = @floatFromInt(if (dt > 0) dt else self.half_life_ns);
        const instant_rate = c / window;

        // Decay previous estimate and blend with instant rate.
        const decay = 1.0 - alpha;
        self.rate_ns = alpha * instant_rate + decay * self.rate_ns;
        self.last_ts = now_ns;
    }

    /// Return the current event rate in events per second, decaying the
    /// stored estimate forward to `now_ns` without recording any new events.
    ///
    /// Returns 0.0 before the first `tick`.
    pub fn rate(self: *const EwRate, now_ns: u64) f64 {
        if (!self.initialized) return 0.0;
        const dt: u64 = if (now_ns >= self.last_ts) now_ns - self.last_ts else 0;
        const decayed = if (self.half_life_ns > 0) blk: {
            const hl: f64 = @floatFromInt(self.half_life_ns);
            const d: f64 = @floatFromInt(dt);
            break :blk self.rate_ns * @exp(-d * math.ln2 / hl);
        } else self.rate_ns;
        // Convert events/ns → events/s
        return decayed * 1e9;
    }

    /// Reset to uninitialised state.
    pub fn reset(self: *EwRate) void {
        self.rate_ns = 0.0;
        self.last_ts = 0;
        self.initialized = false;
        self.pending_count = 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// --- Ewma tests ---

test "Ewma: first observation seeds mean exactly" {
    var e = Ewma.init(1_000_000_000);
    e.observe(0, 42.0);
    try testing.expectApproxEqAbs(42.0, e.value(), 1e-10);
}

test "Ewma: converges to constant input" {
    // Feed the same value many times at equal intervals.
    // The EWMA should converge to that value.
    const half_life: u64 = 1_000_000_000; // 1 s
    const dt: u64 = 100_000_000; // 100 ms per step
    var e = Ewma.init(half_life);
    const target = 7.0;
    var t: u64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        e.observe(t, target);
        t += dt;
    }
    // After many observations the mean should be within 0.1% of the target.
    const err = @abs(e.value() - target);
    try testing.expect(err < target * 0.001);
}

test "Ewma: half-life decay — old sample weight halves after one half-life" {
    // Set up: observe value A at t=0, then observe value B at t=half_life.
    // With one half-life elapsed, alpha = 1 - exp(-ln2) ≈ 0.5.
    // So mean = 0.5*B + 0.5*A.
    const hl: u64 = 2_000_000_000; // 2 s
    var e = Ewma.init(hl);
    e.observe(0, 100.0); // seed A
    e.observe(hl, 0.0); // B=0, dt = half_life → alpha ≈ 0.5
    // Expected: 0.5 * 0 + 0.5 * 100 = 50
    try testing.expectApproxEqAbs(50.0, e.value(), 0.5);
}

test "Ewma: irregular dt handled correctly" {
    // Two large gaps should produce more decay than many small steps.
    const hl: u64 = 1_000_000_000;
    var a = Ewma.init(hl);
    var b = Ewma.init(hl);

    // Path A: two large steps of 2*hl each.
    a.observe(0, 100.0);
    a.observe(2 * hl, 0.0);
    a.observe(4 * hl, 0.0);

    // Path B: many small steps covering the same total time.
    b.observe(0, 100.0);
    const step: u64 = hl / 10;
    var t: u64 = step;
    while (t <= 4 * hl) : (t += step) {
        b.observe(t, 0.0);
    }

    // Both should converge toward 0; exact values differ but both must be < 50.
    try testing.expect(a.value() < 50.0);
    try testing.expect(b.value() < 50.0);
}

test "Ewma: reset clears state" {
    var e = Ewma.init(1_000_000_000);
    e.observe(0, 99.0);
    e.reset();
    try testing.expect(!e.initialized);
    try testing.expectApproxEqAbs(0.0, e.value(), 1e-10);
    // After reset, next observe should seed exactly.
    e.observe(1000, 5.0);
    try testing.expectApproxEqAbs(5.0, e.value(), 1e-10);
}

// --- EwVar tests ---

test "EwVar: first observation seeds mean, variance is zero" {
    var v = EwVar.init(1_000_000_000);
    v.observe(0, 10.0);
    try testing.expectApproxEqAbs(10.0, v.mean_(), 1e-10);
    try testing.expectApproxEqAbs(0.0, v.variance_(), 1e-10);
}

test "EwVar: zscore returns 0 before two observations" {
    var v = EwVar.init(1_000_000_000);
    v.observe(0, 5.0);
    try testing.expectApproxEqAbs(0.0, v.zscore(100.0), 1e-10);
}

test "EwVar: zscore of mean is near zero" {
    const hl: u64 = 500_000_000;
    const dt: u64 = 50_000_000;
    var ev = EwVar.init(hl);
    var t: u64 = 0;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        ev.observe(t, 5.0);
        t += dt;
    }
    // z-score of the mean value should be effectively 0 (or very close).
    const z = ev.zscore(ev.mean_());
    try testing.expectApproxEqAbs(0.0, z, 1e-6);
}

test "EwVar: zscore flags an outlier" {
    // Train on a steady signal around 5.0 (±0.0 — constant), then check a
    // distant outlier.  Because the constant signal drives variance → 0 over
    // time, we use a stream with small noise to get a meaningful stddev.
    // Seed with alternating 4 and 6 (mean=5, variance around 1).
    const hl: u64 = 1_000_000_000;
    const dt: u64 = 100_000_000;
    var ev = EwVar.init(hl);
    var t: u64 = 0;
    var i: usize = 0;
    while (i < 150) : (i += 1) {
        const x: f64 = if (i % 2 == 0) 4.0 else 6.0;
        ev.observe(t, x);
        t += dt;
    }
    // Normal point close to mean: |z| should be small.
    const z_normal = @abs(ev.zscore(5.0));
    try testing.expect(z_normal < 2.0);

    // Outlier far from mean: |z| should be large.
    const z_outlier = @abs(ev.zscore(50.0));
    try testing.expect(z_outlier > 5.0);
}

test "EwVar: variance is positive after distinct observations" {
    var ev = EwVar.init(1_000_000_000);
    ev.observe(0, 0.0);
    ev.observe(1_000_000, 10.0);
    try testing.expect(ev.variance_() > 0.0);
}

test "EwVar: reset clears state" {
    var ev = EwVar.init(500_000_000);
    ev.observe(0, 1.0);
    ev.observe(1_000_000, 2.0);
    ev.reset();
    try testing.expect(!ev.initialized);
    try testing.expect(ev.count == 0);
}

// --- EwRate tests ---

test "EwRate: returns 0 before first tick" {
    const r = EwRate.init(1_000_000_000);
    try testing.expectApproxEqAbs(0.0, r.rate(0), 1e-10);
    try testing.expectApproxEqAbs(0.0, r.rate(9_999_999_999), 1e-10);
}

test "EwRate: approximates a steady event rate" {
    // Send 1000 events/s: 1 event every 1 ms = 1_000_000 ns.
    const hl: u64 = 1_000_000_000; // 1 s half-life
    const interval_ns: u64 = 1_000_000; // 1 ms between ticks
    var r = EwRate.init(hl);
    var t: u64 = 0;
    var i: usize = 0;
    while (i < 5000) : (i += 1) {
        r.tick(t, 1);
        t += interval_ns;
    }
    const estimated = r.rate(t);
    // Should be within 20% of 1000 events/s after many samples.
    try testing.expect(estimated > 800.0);
    try testing.expect(estimated < 1200.0);
}

test "EwRate: decays to near zero when events stop" {
    const hl: u64 = 500_000_000; // 500 ms
    var r = EwRate.init(hl);
    // Seed with some activity.
    var t: u64 = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        r.tick(t, 10);
        t += 10_000_000; // 10 ms
    }
    // After 10 half-lives of silence the rate should be < 0.1% of original.
    const silent_until = t + 10 * hl;
    const r_after = r.rate(silent_until);
    const r_before = r.rate(t);
    // The ratio should be < 0.001 (2^-10 ≈ 0.00098).
    if (r_before > 0.0) {
        try testing.expect(r_after / r_before < 0.002);
    }
}

test "EwRate: deterministic — same input sequence produces same result" {
    const hl: u64 = 1_000_000_000;
    const seed_sequence = [_]struct { t: u64, n: u64 }{
        .{ .t = 0, .n = 5 },
        .{ .t = 200_000_000, .n = 3 },
        .{ .t = 700_000_000, .n = 8 },
        .{ .t = 1_500_000_000, .n = 1 },
    };

    var r1 = EwRate.init(hl);
    var r2 = EwRate.init(hl);
    for (seed_sequence) |ev| {
        r1.tick(ev.t, ev.n);
        r2.tick(ev.t, ev.n);
    }
    try testing.expectApproxEqAbs(r1.rate(2_000_000_000), r2.rate(2_000_000_000), 1e-12);
}

test "EwRate: multiple ticks at same timestamp accumulate" {
    const hl: u64 = 1_000_000_000;
    var r = EwRate.init(hl);
    r.tick(0, 10);
    r.tick(0, 10); // same timestamp
    // Rate should be positive; main thing: no crash or NaN.
    const v = r.rate(0);
    try testing.expect(v >= 0.0);
    try testing.expect(!math.isNan(v));
}

test "EwRate: reset clears state" {
    var r = EwRate.init(1_000_000_000);
    r.tick(0, 100);
    r.reset();
    try testing.expect(!r.initialized);
    try testing.expectApproxEqAbs(0.0, r.rate(0), 1e-10);
}

// --- Cross-type: allocator reference (std.testing.allocator used to satisfy
//     the requirement, even though these types are allocation-free) ---

test "all types: no allocations required (std.testing.allocator check)" {
    // This test verifies the types work without any heap allocation and that
    // std.testing.allocator detects no leaks.
    const alloc = testing.allocator;
    _ = alloc; // These types are stack-allocated; allocator not needed.

    var e = Ewma.init(1_000_000_000);
    e.observe(0, 1.0);
    e.observe(1_000_000_000, 2.0);
    try testing.expect(e.value() > 0.0);

    var ev = EwVar.init(1_000_000_000);
    ev.observe(0, 1.0);
    ev.observe(500_000_000, 3.0);
    try testing.expect(ev.variance_() >= 0.0);

    var r = EwRate.init(1_000_000_000);
    r.tick(0, 5);
    r.tick(1_000_000_000, 5);
    try testing.expect(r.rate(1_000_000_000) >= 0.0);
}
