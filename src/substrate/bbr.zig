// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! BBR-style congestion controller (bandwidth + RTT model).
//!
//! Fully deterministic: callers supply timestamps; no real clock is read.
//! Self-contained: no imports of sibling modules, std-only.
//!
//! ## State machine
//!
//! ```
//!  Startup  ──(bw saturated)──▶  Drain  ──(queue empty)──▶  ProbeBW
//!                                                                │
//!                                              (min-rtt stale)──▶  ProbeRTT
//!                                              (ProbeRTT done)──▶  ProbeBW
//! ```
//!
//! ## API
//!
//!   var bbr = Bbr.init(cfg);
//!   bbr.onAck(now_us, delivered_bytes, rtt_us, app_limited);
//!   _ = bbr.pacingRate();
//!   _ = bbr.cwnd();
//!   _ = bbr.phase();

const std = @import("std");
const toml = @import("../proto/toml.zig");

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// BBR phases.
pub const Phase = enum { Startup, Drain, ProbeBW, ProbeRTT };

/// Default pacing-gain cycle used during ProbeBW (8 slots, wraps).
/// Slot 0 probes upward; slot 1 drains; slots 2-7 cruise.
const PACING_GAIN_CYCLE_DEFAULT: [8]f64 = .{
    1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
};

/// High pacing gain for Startup (2 * ln2 ≈ 1.386; BBR spec uses 2 / ln2 ≈ 2.885).
const STARTUP_PACING_GAIN_DEFAULT: f64 = 2.885;
const STARTUP_CWND_GAIN_DEFAULT: f64 = 2.0;
const PROBE_BW_CWND_GAIN_DEFAULT: f64 = 2.0;
const PROBE_RTT_CWND_FRACTION_DEFAULT: f64 = 0.75;

/// Window length for the max-bandwidth filter (RTT rounds).
const BW_WINDOW_LEN_DEFAULT: usize = 10;
/// Window length for the min-RTT filter (microseconds; 10 s default).
const MIN_RTT_WINDOW_US_DEFAULT: u64 = 10_000_000;
/// ProbeRTT duration: hold cwnd at a reduced level for 200 ms.
const PROBE_RTT_DURATION_US_DEFAULT: u64 = 200_000;
/// Minimum cwnd (bytes) to avoid degenerate congestion windows.
const MIN_CWND_BYTES_DEFAULT: u64 = 4 * 1500;
/// Round/cycle duration fallback before the first RTT sample (100 ms).
const PRE_RTT_ROUND_US_DEFAULT: u64 = 100_000;
/// Minimum bandwidth growth per round to stay in Startup (1.25 = 25%).
const STARTUP_GROWTH_THRESHOLD_DEFAULT: f64 = 1.25;
/// Consecutive flat rounds before exiting Startup.
const STARTUP_FULL_BW_ROUNDS_DEFAULT: u32 = 3;
/// Rounds spent in Drain before ProbeBW.
const DRAIN_ROUNDS_DEFAULT: u32 = 1;

// ---------------------------------------------------------------------------
// Windowed max/min filters (sliding window via three-register algorithm)
// ---------------------------------------------------------------------------

/// A windowed extremal filter based on the Kathleen Nichols / Van Jacobson
/// windowed-min/max algorithm.  `best`, `second`, and `third` each hold a
/// (value, expiry) pair. Monotonically updates in O(1) per sample.
fn WindowedFilter(comptime T: type, comptime is_max: bool) type {
    return struct {
        const Self = @This();
        const Sample = struct { value: T, expiry: u64 };

        best: Sample,
        second: Sample,
        third: Sample,

        pub fn init(neutral: T) Self {
            const s = Sample{ .value = neutral, .expiry = 0 };
            return .{ .best = s, .second = s, .third = s };
        }

        fn better(a: T, b: T) bool {
            return if (is_max) a > b else a < b;
        }

        /// Update the filter with a new sample at logical time `now`.
        /// `window` is the window width in the same units as `now`.
        pub fn update(self: *Self, value: T, now: u64, window: u64) void {
            const expiry = now + window;

            // If the new sample is the best or the existing best has expired:
            if (better(value, self.best.value) or now > self.best.expiry) {
                self.best = .{ .value = value, .expiry = expiry };
                self.second = self.best;
                self.third = self.best;
                return;
            }

            if (better(value, self.second.value) or now > self.second.expiry) {
                self.second = .{ .value = value, .expiry = expiry };
                self.third = self.second;
                return;
            }

            if (better(value, self.third.value) or now > self.third.expiry) {
                self.third = .{ .value = value, .expiry = expiry };
            }
        }

        /// Return the current extremal value.
        pub fn get(self: *const Self) T {
            return self.best.value;
        }
    };
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const Config = struct {
    /// Initial maximum segment size in bytes.
    mss: u64 = 1460,
    /// Min-RTT filter window in microseconds.
    min_rtt_window_us: u64 = MIN_RTT_WINDOW_US_DEFAULT,
    /// Initial bytes-in-flight estimate (used to seed cwnd before first ACK).
    initial_cwnd_bytes: u64 = 10 * 1460,
    /// ProbeBW pacing-gain cycle (8 slots, wraps).
    pacing_gain_cycle: [8]f64 = PACING_GAIN_CYCLE_DEFAULT,
    /// Startup pacing gain (2 / ln2 ≈ 2.885).
    startup_pacing_gain: f64 = STARTUP_PACING_GAIN_DEFAULT,
    /// Startup cwnd gain (also reused as the Drain cwnd gain).
    startup_cwnd_gain: f64 = STARTUP_CWND_GAIN_DEFAULT,
    /// ProbeBW cwnd gain.
    probe_bw_cwnd_gain: f64 = PROBE_BW_CWND_GAIN_DEFAULT,
    /// cwnd fraction held during ProbeRTT.
    probe_rtt_cwnd_fraction: f64 = PROBE_RTT_CWND_FRACTION_DEFAULT,
    /// Max-bandwidth filter window length (RTT rounds).
    bw_window_rounds: usize = BW_WINDOW_LEN_DEFAULT,
    /// ProbeRTT hold duration in microseconds.
    probe_rtt_duration_us: u64 = PROBE_RTT_DURATION_US_DEFAULT,
    /// Floor cwnd to avoid degenerate windows (bytes).
    min_cwnd_bytes: u64 = MIN_CWND_BYTES_DEFAULT,
    /// Round/cycle duration fallback before the first RTT sample (microseconds).
    pre_rtt_round_us: u64 = PRE_RTT_ROUND_US_DEFAULT,
    /// Min bandwidth growth/round to stay in Startup (1.25 = 25%).
    startup_growth_threshold: f64 = STARTUP_GROWTH_THRESHOLD_DEFAULT,
    /// Consecutive flat rounds before exiting Startup.
    startup_full_bw_rounds: u32 = STARTUP_FULL_BW_ROUNDS_DEFAULT,
    /// Rounds spent in Drain before transitioning to ProbeBW.
    drain_rounds: u32 = DRAIN_ROUNDS_DEFAULT,

    /// Derived Drain pacing gain (1 / startup_pacing_gain).
    pub fn drainPacingGain(self: Config) f64 {
        return 1.0 / self.startup_pacing_gain;
    }
    /// Derived Drain cwnd gain (== startup_cwnd_gain).
    pub fn drainCwndGain(self: Config) f64 {
        return self.startup_cwnd_gain;
    }
};

/// Overlay `[transport.congestion.bbr]` keys onto `cfg`. Absent keys are left at
/// their current values, so the default config is behavior-preserving.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    const p = "transport.congestion.bbr.";
    if (doc.getUint(p ++ "mss_bytes")) |v| cfg.mss = v;
    if (doc.getUint(p ++ "min_rtt_window_us")) |v| cfg.min_rtt_window_us = v;
    if (doc.getUint(p ++ "initial_cwnd_bytes")) |v| cfg.initial_cwnd_bytes = v;
    if (doc.getArray(p ++ "pacing_gain_cycle")) |arr| {
        if (arr.len == cfg.pacing_gain_cycle.len) {
            var i: usize = 0;
            while (i < arr.len) : (i += 1) {
                cfg.pacing_gain_cycle[i] = switch (arr[i]) {
                    .float => arr[i].float,
                    .integer => @floatFromInt(arr[i].integer),
                    else => cfg.pacing_gain_cycle[i],
                };
            }
        }
    }
    if (doc.getFloat(p ++ "startup_pacing_gain")) |v| cfg.startup_pacing_gain = v;
    if (doc.getFloat(p ++ "startup_cwnd_gain")) |v| cfg.startup_cwnd_gain = v;
    if (doc.getFloat(p ++ "probe_bw_cwnd_gain")) |v| cfg.probe_bw_cwnd_gain = v;
    if (doc.getFloat(p ++ "probe_rtt_cwnd_fraction")) |v| cfg.probe_rtt_cwnd_fraction = v;
    if (doc.getUint(p ++ "bw_window_rounds")) |v| cfg.bw_window_rounds = @intCast(v);
    if (doc.getUint(p ++ "probe_rtt_duration_us")) |v| cfg.probe_rtt_duration_us = v;
    if (doc.getUint(p ++ "min_cwnd_bytes")) |v| cfg.min_cwnd_bytes = v;
    if (doc.getUint(p ++ "pre_rtt_round_us")) |v| cfg.pre_rtt_round_us = v;
    if (doc.getFloat(p ++ "startup_growth_threshold")) |v| cfg.startup_growth_threshold = v;
    if (doc.getUint(p ++ "startup_full_bw_rounds")) |v| cfg.startup_full_bw_rounds = @intCast(v);
    if (doc.getUint(p ++ "drain_rounds")) |v| cfg.drain_rounds = @intCast(v);
}

// ---------------------------------------------------------------------------
// Bandwidth sample
// ---------------------------------------------------------------------------

const BwSample = struct {
    /// Delivery rate in bytes/s.
    rate_bps: u64,
    /// Whether this sample was taken while the sender was app-limited.
    app_limited: bool,
};

// ---------------------------------------------------------------------------
// Bbr controller
// ---------------------------------------------------------------------------

pub const Bbr = struct {
    cfg: Config,

    // Current phase
    current_phase: Phase,

    // Bandwidth filter: windowed maximum over BW_WINDOW_LEN RTT rounds.
    bw_filter: WindowedFilter(u64, true),

    // Min-RTT filter: windowed minimum.
    min_rtt_filter: WindowedFilter(u64, false),

    // Pacing gain applied this cycle slot.
    pacing_gain: f64,
    // Cwnd gain applied this cycle slot.
    cwnd_gain: f64,

    // Cycle index into PACING_GAIN_CYCLE (ProbeBW only).
    cycle_index: usize,

    // Current best-estimate bandwidth (bytes/s).
    bw_bps: u64,

    // Current minimum RTT (microseconds).
    min_rtt_us: u64,

    // Current congestion window (bytes).
    cwnd_bytes: u64,

    // Round trip tracking: detect when a full RTT has passed.
    // We use a time-based round: a round advances once per min-RTT window.
    round_count: u64,
    // Timestamp at which the current round started.
    round_start_us: u64,
    // Total bytes delivered so far.
    total_delivered: u64,

    // Startup: count of consecutive rounds without meaningful bw gain.
    startup_rounds_without_gain: u32,

    // Drain: how many full rounds we have spent in Drain.
    drain_rounds: u32,
    // Drain: round_count when we entered Drain (to count elapsed rounds).
    drain_enter_round: u64,

    // ProbeBW: timestamp when the current cycle slot began.
    cycle_start_us: u64,

    // ProbeRTT: when we entered ProbeRTT.
    probe_rtt_enter_us: u64,
    // ProbeRTT: phase we return to after ProbeRTT.
    probe_rtt_return_phase: Phase,
    // Timestamp of the last min-RTT update (to detect staleness).
    min_rtt_stamp_us: u64,

    // Previous round's bandwidth (for startup gain detection).
    prev_round_bw_bps: u64,

    // Set to true when updateRound advances the round counter this ACK.
    // Consumed by onAckStartup to check gain once per round.
    round_advanced: bool,

    pub fn init(cfg: Config) Bbr {
        return .{
            .cfg = cfg,
            .current_phase = .Startup,
            .bw_filter = WindowedFilter(u64, true).init(0),
            .min_rtt_filter = WindowedFilter(u64, false).init(std.math.maxInt(u64)),
            .pacing_gain = cfg.startup_pacing_gain,
            .cwnd_gain = cfg.startup_cwnd_gain,
            .cycle_index = 0,
            .bw_bps = 0,
            .min_rtt_us = std.math.maxInt(u64),
            .cwnd_bytes = cfg.initial_cwnd_bytes,
            .round_count = 0,
            .round_start_us = 0,
            .total_delivered = 0,
            .startup_rounds_without_gain = 0,
            .drain_rounds = 0,
            .drain_enter_round = 0,
            .cycle_start_us = 0,
            .probe_rtt_enter_us = 0,
            .probe_rtt_return_phase = .ProbeBW,
            .min_rtt_stamp_us = 0,
            .prev_round_bw_bps = 0,
            .round_advanced = false,
        };
    }

    /// Feed an ACK event into the controller.
    ///
    /// - `now_us`: current time in microseconds (monotonic, caller-supplied).
    /// - `delivered_bytes`: number of bytes newly acknowledged by this ACK.
    /// - `rtt_us`: round-trip time measured for this ACK, in microseconds.
    /// - `app_limited`: true if the sender was limited by the application
    ///   (not by the network) when these bytes were sent.
    pub fn onAck(
        self: *Bbr,
        now_us: u64,
        delivered_bytes: u64,
        rtt_us: u64,
        app_limited: bool,
    ) void {
        // 1. Accumulate delivered bytes.
        self.total_delivered += delivered_bytes;

        // 2. Update round counter.
        self.updateRound(now_us);

        // 3. Compute a delivery-rate sample (bytes/s).
        const rate_bps: u64 = if (rtt_us > 0)
            (delivered_bytes * 1_000_000) / rtt_us
        else
            0;

        const sample = BwSample{ .rate_bps = rate_bps, .app_limited = app_limited };

        // 4. Update bandwidth filter (skip app-limited samples that would lower bw).
        if (!sample.app_limited or sample.rate_bps > self.bw_bps) {
            self.bw_filter.update(sample.rate_bps, self.round_count, self.cfg.bw_window_rounds);
            self.bw_bps = self.bw_filter.get();
        }

        // 5. Update min-RTT filter.
        self.min_rtt_filter.update(rtt_us, now_us, self.cfg.min_rtt_window_us);
        const prev_min_rtt = self.min_rtt_us;
        self.min_rtt_us = self.min_rtt_filter.get();
        if (self.min_rtt_us < prev_min_rtt) {
            // Fresh minimum: stamp the time so we know when it expires.
            self.min_rtt_stamp_us = now_us;
        }

        // 6. Advance the state machine.
        switch (self.current_phase) {
            .Startup => self.onAckStartup(now_us),
            .Drain => self.onAckDrain(now_us),
            .ProbeBW => self.onAckProbeBW(now_us),
            .ProbeRTT => self.onAckProbeRTT(now_us),
        }

        // 7. Check if we should enter ProbeRTT (min-rtt window has expired).
        if (self.current_phase != .ProbeRTT) {
            const min_rtt_age = if (now_us >= self.min_rtt_stamp_us)
                now_us - self.min_rtt_stamp_us
            else
                0;
            if (min_rtt_age > self.cfg.min_rtt_window_us) {
                self.enterProbeRTT(now_us);
            }
        }

        // 8. Recompute cwnd.
        self.updateCwnd();
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    /// Current pacing rate in bytes/s.
    pub fn pacingRate(self: *const Bbr) u64 {
        if (self.bw_bps == 0) return 0;
        const rate = @as(f64, @floatFromInt(self.bw_bps)) * self.pacing_gain;
        return @intFromFloat(rate);
    }

    /// Current congestion window in bytes.
    pub fn cwnd(self: *const Bbr) u64 {
        return self.cwnd_bytes;
    }

    /// Current BBR phase.
    pub fn phase(self: *const Bbr) Phase {
        return self.current_phase;
    }

    // -----------------------------------------------------------------------
    // Private: round tracking
    // -----------------------------------------------------------------------

    /// Advance the round counter when at least one min-RTT has elapsed.
    /// Uses time-based rounds: a new round starts each min-RTT window.
    fn updateRound(self: *Bbr, now_us: u64) void {
        const round_duration = if (self.min_rtt_us != std.math.maxInt(u64))
            self.min_rtt_us
        else
            self.cfg.pre_rtt_round_us; // fallback before first RTT sample

        self.round_advanced = false;
        if (now_us >= self.round_start_us + round_duration) {
            self.prev_round_bw_bps = self.bw_bps;
            self.round_count += 1;
            self.round_start_us = now_us;
            self.round_advanced = true;
        }
    }

    // -----------------------------------------------------------------------
    // Private: cwnd update
    // -----------------------------------------------------------------------

    fn updateCwnd(self: *Bbr) void {
        if (self.bw_bps == 0 or self.min_rtt_us == std.math.maxInt(u64)) {
            // No bandwidth or RTT estimate yet; keep initial cwnd.
            return;
        }

        const bdp = self.bdpBytes();

        self.cwnd_bytes = switch (self.current_phase) {
            .ProbeRTT => @max(
                self.cfg.min_cwnd_bytes,
                @as(u64, @intFromFloat(@as(f64, @floatFromInt(bdp)) * self.cfg.probe_rtt_cwnd_fraction)),
            ),
            else => @max(
                self.cfg.min_cwnd_bytes,
                @as(u64, @intFromFloat(@as(f64, @floatFromInt(bdp)) * self.cwnd_gain)),
            ),
        };
    }

    /// BDP in bytes: bw_bps * min_rtt_us / 1_000_000.
    fn bdpBytes(self: *const Bbr) u64 {
        if (self.min_rtt_us == std.math.maxInt(u64)) return self.cfg.initial_cwnd_bytes;
        // Avoid overflow: bw_bps can be large; use u128 intermediary.
        const bdp128: u128 = @as(u128, self.bw_bps) * @as(u128, self.min_rtt_us);
        return @as(u64, @intCast(bdp128 / 1_000_000));
    }

    // -----------------------------------------------------------------------
    // Private: Startup
    // -----------------------------------------------------------------------

    fn onAckStartup(self: *Bbr, now_us: u64) void {
        _ = now_us;
        // Only evaluate bandwidth gain once per round transition.
        if (!self.round_advanced) return;

        // Exit Startup when bandwidth has not grown by at least 25% for
        // 3 consecutive rounds (queue is saturated).
        // prev_round_bw_bps was captured at the start of this round.
        if (self.prev_round_bw_bps > 0 and self.bw_bps > 0) {
            const threshold: u64 = @intFromFloat(@as(f64, @floatFromInt(self.prev_round_bw_bps)) * self.cfg.startup_growth_threshold);
            if (self.bw_bps < threshold) {
                self.startup_rounds_without_gain += 1;
            } else {
                self.startup_rounds_without_gain = 0;
            }
        }

        if (self.startup_rounds_without_gain >= self.cfg.startup_full_bw_rounds) {
            self.enterDrain();
        }
    }

    fn enterDrain(self: *Bbr) void {
        self.current_phase = .Drain;
        self.pacing_gain = self.cfg.drainPacingGain();
        self.cwnd_gain = self.cfg.drainCwndGain();
        self.drain_rounds = 0;
        self.drain_enter_round = self.round_count;
    }

    // -----------------------------------------------------------------------
    // Private: Drain
    // -----------------------------------------------------------------------

    fn onAckDrain(self: *Bbr, now_us: u64) void {
        // Exit Drain after spending at least one full round in Drain.
        // The reduced pacing_gain (< 1) has had time to drain the queue.
        if (self.round_advanced) {
            self.drain_rounds += 1;
        }
        if (self.drain_rounds >= self.cfg.drain_rounds) {
            self.enterProbeBW(now_us);
        }
    }

    // -----------------------------------------------------------------------
    // Private: ProbeBW
    // -----------------------------------------------------------------------

    fn enterProbeBW(self: *Bbr, now_us: u64) void {
        self.current_phase = .ProbeBW;
        self.cycle_index = 0;
        self.cycle_start_us = now_us;
        self.pacing_gain = self.cfg.pacing_gain_cycle[0];
        self.cwnd_gain = self.cfg.probe_bw_cwnd_gain;
    }

    fn onAckProbeBW(self: *Bbr, now_us: u64) void {
        // Advance the pacing-gain cycle approximately once per min-RTT.
        const cycle_duration = if (self.min_rtt_us != std.math.maxInt(u64))
            self.min_rtt_us
        else
            self.cfg.pre_rtt_round_us; // fallback before first RTT sample

        if (now_us >= self.cycle_start_us + cycle_duration) {
            self.cycle_index = (self.cycle_index + 1) % self.cfg.pacing_gain_cycle.len;
            self.pacing_gain = self.cfg.pacing_gain_cycle[self.cycle_index];
            self.cycle_start_us = now_us;
        }
    }

    // -----------------------------------------------------------------------
    // Private: ProbeRTT
    // -----------------------------------------------------------------------

    fn enterProbeRTT(self: *Bbr, now_us: u64) void {
        self.probe_rtt_return_phase = self.current_phase;
        self.current_phase = .ProbeRTT;
        self.probe_rtt_enter_us = now_us;
        self.pacing_gain = 1.0;
        // cwnd_gain is overridden inside updateCwnd for ProbeRTT.
        self.cwnd_gain = 1.0;
    }

    fn onAckProbeRTT(self: *Bbr, now_us: u64) void {
        // Stay in ProbeRTT for the configured hold duration.
        if (now_us >= self.probe_rtt_enter_us + self.cfg.probe_rtt_duration_us) {
            // Refresh the min-rtt stamp and return to the previous phase.
            self.min_rtt_stamp_us = now_us;
            switch (self.probe_rtt_return_phase) {
                .ProbeBW => self.enterProbeBW(now_us),
                .Startup => {
                    self.current_phase = .Startup;
                    self.pacing_gain = self.cfg.startup_pacing_gain;
                    self.cwnd_gain = self.cfg.startup_cwnd_gain;
                },
                .Drain => {
                    self.current_phase = .Drain;
                    self.pacing_gain = self.cfg.drainPacingGain();
                    self.cwnd_gain = self.cfg.drainCwndGain();
                },
                .ProbeRTT => self.enterProbeBW(now_us),
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "WindowedFilter max tracks rolling maximum" {
    var f = WindowedFilter(u64, true).init(0);

    // Insert samples with window of 3 time units.
    f.update(100, 1, 3);
    try std.testing.expectEqual(@as(u64, 100), f.get());

    f.update(200, 2, 3);
    try std.testing.expectEqual(@as(u64, 200), f.get());

    f.update(50, 3, 3);
    try std.testing.expectEqual(@as(u64, 200), f.get());

    // Advance time past the 200 sample's expiry (expiry = 2+3=5; now=6 > 5).
    f.update(80, 6, 3);
    try std.testing.expectEqual(@as(u64, 80), f.get());
}

test "WindowedFilter min tracks rolling minimum" {
    var f = WindowedFilter(u64, false).init(std.math.maxInt(u64));

    f.update(1000, 1, 5);
    try std.testing.expectEqual(@as(u64, 1000), f.get());

    f.update(500, 2, 5);
    try std.testing.expectEqual(@as(u64, 500), f.get());

    f.update(2000, 3, 5);
    try std.testing.expectEqual(@as(u64, 500), f.get());

    // Expire old minimum (expiry = 2+5=7; now=8 > 7).
    f.update(1500, 8, 5);
    try std.testing.expectEqual(@as(u64, 1500), f.get());
}

test "Bbr init has Startup phase" {
    const bbr = Bbr.init(.{});
    try std.testing.expectEqual(Phase.Startup, bbr.phase());
}

test "Startup ramps bandwidth and transitions to Drain" {
    var bbr = Bbr.init(.{ .initial_cwnd_bytes = 10 * 1460 });

    // Phase 1: grow bandwidth for 10 rounds (doubles each round).
    // Phase 2: plateau at max bandwidth for 20 rounds so Startup detects saturation.
    var now_us: u64 = 0;
    var bw_last: u64 = 0;
    var saw_drain = false;
    const rtt_us: u64 = 10_000; // 10 ms fixed RTT

    // Growing phase
    var round: usize = 0;
    while (round < 10) : (round += 1) {
        const delivered: u64 = 65536 * (@as(u64, 1) << @intCast(round));
        bbr.onAck(now_us, delivered, rtt_us, false);
        now_us += rtt_us;
        if (bbr.phase() == .Drain) {
            saw_drain = true;
            break;
        }
        const pr = bbr.pacingRate();
        if (pr > 0) {
            try std.testing.expect(pr >= bw_last or round < 2);
        }
        bw_last = pr;
    }

    if (!saw_drain) {
        // Plateau phase: same bandwidth for 20 rounds; should trigger Startup exit.
        const plateau_bytes: u64 = 65536 * (@as(u64, 1) << 9); // same as last growing round
        var j: usize = 0;
        while (j < 20) : (j += 1) {
            bbr.onAck(now_us, plateau_bytes, rtt_us, false);
            now_us += rtt_us;
            if (bbr.phase() == .Drain) {
                saw_drain = true;
                break;
            }
        }
    }

    // We must reach Drain.
    try std.testing.expect(saw_drain);
    try std.testing.expectEqual(Phase.Drain, bbr.phase());
}

/// Helper: drive a fresh Bbr controller to Drain phase.
/// Returns now_us after reaching Drain.
fn driveToPhase(bbr: *Bbr, target: Phase, start_us: u64) u64 {
    var now_us = start_us;
    const rtt_us: u64 = 10_000;
    // Growing phase
    var round: usize = 0;
    while (round < 10) : (round += 1) {
        const delivered: u64 = 65536 * (@as(u64, 1) << @intCast(round));
        bbr.onAck(now_us, delivered, rtt_us, false);
        now_us += rtt_us;
        if (bbr.phase() == target) return now_us;
    }
    // Plateau phase
    const plateau: u64 = 65536 * (@as(u64, 1) << 9);
    var j: usize = 0;
    while (j < 30) : (j += 1) {
        bbr.onAck(now_us, plateau, rtt_us, false);
        now_us += rtt_us;
        if (bbr.phase() == target) return now_us;
    }
    return now_us;
}

test "Drain transitions to ProbeBW" {
    var bbr = Bbr.init(.{ .initial_cwnd_bytes = 10 * 1460 });
    var now_us: u64 = 0;

    // Drive into Drain.
    now_us = driveToPhase(&bbr, .Drain, now_us);
    try std.testing.expectEqual(Phase.Drain, bbr.phase());

    // One more round in Drain should push us to ProbeBW (drain_rounds >= 1).
    var j: usize = 0;
    while (j < 5) : (j += 1) {
        bbr.onAck(now_us, 1460, 10_000, false);
        now_us += 10_000;
        if (bbr.phase() == .ProbeBW) break;
    }
    try std.testing.expectEqual(Phase.ProbeBW, bbr.phase());
}

test "ProbeBW cycles pacing gain" {
    var bbr = Bbr.init(.{ .initial_cwnd_bytes = 10 * 1460 });

    // Rush to ProbeBW using the helper.
    var now_us: u64 = 0;
    now_us = driveToPhase(&bbr, .ProbeBW, now_us);
    try std.testing.expectEqual(Phase.ProbeBW, bbr.phase());

    // Advance by min_rtt steps to cycle through the gain table.
    // Gains should include 1.25, 0.75, and 1.0 slots.
    var saw_above_one = false;
    var saw_below_one = false;

    var j: usize = 0;
    while (j < 32) : (j += 1) {
        // Advance by one min-RTT worth of time per ACK so the cycle slot advances.
        const min_rtt = bbr.min_rtt_us;
        if (min_rtt != std.math.maxInt(u64)) {
            now_us += min_rtt + 1; // step just past cycle boundary
        } else {
            now_us += 10_001;
        }
        bbr.onAck(now_us, 8192, 10_000, false);

        const pr = bbr.pacingRate();
        const bw = bbr.bw_bps;
        if (bw > 0) {
            const ratio = @as(f64, @floatFromInt(pr)) / @as(f64, @floatFromInt(bw));
            if (ratio > 1.1) saw_above_one = true;
            if (ratio < 0.9) saw_below_one = true;
        }
    }

    try std.testing.expect(saw_above_one);
    try std.testing.expect(saw_below_one);
}

test "min-RTT filter captures the minimum" {
    var bbr = Bbr.init(.{});
    var now_us: u64 = 0;

    // Feed RTTs that include a clear minimum.
    const rtts = [_]u64{ 30_000, 20_000, 10_000, 25_000, 15_000 };
    for (rtts) |rtt| {
        bbr.onAck(now_us, 4096, rtt, false);
        now_us += rtt;
    }

    // The stored min-RTT should be 10_000.
    try std.testing.expectEqual(@as(u64, 10_000), bbr.min_rtt_us);
}

test "ProbeRTT engages after min-rtt window expires" {
    const min_rtt_window_us: u64 = 500_000; // 0.5 s for faster test
    var bbr = Bbr.init(.{ .min_rtt_window_us = min_rtt_window_us });

    // First: reach ProbeBW using the shared helper.
    var now_us: u64 = 0;
    now_us = driveToPhase(&bbr, .ProbeBW, now_us);
    try std.testing.expectEqual(Phase.ProbeBW, bbr.phase());

    // Advance far past the min-rtt window — the next onAck must trigger ProbeRTT.
    // Use the same RTT as during the helper (10_000) to avoid resetting the stamp.
    now_us += min_rtt_window_us + 1;
    bbr.onAck(now_us, 4096, 10_000, false);
    try std.testing.expectEqual(Phase.ProbeRTT, bbr.phase());

    // After PROBE_RTT_DURATION_US, should return to ProbeBW.
    now_us += PROBE_RTT_DURATION_US_DEFAULT + 1;
    bbr.onAck(now_us, 4096, 10_000, false);
    try std.testing.expectEqual(Phase.ProbeBW, bbr.phase());
}

test "cwnd tracks BDP (bw * min_rtt)" {
    var bbr = Bbr.init(.{});

    // Stable steady-state: constant bandwidth and RTT.
    var now_us: u64 = 0;
    const rtt_us: u64 = 20_000; // 20 ms
    const delivered: u64 = 8192;

    var j: usize = 0;
    while (j < 40) : (j += 1) {
        bbr.onAck(now_us, delivered, rtt_us, false);
        now_us += rtt_us;
    }

    // BDP = bw_bps * min_rtt_us / 1e6, then multiplied by cwnd_gain.
    if (bbr.bw_bps > 0 and bbr.min_rtt_us != std.math.maxInt(u64)) {
        const bdp: u64 = @intCast(@as(u128, bbr.bw_bps) * @as(u128, bbr.min_rtt_us) / 1_000_000);
        const expected_min = bdp; // at minimum 1x BDP
        try std.testing.expect(bbr.cwnd() >= expected_min);
        // cwnd should not exceed cwnd_gain * bdp * some tolerance.
        const ceiling = bdp * 4 + MIN_CWND_BYTES_DEFAULT;
        try std.testing.expect(bbr.cwnd() <= ceiling);
    }
}

test "app-limited samples do not lower bandwidth estimate" {
    var bbr = Bbr.init(.{});
    var now_us: u64 = 0;

    // Establish a high bandwidth with real samples.
    var k: usize = 0;
    while (k < 15) : (k += 1) {
        bbr.onAck(now_us, 65536, 10_000, false);
        now_us += 10_000;
    }
    const bw_before = bbr.bw_bps;
    try std.testing.expect(bw_before > 0);

    // Feed app-limited samples with a tiny delivery rate (should be ignored).
    var m: usize = 0;
    while (m < 10) : (m += 1) {
        bbr.onAck(now_us, 100, 10_000, true);
        now_us += 10_000;
    }

    // Bandwidth estimate must not have dropped.
    try std.testing.expect(bbr.bw_bps >= bw_before);
}

test "deterministic given identical input sequence" {
    const rng_rtts = [_]u64{ 12_000, 11_500, 13_000, 10_800, 12_200, 11_000 };
    const rng_dlvr = [_]u64{ 32768, 49152, 16384, 65536, 40960, 24576 };

    var bbr1 = Bbr.init(.{});
    var bbr2 = Bbr.init(.{});

    var now_us: u64 = 0;
    for (rng_rtts, 0..) |rtt, idx| {
        const dlvr = rng_dlvr[idx];
        bbr1.onAck(now_us, dlvr, rtt, false);
        bbr2.onAck(now_us, dlvr, rtt, false);
        now_us += rtt;
    }

    try std.testing.expectEqual(bbr1.phase(), bbr2.phase());
    try std.testing.expectEqual(bbr1.bw_bps, bbr2.bw_bps);
    try std.testing.expectEqual(bbr1.min_rtt_us, bbr2.min_rtt_us);
    try std.testing.expectEqual(bbr1.pacingRate(), bbr2.pacingRate());
    try std.testing.expectEqual(bbr1.cwnd(), bbr2.cwnd());
}

test "pacing_rate equals pacing_gain times bw" {
    var bbr = Bbr.init(.{});
    var now_us: u64 = 0;

    // Feed enough acks to get a non-zero bandwidth estimate.
    var n: usize = 0;
    while (n < 20) : (n += 1) {
        bbr.onAck(now_us, 32768, 15_000, false);
        now_us += 15_000;
    }

    if (bbr.bw_bps > 0) {
        const expected: u64 = @intFromFloat(@as(f64, @floatFromInt(bbr.bw_bps)) * bbr.pacing_gain);
        try std.testing.expectEqual(expected, bbr.pacingRate());
    }
}

test "applyToml overlays bbr keys and leaves absent keys at defaults" {
    const src =
        \\[transport.congestion.bbr]
        \\mss_bytes = 1200
        \\min_rtt_window_us = 8000000
        \\initial_cwnd_bytes = 30000
        \\pacing_gain_cycle = [1.5, 0.5, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
        \\startup_pacing_gain = 2.0
        \\startup_cwnd_gain = 3.0
        \\probe_bw_cwnd_gain = 2.5
        \\probe_rtt_cwnd_fraction = 0.5
        \\bw_window_rounds = 16
        \\probe_rtt_duration_us = 150000
        \\min_cwnd_bytes = 8000
        \\pre_rtt_round_us = 50000
        \\startup_growth_threshold = 1.5
        \\startup_full_bw_rounds = 5
        \\drain_rounds = 2
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    applyToml(&cfg, &doc);

    try std.testing.expectEqual(@as(u64, 1200), cfg.mss);
    try std.testing.expectEqual(@as(u64, 8_000_000), cfg.min_rtt_window_us);
    try std.testing.expectEqual(@as(u64, 30_000), cfg.initial_cwnd_bytes);
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), cfg.pacing_gain_cycle[0], 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), cfg.pacing_gain_cycle[1], 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 2.0), cfg.startup_pacing_gain, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 3.0), cfg.startup_cwnd_gain, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 2.5), cfg.probe_bw_cwnd_gain, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), cfg.probe_rtt_cwnd_fraction, 1e-9);
    try std.testing.expectEqual(@as(usize, 16), cfg.bw_window_rounds);
    try std.testing.expectEqual(@as(u64, 150_000), cfg.probe_rtt_duration_us);
    try std.testing.expectEqual(@as(u64, 8_000), cfg.min_cwnd_bytes);
    try std.testing.expectEqual(@as(u64, 50_000), cfg.pre_rtt_round_us);
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), cfg.startup_growth_threshold, 1e-9);
    try std.testing.expectEqual(@as(u32, 5), cfg.startup_full_bw_rounds);
    try std.testing.expectEqual(@as(u32, 2), cfg.drain_rounds);
}

test "applyToml leaves config untouched when section is absent" {
    var doc = try toml.parse(std.testing.allocator, "title = \"x\"\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    applyToml(&cfg, &doc);

    const def = Config{};
    try std.testing.expectEqual(def.mss, cfg.mss);
    try std.testing.expectEqual(def.min_rtt_window_us, cfg.min_rtt_window_us);
    try std.testing.expectApproxEqAbs(def.startup_pacing_gain, cfg.startup_pacing_gain, 1e-9);
    try std.testing.expectEqual(def.startup_full_bw_rounds, cfg.startup_full_bw_rounds);
    try std.testing.expectApproxEqAbs(def.pacing_gain_cycle[0], cfg.pacing_gain_cycle[0], 1e-9);
}
