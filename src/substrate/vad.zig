// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Voice Activity Detector (VAD) over PCM i16 frames.
//!
//! Features:
//!   - Energy (RMS) estimation per frame
//!   - Zero-crossing rate (ZCR) per frame
//!   - Adaptive noise-floor estimator: minimum-statistics tracker with slow
//!     rise (noise can only creep up slowly) and fast adapt (floor drops
//!     quickly when energy falls below current estimate).
//!   - Hysteresis via separate speech-onset and speech-hangover thresholds so
//!     brief dips do not cut detected speech.
//!   - State machine: .silence / .speech with configurable hangover frames.
//!
//! Usage:
//!   var vad = Vad.init(Vad.Config{});
//!   const is_speech = vad.process(frame);  // frame: []const i16
//!   const snr_db    = vad.snrDb();

const std = @import("std");
const math = std.math;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

pub const State = enum { silence, speech };

/// Tunable parameters.  All fields have defaults suitable for 16 kHz mono
/// 160-sample (10 ms) frames, but the VAD is frame-rate agnostic.
pub const Config = struct {
    /// Minimum RMS energy (linear) below which the noise floor is never set.
    /// Prevents division-by-zero and protects against digital silence.
    noise_floor_min: f32 = 8.0,

    /// Speech onset threshold: speech is declared when
    ///   rms > noise_floor * onset_snr_factor
    onset_snr_factor: f32 = 3.5,

    /// Hangover threshold: once in speech, stay in speech while
    ///   rms > noise_floor * hangover_snr_factor
    hangover_snr_factor: f32 = 2.0,

    /// Number of consecutive sub-threshold frames before returning to silence.
    hangover_frames: u32 = 8,

    /// Noise floor adaptation rate when energy < current floor (fast drop).
    alpha_fast: f32 = 0.05,

    /// Noise floor adaptation rate when energy > current floor (slow rise).
    alpha_slow: f32 = 0.002,

    /// Weight given to ZCR when blending with energy for the speech decision.
    /// 0.0 = pure energy, 1.0 = pure ZCR.  Default is light ZCR influence.
    zcr_weight: f32 = 0.15,

    /// ZCR threshold (crossings per sample) above which the frame looks
    /// noise-like rather than tonal.  Used to down-weight the speech score
    /// for very high-ZCR frames (unvoiced-noise guard).
    zcr_noise_threshold: f32 = 0.35,
};

pub const Vad = struct {
    cfg: Config,
    noise_floor: f32,
    state: State,
    hangover_count: u32,
    /// Last computed RMS of the most recent process() call.
    last_rms: f32,
    /// Last computed zero-crossing rate (crossings / sample).
    last_zcr: f32,

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    pub fn init(cfg: Config) Vad {
        return .{
            .cfg = cfg,
            .noise_floor = cfg.noise_floor_min,
            .state = .silence,
            .hangover_count = 0,
            .last_rms = 0.0,
            .last_zcr = 0.0,
        };
    }

    // ------------------------------------------------------------------
    // Core API
    // ------------------------------------------------------------------

    /// Process one frame of PCM i16 samples.
    /// Returns true while voice activity is detected (including hangover).
    pub fn process(self: *Vad, frame: []const i16) bool {
        if (frame.len == 0) return self.state == .speech;

        const rms = computeRms(frame);
        const zcr = computeZcr(frame);
        self.last_rms = rms;
        self.last_zcr = zcr;

        // Adapt noise floor.
        self.updateNoiseFloor(rms);

        // Compute a blended energy-like score that is slightly discounted for
        // very high ZCR frames (broadband noise resembles speech in energy
        // alone but has a high ZCR).
        const zcr_discount: f32 = if (zcr > self.cfg.zcr_noise_threshold)
            1.0 - self.cfg.zcr_weight
        else
            1.0;
        const effective_rms = rms * zcr_discount;

        const onset_thresh = self.noise_floor * self.cfg.onset_snr_factor;
        const hang_thresh = self.noise_floor * self.cfg.hangover_snr_factor;

        switch (self.state) {
            .silence => {
                if (effective_rms >= onset_thresh) {
                    self.state = .speech;
                    self.hangover_count = 0;
                }
            },
            .speech => {
                if (effective_rms < hang_thresh) {
                    self.hangover_count += 1;
                    if (self.hangover_count >= self.cfg.hangover_frames) {
                        self.state = .silence;
                        self.hangover_count = 0;
                    }
                } else {
                    // Still loud enough — reset hangover counter.
                    self.hangover_count = 0;
                }
            },
        }

        return self.state == .speech;
    }

    /// Current signal-to-noise ratio estimate in dB.
    /// Returns 0 when last_rms == 0.
    pub fn snrDb(self: *const Vad) f32 {
        if (self.last_rms <= 0.0 or self.noise_floor <= 0.0) return 0.0;
        return 20.0 * @log10(self.last_rms / self.noise_floor);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn updateNoiseFloor(self: *Vad, rms: f32) void {
        const alpha = if (rms < self.noise_floor) self.cfg.alpha_fast else self.cfg.alpha_slow;
        const updated = self.noise_floor + alpha * (rms - self.noise_floor);
        self.noise_floor = @max(updated, self.cfg.noise_floor_min);
    }
};

// ---------------------------------------------------------------------------
// Feature computation (free functions, usable independently)
// ---------------------------------------------------------------------------

/// RMS energy of a PCM i16 frame (linear, same unit as sample amplitude).
pub fn computeRms(frame: []const i16) f32 {
    if (frame.len == 0) return 0.0;
    var sum_sq: f64 = 0.0;
    for (frame) |s| {
        const sf: f64 = @floatFromInt(s);
        sum_sq += sf * sf;
    }
    return @floatCast(math.sqrt(sum_sq / @as(f64, @floatFromInt(frame.len))));
}

/// Zero-crossing rate: number of sign changes per sample (range 0..1).
/// DC offset is ignored; transitions through zero count once.
pub fn computeZcr(frame: []const i16) f32 {
    if (frame.len < 2) return 0.0;
    var crossings: u32 = 0;
    var prev = frame[0];
    for (frame[1..]) |cur| {
        // A crossing occurs when the product of consecutive samples is negative,
        // or when prev != 0 and cur == 0 (edge case: lands exactly on zero).
        if ((@as(i32, prev) * @as(i32, cur)) < 0) {
            crossings += 1;
        }
        prev = cur;
    }
    return @as(f32, @floatFromInt(crossings)) / @as(f32, @floatFromInt(frame.len - 1));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "pure silence produces no speech" {
    var vad = Vad.init(.{});
    // 100 frames of all-zero samples => always silence.
    const frame = [_]i16{0} ** 160;
    for (0..100) |_| {
        const speech = vad.process(&frame);
        try std.testing.expect(!speech);
    }
    try std.testing.expectEqual(State.silence, vad.state);
}

test "loud tone burst triggers speech onset" {
    // Sine-like constant amplitude frame at ~1000 Hz, 16 kHz SR.
    // We use a simple triangle wave for determinism.
    var vad = Vad.init(.{});

    // Feed some silence first so the noise floor settles low.
    const silence = [_]i16{0} ** 160;
    for (0..20) |_| _ = vad.process(&silence);

    // Build a loud frame (amplitude 8000, well above noise floor).
    var loud_frame: [160]i16 = undefined;
    for (0..160) |i| {
        const t: f32 = @as(f32, @floatFromInt(i)) / 160.0;
        loud_frame[i] = @intFromFloat(8000.0 * @sin(2.0 * math.pi * t * 10.0));
    }

    var detected = false;
    for (0..5) |_| {
        if (vad.process(&loud_frame)) detected = true;
    }
    try std.testing.expect(detected);
}

test "hangover keeps speech active through a short gap" {
    var cfg = Config{};
    cfg.hangover_frames = 8;
    var vad = Vad.init(cfg);

    // Prime with silence so noise floor is minimal.
    const silence = [_]i16{0} ** 160;
    for (0..20) |_| _ = vad.process(&silence);

    // Create loud frame (RMS ~5657).
    var loud: [160]i16 = undefined;
    for (0..160) |i| loud[i] = if (i % 2 == 0) 8000 else -8000;

    // Start speech.
    for (0..5) |_| _ = vad.process(&loud);
    try std.testing.expect(vad.state == .speech);

    // Insert a SHORT gap (fewer than hangover_frames silent frames).
    for (0..4) |_| {
        const still_speech = vad.process(&silence);
        try std.testing.expect(still_speech); // hangover should keep it true
    }

    // After the gap ends, re-introduce loud signal; should still be speech.
    _ = vad.process(&loud);
    try std.testing.expect(vad.state == .speech);
}

test "hangover expires after long enough gap" {
    var cfg = Config{};
    cfg.hangover_frames = 4;
    var vad = Vad.init(cfg);

    const silence = [_]i16{0} ** 160;
    for (0..20) |_| _ = vad.process(&silence);

    var loud: [160]i16 = undefined;
    for (0..160) |i| loud[i] = if (i % 2 == 0) 8000 else -8000;

    for (0..5) |_| _ = vad.process(&loud);
    try std.testing.expect(vad.state == .speech);

    // Feed MORE silent frames than hangover_frames; eventually silence.
    var ended = false;
    for (0..20) |_| {
        if (!vad.process(&silence)) ended = true;
    }
    try std.testing.expect(ended);
    try std.testing.expectEqual(State.silence, vad.state);
}

test "adapts to rising noise floor — no false trigger on steady noise" {
    // A moderate-amplitude steady noise should eventually be absorbed into the
    // noise floor so that the VAD does not keep reporting speech.
    var cfg = Config{};
    cfg.alpha_slow = 0.05; // faster adaptation for this test
    cfg.alpha_fast = 0.3;
    cfg.onset_snr_factor = 3.5;
    var vad = Vad.init(cfg);

    // Constant-energy "noise" frame: alternating +/-300.
    var noise: [160]i16 = undefined;
    for (0..160) |i| noise[i] = if (i % 2 == 0) 300 else -300;

    // After many frames the noise floor should have adapted upward so the
    // VAD no longer triggers speech.
    var last_speech = false;
    for (0..200) |_| {
        last_speech = vad.process(&noise);
    }
    // After 200 frames the noise floor must have caught up; no speech.
    try std.testing.expect(!last_speech);
    try std.testing.expectEqual(State.silence, vad.state);
}

test "zero-crossing rate: pure tone has low ZCR" {
    // A 1 kHz sine at 16 kHz SR crosses zero ~2000/16000 = 0.125 per sample.
    var frame: [160]i16 = undefined;
    for (0..160) |i| {
        const t: f32 = @as(f32, @floatFromInt(i)) / 16000.0;
        frame[i] = @intFromFloat(8000.0 * @sin(2.0 * math.pi * 1000.0 * t));
    }
    const zcr = computeZcr(&frame);
    // Allow some tolerance; ZCR should be well below 0.35 (noise threshold).
    try std.testing.expect(zcr < 0.25);
}

test "zero-crossing rate: white-noise-like frame has high ZCR" {
    // Alternating +/-1 is the highest possible ZCR (crosses every sample).
    var frame: [160]i16 = undefined;
    for (0..160) |i| frame[i] = if (i % 2 == 0) 1000 else -1000;
    const zcr = computeZcr(&frame);
    // Every transition is a crossing: ZCR should be close to 1.0.
    try std.testing.expect(zcr > 0.9);
}

test "ZCR discounts noisy-looking high-ZCR frame below onset" {
    // Demonstrate that a high-ZCR frame whose raw energy would exceed the onset
    // threshold is suppressed by the ZCR discount.
    //
    // Noise floor minimum = 8 (default).
    // onset_snr_factor = 4.0  => raw threshold = 4 * 8 = 32.
    // Frame amplitude = 50    => raw RMS = 50, which is > 32 (would trigger).
    // zcr_weight = 0.8, zcr_noise_threshold = 0.5.
    // Alternating +-50: ZCR ≈ 1.0 > 0.5, so discount factor = 1 - 0.8 = 0.2.
    // effective_rms = 50 * 0.2 = 10 < 32 => NO speech.
    var cfg = Config{};
    cfg.zcr_weight = 0.8;
    cfg.zcr_noise_threshold = 0.5;
    cfg.onset_snr_factor = 4.0;
    var vad = Vad.init(cfg);

    // Silence first so noise floor stays at minimum.
    const silence = [_]i16{0} ** 160;
    for (0..20) |_| _ = vad.process(&silence);

    // High-ZCR frame at amplitude 50 (raw RMS=50, effective=10 after discount).
    var noisy: [160]i16 = undefined;
    for (0..160) |i| noisy[i] = if (i % 2 == 0) 50 else -50;

    var speech_detected = false;
    for (0..10) |_| {
        if (vad.process(&noisy)) speech_detected = true;
    }
    try std.testing.expect(!speech_detected);

    // Sanity check: same amplitude but LOW ZCR (pure tone pattern) SHOULD trigger
    // with the same config because no discount is applied.
    var vad2 = Vad.init(cfg);
    for (0..20) |_| _ = vad2.process(&silence);
    var tonal: [160]i16 = undefined;
    // Constant +50 => ZCR = 0, no discount; RMS = 50 > threshold 32.
    for (0..160) |i| tonal[i] = if (i < 80) 50 else -50; // one crossing, ZCR ~0.006
    var tonal_detected = false;
    for (0..10) |_| {
        if (vad2.process(&tonal)) tonal_detected = true;
    }
    try std.testing.expect(tonal_detected);
}

test "snrDb returns non-negative value during speech" {
    var vad = Vad.init(.{});

    const silence = [_]i16{0} ** 160;
    for (0..20) |_| _ = vad.process(&silence);

    var loud: [160]i16 = undefined;
    for (0..160) |i| loud[i] = if (i % 2 == 0) 8000 else -8000;
    for (0..5) |_| _ = vad.process(&loud);

    const snr = vad.snrDb();
    try std.testing.expect(snr > 0.0);
}

test "deterministic on fixed input" {
    // Two VADs with identical config fed identical data must produce identical results.
    const cfg = Config{};
    var vad1 = Vad.init(cfg);
    var vad2 = Vad.init(cfg);

    var frame: [160]i16 = undefined;
    // Pseudo-random-looking but fixed pattern.
    for (0..160) |i| {
        const v: i32 = @intCast((i *% 6364136223846793005 +% 1442695040888963407) % 32768);
        frame[i] = @intCast(v - 16384);
    }

    for (0..50) |_| {
        const r1 = vad1.process(&frame);
        const r2 = vad2.process(&frame);
        try std.testing.expectEqual(r1, r2);
    }
    try std.testing.expectEqual(vad1.state, vad2.state);
    try std.testing.expectApproxEqAbs(vad1.noise_floor, vad2.noise_floor, 1e-4);
}

test "computeRms: empty frame returns zero" {
    const rms = computeRms(&[_]i16{});
    try std.testing.expectApproxEqAbs(rms, 0.0, 1e-6);
}

test "computeRms: constant amplitude frame" {
    // All samples at 1000 => RMS == 1000.
    const frame = [_]i16{1000} ** 64;
    const rms = computeRms(&frame);
    try std.testing.expectApproxEqAbs(rms, 1000.0, 0.5);
}

test "computeZcr: constant positive frame has zero crossings" {
    const frame = [_]i16{500} ** 64;
    const zcr = computeZcr(&frame);
    try std.testing.expectApproxEqAbs(zcr, 0.0, 1e-6);
}
