// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Discontinuous Transmission (DTX) and Comfort Noise Generation (CNG).
//!
//! DTX suppresses transmission during silence to save bandwidth. The sender
//! classifies each audio frame as speech or silence using a short-term energy
//! measure plus a hangover counter, then emits one of three decisions:
//!
//!   .speech    – full PCM frame passes through
//!   .sid       – Silence Insertion Descriptor carrying the noise energy level
//!   .no_transmit – silence continuation; receiver keeps using the last SID
//!
//! The receiver generates comfort noise from the latest SID level so the line
//! does not go silent and cause the listener to think the call dropped.
//!
//! All arithmetic is integer-only (no floating-point) for deterministic,
//! cross-platform behaviour. Audio samples are signed 16-bit PCM. Frame size
//! is a compile-time parameter (default 160 samples = 20 ms at 8 kHz).

const std = @import("std");

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result returned by `Sender.analyze`.
pub const Decision = union(enum) {
    /// Full speech frame – the original samples are in the payload.
    speech: Frame,
    /// Silence Insertion Descriptor – carry noise level to the receiver.
    sid: SidFrame,
    /// No transmission required; receiver will synthesise comfort noise.
    no_transmit,
};

/// A PCM audio frame. Samples are signed 16-bit, little-endian order.
pub fn AudioFrame(comptime frame_size: usize) type {
    return struct {
        samples: [frame_size]i16,
    };
}

/// SID frame: carries the RMS energy of background noise (in PCM units).
pub const SidFrame = struct {
    /// Background noise energy estimate (RMS, integer approximation).
    noise_level: u32,
};

// Convenient aliases used throughout this file for the default frame size.
pub const default_frame_size: usize = 160; // 20 ms @ 8 kHz
pub const Frame = AudioFrame(default_frame_size);

// ---------------------------------------------------------------------------
// Tuning constants
// ---------------------------------------------------------------------------

/// Number of consecutive silent frames before we begin DTX suppression.
const hangover_frames: u8 = 8;

/// Energy threshold (RMS² to avoid a sqrt) above which a frame is "speech".
/// For 16-bit PCM silence typically sits well below 100 RMS; adjust per codec.
const speech_energy_threshold: u64 = 2500; // ~ RMS 50

/// How often (in suppressed frames) we re-send a SID update.
const sid_refresh_interval: u32 = 50; // every ~1 s at 20 ms frames

// ---------------------------------------------------------------------------
// Minimal xoshiro128** PRNG  (seeded, no external deps)
// ---------------------------------------------------------------------------
//
// We need a small, seedable PRNG for comfort-noise generation. Using the
// Zig standard-library PRNG directly would require an Allocator, but
// std.rand.Xoshiro128 is a value type – we embed it directly.

const Prng = std.Random.Xoshiro256;

fn prngInit(seed: u64) Prng {
    return Prng.init(seed);
}

// ---------------------------------------------------------------------------
// Energy helpers
// ---------------------------------------------------------------------------

/// Compute mean-square energy of a frame (sum of x² / N).
/// Returns a u64 to avoid overflow for 16-bit samples.
fn frameMeanSquare(samples: []const i16) u64 {
    var acc: u64 = 0;
    for (samples) |s| {
        const v: i64 = @intCast(s);
        acc +|= @as(u64, @intCast(v * v));
    }
    return acc / @max(samples.len, 1);
}

/// Integer square-root (floor). Used to convert mean-square to RMS.
fn isqrt(n: u64) u32 {
    if (n == 0) return 0;
    var x: u64 = n;
    var y: u64 = (x + 1) / 2;
    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }
    return @intCast(x);
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// DTX encoder / speech–silence classifier.
///
/// Uses a dual-path design:
///  - VAD path: instantaneous per-frame mean-square energy vs. threshold for
///    fast attack.  A hangover counter keeps the "speech" flag raised for
///    `hangover_frames` frames after the energy drops below the threshold so
///    that brief pauses within an utterance are not falsely classified as
///    silence.
///  - Background path: slow leaky integrator (α ≈ 0.875) that only updates
///    while in VAD-silence to track the ambient noise floor for SID payloads.
///
/// Call `analyze` once per frame. The returned `Decision` tells the transport
/// layer what to send (or not send).
pub const Sender = struct {
    /// Frames remaining in the hangover period after last speech.
    hangover: u8 = 0,
    /// True once we have moved into DTX silence mode.
    in_silence: bool = false,
    /// Number of frames suppressed since the last SID was transmitted.
    suppress_count: u32 = 0,
    /// Last measured background noise level (RMS).
    background_level: u32 = 0,
    /// Slow leaky integrator for background noise (only updated in silence).
    bg_smoothed_ms: u64 = 0,

    /// Initialise a sender with default state.
    pub fn init() Sender {
        return .{};
    }

    /// Classify `frame` and return the appropriate `Decision`.
    ///
    /// Must be called with consecutive frames in transmission order.
    pub fn analyze(self: *Sender, frame: Frame) Decision {
        const ms = frameMeanSquare(&frame.samples);

        // VAD decision: instantaneous energy vs threshold.
        const is_active = ms >= speech_energy_threshold;

        if (is_active) {
            // Speech activity detected – reset hangover, exit silence mode.
            self.hangover = hangover_frames;
            self.in_silence = false;
            self.suppress_count = 0;
            return Decision{ .speech = frame };
        }

        // Below threshold – count down hangover.
        if (self.hangover > 0) {
            self.hangover -= 1;
            // Update background smoother during hangover so it adjusts quickly.
            self.bg_smoothed_ms = (self.bg_smoothed_ms * 14 + ms * 2) / 16;
            return Decision{ .speech = frame };
        }

        // Silence confirmed. Update background noise estimate.
        self.bg_smoothed_ms = (self.bg_smoothed_ms * 14 + ms * 2) / 16;
        self.background_level = isqrt(self.bg_smoothed_ms);

        if (!self.in_silence) {
            // First entry into silence: send an initial SID.
            self.in_silence = true;
            self.suppress_count = 0;
            return Decision{ .sid = .{ .noise_level = self.background_level } };
        }

        self.suppress_count += 1;

        if (self.suppress_count % sid_refresh_interval == 0) {
            // Periodic SID refresh so the receiver can track noise drift.
            return Decision{ .sid = .{ .noise_level = self.background_level } };
        }

        return Decision.no_transmit;
    }
};

// ---------------------------------------------------------------------------
// Receiver / Comfort Noise Generator
// ---------------------------------------------------------------------------

/// DTX decoder / comfort-noise synthesiser.
///
/// Feed incoming `SidFrame` values with `updateSid`; call `generate` whenever
/// a frame slot has no transmitted audio (i.e. a `no_transmit` slot or any
/// gap in the stream). Returns synthesised comfort noise shaped to the last
/// SID level.
pub const Receiver = struct {
    /// Last known noise level from the remote sender.
    noise_level: u32 = 0,
    /// PRNG state for white noise generation.
    prng: Prng,

    /// Create a receiver seeded for deterministic comfort noise.
    pub fn init(seed: u64) Receiver {
        return .{ .prng = prngInit(seed) };
    }

    /// Update the stored noise level when a SID frame arrives.
    pub fn updateSid(self: *Receiver, sid: SidFrame) void {
        self.noise_level = sid.noise_level;
    }

    /// Generate one comfort-noise frame at the current SID level.
    ///
    /// White noise is scaled so its approximate RMS equals `noise_level`.
    /// Scaling: each sample = rand_uniform(-1,+1) × noise_level × √3,
    /// where √3 ≈ 1.732 is the correction factor for a uniform distribution
    /// (uniform on [-A,A] has RMS = A/√3, so to get RMS = L we need A = L×√3).
    /// We approximate √3 with the integer fraction 7/4 = 1.75 (≈ 1% error).
    pub fn generate(self: *Receiver) Frame {
        var frame: Frame = undefined;
        const rng = self.prng.random();
        // Amplitude for uniform[-A,A] to yield noise_level RMS: A = level * 7/4
        const amplitude: i64 = @divTrunc(@as(i64, @intCast(self.noise_level)) * 7, 4);

        for (&frame.samples) |*s| {
            if (amplitude == 0) {
                s.* = 0;
                continue;
            }
            // Draw uniform integer in [0, 2*amplitude)  then shift to [-amplitude, amplitude)
            const span: u64 = @intCast(amplitude * 2);
            const draw: i64 = @intCast(rng.uintLessThan(u64, span));
            const centered: i64 = draw - amplitude;
            // Clamp to i16 range.
            s.* = @intCast(std.math.clamp(centered, std.math.minInt(i16), std.math.maxInt(i16)));
        }
        return frame;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "speech frames are transmitted" {
    var sender = Sender.init();
    // Construct a frame with high energy (RMS well above threshold).
    var frame: Frame = undefined;
    for (&frame.samples, 0..) |*s, i| {
        s.* = if (i % 2 == 0) 2000 else -2000; // alternating ±2000
    }

    // Feed enough speech frames for the smoother to fully activate.
    var saw_speech = false;
    for (0..20) |_| {
        const d = sender.analyze(frame);
        switch (d) {
            .speech => saw_speech = true,
            else => {},
        }
    }
    try std.testing.expect(saw_speech);
}

test "sustained silence emits SID then suppresses" {
    var sender = Sender.init();
    var frame: Frame = undefined;
    @memset(&frame.samples, 0); // absolute silence, energy = 0

    var sid_count: u32 = 0;
    var no_tx_count: u32 = 0;

    // Run many frames to get well past the hangover.
    for (0..200) |_| {
        switch (sender.analyze(frame)) {
            .speech => {},
            .sid => sid_count += 1,
            .no_transmit => no_tx_count += 1,
        }
    }

    // Must have seen at least one SID.
    try std.testing.expect(sid_count >= 1);
    // Must have suppressed at least a few frames.
    try std.testing.expect(no_tx_count > 10);
}

test "SID refresh fires periodically" {
    var sender = Sender.init();
    var frame: Frame = undefined;
    @memset(&frame.samples, 0);

    // Exhaust the hangover first.
    for (0..30) |_| {
        _ = sender.analyze(frame);
    }

    // Now count SIDs over several refresh intervals.
    var sid_count: u32 = 0;
    for (0..@as(usize, sid_refresh_interval) * 3 + 10) |_| {
        if (sender.analyze(frame) == .sid) sid_count += 1;
    }
    // We should see at least 2 periodic SIDs (initial one may have occurred earlier).
    try std.testing.expect(sid_count >= 2);
}

test "hangover: speech->silence transition respects hangover count" {
    var sender = Sender.init();

    // Speech frame.
    var speech_frame: Frame = undefined;
    for (&speech_frame.samples, 0..) |*s, i| {
        s.* = if (i % 2 == 0) 3000 else -3000;
    }
    var silence_frame: Frame = undefined;
    @memset(&silence_frame.samples, 0);

    // Warm up the energy smoother with speech.
    for (0..30) |_| {
        _ = sender.analyze(speech_frame);
    }

    // Switch to silence – should stay in hangover (speech decisions) for a while.
    var speech_after_switch: u32 = 0;
    for (0..@as(usize, hangover_frames) + 2) |_| {
        switch (sender.analyze(silence_frame)) {
            .speech => speech_after_switch += 1,
            else => {},
        }
    }
    // Expect roughly hangover_frames speech decisions before silence kicks in.
    try std.testing.expect(speech_after_switch >= hangover_frames - 2);
}

test "comfort noise energy approximately matches SID level" {
    const target_rms: u32 = 200;
    var rx = Receiver.init(42);
    rx.updateSid(.{ .noise_level = target_rms });

    // Generate several frames and measure RMS.
    var total_ms: u64 = 0;
    const num_frames = 20;
    for (0..num_frames) |_| {
        const f = rx.generate();
        total_ms += frameMeanSquare(&f.samples);
    }
    const avg_ms = total_ms / num_frames;
    const measured_rms = isqrt(avg_ms);

    // Allow ±50% tolerance for statistical noise over 20 frames.
    const lo = target_rms / 2;
    const hi = target_rms * 2;
    try std.testing.expect(measured_rms >= lo and measured_rms <= hi);
}

test "zero SID level produces silence" {
    var rx = Receiver.init(7);
    rx.updateSid(.{ .noise_level = 0 });
    const f = rx.generate();
    for (f.samples) |s| {
        try std.testing.expectEqual(@as(i16, 0), s);
    }
}

test "deterministic: same seed same output" {
    var rx1 = Receiver.init(123);
    var rx2 = Receiver.init(123);
    rx1.updateSid(.{ .noise_level = 150 });
    rx2.updateSid(.{ .noise_level = 150 });
    const f1 = rx1.generate();
    const f2 = rx2.generate();
    try std.testing.expectEqualSlices(i16, &f1.samples, &f2.samples);
}

test "different seeds produce different output" {
    var rx1 = Receiver.init(1);
    var rx2 = Receiver.init(999);
    rx1.updateSid(.{ .noise_level = 150 });
    rx2.updateSid(.{ .noise_level = 150 });
    const f1 = rx1.generate();
    const f2 = rx2.generate();
    // Very unlikely to be equal; treat collision as test failure.
    var same = true;
    for (f1.samples, f2.samples) |a, b| {
        if (a != b) {
            same = false;
            break;
        }
    }
    try std.testing.expect(!same);
}

test "isqrt sanity" {
    try std.testing.expectEqual(@as(u32, 0), isqrt(0));
    try std.testing.expectEqual(@as(u32, 1), isqrt(1));
    try std.testing.expectEqual(@as(u32, 3), isqrt(9));
    try std.testing.expectEqual(@as(u32, 4), isqrt(16));
    try std.testing.expectEqual(@as(u32, 10), isqrt(100));
    try std.testing.expectEqual(@as(u32, 31), isqrt(1000));
    try std.testing.expectEqual(@as(u32, 100), isqrt(10000));
}

test "SID can be updated mid-silence and new level takes effect" {
    var rx = Receiver.init(55);
    rx.updateSid(.{ .noise_level = 10 });
    const f1 = rx.generate();
    const ms1 = frameMeanSquare(&f1.samples);

    rx.updateSid(.{ .noise_level = 500 });
    const f2 = rx.generate();
    const ms2 = frameMeanSquare(&f2.samples);

    // Louder SID should yield higher energy.
    try std.testing.expect(ms2 > ms1);
}

test "frameMeanSquare of all-zero frame is zero" {
    var f: Frame = undefined;
    @memset(&f.samples, 0);
    try std.testing.expectEqual(@as(u64, 0), frameMeanSquare(&f.samples));
}

test "sender full pipeline: speech burst followed by long silence" {
    var sender = Sender.init();

    var speech_frame: Frame = undefined;
    for (&speech_frame.samples, 0..) |*s, i| {
        s.* = if (i % 2 == 0) 2500 else -2500;
    }
    var silence_frame: Frame = undefined;
    @memset(&silence_frame.samples, 0);

    // 40 speech frames.
    var speech_transmitted: u32 = 0;
    for (0..40) |_| {
        if (sender.analyze(speech_frame) == .speech) speech_transmitted += 1;
    }
    try std.testing.expect(speech_transmitted > 20);

    // 300 silence frames: gather stats.
    var sid_count: u32 = 0;
    var no_tx_count: u32 = 0;
    for (0..300) |_| {
        switch (sender.analyze(silence_frame)) {
            .speech => {},
            .sid => sid_count += 1,
            .no_transmit => no_tx_count += 1,
        }
    }
    try std.testing.expect(sid_count >= 1);
    try std.testing.expect(no_tx_count > 100);
    // SIDs + no-transmits should account for the large majority of the 300 frames.
    // (a few frames may be consumed by the energy smoother draining from speech)
    try std.testing.expect(sid_count + no_tx_count >= 270);
}
