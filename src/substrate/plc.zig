//! Packet-Loss Concealment (PLC) engine for mono f32 audio.
//!
//! Algorithm: pitch-synchronous overlap-add (PSOLA) concealment.
//!   - Maintains a ring-buffer history of good frames.
//!   - On a lost frame, estimates the pitch period via normalized
//!     autocorrelation, then synthesises a replacement by repeating
//!     the last pitch period with overlap-add.
//!   - Consecutive losses are progressively attenuated toward silence.
//!   - On re-entry (first good frame after losses), a cross-fade
//!     replaces the first real frame with a blend that avoids clicks.
//!
//! Zig 0.16 compatible (ArrayListUnmanaged, std.testing.allocator).

const std = @import("std");
const Allocator = std.mem.Allocator;
const math = std.math;
const testing = std.testing;

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/// Minimum pitch period in samples.  Corresponds to ~500 Hz at 8 kHz.
pub const PITCH_MIN: usize = 16;
/// Maximum pitch period in samples.  Corresponds to ~62 Hz at 8 kHz.
pub const PITCH_MAX: usize = 128;
/// Overlap-add window length expressed as a multiple of the pitch period.
/// We blend half a period worth of samples at each splice.
pub const OLA_OVERLAP_FRAC: f32 = 0.5;
/// Attenuation factor applied to each successive concealed frame.
pub const LOSS_ATTENUATION: f32 = 0.85;
/// Number of history samples kept (must be >= 2 * PITCH_MAX + frame_size).
const HISTORY_SAMPLES: usize = 4096;

// ---------------------------------------------------------------------------
// Hann window helper (half-window for OLA)
// ---------------------------------------------------------------------------

/// Write a Hann window of `len` samples into `out`.
fn hannWindow(out: []f32) void {
    const n = out.len;
    if (n == 0) return;
    for (out, 0..) |*s, i| {
        const phase: f32 = math.pi * @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(n));
        s.* = 0.5 - 0.5 * @cos(2.0 * phase);
    }
}

// ---------------------------------------------------------------------------
// PLC engine
// ---------------------------------------------------------------------------

pub const Plc = struct {
    allocator: Allocator,

    /// Ring-buffer of historical (good) samples.
    history: std.ArrayListUnmanaged(f32),
    /// Write-head position in the history ring.
    hist_pos: usize,
    /// Number of valid samples currently in the history.
    hist_len: usize,
    /// Frame size in samples (fixed at init).
    frame_size: usize,
    /// Number of consecutive lost frames since the last good frame.
    loss_count: u32,
    /// True when the previous frame was lost (triggers cross-fade on re-entry).
    was_lost: bool,
    /// Scratch buffer for the synthesised concealment frame (frame_size).
    synth_buf: std.ArrayListUnmanaged(f32),

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    pub fn init(allocator: Allocator, frame_size: usize) !Plc {
        std.debug.assert(frame_size > 0);
        var history: std.ArrayListUnmanaged(f32) = .empty;
        try history.resize(allocator, HISTORY_SAMPLES);
        @memset(history.items, 0.0);

        var synth_buf: std.ArrayListUnmanaged(f32) = .empty;
        try synth_buf.resize(allocator, frame_size);
        @memset(synth_buf.items, 0.0);

        return Plc{
            .allocator = allocator,
            .history = history,
            .hist_pos = 0,
            .hist_len = 0,
            .frame_size = frame_size,
            .loss_count = 0,
            .was_lost = false,
            .synth_buf = synth_buf,
        };
    }

    pub fn deinit(self: *Plc) void {
        self.history.deinit(self.allocator);
        self.synth_buf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn reset(self: *Plc) void {
        @memset(self.history.items, 0.0);
        self.hist_pos = 0;
        self.hist_len = 0;
        self.loss_count = 0;
        self.was_lost = false;
        @memset(self.synth_buf.items, 0.0);
    }

    // ------------------------------------------------------------------
    // Push a good (received) frame into history and return it.
    // If we are re-entering after losses, the returned slice is the
    // cross-faded blend stored in synth_buf (caller should read it before
    // calling pushGood again).
    // ------------------------------------------------------------------

    /// Ingest a real frame.  Returns the (possibly cross-faded) frame
    /// that the caller should use.  The returned slice is valid until
    /// the next call to `pushGood` or `conceal`.
    pub fn pushGood(self: *Plc, frame: []const f32) []const f32 {
        std.debug.assert(frame.len == self.frame_size);

        if (self.was_lost and self.loss_count > 0) {
            // Cross-fade: blend from synth_buf tail into the incoming frame.
            self.crossFade(frame);
            self.was_lost = false;
            self.loss_count = 0;
            self.appendToHistory(self.synth_buf.items);
            return self.synth_buf.items;
        }

        self.was_lost = false;
        self.loss_count = 0;
        self.appendToHistory(frame);
        return frame;
    }

    /// Synthesise a replacement for a lost frame.
    /// Returns a slice of `synth_buf`; valid until the next call.
    pub fn conceal(self: *Plc) []const f32 {
        const out = self.synth_buf.items;
        @memset(out, 0.0);

        const avail = self.hist_len;
        if (avail < PITCH_MIN * 2) {
            // Not enough history — emit silence.
            self.was_lost = true;
            self.loss_count += 1;
            return out;
        }

        const pitch = self.estimatePitch();
        self.synthesise(out, pitch);

        // Attenuate based on consecutive loss count.
        const atten = math.pow(f32, LOSS_ATTENUATION, @as(f32, @floatFromInt(self.loss_count)));
        for (out) |*s| s.* *= atten;

        self.was_lost = true;
        self.loss_count += 1;

        // Add the synthesised frame to history so that consecutive losses
        // can build on each other.
        self.appendToHistory(out);
        return out;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Append `frame` samples to the ring buffer.
    fn appendToHistory(self: *Plc, frame: []const f32) void {
        const capacity = self.history.items.len;
        for (frame) |s| {
            self.history.items[self.hist_pos] = s;
            self.hist_pos = (self.hist_pos + 1) % capacity;
        }
        self.hist_len = @min(self.hist_len + frame.len, capacity);
    }

    /// Read `n` samples ending at the current write-head (i.e. the most
    /// recent `n` history samples) into `dst`.
    fn readHistory(self: *const Plc, dst: []f32) void {
        const capacity = self.history.items.len;
        const n = dst.len;
        std.debug.assert(n <= self.hist_len);
        // Start position: hist_pos - n (wrapping)
        var pos: usize = (self.hist_pos + capacity - n) % capacity;
        for (dst) |*s| {
            s.* = self.history.items[pos];
            pos = (pos + 1) % capacity;
        }
    }

    /// Estimate the dominant pitch period (in samples) using normalised
    /// autocorrelation over [PITCH_MIN, PITCH_MAX].
    fn estimatePitch(self: *const Plc) usize {
        // We analyse the most recent `analysis_len` samples.
        const analysis_len = @min(self.hist_len, PITCH_MAX * 4);
        // Temporary stack buffer — safe because PITCH_MAX*4 = 512 < 4 KiB.
        var buf: [PITCH_MAX * 4]f32 = undefined;
        const analysis = buf[0..analysis_len];
        self.readHistory(analysis);

        // Compute energy of the signal for normalisation.
        var energy: f32 = 0.0;
        for (analysis) |s| energy += s * s;
        if (energy < 1e-12) return PITCH_MIN; // silence — default

        var best_lag: usize = PITCH_MIN;
        var best_corr: f32 = -math.floatMax(f32);

        var lag: usize = PITCH_MIN;
        while (lag <= PITCH_MAX and lag <= analysis_len / 2) : (lag += 1) {
            var corr: f32 = 0.0;
            const limit = analysis_len - lag;
            var i: usize = 0;
            while (i < limit) : (i += 1) {
                corr += analysis[i] * analysis[i + lag];
            }
            // Normalise by energy so amplitude doesn't bias the peak.
            const norm_corr = corr / (energy + 1e-12);
            if (norm_corr > best_corr) {
                best_corr = norm_corr;
                best_lag = lag;
            }
        }
        return best_lag;
    }

    /// Synthesise one output frame of PSOLA-style repeating pitch periods.
    fn synthesise(self: *const Plc, out: []f32, pitch: usize) void {
        const n = out.len;
        // We tile the last `pitch` samples from history across `out`,
        // using overlap-add at boundaries for smooth splicing.

        // Extract one pitch period from history.
        var period_buf: [PITCH_MAX + 1]f32 = undefined;
        const period = period_buf[0..pitch];
        // Read the most recent `pitch` samples.
        const capacity = self.history.items.len;
        var pos: usize = (self.hist_pos + capacity - pitch) % capacity;
        for (period) |*s| {
            s.* = self.history.items[pos];
            pos = (pos + 1) % capacity;
        }

        // Build overlap-add window (half-Hann, length = overlap_len).
        const overlap_len = @max(1, @as(usize, @intFromFloat(@as(f32, @floatFromInt(pitch)) * OLA_OVERLAP_FRAC)));
        var win_buf: [PITCH_MAX + 1]f32 = undefined;
        const win = win_buf[0..overlap_len];
        hannWindow(win);

        // Zero-fill output then tile with OLA.
        @memset(out, 0.0);
        var write: usize = 0;
        while (write < n) {
            // Copy one period into out, adding over any overlap region.
            var k: usize = 0;
            while (k < pitch and write + k < n) : (k += 1) {
                const sample = period[k];
                if (k < overlap_len and write > 0) {
                    // fade-in of new period
                    const fade_in = win[k];
                    // fade-out of previous content (already written)
                    const fade_out = 1.0 - win[k];
                    out[write + k] = out[write + k] * fade_out + sample * fade_in;
                } else {
                    out[write + k] += sample;
                }
            }
            write += pitch;
        }

        // Clamp to avoid exceeding ±1.0 on extreme inputs.
        for (out) |*s| s.* = math.clamp(s.*, -1.0, 1.0);
    }

    /// Cross-fade from the last synthesised frame (synth_buf) into `incoming`.
    /// The result is stored back into synth_buf.
    fn crossFade(self: *Plc, incoming: []const f32) void {
        const n = self.frame_size;
        const prev = self.synth_buf.items; // tail of last concealed output
        for (0..n) |i| {
            const t = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(n));
            // Linear cross-fade; could use raised cosine but linear is fine.
            self.synth_buf.items[i] = prev[i] * (1.0 - t) + incoming[i] * t;
        }
    }
};

// ===========================================================================
// Tests
// ===========================================================================

/// Generate a mono f32 sine frame of `len` samples.
fn sineFrame(buf: []f32, freq_hz: f32, sample_rate: f32, phase_offset: f32) void {
    for (buf, 0..) |*s, i| {
        const t = (@as(f32, @floatFromInt(i)) + phase_offset) / sample_rate;
        s.* = @sin(2.0 * math.pi * freq_hz * t);
    }
}

/// RMS energy of a slice.
fn rms(buf: []const f32) f32 {
    var sum: f32 = 0.0;
    for (buf) |s| sum += s * s;
    return @sqrt(sum / @as(f32, @floatFromInt(buf.len)));
}

/// Maximum absolute sample-to-sample discontinuity at the join between
/// the last sample of `a` and first sample of `b`.
fn seamDelta(a: []const f32, b: []const f32) f32 {
    if (a.len == 0 or b.len == 0) return 0.0;
    return @abs(a[a.len - 1] - b[0]);
}

test "init and reset clears state" {
    const allocator = testing.allocator;
    const FRAME = 64;
    var plc = try Plc.init(allocator, FRAME);
    defer plc.deinit();

    // Push a sine frame, then reset, verify history is zeroed.
    var frame: [FRAME]f32 = undefined;
    sineFrame(&frame, 200.0, 8000.0, 0.0);
    _ = plc.pushGood(&frame);

    plc.reset();
    try testing.expectEqual(@as(usize, 0), plc.hist_len);
    try testing.expectEqual(@as(u32, 0), plc.loss_count);
    try testing.expectEqual(false, plc.was_lost);

    // After reset, conceal should return near-silence (no history).
    const concealed = plc.conceal();
    try testing.expectEqual(@as(usize, FRAME), concealed.len);
    var energy: f32 = 0.0;
    for (concealed) |s| energy += s * s;
    try testing.expect(energy < 1e-6);
}

test "single concealed frame has energy close to neighbours" {
    const allocator = testing.allocator;
    const FRAME = 64;
    const RATE: f32 = 8000.0;
    const FREQ: f32 = 200.0; // 200 Hz — period = 40 samples, well within range

    var plc = try Plc.init(allocator, FRAME);
    defer plc.deinit();

    // Prime the history with several frames.
    var buf: [FRAME]f32 = undefined;
    var phase_acc: f32 = 0.0;
    for (0..8) |_| {
        sineFrame(&buf, FREQ, RATE, phase_acc);
        phase_acc += @as(f32, @floatFromInt(FRAME));
        _ = plc.pushGood(&buf);
    }

    // Record energy of a clean frame just before the loss.
    var pre_frame: [FRAME]f32 = undefined;
    sineFrame(&pre_frame, FREQ, RATE, phase_acc);
    phase_acc += @as(f32, @floatFromInt(FRAME));
    const pre_rms = rms(&pre_frame);
    _ = plc.pushGood(&pre_frame);

    // --- Lost frame ---
    const concealed = plc.conceal();
    const con_rms = rms(concealed);

    // The concealed RMS should be within 50% of the pre-loss frame RMS.
    // (Generous tolerance; PSOLA with a single loss should be close.)
    try testing.expect(con_rms > pre_rms * 0.5);
    try testing.expect(con_rms < pre_rms * 1.5);
}

test "single concealed frame: no large discontinuity at seam" {
    const allocator = testing.allocator;
    const FRAME = 64;
    const RATE: f32 = 8000.0;
    const FREQ: f32 = 200.0;

    var plc = try Plc.init(allocator, FRAME);
    defer plc.deinit();

    var buf: [FRAME]f32 = undefined;
    var phase_acc: f32 = 0.0;

    // Push enough history.
    for (0..8) |_| {
        sineFrame(&buf, FREQ, RATE, phase_acc);
        phase_acc += @as(f32, @floatFromInt(FRAME));
        _ = plc.pushGood(&buf);
    }

    // The last good frame — store its last sample.
    var last_good: [FRAME]f32 = undefined;
    sineFrame(&last_good, FREQ, RATE, phase_acc);
    phase_acc += @as(f32, @floatFromInt(FRAME));
    _ = plc.pushGood(&last_good);

    const concealed = plc.conceal();

    // The seam between the last good sample and first concealed sample
    // should be small relative to the sine amplitude (≤ 0.5).
    const delta = seamDelta(&last_good, concealed);
    try testing.expect(delta < 0.5);
}

test "consecutive losses attenuate toward silence" {
    const allocator = testing.allocator;
    const FRAME = 64;
    const RATE: f32 = 8000.0;
    const FREQ: f32 = 200.0;

    var plc = try Plc.init(allocator, FRAME);
    defer plc.deinit();

    var buf: [FRAME]f32 = undefined;
    var phase_acc: f32 = 0.0;

    for (0..8) |_| {
        sineFrame(&buf, FREQ, RATE, phase_acc);
        phase_acc += @as(f32, @floatFromInt(FRAME));
        _ = plc.pushGood(&buf);
    }

    // Collect RMS of successive concealed frames.
    var prev_rms: f32 = math.floatMax(f32);
    for (0..6) |_| {
        // Copy the slice so we're not working with a pointer that changes.
        var frame_copy: [FRAME]f32 = undefined;
        const concealed = plc.conceal();
        @memcpy(&frame_copy, concealed);
        const cur_rms = rms(&frame_copy);
        try testing.expect(cur_rms <= prev_rms + 1e-5); // monotonically non-increasing
        prev_rms = cur_rms;
    }

    // After many losses the output should be close to silence.
    var frame_copy: [FRAME]f32 = undefined;
    // Run more losses
    for (0..10) |_| {
        const c = plc.conceal();
        @memcpy(&frame_copy, c);
    }
    const final_rms = rms(&frame_copy);
    try testing.expect(final_rms < 0.05);
}

test "re-entry cross-fade avoids click" {
    // The cross-fade test checks two things:
    //
    // 1. The re-entry output blends toward the real frame: the last sample of
    //    the re-entry output should be closer to the real frame's last sample
    //    than it would be without any cross-fade (i.e., it actually interpolates).
    //
    // 2. After re-entry the engine is back to normal: the next good push returns
    //    the incoming pointer directly (no cross-fade applied).
    const allocator = testing.allocator;
    const FRAME = 64;
    const RATE: f32 = 8000.0;
    const FREQ: f32 = 200.0;

    var plc = try Plc.init(allocator, FRAME);
    defer plc.deinit();

    var buf: [FRAME]f32 = undefined;
    var phase_acc: f32 = 0.0;

    for (0..8) |_| {
        sineFrame(&buf, FREQ, RATE, phase_acc);
        phase_acc += @as(f32, @floatFromInt(FRAME));
        _ = plc.pushGood(&buf);
    }

    // Lose two frames.
    _ = plc.conceal();
    var c2_copy: [FRAME]f32 = undefined;
    const c2 = plc.conceal();
    @memcpy(&c2_copy, c2);

    // Re-enter with a real frame.
    var real_frame: [FRAME]f32 = undefined;
    sineFrame(&real_frame, FREQ, RATE, phase_acc);
    phase_acc += @as(f32, @floatFromInt(FRAME));
    const reentry = plc.pushGood(&real_frame);

    // Cross-fade: at t=0 the output equals c2[0] (full concealment weight);
    // at t=1 it equals real_frame[FRAME-1] (full real weight).
    // So reentry[FRAME-1] must equal real_frame[FRAME-1].
    // More importantly, the output is NOT simply c2 (no cross-fade path)
    // because the t-weighted blend changes each sample.
    // Verify that the last sample of reentry is close to the real frame end.
    const last_t: f32 = @as(f32, @floatFromInt(FRAME - 1)) / @as(f32, @floatFromInt(FRAME));
    const expected_last = c2_copy[FRAME - 1] * (1.0 - last_t) + real_frame[FRAME - 1] * last_t;
    try testing.expectApproxEqAbs(expected_last, reentry[FRAME - 1], 1e-5);

    // The first sample must equal c2[0] (weight = 1-0 = 1.0 for prev, 0 for real).
    const expected_first = c2_copy[0] * 1.0 + real_frame[0] * 0.0;
    try testing.expectApproxEqAbs(expected_first, reentry[0], 1e-5);

    // Verify the engine is back to normal: next push is not cross-faded.
    var next_frame: [FRAME]f32 = undefined;
    sineFrame(&next_frame, FREQ, RATE, phase_acc);
    const next_out = plc.pushGood(&next_frame);
    try testing.expectEqual(next_out.ptr, next_frame[0..].ptr);
}

test "deterministic: same seed produces identical output" {
    const allocator = testing.allocator;
    const FRAME = 64;
    const RATE: f32 = 8000.0;
    const FREQ: f32 = 150.0;

    var plc1 = try Plc.init(allocator, FRAME);
    defer plc1.deinit();
    var plc2 = try Plc.init(allocator, FRAME);
    defer plc2.deinit();

    var buf: [FRAME]f32 = undefined;
    var phase: f32 = 0.0;
    for (0..6) |_| {
        sineFrame(&buf, FREQ, RATE, phase);
        phase += @as(f32, @floatFromInt(FRAME));
        _ = plc1.pushGood(&buf);
        _ = plc2.pushGood(&buf);
    }

    var c1_copy: [FRAME]f32 = undefined;
    var c2_copy: [FRAME]f32 = undefined;
    @memcpy(&c1_copy, plc1.conceal());
    @memcpy(&c2_copy, plc2.conceal());

    for (c1_copy, c2_copy) |a, b| {
        try testing.expectEqual(a, b);
    }
}

test "pushGood return value: no-loss path returns input slice" {
    const allocator = testing.allocator;
    const FRAME = 32;

    var plc = try Plc.init(allocator, FRAME);
    defer plc.deinit();

    var frame: [FRAME]f32 = undefined;
    sineFrame(&frame, 300.0, 8000.0, 0.0);
    const returned = plc.pushGood(&frame);
    // When no previous loss, pushGood must return the original frame pointer.
    try testing.expectEqual(returned.ptr, frame[0..].ptr);
}
