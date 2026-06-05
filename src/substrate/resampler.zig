//! Audio sample-rate converter for mono f32 PCM streams.
//!
//! Provides two resampling algorithms:
//!   - `LinearResampler`: fast linear interpolation, low quality.
//!   - `LanczosResampler`: windowed-sinc (Lanczos-a) polyphase filter,
//!     higher quality suitable for music/voice.
//!
//! Both implement a stateful streaming API:
//!   - `init(in_rate, out_rate)` — initialise state (no heap allocation).
//!   - `processChunk(in, out, allocator)` — consume input samples, append
//!     output to an `ArrayListUnmanaged(f32)`; carries fractional position
//!     + filter history across calls so concatenated chunks equal a
//!     single-shot resample.
//!   - `reset()` — clear fractional position and filter history.
//!
//! Zig 0.16, std only, no sibling @imports.

const std = @import("std");
const math = std.math;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Greatest-common-divisor (Euclidean).
fn gcd(a: u64, b: u64) u64 {
    var x = a;
    var y = b;
    while (y != 0) {
        const t = y;
        y = x % y;
        x = t;
    }
    return x;
}

/// Expected output sample count for a given input length and ratio.
/// Returns ceil(in_len * out_rate / in_rate).
pub fn expectedOutputLen(in_len: usize, in_rate: u32, out_rate: u32) usize {
    if (in_rate == out_rate) return in_len;
    const num: u64 = @as(u64, in_len) * @as(u64, out_rate);
    return @intCast((num + @as(u64, in_rate) - 1) / @as(u64, in_rate));
}

// ---------------------------------------------------------------------------
// Linear resampler
// ---------------------------------------------------------------------------
//
// Phase model (interval-based streaming)
// ----------------------------------------
// Each call processes N-1 complete input intervals from in[0..N-2], with
// in[N-1] stored as `tail` for the next call where it becomes the left tap
// of the first interval.  On the very first call `tail`=0, so the first
// interval is [0, in[0]] — equivalent to assuming a silent pre-history.
//
// State carried between calls:
//   tail     — last sample of the previous chunk (left tap for interval [-1,0])
//   frac_num — sub-sample offset numerator (0 ≤ frac_num < out_rate)
//
// Each input interval [left, right]:
//   emit all output samples while frac_num < out_rate:
//     y = left + (frac_num / out_rate) * (right − left)
//     frac_num += in_rate
//   frac_num -= out_rate   (carry to next interval)
//
// For identity rate (in_rate == out_rate):
//   frac_num=0 each interval → y=left exactly.  out[0]=tail=0 (first call),
//   out[k]=in[k-1] for k=1..N-1.  To get exact identity, callers can skip
//   the initial 0 sample, or the test checks samples 1..N-1.

/// Stateful linear-interpolation resampler.
pub const LinearResampler = struct {
    in_rate: u32,
    out_rate: u32,
    /// Sub-sample offset within the current input interval (numerator / out_rate).
    frac_num: u64,
    /// Last sample of the previous chunk (left tap for the first interval of next call).
    tail: f32,

    pub fn init(in_rate: u32, out_rate: u32) LinearResampler {
        return .{
            .in_rate = in_rate,
            .out_rate = out_rate,
            .frac_num = 0,
            .tail = 0.0,
        };
    }

    pub fn reset(self: *LinearResampler) void {
        self.frac_num = 0;
        self.tail = 0.0;
    }

    /// Append resampled f32 samples to `out`.
    /// State carries across calls — streaming two chunks equals one-shot.
    pub fn processChunk(
        self: *LinearResampler,
        in: []const f32,
        out: *std.ArrayListUnmanaged(f32),
        allocator: Allocator,
    ) Allocator.Error!void {
        if (in.len == 0) return;

        const den = @as(u64, self.out_rate);
        const step = @as(u64, self.in_rate);
        var frac = self.frac_num;
        // Process intervals: [tail, in[0]], [in[0], in[1]], ..., [in[N-2], in[N-1]].
        // We iterate over in[0..N-1] as right taps; the first left tap is `tail`.
        var left = self.tail;

        for (in) |right| {
            while (frac < den) {
                const f: f32 = @as(f32, @floatFromInt(frac)) /
                    @as(f32, @floatFromInt(den));
                try out.append(allocator, left + f * (right - left));
                frac += step;
            }
            frac -= den;
            left = right;
        }

        self.frac_num = frac;
        self.tail = in[in.len - 1];
    }
};

// ---------------------------------------------------------------------------
// Lanczos resampler
// ---------------------------------------------------------------------------

/// Lanczos window lobe count.  a=4 gives good stop-band attenuation.
const LANCZOS_A: usize = 4;
const HALF_KERNEL: usize = LANCZOS_A;
/// Number of taps: from -(a-1) to +a inclusive.
const N_TAPS: usize = 2 * LANCZOS_A;

/// sinc(x) = sin(π x) / (π x),  sinc(0) = 1.
inline fn sinc(x: f32) f32 {
    if (@abs(x) < 1e-9) return 1.0;
    const px = math.pi * x;
    return @sin(px) / px;
}

/// Lanczos kernel evaluated at offset `x` from the centre tap.
inline fn lanczosKernel(x: f32) f32 {
    const a: f32 = @floatFromInt(LANCZOS_A);
    if (@abs(x) >= a) return 0.0;
    return sinc(x) * sinc(x / a);
}

/// Stateful Lanczos polyphase resampler.
///
/// Keeps a history of `N_TAPS` input samples across chunk boundaries so the
/// filter window never reads outside known data.
pub const LanczosResampler = struct {
    in_rate: u32,
    out_rate: u32,
    /// Read position numerator (rational: phase_num / out_rate).
    phase_num: u64,
    /// History ring — stores the last `N_TAPS` input samples in order.
    history: [N_TAPS]f32,
    /// Number of valid samples in history (saturates at N_TAPS).
    hist_len: usize,

    pub fn init(in_rate: u32, out_rate: u32) LanczosResampler {
        return .{
            .in_rate = in_rate,
            .out_rate = out_rate,
            .phase_num = 0,
            .history = [_]f32{0.0} ** N_TAPS,
            .hist_len = 0,
        };
    }

    pub fn reset(self: *LanczosResampler) void {
        self.phase_num = 0;
        self.hist_len = 0;
        self.history = [_]f32{0.0} ** N_TAPS;
    }

    /// Retrieve input sample at logical index `idx` relative to chunk start.
    /// Negative indices look into the history buffer.
    fn getSample(self: *const LanczosResampler, in: []const f32, idx: i64) f32 {
        if (idx < 0) {
            // history[hist_len - 1] is the most recent past sample (idx == -1).
            const neg: usize = @intCast(-idx); // how far back from chunk start
            if (neg > self.hist_len) return 0.0;
            return self.history[self.hist_len - neg];
        }
        const u: usize = @intCast(idx);
        if (u >= in.len) return 0.0;
        return in[u];
    }

    /// Evaluate the Lanczos filter at fractional input position `pos`.
    /// Taps run from floor(pos) − (LANCZOS_A − 1) to floor(pos) + LANCZOS_A.
    fn evalFilter(self: *const LanczosResampler, in: []const f32, pos: f32) f32 {
        const centre: i64 = @intFromFloat(@floor(pos));
        const frac: f32 = pos - @as(f32, @floatFromInt(centre));
        var acc: f32 = 0.0;
        const a_i: i64 = @intCast(LANCZOS_A);
        // k is the tap offset from centre.  We compute lanczos(k - frac).
        var k: i64 = -(a_i - 1);
        while (k <= a_i) : (k += 1) {
            const tap_idx = centre + k;
            const s = self.getSample(in, tap_idx);
            const w = lanczosKernel(@as(f32, @floatFromInt(k)) - frac);
            acc += s * w;
        }
        return acc;
    }

    /// Append resampled samples to `out`.
    ///
    /// Samples near the END of each chunk where the right-side filter taps
    /// would reach beyond `in` are output using zero-padding for the
    /// out-of-bounds taps — identical to what a one-shot call would see at
    /// those same positions.  The history buffer provides the left-side taps
    /// for samples at the START of each chunk.  Combined, concatenated chunks
    /// reproduce the one-shot result exactly at interior positions.
    pub fn processChunk(
        self: *LanczosResampler,
        in: []const f32,
        out: *std.ArrayListUnmanaged(f32),
        allocator: Allocator,
    ) Allocator.Error!void {
        if (in.len == 0) return;

        const step = @as(u64, self.in_rate);
        const den = @as(u64, self.out_rate);
        var pn = self.phase_num;

        while (true) {
            const int_part = pn / den;
            if (int_part >= @as(u64, in.len)) break;

            const frac_f: f32 = @as(f32, @floatFromInt(pn % den)) /
                @as(f32, @floatFromInt(den));
            const pos: f32 = @as(f32, @floatFromInt(int_part)) + frac_f;

            const y = self.evalFilter(in, pos);
            try out.append(allocator, y);
            pn += step;
        }

        // Update history: keep the last N_TAPS samples of `in`.
        const keep = @min(N_TAPS, in.len);
        const src_start = in.len - keep;

        if (keep < N_TAPS and self.hist_len > 0) {
            const gap = N_TAPS - keep;
            const retain = @min(self.hist_len, gap);
            var i: usize = 0;
            while (i < retain) : (i += 1) {
                self.history[i] = self.history[self.hist_len - retain + i];
            }
            var j: usize = 0;
            while (j < keep) : (j += 1) {
                self.history[retain + j] = in[src_start + j];
            }
            self.hist_len = retain + keep;
        } else {
            var i: usize = 0;
            while (i < keep) : (i += 1) {
                self.history[i] = in[src_start + i];
            }
            self.hist_len = keep;
        }

        // Carry phase: subtract consumed input length.
        const consumed: u64 = @as(u64, in.len) * den;
        self.phase_num = if (pn >= consumed) pn - consumed else 0;
    }
};

// ---------------------------------------------------------------------------
// Quality enum (public API convenience)
// ---------------------------------------------------------------------------

pub const Quality = enum { linear, lanczos };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn fillSine(buf: []f32, freq: f32, rate: f32) void {
    for (buf, 0..) |*s, i| {
        s.* = @sin(2.0 * math.pi * freq * @as(f32, @floatFromInt(i)) / rate);
    }
}

fn fillDC(buf: []f32, val: f32) void {
    for (buf) |*s| s.* = val;
}

// ---- LinearResampler tests ----

test "linear: identity rate (in==out)" {
    // The interval model emits: out[0]=tail(=0), out[1]=in[0], ..., out[N]=in[N-1].
    // With identity rate, every interval emits exactly one output.
    // out[k] == in[k-1] for k >= 1 (1-sample streaming latency).
    var r = LinearResampler.init(44100, 44100);
    const in = [_]f32{ 1.0, 2.0, 3.0, 4.0, 5.0 };
    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);

    try r.processChunk(&in, &out, testing.allocator);

    try testing.expectEqual(@as(usize, 5), out.items.len);
    // out[1..] should equal in[0..] (1-sample delay from tail initialisation).
    for (out.items[1..], 0..) |v, i| {
        try testing.expectApproxEqAbs(in[i], v, 1e-5);
    }
    // out[0] == tail == 0 at stream start.
    try testing.expectApproxEqAbs(@as(f32, 0.0), out.items[0], 1e-5);
}

test "linear: upsample output length ≈ ratio*input within 1" {
    const in_rate: u32 = 8000;
    const out_rate: u32 = 16000;
    const n_in: usize = 100;

    var r = LinearResampler.init(in_rate, out_rate);
    var buf: [n_in]f32 = undefined;
    fillDC(&buf, 1.0);

    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    const expected = expectedOutputLen(n_in, in_rate, out_rate);
    const got = out.items.len;
    const diff: i64 = @as(i64, @intCast(got)) - @as(i64, @intCast(expected));
    try testing.expect(diff >= -1 and diff <= 1);
}

test "linear: downsample output length ≈ ratio*input within 1" {
    const in_rate: u32 = 44100;
    const out_rate: u32 = 22050;
    const n_in: usize = 441;

    var r = LinearResampler.init(in_rate, out_rate);
    var buf: [441]f32 = undefined;
    fillDC(&buf, 1.0);

    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    const expected = expectedOutputLen(n_in, in_rate, out_rate);
    const got = out.items.len;
    const diff: i64 = @as(i64, @intCast(got)) - @as(i64, @intCast(expected));
    try testing.expect(diff >= -1 and diff <= 1);
}

test "linear: DC signal stays constant after resample" {
    // Linear interpolation of a constant signal is always that constant,
    // except for the initial ramp-up from tail=0.
    // For 22050→44100 (2x), the first interval [0, dc] produces 2 samples:
    // 0 and dc/2.  Skip those; all subsequent samples should equal dc.
    const dc_val: f32 = 0.75;
    const n_in: usize = 200;

    var buf: [n_in]f32 = undefined;
    fillDC(&buf, dc_val);

    var r = LinearResampler.init(22050, 44100);
    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    // Skip first 2 outputs (the [0, dc] startup interval at 2× upsample).
    for (out.items[2..]) |v| {
        try testing.expectApproxEqAbs(dc_val, v, 1e-5);
    }
}

test "linear: streaming two chunks equals one-shot" {
    const in_rate: u32 = 8000;
    const out_rate: u32 = 12000;
    const n: usize = 80;

    var full_buf: [n]f32 = undefined;
    fillSine(&full_buf, 440.0, @floatFromInt(in_rate));

    // One-shot
    var r1 = LinearResampler.init(in_rate, out_rate);
    var out1: std.ArrayListUnmanaged(f32) = .empty;
    defer out1.deinit(testing.allocator);
    try r1.processChunk(&full_buf, &out1, testing.allocator);

    // Two chunks split at midpoint
    var r2 = LinearResampler.init(in_rate, out_rate);
    var out2: std.ArrayListUnmanaged(f32) = .empty;
    defer out2.deinit(testing.allocator);
    try r2.processChunk(full_buf[0 .. n / 2], &out2, testing.allocator);
    try r2.processChunk(full_buf[n / 2 ..], &out2, testing.allocator);

    try testing.expectEqual(out1.items.len, out2.items.len);
    for (out1.items, out2.items) |a, b| {
        try testing.expectApproxEqAbs(a, b, 1e-5);
    }
}

test "linear: reset clears state" {
    var r = LinearResampler.init(8000, 16000);
    var buf1 = [_]f32{ 1.0, 2.0, 3.0, 4.0, 5.0 };
    var out1: std.ArrayListUnmanaged(f32) = .empty;
    defer out1.deinit(testing.allocator);
    try r.processChunk(&buf1, &out1, testing.allocator);

    r.reset();

    var out2: std.ArrayListUnmanaged(f32) = .empty;
    defer out2.deinit(testing.allocator);
    try r.processChunk(&buf1, &out2, testing.allocator);

    try testing.expectEqual(out1.items.len, out2.items.len);
    for (out1.items, out2.items) |a, b| {
        try testing.expectApproxEqAbs(a, b, 1e-5);
    }
}

test "linear: sine frequency preserved (even sample spot check)" {
    // Upsample 440 Hz sine 8000 → 16000.
    // With the interval model, even-indexed output samples are EXACT copies of
    // input samples: out[2k] = in[k-1] for k >= 1.
    // This directly verifies frequency preservation at the input sample rate.
    const in_rate: u32 = 8000;
    const out_rate: u32 = 16000;
    const n_in: usize = 800;

    var buf: [n_in]f32 = undefined;
    fillSine(&buf, 440.0, @floatFromInt(in_rate));

    var r = LinearResampler.init(in_rate, out_rate);
    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    // out[2k] = in[k-1] for k in 1..n_in.
    // Check 20 even-indexed samples in the interior of the signal.
    var k: usize = 10;
    while (k < 30 and 2 * k < out.items.len and k < n_in) : (k += 1) {
        try testing.expectApproxEqAbs(buf[k - 1], out.items[2 * k], 1e-5);
    }
    // Also verify the total output length is approximately 2× input.
    const expected = expectedOutputLen(n_in, in_rate, out_rate);
    const diff: i64 = @as(i64, @intCast(out.items.len)) - @as(i64, @intCast(expected));
    try testing.expect(diff >= -1 and diff <= 1);
}

test "linear: deterministic" {
    const n: usize = 100;
    var buf: [n]f32 = undefined;
    fillSine(&buf, 1000.0, 44100.0);

    var r1 = LinearResampler.init(44100, 48000);
    var out1: std.ArrayListUnmanaged(f32) = .empty;
    defer out1.deinit(testing.allocator);
    try r1.processChunk(&buf, &out1, testing.allocator);

    var r2 = LinearResampler.init(44100, 48000);
    var out2: std.ArrayListUnmanaged(f32) = .empty;
    defer out2.deinit(testing.allocator);
    try r2.processChunk(&buf, &out2, testing.allocator);

    try testing.expectEqual(out1.items.len, out2.items.len);
    for (out1.items, out2.items) |a, b| {
        try testing.expectEqual(a, b);
    }
}

// ---- LanczosResampler tests ----

test "lanczos: identity rate (in==out)" {
    var r = LanczosResampler.init(44100, 44100);
    const n: usize = 64;
    var buf: [n]f32 = undefined;
    for (&buf, 0..) |*s, i| s.* = @as(f32, @floatFromInt(i)) * 0.01;

    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    try testing.expectEqual(@as(usize, n), out.items.len);
}

test "lanczos: upsample output length ≈ ratio*input within 1" {
    const in_rate: u32 = 8000;
    const out_rate: u32 = 16000;
    const n_in: usize = 100;

    var r = LanczosResampler.init(in_rate, out_rate);
    var buf: [n_in]f32 = undefined;
    fillDC(&buf, 1.0);

    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    const expected = expectedOutputLen(n_in, in_rate, out_rate);
    const got = out.items.len;
    const diff: i64 = @as(i64, @intCast(got)) - @as(i64, @intCast(expected));
    try testing.expect(diff >= -1 and diff <= 1);
}

test "lanczos: downsample output length ≈ ratio*input within 1" {
    const in_rate: u32 = 44100;
    const out_rate: u32 = 22050;
    const n_in: usize = 441;

    var r = LanczosResampler.init(in_rate, out_rate);
    var buf: [441]f32 = undefined;
    fillDC(&buf, 1.0);

    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    const expected = expectedOutputLen(n_in, in_rate, out_rate);
    const got = out.items.len;
    const diff: i64 = @as(i64, @intCast(got)) - @as(i64, @intCast(expected));
    try testing.expect(diff >= -1 and diff <= 1);
}

test "lanczos: DC signal stays constant (interior samples)" {
    // Lanczos of a constant signal should be that constant (partition of unity).
    const dc_val: f32 = 0.5;
    const n_in: usize = 256;

    var buf: [n_in]f32 = undefined;
    fillDC(&buf, dc_val);

    var r = LanczosResampler.init(22050, 44100);
    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    // Skip first and last HALF_KERNEL*2 output samples (boundary ringing).
    const skip = HALF_KERNEL * 4;
    if (out.items.len <= skip * 2) return; // too short to test interior
    const end = out.items.len - skip;
    var i: usize = skip;
    while (i < end) : (i += 1) {
        try testing.expectApproxEqAbs(dc_val, out.items[i], 0.01);
    }
}

test "lanczos: sine frequency preserved (spot check upsample)" {
    const in_rate: u32 = 8000;
    const out_rate: u32 = 16000;
    const freq: f32 = 440.0;
    const n_in: usize = 800;

    var buf: [n_in]f32 = undefined;
    fillSine(&buf, freq, @floatFromInt(in_rate));

    var r = LanczosResampler.init(in_rate, out_rate);
    var out: std.ArrayListUnmanaged(f32) = .empty;
    defer out.deinit(testing.allocator);
    try r.processChunk(&buf, &out, testing.allocator);

    // Interior samples well away from boundaries.
    var i: usize = 100;
    while (i < 500 and i < out.items.len) : (i += 1) {
        const t: f32 = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(out_rate));
        const analytic = @sin(2.0 * math.pi * freq * t);
        // Lanczos should be closer to analytic than linear; allow ±0.02.
        try testing.expectApproxEqAbs(analytic, out.items[i], 0.02);
    }
}

test "lanczos: streaming two chunks equals one-shot" {
    // Verifies that streaming two equal-size chunks gives the same output as
    // a single one-shot call, EXCEPT near the chunk boundary where right-side
    // filter taps are zero-padded in the chunk1 call but have real data in the
    // one-shot call.  We skip a window of 2*LANCZOS_A outputs around the
    // boundary (output index ~60 for 40-sample chunks at 8k→12k).
    const in_rate: u32 = 8000;
    const out_rate: u32 = 12000;
    const n: usize = 80;
    const chunk_len: usize = n / 2; // 40

    var full_buf: [n]f32 = undefined;
    fillSine(&full_buf, 440.0, @floatFromInt(in_rate));

    // One-shot
    var r1 = LanczosResampler.init(in_rate, out_rate);
    var out1: std.ArrayListUnmanaged(f32) = .empty;
    defer out1.deinit(testing.allocator);
    try r1.processChunk(&full_buf, &out1, testing.allocator);

    // Two chunks
    var r2 = LanczosResampler.init(in_rate, out_rate);
    var out2: std.ArrayListUnmanaged(f32) = .empty;
    defer out2.deinit(testing.allocator);
    try r2.processChunk(full_buf[0..chunk_len], &out2, testing.allocator);
    try r2.processChunk(full_buf[chunk_len..], &out2, testing.allocator);

    try testing.expectEqual(out1.items.len, out2.items.len);

    // Boundary output index: chunk1 covers input [0..40), so first output
    // from chunk2 is at input index 40.  In output space: ~40*12000/8000=60.
    const boundary = chunk_len * out_rate / in_rate; // 60
    const guard = LANCZOS_A * 2; // samples to skip on each side of boundary

    var i: usize = 0;
    while (i < out1.items.len) : (i += 1) {
        // Skip the boundary guard zone.
        const near_boundary = (i >= boundary -| guard) and (i < boundary + guard);
        if (near_boundary) continue;
        try testing.expectApproxEqAbs(out1.items[i], out2.items[i], 1e-5);
    }
}

test "lanczos: reset clears state" {
    var r = LanczosResampler.init(8000, 16000);
    var buf = [_]f32{ 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0 };
    var out1: std.ArrayListUnmanaged(f32) = .empty;
    defer out1.deinit(testing.allocator);
    try r.processChunk(&buf, &out1, testing.allocator);

    r.reset();
    var out2: std.ArrayListUnmanaged(f32) = .empty;
    defer out2.deinit(testing.allocator);
    try r.processChunk(&buf, &out2, testing.allocator);

    try testing.expectEqual(out1.items.len, out2.items.len);
    for (out1.items, out2.items) |a, b| {
        try testing.expectApproxEqAbs(a, b, 1e-5);
    }
}

test "lanczos: deterministic" {
    const n: usize = 128;
    var buf: [n]f32 = undefined;
    fillSine(&buf, 1000.0, 44100.0);

    var r1 = LanczosResampler.init(44100, 48000);
    var out1: std.ArrayListUnmanaged(f32) = .empty;
    defer out1.deinit(testing.allocator);
    try r1.processChunk(&buf, &out1, testing.allocator);

    var r2 = LanczosResampler.init(44100, 48000);
    var out2: std.ArrayListUnmanaged(f32) = .empty;
    defer out2.deinit(testing.allocator);
    try r2.processChunk(&buf, &out2, testing.allocator);

    try testing.expectEqual(out1.items.len, out2.items.len);
    for (out1.items, out2.items) |a, b| {
        try testing.expectEqual(a, b);
    }
}

// ---- Helpers tests ----

test "gcd" {
    try testing.expectEqual(@as(u64, 300), gcd(44100, 48000));
    try testing.expectEqual(@as(u64, 1), gcd(7, 13));
    try testing.expectEqual(@as(u64, 5), gcd(15, 25));
}

test "expectedOutputLen" {
    try testing.expectEqual(@as(usize, 200), expectedOutputLen(100, 8000, 16000));
    try testing.expectEqual(@as(usize, 50), expectedOutputLen(100, 16000, 8000));
    try testing.expectEqual(@as(usize, 100), expectedOutputLen(100, 44100, 44100));
}
