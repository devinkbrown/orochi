//! PCM audio sample utilities.
//!
//! Provides i16<->f32 conversion, interleave/deinterleave for N channels,
//! gain with saturation, mono<->stereo mixing, peak/RMS/dBFS measurement,
//! and hard/soft clipping. All functions operate on slices. Self-contained,
//! no external dependencies beyond std.

const std = @import("std");
const math = std.math;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum value of a signed 16-bit sample as f32.
const I16_MAX_F: f32 = 32767.0;
/// Minimum value of a signed 16-bit sample as f32.
const I16_MIN_F: f32 = -32768.0;

// ---------------------------------------------------------------------------
// i16 <-> f32 conversion
// ---------------------------------------------------------------------------

/// Convert a single i16 PCM sample to f32 in [-1.0, 1.0].
/// Divides by 32767 so that +32767 -> +1.0 exactly.
pub fn i16ToF32(sample: i16) f32 {
    return @as(f32, @floatFromInt(sample)) / I16_MAX_F;
}

/// Convert a single f32 sample in [-1.0, 1.0] to i16.
/// Clamps before conversion to prevent undefined behaviour on overflow.
pub fn f32ToI16(sample: f32) i16 {
    const clamped = std.math.clamp(sample, -1.0, 1.0);
    // Scale and round to nearest integer.
    const scaled = clamped * I16_MAX_F;
    const rounded = @round(scaled);
    return @as(i16, @intFromFloat(rounded));
}

/// Convert a slice of i16 samples to f32, writing into `out`.
/// `in` and `out` must have the same length.
pub fn i16SliceToF32(in: []const i16, out: []f32) void {
    std.debug.assert(in.len == out.len);
    for (in, 0..) |s, i| {
        out[i] = i16ToF32(s);
    }
}

/// Convert a slice of f32 samples to i16, writing into `out`.
/// `in` and `out` must have the same length.
pub fn f32SliceToI16(in: []const f32, out: []i16) void {
    std.debug.assert(in.len == out.len);
    for (in, 0..) |s, i| {
        out[i] = f32ToI16(s);
    }
}

// ---------------------------------------------------------------------------
// Interleave / deinterleave
// ---------------------------------------------------------------------------

/// Interleave `channels` planar buffers into a single interleaved buffer.
///
/// `planes`   - slice of channel slices, each of length `frames`.
/// `out`      - output slice of length `frames * channels`.
pub fn interleave(planes: []const []const f32, out: []f32) void {
    if (planes.len == 0) return;
    const channels = planes.len;
    const frames = planes[0].len;
    std.debug.assert(out.len == frames * channels);
    for (0..frames) |f| {
        for (0..channels) |c| {
            out[f * channels + c] = planes[c][f];
        }
    }
}

/// Deinterleave an interleaved buffer into `channels` planar buffers.
///
/// `in`       - interleaved input of length `frames * channels`.
/// `planes`   - slice of channel slices, each of length `frames`.
pub fn deinterleave(in: []const f32, planes: [][]f32) void {
    if (planes.len == 0) return;
    const channels = planes.len;
    const frames = planes[0].len;
    std.debug.assert(in.len == frames * channels);
    for (0..frames) |f| {
        for (0..channels) |c| {
            planes[c][f] = in[f * channels + c];
        }
    }
}

// ---------------------------------------------------------------------------
// Gain
// ---------------------------------------------------------------------------

/// Apply a linear gain factor to every sample in `buf`, saturating at ±1.0.
/// Operates in-place.
pub fn applyGain(buf: []f32, gain: f32) void {
    for (buf) |*s| {
        s.* = std.math.clamp(s.* * gain, -1.0, 1.0);
    }
}

/// Apply gain and write result to `out` (non-destructive).
/// `in` and `out` must have the same length.
pub fn applyGainTo(in: []const f32, gain: f32, out: []f32) void {
    std.debug.assert(in.len == out.len);
    for (in, 0..) |s, i| {
        out[i] = std.math.clamp(s * gain, -1.0, 1.0);
    }
}

// ---------------------------------------------------------------------------
// Mono <-> Stereo
// ---------------------------------------------------------------------------

/// Downmix stereo interleaved input to mono by averaging L+R pairs.
///
/// `stereo`  - interleaved [L0, R0, L1, R1, ...], length must be even.
/// `mono`    - output slice of length `stereo.len / 2`.
pub fn stereoToMono(stereo: []const f32, mono: []f32) void {
    std.debug.assert(stereo.len % 2 == 0);
    std.debug.assert(mono.len == stereo.len / 2);
    for (0..mono.len) |i| {
        mono[i] = (stereo[i * 2] + stereo[i * 2 + 1]) * 0.5;
    }
}

/// Upmix mono input to stereo interleaved by duplicating each sample.
///
/// `mono`    - input slice of length N.
/// `stereo`  - output slice of length N * 2.
pub fn monoToStereo(mono: []const f32, stereo: []f32) void {
    std.debug.assert(stereo.len == mono.len * 2);
    for (mono, 0..) |s, i| {
        stereo[i * 2] = s;
        stereo[i * 2 + 1] = s;
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Return the peak absolute sample value in `buf`, or 0.0 if empty.
pub fn peak(buf: []const f32) f32 {
    var max: f32 = 0.0;
    for (buf) |s| {
        const a = @abs(s);
        if (a > max) max = a;
    }
    return max;
}

/// Return the root-mean-square of `buf`, or 0.0 if empty.
pub fn rms(buf: []const f32) f32 {
    if (buf.len == 0) return 0.0;
    var sum: f32 = 0.0;
    for (buf) |s| {
        sum += s * s;
    }
    return math.sqrt(sum / @as(f32, @floatFromInt(buf.len)));
}

/// Convert a linear amplitude value to dBFS.
/// Returns -infinity (as a very large negative number) for amplitude <= 0.
pub fn linearToDbfs(amplitude: f32) f32 {
    if (amplitude <= 0.0) return -math.floatMax(f32);
    return 20.0 * math.log10(amplitude);
}

/// Return the peak level of `buf` in dBFS.
pub fn peakDbfs(buf: []const f32) f32 {
    return linearToDbfs(peak(buf));
}

/// Return the RMS level of `buf` in dBFS.
pub fn rmsDbfs(buf: []const f32) f32 {
    return linearToDbfs(rms(buf));
}

// ---------------------------------------------------------------------------
// Clipping
// ---------------------------------------------------------------------------

/// Hard clip: clamp every sample to [-1.0, 1.0] in-place.
pub fn hardClip(buf: []f32) void {
    for (buf) |*s| {
        s.* = std.math.clamp(s.*, -1.0, 1.0);
    }
}

/// Hard clip a single sample.
pub fn hardClipSample(s: f32) f32 {
    return std.math.clamp(s, -1.0, 1.0);
}

/// Soft clip using the cubic function f(x) = x - x^3/3, scaled so that the
/// output is bounded to [-2/3, 2/3] before rescaling to [-1.0, 1.0].
///
/// For |x| >= 1.0 the function is hard-clamped to ±1.0 (overdrive region).
/// This gives a smooth transition: the derivative is continuous at x = ±1.
pub fn softClipSample(s: f32) f32 {
    if (s >= 1.0) return 1.0;
    if (s <= -1.0) return -1.0;
    // f(x) = (3/2) * (x - x^3/3) maps [-1,1] -> [-1,1].
    return 1.5 * (s - (s * s * s) / 3.0);
}

/// Soft clip every sample in `buf` in-place.
pub fn softClip(buf: []f32) void {
    for (buf) |*s| {
        s.* = softClipSample(s.*);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "i16 to f32: known values" {
    const eps = 1.0 / I16_MAX_F + math.floatEps(f32);
    try std.testing.expectApproxEqAbs(i16ToF32(0), 0.0, eps);
    try std.testing.expectApproxEqAbs(i16ToF32(32767), 1.0, eps);
    try std.testing.expectApproxEqAbs(i16ToF32(-32767), -1.0, eps);
    // -32768 maps slightly below -1.0; confirm it rounds correctly.
    const v = i16ToF32(-32768);
    try std.testing.expect(v < -1.0 + eps * 2.0);
}

test "f32 to i16: clamping at full scale" {
    try std.testing.expectEqual(f32ToI16(1.0), @as(i16, 32767));
    try std.testing.expectEqual(f32ToI16(-1.0), @as(i16, -32767));
    try std.testing.expectEqual(f32ToI16(2.0), @as(i16, 32767));
    try std.testing.expectEqual(f32ToI16(-2.0), @as(i16, -32767));
    try std.testing.expectEqual(f32ToI16(0.0), @as(i16, 0));
}

test "i16 <-> f32 round-trip within quantization error" {
    const values = [_]i16{ -32767, -1000, -1, 0, 1, 1000, 32767 };
    for (values) |original| {
        const as_f = i16ToF32(original);
        const back = f32ToI16(as_f);
        // Allow at most 1 LSB of error from rounding.
        const diff: i32 = @as(i32, back) - @as(i32, original);
        try std.testing.expect(diff >= -1 and diff <= 1);
    }
}

test "f32 slice conversion round-trip" {
    const allocator = std.testing.allocator;
    const n = 16;
    const src = try allocator.alloc(i16, n);
    defer allocator.free(src);
    const mid = try allocator.alloc(f32, n);
    defer allocator.free(mid);
    const dst = try allocator.alloc(i16, n);
    defer allocator.free(dst);

    for (src, 0..) |*s, i| {
        s.* = @as(i16, @intCast(@as(i32, @intCast(i)) * 2000 - 16000));
    }
    i16SliceToF32(src, mid);
    f32SliceToI16(mid, dst);
    for (src, 0..) |original, i| {
        const diff: i32 = @as(i32, dst[i]) - @as(i32, original);
        try std.testing.expect(diff >= -1 and diff <= 1);
    }
}

test "interleave / deinterleave are inverse operations" {
    const allocator = std.testing.allocator;
    const frames: usize = 8;
    const channels: usize = 3;

    // Build planar source data.
    var plane0 = try allocator.alloc(f32, frames);
    defer allocator.free(plane0);
    var plane1 = try allocator.alloc(f32, frames);
    defer allocator.free(plane1);
    var plane2 = try allocator.alloc(f32, frames);
    defer allocator.free(plane2);

    for (0..frames) |i| {
        plane0[i] = @as(f32, @floatFromInt(i)) * 0.1;
        plane1[i] = @as(f32, @floatFromInt(i)) * -0.1;
        plane2[i] = @as(f32, @floatFromInt(i)) * 0.05;
    }

    const interleaved = try allocator.alloc(f32, frames * channels);
    defer allocator.free(interleaved);

    const planes_in = [_][]const f32{ plane0, plane1, plane2 };
    interleave(&planes_in, interleaved);

    // Deinterleave back into fresh buffers.
    const out0 = try allocator.alloc(f32, frames);
    defer allocator.free(out0);
    const out1 = try allocator.alloc(f32, frames);
    defer allocator.free(out1);
    const out2 = try allocator.alloc(f32, frames);
    defer allocator.free(out2);

    var planes_out = [_][]f32{ out0, out1, out2 };
    deinterleave(interleaved, &planes_out);

    const eps = math.floatEps(f32) * 4.0;
    for (0..frames) |i| {
        try std.testing.expectApproxEqAbs(out0[i], plane0[i], eps);
        try std.testing.expectApproxEqAbs(out1[i], plane1[i], eps);
        try std.testing.expectApproxEqAbs(out2[i], plane2[i], eps);
    }
}

test "interleave layout sanity" {
    var ch0 = [_]f32{ 0.1, 0.2 };
    var ch1 = [_]f32{ 0.3, 0.4 };
    var out = [_]f32{ 0.0, 0.0, 0.0, 0.0 };
    const planes = [_][]const f32{ &ch0, &ch1 };
    interleave(&planes, &out);
    try std.testing.expectApproxEqAbs(out[0], 0.1, 1e-6);
    try std.testing.expectApproxEqAbs(out[1], 0.3, 1e-6);
    try std.testing.expectApproxEqAbs(out[2], 0.2, 1e-6);
    try std.testing.expectApproxEqAbs(out[3], 0.4, 1e-6);
}

test "gain doubling" {
    var buf = [_]f32{ 0.0, 0.25, 0.5, -0.25, -0.5 };
    applyGain(&buf, 2.0);
    const eps = 1e-6;
    try std.testing.expectApproxEqAbs(buf[0], 0.0, eps);
    try std.testing.expectApproxEqAbs(buf[1], 0.5, eps);
    try std.testing.expectApproxEqAbs(buf[2], 1.0, eps);
    try std.testing.expectApproxEqAbs(buf[3], -0.5, eps);
    try std.testing.expectApproxEqAbs(buf[4], -1.0, eps);
}

test "gain saturation at full scale" {
    var buf = [_]f32{ 0.9, 1.0, -1.0, -0.9 };
    applyGain(&buf, 10.0);
    // All should be clamped to ±1.0.
    for (buf) |s| {
        try std.testing.expect(s >= -1.0 and s <= 1.0);
    }
    try std.testing.expectApproxEqAbs(buf[0], 1.0, 1e-6);
    try std.testing.expectApproxEqAbs(buf[1], 1.0, 1e-6);
    try std.testing.expectApproxEqAbs(buf[2], -1.0, 1e-6);
    try std.testing.expectApproxEqAbs(buf[3], -1.0, 1e-6);
}

test "applyGainTo non-destructive" {
    const in = [_]f32{ 0.5, -0.5 };
    var out = [_]f32{ 0.0, 0.0 };
    applyGainTo(&in, 2.0, &out);
    try std.testing.expectApproxEqAbs(out[0], 1.0, 1e-6);
    try std.testing.expectApproxEqAbs(out[1], -1.0, 1e-6);
    // Source unchanged.
    try std.testing.expectApproxEqAbs(in[0], 0.5, 1e-6);
}

test "stereo to mono downmix average" {
    // Stereo: L=0.8, R=0.4 -> mono 0.6; L=-0.6, R=-0.2 -> mono -0.4
    const stereo = [_]f32{ 0.8, 0.4, -0.6, -0.2 };
    var mono = [_]f32{ 0.0, 0.0 };
    stereoToMono(&stereo, &mono);
    try std.testing.expectApproxEqAbs(mono[0], 0.6, 1e-6);
    try std.testing.expectApproxEqAbs(mono[1], -0.4, 1e-6);
}

test "mono to stereo upmix duplicate" {
    const mono_buf = [_]f32{ 0.3, -0.7 };
    var stereo = [_]f32{ 0.0, 0.0, 0.0, 0.0 };
    monoToStereo(&mono_buf, &stereo);
    try std.testing.expectApproxEqAbs(stereo[0], 0.3, 1e-6);
    try std.testing.expectApproxEqAbs(stereo[1], 0.3, 1e-6);
    try std.testing.expectApproxEqAbs(stereo[2], -0.7, 1e-6);
    try std.testing.expectApproxEqAbs(stereo[3], -0.7, 1e-6);
}

test "stereo upmix then downmix round-trip" {
    const src = [_]f32{ 0.5, -0.3, 0.0, 1.0 };
    var stereo = [_]f32{0.0} ** 8;
    monoToStereo(&src, &stereo);
    var back = [_]f32{0.0} ** 4;
    stereoToMono(&stereo, &back);
    const eps = 1e-6;
    for (src, 0..) |s, i| {
        try std.testing.expectApproxEqAbs(back[i], s, eps);
    }
}

test "peak and RMS on silence" {
    const silence = [_]f32{ 0.0, 0.0, 0.0 };
    try std.testing.expectApproxEqAbs(peak(&silence), 0.0, 1e-9);
    try std.testing.expectApproxEqAbs(rms(&silence), 0.0, 1e-9);
}

test "peak and RMS on known constant signal" {
    // All samples == 0.5: peak = 0.5, rms = 0.5.
    const buf = [_]f32{ 0.5, 0.5, 0.5, 0.5 };
    try std.testing.expectApproxEqAbs(peak(&buf), 0.5, 1e-6);
    try std.testing.expectApproxEqAbs(rms(&buf), 0.5, 1e-6);
}

test "peak and RMS on a known sine wave" {
    // Build one full cycle of a sine at amplitude A.
    // Theoretical: peak = A, RMS = A / sqrt(2).
    const allocator = std.testing.allocator;
    const N = 4096;
    const A: f32 = 0.8;
    var buf = try allocator.alloc(f32, N);
    defer allocator.free(buf);

    for (0..N) |i| {
        const t: f32 = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(N));
        buf[i] = A * math.sin(2.0 * math.pi * t);
    }

    const measured_peak = peak(buf);
    const measured_rms = rms(buf);

    try std.testing.expectApproxEqAbs(measured_peak, A, 1e-4);
    try std.testing.expectApproxEqAbs(measured_rms, A / math.sqrt(2.0), 1e-3);
}

test "dBFS on full scale: 0 dBFS" {
    const full = [_]f32{ 1.0, -1.0 };
    const p_db = peakDbfs(&full);
    // peak = 1.0 -> 20*log10(1) = 0.0 dBFS
    try std.testing.expectApproxEqAbs(p_db, 0.0, 1e-5);
}

test "dBFS on half amplitude: ~-6 dBFS" {
    const half = [_]f32{ 0.5, -0.5 };
    const p_db = peakDbfs(&half);
    // 20*log10(0.5) = -6.0206...
    try std.testing.expectApproxEqAbs(p_db, -6.0206, 1e-3);
}

test "dBFS on silence" {
    const silence = [_]f32{0.0};
    const p_db = peakDbfs(&silence);
    try std.testing.expect(p_db < -1e30);
}

test "hard clip: values already in range are unchanged" {
    var buf = [_]f32{ -1.0, -0.5, 0.0, 0.5, 1.0 };
    hardClip(&buf);
    const eps = 1e-9;
    try std.testing.expectApproxEqAbs(buf[0], -1.0, eps);
    try std.testing.expectApproxEqAbs(buf[1], -0.5, eps);
    try std.testing.expectApproxEqAbs(buf[2], 0.0, eps);
    try std.testing.expectApproxEqAbs(buf[3], 0.5, eps);
    try std.testing.expectApproxEqAbs(buf[4], 1.0, eps);
}

test "hard clip: out-of-range values clamped" {
    var buf = [_]f32{ 2.0, -3.5, 1.001, -1.001 };
    hardClip(&buf);
    for (buf) |s| {
        try std.testing.expect(s >= -1.0 and s <= 1.0);
    }
}

test "soft clip: within [-1,1] output is bounded" {
    const inputs = [_]f32{ -2.0, -1.0, -0.5, 0.0, 0.5, 1.0, 2.0 };
    for (inputs) |x| {
        const y = softClipSample(x);
        try std.testing.expect(y >= -1.0 and y <= 1.0);
    }
}

test "soft clip: monotonic" {
    // Sample at fine steps; each output must be >= previous.
    const steps: usize = 1000;
    var prev: f32 = softClipSample(-2.0);
    for (1..steps) |k| {
        const x: f32 = -2.0 + 4.0 * @as(f32, @floatFromInt(k)) / @as(f32, @floatFromInt(steps));
        const y = softClipSample(x);
        try std.testing.expect(y >= prev - 1e-7);
        prev = y;
    }
}

test "soft clip: zero in, zero out" {
    try std.testing.expectApproxEqAbs(softClipSample(0.0), 0.0, 1e-9);
}

test "soft clip slice" {
    var buf = [_]f32{ 0.0, 0.5, 1.0, 2.0, -2.0 };
    softClip(&buf);
    for (buf) |s| {
        try std.testing.expect(s >= -1.0 and s <= 1.0);
    }
}

test "empty slice edge cases" {
    // These should not crash.
    const empty_f32: []const f32 = &.{};
    try std.testing.expectApproxEqAbs(peak(empty_f32), 0.0, 1e-9);
    try std.testing.expectApproxEqAbs(rms(empty_f32), 0.0, 1e-9);

    const empty_mut: []f32 = &.{};
    hardClip(empty_mut);
    softClip(empty_mut);
    applyGain(empty_mut, 2.0);
}

test "interleave with zero channels is a no-op" {
    var out = [_]f32{};
    const planes: []const []const f32 = &.{};
    interleave(planes, &out); // must not crash
}
