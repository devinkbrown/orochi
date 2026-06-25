// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OPVOX audio codec spike: IMA ADPCM (16-bit PCM <-> 4-bit).
//!
//! A compact, deterministic, allocation-free voice codec building block for the
//! OPVOX band: each 16-bit PCM sample is coded to a 4-bit nibble against an
//! adaptive step size, giving ~4:1 compression at voice quality. Lossy but
//! bounded — the adaptive predictor tracks the signal, so reconstruction error
//! stays small for the smooth, band-limited signals voice produces.
//!
//! Pure integer math (no float, no allocation), so it runs identically on the
//! native daemon and a future WASM browser build (#32). State is explicit so a
//! caller can checkpoint/reset per packet (each OPVOX frame is independently
//! decodable when it carries its starting predictor+index).
const std = @import("std");

/// Step-index adjustment per 3-bit magnitude code (the sign bit is ignored).
const index_table = [16]i8{ -1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8 };

/// Standard 89-entry IMA step-size table.
const step_table = [89]i32{
    7,     8,     9,     10,    11,    12,    13,    14,    16,    17,
    19,    21,    23,    25,    28,    31,    34,    37,    41,    45,
    50,    55,    60,    66,    73,    80,    88,    97,    107,   118,
    130,   143,   157,   173,   190,   209,   230,   253,   279,   307,
    337,   371,   408,   449,   494,   544,   598,   658,   724,   796,
    876,   963,   1060,  1166,  1282,  1411,  1552,  1707,  1878,  2066,
    2272,  2499,  2749,  3024,  3327,  3660,  4026,  4428,  4871,  5358,
    5894,  6484,  7132,  7845,  8630,  9493,  10442, 11487, 12635, 13899,
    15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
};

/// Adaptive coder state. Reset to `.{}` (predictor 0, index 0) at the start of an
/// independently-decodable frame; both encoder and decoder must start equal.
pub const State = struct {
    predictor: i32 = 0,
    index: i32 = 0,

    fn step(self: *const State) i32 {
        return step_table[@intCast(self.index)];
    }

    fn advance(self: *State, code: u4) void {
        self.index += index_table[code];
        if (self.index < 0) self.index = 0;
        if (self.index > 88) self.index = 88;
    }
};

/// Number of packed ADPCM bytes for `sample_count` samples (2 nibbles per byte).
pub fn encodedLen(sample_count: usize) usize {
    return (sample_count + 1) / 2;
}

/// Encode `pcm` into `out` (must be >= encodedLen(pcm.len)); returns bytes
/// written. Nibbles are packed low-then-high (IMA convention). `state` advances.
pub fn encode(state: *State, pcm: []const i16, out: []u8) usize {
    const n = encodedLen(pcm.len);
    std.debug.assert(out.len >= n);
    var byte: u8 = 0;
    for (pcm, 0..) |sample, i| {
        const code = encodeSample(state, sample);
        if (i & 1 == 0) {
            byte = code; // low nibble
        } else {
            out[i >> 1] = byte | (@as(u8, code) << 4); // high nibble
        }
    }
    if (pcm.len & 1 == 1) out[pcm.len >> 1] = byte; // trailing low nibble
    return n;
}

/// Decode `adpcm` into `out` (must hold `sample_count` samples); returns samples
/// written. `state` must match the encoder's starting state and advances.
pub fn decode(state: *State, adpcm: []const u8, sample_count: usize, out: []i16) usize {
    std.debug.assert(out.len >= sample_count);
    var i: usize = 0;
    while (i < sample_count) : (i += 1) {
        const packed_byte = adpcm[i >> 1];
        const code: u4 = if (i & 1 == 0) @truncate(packed_byte) else @truncate(packed_byte >> 4);
        out[i] = decodeSample(state, code);
    }
    return sample_count;
}

fn encodeSample(state: *State, sample: i16) u4 {
    var step = state.step();
    var diff: i32 = @as(i32, sample) - state.predictor;
    var code: u4 = 0;
    if (diff < 0) {
        code = 8; // sign bit
        diff = -diff;
    }
    var vpdiff: i32 = step >> 3;
    if (diff >= step) {
        code |= 4;
        diff -= step;
        vpdiff += step;
    }
    step >>= 1;
    if (diff >= step) {
        code |= 2;
        diff -= step;
        vpdiff += step;
    }
    step >>= 1;
    if (diff >= step) {
        code |= 1;
        vpdiff += step;
    }
    if (code & 8 != 0) state.predictor -= vpdiff else state.predictor += vpdiff;
    clampPredictor(state);
    state.advance(code);
    return code;
}

fn decodeSample(state: *State, code: u4) i16 {
    const step = state.step();
    var vpdiff: i32 = step >> 3;
    if (code & 4 != 0) vpdiff += step;
    if (code & 2 != 0) vpdiff += step >> 1;
    if (code & 1 != 0) vpdiff += step >> 2;
    if (code & 8 != 0) state.predictor -= vpdiff else state.predictor += vpdiff;
    clampPredictor(state);
    state.advance(code);
    return @intCast(state.predictor);
}

fn clampPredictor(state: *State) void {
    if (state.predictor > 32767) state.predictor = 32767;
    if (state.predictor < -32768) state.predictor = -32768;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "encodedLen packs two samples per byte" {
    try testing.expectEqual(@as(usize, 0), encodedLen(0));
    try testing.expectEqual(@as(usize, 1), encodedLen(1));
    try testing.expectEqual(@as(usize, 1), encodedLen(2));
    try testing.expectEqual(@as(usize, 2), encodedLen(3));
}

test "round-trips a sine wave within ADPCM error bounds" {
    var pcm: [256]i16 = undefined;
    for (&pcm, 0..) |*s, i| {
        const phase = @as(f32, @floatFromInt(i)) * 0.20;
        s.* = @intFromFloat(@sin(phase) * 8000.0);
    }
    var enc_state = State{};
    var packed_buf: [encodedLen(256)]u8 = undefined;
    _ = encode(&enc_state, &pcm, &packed_buf);

    var dec_state = State{};
    var out: [256]i16 = undefined;
    _ = decode(&dec_state, &packed_buf, 256, &out);

    // Skip the initial samples while the adaptive step ramps from 0.
    var max_err: u32 = 0;
    for (pcm[16..], out[16..]) |a, b| {
        const e = @abs(@as(i32, a) - @as(i32, b));
        if (e > max_err) max_err = e;
    }
    try testing.expect(max_err < 1500); // ~4.6% of the 8000 amplitude
}

test "encoder and decoder stay in lockstep (decode of encode tracks input energy)" {
    // A quiet/silent signal must stay near zero through the codec.
    var pcm = [_]i16{0} ** 64;
    var es = State{};
    var buf: [32]u8 = undefined;
    _ = encode(&es, &pcm, &buf);
    var ds = State{};
    var out: [64]i16 = undefined;
    _ = decode(&ds, &buf, 64, &out);
    for (out) |s| try testing.expect(@abs(@as(i32, s)) <= 2);
}

test "odd sample count round-trips (trailing nibble handled)" {
    const pcm = [_]i16{ 100, -200, 300, -400, 500 };
    var es = State{};
    var buf: [encodedLen(5)]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), encode(&es, &pcm, &buf));
    var ds = State{};
    var out: [5]i16 = undefined;
    try testing.expectEqual(@as(usize, 5), decode(&ds, &buf, 5, &out));
    // The first sample is the most accurate (small step, small delta).
    try testing.expect(@abs(@as(i32, out[0]) - 100) < 200);
}

test "step index stays within table bounds under a loud ramp" {
    var pcm: [128]i16 = undefined;
    for (&pcm, 0..) |*s, i| s.* = @intCast(@as(i32, @intCast(i)) * 256 - 16384);
    var es = State{};
    var buf: [64]u8 = undefined;
    _ = encode(&es, &pcm, &buf);
    try testing.expect(es.index >= 0 and es.index <= 88);
}
