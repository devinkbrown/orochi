//! OPVIS video codec spike: lossless delta + run-length frames.
//!
//! A compact, deterministic, allocation-free building block for the OPVIS band,
//! tuned for the low-motion video the mesh carries most (talking-head, screen
//! share, comic-chat panels): an inter-frame is XORed against the previous frame
//! and the (mostly-zero) residual run-length coded, so a static background costs
//! almost nothing. Intra-frames RLE the raw bytes for seeking / loss recovery.
//!
//! Format-agnostic: operates on raw byte planes of a fixed size (the caller owns
//! width/height/pixel format). Lossless and pure-integer, so it round-trips
//! exactly and runs identically on the daemon and a future WASM build (#32).
//!
//! RLE token stream: repeated `[count:u16 LE][value:u8]` runs covering the whole
//! frame; runs longer than 65535 split across tokens.
const std = @import("std");

pub const Error = error{ OutputTooSmall, Truncated, LengthMismatch };

const max_run: usize = std.math.maxInt(u16);

/// Worst-case encoded size for `n` raw bytes (every byte its own run).
pub fn worstCaseLen(n: usize) usize {
    return n * 3;
}

fn rleEncode(src: []const u8, out: []u8) Error!usize {
    var w: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        const value = src[i];
        var run: usize = 1;
        while (i + run < src.len and src[i + run] == value and run < max_run) run += 1;
        if (w + 3 > out.len) return error.OutputTooSmall;
        std.mem.writeInt(u16, out[w..][0..2], @intCast(run), .little);
        out[w + 2] = value;
        w += 3;
        i += run;
    }
    return w;
}

fn rleDecode(src: []const u8, out: []u8) Error!usize {
    var r: usize = 0;
    var w: usize = 0;
    while (r + 3 <= src.len) : (r += 3) {
        const run = std.mem.readInt(u16, src[r..][0..2], .little);
        const value = src[r + 2];
        if (w + run > out.len) return error.OutputTooSmall;
        @memset(out[w .. w + run], value);
        w += run;
    }
    if (r != src.len) return error.Truncated;
    return w;
}

/// Encode a standalone (intra) frame: RLE of the raw bytes. Returns bytes written.
pub fn encodeIntra(frame: []const u8, out: []u8) Error!usize {
    return rleEncode(frame, out);
}

/// Decode an intra frame into `out` (must equal the original frame length).
pub fn decodeIntra(coded: []const u8, out: []u8) Error!usize {
    return rleDecode(coded, out);
}

/// Encode an inter frame: `frame` XOR `prev`, then RLE the residual. `prev` and
/// `frame` must be the same length. A static frame collapses to one zero-run.
pub fn encodeInter(prev: []const u8, frame: []const u8, out: []u8) Error!usize {
    if (prev.len != frame.len) return error.LengthMismatch;
    var w: usize = 0;
    var i: usize = 0;
    while (i < frame.len) {
        const value = frame[i] ^ prev[i];
        var run: usize = 1;
        while (i + run < frame.len and (frame[i + run] ^ prev[i + run]) == value and run < max_run) run += 1;
        if (w + 3 > out.len) return error.OutputTooSmall;
        std.mem.writeInt(u16, out[w..][0..2], @intCast(run), .little);
        out[w + 2] = value;
        w += 3;
        i += run;
    }
    return w;
}

/// Decode an inter frame: RLE-decode the residual, then XOR with `prev` to
/// reconstruct `frame`. `out` and `prev` must be the same length.
pub fn decodeInter(prev: []const u8, coded: []const u8, out: []u8) Error!usize {
    if (out.len != prev.len) return error.LengthMismatch;
    const n = try rleDecode(coded, out); // out now holds the residual
    if (n != prev.len) return error.LengthMismatch;
    for (out, prev) |*o, p| o.* ^= p;
    return n;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "intra frame round-trips losslessly" {
    const frame = [_]u8{ 1, 1, 1, 2, 2, 9, 9, 9, 9, 0, 0 };
    var coded: [worstCaseLen(frame.len)]u8 = undefined;
    const n = try encodeIntra(&frame, &coded);
    var out: [frame.len]u8 = undefined;
    _ = try decodeIntra(coded[0..n], &out);
    try testing.expectEqualSlices(u8, &frame, &out);
    // 4 runs -> 12 bytes, smaller than 11*3 worst case.
    try testing.expectEqual(@as(usize, 12), n);
}

test "a static inter frame collapses to a single zero-run" {
    const prev = [_]u8{ 7, 7, 7, 7, 7, 7, 7, 7 };
    const frame = prev; // unchanged
    var coded: [worstCaseLen(frame.len)]u8 = undefined;
    const n = try encodeInter(&prev, &frame, &coded);
    try testing.expectEqual(@as(usize, 3), n); // one run: [8][0]

    var out: [frame.len]u8 = undefined;
    _ = try decodeInter(&prev, coded[0..n], &out);
    try testing.expectEqualSlices(u8, &frame, &out);
}

test "inter frame round-trips losslessly under partial change" {
    const prev = [_]u8{ 10, 20, 30, 40, 50, 60, 70, 80 };
    const frame = [_]u8{ 10, 20, 99, 40, 50, 60, 71, 80 }; // two pixels changed
    var coded: [worstCaseLen(frame.len)]u8 = undefined;
    const n = try encodeInter(&prev, &frame, &coded);
    var out: [frame.len]u8 = undefined;
    _ = try decodeInter(&prev, coded[0..n], &out);
    try testing.expectEqualSlices(u8, &frame, &out);
}

test "runs longer than 65535 split across tokens" {
    const big = 70_000;
    const frame = try testing.allocator.alloc(u8, big);
    defer testing.allocator.free(frame);
    @memset(frame, 0xAB);
    const coded = try testing.allocator.alloc(u8, worstCaseLen(big));
    defer testing.allocator.free(coded);
    const n = try encodeIntra(frame, coded);
    try testing.expectEqual(@as(usize, 6), n); // 65535 + 4465 = two runs
    const out = try testing.allocator.alloc(u8, big);
    defer testing.allocator.free(out);
    _ = try decodeIntra(coded[0..n], out);
    try testing.expectEqualSlices(u8, frame, out);
}

test "encode reports OutputTooSmall rather than overflowing" {
    const frame = [_]u8{ 1, 2, 3, 4 };
    var tiny: [3]u8 = undefined; // room for exactly one run
    try testing.expectError(error.OutputTooSmall, encodeIntra(&frame, &tiny));
}

test "a truncated token stream is rejected" {
    var out: [8]u8 = undefined;
    try testing.expectError(error.Truncated, decodeIntra(&[_]u8{ 0x02, 0x00 }, &out)); // 2 of 3 bytes
}
