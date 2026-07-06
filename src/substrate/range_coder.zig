// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Byte-oriented binary range coder for kagura entropy coding.
//!
//! The coder uses a fixed 12-bit probability scale and an adaptive binary
//! model. Callers must use matching model configuration and bit order for
//! encoding and decoding.
const std = @import("std");

const Allocator = std.mem.Allocator;

const PROB_BITS: u5 = 12;
const TOTAL: u32 = @as(u32, 1) << PROB_BITS;
const MIN_PROB: u32 = 1;
const MAX_PROB: u32 = TOTAL - 1;
const TOP: u32 = 1 << 24;
const FULL_RANGE: u32 = 0xffff_ffff;

pub const ModelConfig = struct {
    /// Initial probability of a zero bit on the 12-bit fixed scale.
    initial_zero: u16 = TOTAL / 2,
    /// Higher values adapt more slowly. Values outside [1, 15] are clamped.
    update_shift: u5 = 5,
};

pub const BitModel = struct {
    zero: u16 = TOTAL / 2,
    update_shift: u5 = 5,

    pub fn init(config: ModelConfig) BitModel {
        return .{
            .zero = @intCast(clampProb(config.initial_zero)),
            .update_shift = clampShift(config.update_shift),
        };
    }

    pub fn probabilityZero(self: BitModel) u32 {
        return self.zero;
    }

    pub fn update(self: *BitModel, bit: bool) void {
        var p0: u32 = self.zero;
        if (bit) {
            const delta = @max(@as(u32, 1), p0 >> self.update_shift);
            p0 = if (p0 > MIN_PROB + delta) p0 - delta else MIN_PROB;
        } else {
            const delta = @max(@as(u32, 1), (TOTAL - p0) >> self.update_shift);
            p0 = if (p0 + delta < MAX_PROB) p0 + delta else MAX_PROB;
        }
        self.zero = @intCast(p0);
    }
};

pub const EncodeError = Allocator.Error || error{
    Finished,
};

pub const DecodeError = error{
    Truncated,
    CorruptInput,
};

pub const Encoder = struct {
    allocator: Allocator,
    out: std.ArrayList(u8) = .empty,
    low: u64 = 0,
    range: u32 = FULL_RANGE,
    cache: u8 = 0,
    cache_size: u32 = 1,
    finished: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        self.out.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn encodeBit(self: *Self, model: *BitModel, bit: bool) EncodeError!void {
        if (self.finished) return error.Finished;

        const p0 = model.probabilityZero();
        const bound = (self.range >> PROB_BITS) * p0;
        if (bit) {
            self.low += bound;
            self.range -= bound;
        } else {
            self.range = bound;
        }

        try self.normalize();
        model.update(bit);
    }

    pub fn finish(self: *Self) EncodeError![]u8 {
        if (self.finished) return error.Finished;
        self.finished = true;

        var i: usize = 0;
        while (i < 5) : (i += 1) try self.shiftLow();

        return self.out.toOwnedSlice(self.allocator);
    }

    fn normalize(self: *Self) Allocator.Error!void {
        while (self.range < TOP) {
            self.range <<= 8;
            try self.shiftLow();
        }
    }

    fn shiftLow(self: *Self) Allocator.Error!void {
        const low32: u32 = @truncate(self.low);
        const high: u32 = @intCast(self.low >> 32);
        if (low32 < 0xff00_0000 or high != 0) {
            var temp = self.cache;
            while (true) {
                try self.out.append(self.allocator, @truncate(@as(u16, temp) + high));
                self.cache_size -= 1;
                if (self.cache_size == 0) break;
                temp = 0xff;
            }
            self.cache = @intCast((self.low >> 24) & 0xff);
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00ff_ffff) << 8;
    }
};

pub const Decoder = struct {
    input: []const u8,
    pos: usize = 0,
    code: u32 = 0,
    range: u32 = FULL_RANGE,

    const Self = @This();

    pub fn init(input: []const u8) DecodeError!Self {
        if (input.len < 5) return error.Truncated;
        var self = Self{ .input = input };
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            self.code = (self.code *% 256) | self.readByte();
        }
        return self;
    }

    pub fn decodeBit(self: *Self, model: *BitModel) DecodeError!bool {
        const p0 = model.probabilityZero();
        const bound = (self.range >> PROB_BITS) * p0;
        if (bound == 0) return error.CorruptInput;

        const bit = self.code >= bound;
        if (bit) {
            self.code -= bound;
            self.range -= bound;
        } else {
            self.range = bound;
        }

        self.normalize();
        model.update(bit);
        return bit;
    }

    fn normalize(self: *Self) void {
        while (self.range < TOP) {
            self.range <<= 8;
            self.code = (self.code *% 256) | self.readByte();
        }
    }

    fn readByte(self: *Self) u32 {
        if (self.pos >= self.input.len) return 0;
        const b = self.input[self.pos];
        self.pos += 1;
        return b;
    }
};

fn clampProb(value: u32) u32 {
    return @min(MAX_PROB, @max(MIN_PROB, value));
}

fn clampShift(value: u5) u5 {
    return @min(@as(u5, 15), @max(@as(u5, 1), value));
}

fn encodeBits(allocator: Allocator, bits: []const bool, config: ModelConfig) ![]u8 {
    var enc = Encoder.init(allocator);
    defer enc.deinit();

    var model = BitModel.init(config);
    for (bits) |bit| try enc.encodeBit(&model, bit);
    return enc.finish();
}

fn expectRoundTrip(bits: []const bool, config: ModelConfig) !void {
    const allocator = std.testing.allocator;
    const encoded = try encodeBits(allocator, bits, config);
    defer allocator.free(encoded);

    var dec = try Decoder.init(encoded);
    var model = BitModel.init(config);
    for (bits) |expected| {
        const actual = try dec.decodeBit(&model);
        try std.testing.expectEqual(expected, actual);
    }
}

const SplitMix64 = struct {
    state: u64,

    fn init(seed: u64) SplitMix64 {
        return .{ .state = seed };
    }

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e37_79b9_7f4a_7c15;
        var z = self.state;
        z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
        z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
        return z ^ (z >> 31);
    }

    fn bit(self: *SplitMix64) bool {
        return (self.next() & 1) != 0;
    }

    fn chance(self: *SplitMix64, numerator: u32, denominator: u32) bool {
        return self.next() % denominator < numerator;
    }
};

test "empty stream produces deterministic final bytes" {
    const allocator = std.testing.allocator;

    const first = try encodeBits(allocator, &.{}, .{});
    defer allocator.free(first);
    const second = try encodeBits(allocator, &.{}, .{});
    defer allocator.free(second);

    try std.testing.expectEqual(@as(usize, 5), first.len);
    try std.testing.expectEqualSlices(u8, first, second);
    _ = try Decoder.init(first);
    try std.testing.expectError(error.Truncated, Decoder.init(&.{ 0, 1, 2 }));
}

test "edge patterns round trip" {
    const all_zero = @as([257]bool, @splat(false));
    const all_one = @as([257]bool, @splat(true));
    var alternating: [513]bool = undefined;
    for (&alternating, 0..) |*slot, i| slot.* = (i & 1) != 0;

    try expectRoundTrip(&all_zero, .{ .initial_zero = 2048, .update_shift = 2 });
    try expectRoundTrip(&all_one, .{ .initial_zero = 2048, .update_shift = 2 });
    try expectRoundTrip(&alternating, .{ .initial_zero = 3072, .update_shift = 8 });
}

test "seeded random sequences round trip across model configs" {
    const allocator = std.testing.allocator;
    const configs = [_]ModelConfig{
        .{ .initial_zero = 16, .update_shift = 1 },
        .{ .initial_zero = 512, .update_shift = 3 },
        .{ .initial_zero = 2048, .update_shift = 5 },
        .{ .initial_zero = 3584, .update_shift = 9 },
        .{ .initial_zero = 4095, .update_shift = 15 },
    };
    const seeds = [_]u64{
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0xfeed_face_cafe_beef,
        0xa5a5_a5a5_5a5a_5a5a,
    };

    for (configs) |config| {
        for (seeds) |seed| {
            const bits = try allocator.alloc(bool, 4096);
            defer allocator.free(bits);

            var rng = SplitMix64.init(seed ^ (@as(u64, config.initial_zero) << 16) ^ config.update_shift);
            for (bits) |*bit_slot| bit_slot.* = rng.bit();
            try expectRoundTrip(bits, config);
        }
    }
}

test "biased source compresses below raw bit count" {
    const allocator = std.testing.allocator;
    const bits = try allocator.alloc(bool, 8192);
    defer allocator.free(bits);

    var rng = SplitMix64.init(0x1ced_c0de_90ab_1e55);
    for (bits) |*slot| {
        slot.* = !rng.chance(9, 10);
    }

    const encoded = try encodeBits(allocator, bits, .{ .initial_zero = 2048, .update_shift = 5 });
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len * 8 < bits.len);
    var dec = try Decoder.init(encoded);
    var model = BitModel.init(.{ .initial_zero = 2048, .update_shift = 5 });
    for (bits) |expected| try std.testing.expectEqual(expected, try dec.decodeBit(&model));
}

test "same input and config encode identically" {
    const allocator = std.testing.allocator;
    var bits: [1024]bool = undefined;
    var rng = SplitMix64.init(0xdec0_de1d_5eed_0001);
    for (&bits) |*slot| slot.* = rng.chance(7, 16);

    const config = ModelConfig{ .initial_zero = 1234, .update_shift = 6 };
    const first = try encodeBits(allocator, &bits, config);
    defer allocator.free(first);
    const second = try encodeBits(allocator, &bits, config);
    defer allocator.free(second);

    try std.testing.expectEqualSlices(u8, first, second);
    try expectRoundTrip(&bits, config);
}
