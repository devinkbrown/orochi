//! Standalone HyperLogLog cardinality estimator.
//!
//! The estimator accepts caller-provided 64-bit hashes. It does not hash byte
//! strings itself, which keeps this module independent from any protocol or
//! storage-layer domain separation used by callers.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    InvalidPrecision,
    IncompatiblePrecision,
};

/// Runtime-configurable HyperLogLog with 6-bit register values.
///
/// `precision` selects `2^precision` registers. Values from 4 through 20 are
/// accepted: that range keeps rank values within six bits and avoids accidental
/// multi-gigabyte allocations from malformed input.
pub const HyperLogLog = struct {
    precision: u6,
    registers: []u8,

    const Self = @This();
    pub const min_precision: u6 = 4;
    pub const max_precision: u6 = 20;
    pub const max_register_value: u8 = 63;

    /// Create an empty estimator with `2^precision` zeroed registers.
    pub fn init(allocator: Allocator, precision: u6) !Self {
        if (!validPrecision(precision)) return Error.InvalidPrecision;

        const registers = try allocator.alloc(u8, registerCount(precision));
        @memset(registers, 0);
        return .{
            .precision = precision,
            .registers = registers,
        };
    }

    /// Release register storage.
    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.registers);
        self.* = undefined;
    }

    /// Reset all registers to zero while preserving precision and allocation.
    pub fn clear(self: *Self) void {
        @memset(self.registers, 0);
    }

    /// Add one caller-provided 64-bit hash.
    pub fn add(self: *Self, hash: u64) void {
        const e = effect(self.precision, hash);
        if (self.registers[e.index] < e.rank) self.registers[e.index] = e.rank;
    }

    /// Merge another estimator into this one using elementwise register max.
    pub fn merge(self: *Self, other: Self) Error!void {
        if (self.precision != other.precision) return Error.IncompatiblePrecision;

        for (self.registers, other.registers) |*mine, theirs| {
            if (mine.* < theirs) mine.* = theirs;
        }
    }

    /// Estimate cardinality with standard HLL alpha and small-range correction.
    pub fn estimate(self: Self) f64 {
        const m: f64 = @floatFromInt(self.registers.len);
        var harmonic: f64 = 0.0;
        var zero_count: usize = 0;

        for (self.registers) |rank| {
            harmonic += std.math.pow(f64, 2.0, -@as(f64, @floatFromInt(rank)));
            if (rank == 0) zero_count += 1;
        }

        const raw = alpha(self.registers.len) * m * m / harmonic;
        if (raw <= 2.5 * m and zero_count != 0) {
            return m * @log(m / @as(f64, @floatFromInt(zero_count)));
        }

        return raw;
    }

    /// Count registers that have not yet been touched.
    pub fn zeroRegisters(self: Self) usize {
        var zeros: usize = 0;
        for (self.registers) |rank| {
            if (rank == 0) zeros += 1;
        }
        return zeros;
    }

    /// Duplicate the estimator and its register state.
    pub fn clone(self: Self, allocator: Allocator) !Self {
        const registers = try allocator.dupe(u8, self.registers);
        return .{
            .precision = self.precision,
            .registers = registers,
        };
    }
};

pub const RegisterEffect = struct {
    index: usize,
    rank: u8,
};

pub fn validPrecision(precision: u6) bool {
    return precision >= HyperLogLog.min_precision and precision <= HyperLogLog.max_precision;
}

pub fn registerCount(precision: u6) usize {
    return @as(usize, 1) << precision;
}

/// Return the register mutation that `hash` would cause for `precision`.
pub fn effect(precision: u6, hash: u64) RegisterEffect {
    std.debug.assert(validPrecision(precision));

    const index_shift: u6 = 63 - precision + 1;
    const index = @as(usize, @intCast(hash >> index_shift));
    const shifted = hash << precision;
    const max_rank = 65 - @as(u8, precision);
    const rank = @min(@as(u8, @intCast(@clz(shifted) + 1)), max_rank);

    return .{
        .index = index,
        .rank = @min(rank, HyperLogLog.max_register_value),
    };
}

fn alpha(register_count: usize) f64 {
    return switch (register_count) {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        else => 0.7213 / (1.0 + (1.079 / @as(f64, @floatFromInt(register_count)))),
    };
}

fn mix64(input: u64) u64 {
    var x = input +% 0x9e37_79b9_7f4a_7c15;
    x = (x ^ (x >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    x = (x ^ (x >> 27)) *% 0x94d0_49bb_1331_11eb;
    return x ^ (x >> 31);
}

fn testHash(value: u64) u64 {
    return mix64(value ^ 0x4d69_7a63_6869_484c);
}

fn relativeError(estimate_value: f64, actual: usize) f64 {
    const actual_float: f64 = @floatFromInt(actual);
    const diff = @abs(estimate_value - actual_float);
    return diff / actual_float;
}

fn expectEstimateWithin(hll: HyperLogLog, actual: usize, tolerance: f64) !void {
    const err = relativeError(hll.estimate(), actual);
    try std.testing.expect(err <= tolerance);
}

test "invalid precision is rejected before allocation" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(Error.InvalidPrecision, HyperLogLog.init(allocator, 3));
    try std.testing.expectError(Error.InvalidPrecision, HyperLogLog.init(allocator, 21));
}

test "empty estimator reports zero" {
    const allocator = std.testing.allocator;
    var hll = try HyperLogLog.init(allocator, 10);
    defer hll.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1024), hll.zeroRegisters());
    try std.testing.expectEqual(@as(f64, 0.0), hll.estimate());
}

test "effect uses high precision bits for register index" {
    const e = effect(6, 0b10101100_10000000_00000000_00000000_00000000_00000000_00000000_00000000);

    try std.testing.expectEqual(@as(usize, 0b101011), e.index);
    try std.testing.expectEqual(@as(u8, 3), e.rank);
}

test "add is deterministic and order independent" {
    const allocator = std.testing.allocator;
    var a = try HyperLogLog.init(allocator, 12);
    defer a.deinit(allocator);
    var b = try HyperLogLog.init(allocator, 12);
    defer b.deinit(allocator);

    for (0..5000) |i| a.add(testHash(@intCast(i)));
    var i: usize = 5000;
    while (i > 0) {
        i -= 1;
        b.add(testHash(@intCast(i)));
    }

    try std.testing.expectEqualSlices(u8, a.registers, b.registers);
    try std.testing.expectEqual(a.estimate(), b.estimate());
}

test "duplicate hashes do not increase estimate materially" {
    const allocator = std.testing.allocator;
    var hll = try HyperLogLog.init(allocator, 12);
    defer hll.deinit(allocator);

    for (0..2000) |i| hll.add(testHash(@intCast(i)));
    const once = hll.estimate();

    for (0..8) |_| {
        for (0..2000) |i| hll.add(testHash(@intCast(i)));
    }

    try std.testing.expectEqualSlices(u8, hll.registers, hll.registers);
    try std.testing.expect(@abs(hll.estimate() - once) < 0.000001);
}

test "linear counting is accurate for small cardinalities" {
    const allocator = std.testing.allocator;
    var hll = try HyperLogLog.init(allocator, 12);
    defer hll.deinit(allocator);

    for (0..50) |i| hll.add(testHash(@intCast(i)));

    try std.testing.expect(hll.zeroRegisters() > 0);
    try expectEstimateWithin(hll, 50, 0.08);
}

test "estimate stays within a few percent for several cardinalities" {
    const allocator = std.testing.allocator;
    const cases = [_]usize{ 1_000, 10_000, 50_000, 100_000 };

    for (cases) |n| {
        var hll = try HyperLogLog.init(allocator, 14);
        defer hll.deinit(allocator);

        for (0..n) |i| hll.add(testHash(@intCast(i)));

        try expectEstimateWithin(hll, n, 0.035);
    }
}

test "merge equals union of distinct sets" {
    const allocator = std.testing.allocator;
    var left = try HyperLogLog.init(allocator, 14);
    defer left.deinit(allocator);
    var right = try HyperLogLog.init(allocator, 14);
    defer right.deinit(allocator);
    var union_hll = try HyperLogLog.init(allocator, 14);
    defer union_hll.deinit(allocator);

    for (0..25_000) |i| {
        const hash = testHash(@intCast(i));
        left.add(hash);
        union_hll.add(hash);
    }
    for (25_000..55_000) |i| {
        const hash = testHash(@intCast(i));
        right.add(hash);
        union_hll.add(hash);
    }

    try left.merge(right);
    try std.testing.expectEqualSlices(u8, union_hll.registers, left.registers);
    try expectEstimateWithin(left, 55_000, 0.035);
}

test "merge accounts for overlapping sets once" {
    const allocator = std.testing.allocator;
    var left = try HyperLogLog.init(allocator, 14);
    defer left.deinit(allocator);
    var right = try HyperLogLog.init(allocator, 14);
    defer right.deinit(allocator);

    for (0..40_000) |i| left.add(testHash(@intCast(i)));
    for (20_000..60_000) |i| right.add(testHash(@intCast(i)));

    try left.merge(right);
    try expectEstimateWithin(left, 60_000, 0.035);
}

test "merge rejects mismatched precision" {
    const allocator = std.testing.allocator;
    var left = try HyperLogLog.init(allocator, 10);
    defer left.deinit(allocator);
    var right = try HyperLogLog.init(allocator, 11);
    defer right.deinit(allocator);

    try std.testing.expectError(Error.IncompatiblePrecision, left.merge(right));
}

test "clone preserves deterministic state independently" {
    const allocator = std.testing.allocator;
    var original = try HyperLogLog.init(allocator, 12);
    defer original.deinit(allocator);

    for (0..4096) |i| original.add(testHash(@intCast(i)));

    var cloned = try original.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expectEqualSlices(u8, original.registers, cloned.registers);
    try std.testing.expectEqual(original.estimate(), cloned.estimate());

    cloned.registers[0] = HyperLogLog.max_register_value;
    try std.testing.expect(!std.mem.eql(u8, original.registers, cloned.registers));
}
