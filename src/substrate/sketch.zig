//! Probabilistic sketches for LADON anti-entropy planning.
//!
//! Bloom filters and HyperLogLog counters are intentionally domain separated:
//! callers provide a salt derived from the LADON frame type and mesh epoch so
//! the same input hash cannot be reused across protocols or epochs.
const std = @import("std");

/// Fixed-size Bloom filter.
///
/// `cfg` requires:
/// - `bits`: number of filter bits.
/// - `hashes`: number of double-hash probes.
pub fn BloomFilter(comptime cfg: anytype) type {
    const bit_count: usize = cfg.bits;
    const hash_count: usize = cfg.hashes;
    const word_count = (bit_count + 63) / 64;

    comptime {
        if (bit_count == 0) @compileError("BloomFilter cfg.bits must be non-zero");
        if (hash_count == 0) @compileError("BloomFilter cfg.hashes must be non-zero");
    }

    return struct {
        bits: [word_count]u64 = [_]u64{0} ** word_count,
        inserts: u64 = 0,
        salt: u64,

        const Self = @This();

        /// Create an empty filter for one domain-separated frame/epoch salt.
        pub fn init(salt: u64) Self {
            return .{ .salt = salt };
        }

        /// Remove all entries while keeping the same domain salt.
        pub fn clear(self: *Self) void {
            @memset(&self.bits, 0);
            self.inserts = 0;
        }

        /// Add one caller-provided 64-bit hash to the filter.
        pub fn add(self: *Self, hash: u64) void {
            const pos = self.positions(hash);
            for (pos) |bit| self.setBit(bit);
            self.inserts += 1;
        }

        /// Return true when `hash` may be present, false when definitely absent.
        pub fn mightContain(self: Self, hash: u64) bool {
            const pos = self.positions(hash);
            for (pos) |bit| {
                if (!self.isSet(bit)) return false;
            }
            return true;
        }

        /// Estimate false-positive probability from configured size and inserts.
        pub fn estimatedFpp(self: Self) f64 {
            if (self.inserts == 0) return 0.0;

            const m: f64 = @floatFromInt(bit_count);
            const k: f64 = @floatFromInt(hash_count);
            const n: f64 = @floatFromInt(self.inserts);
            const empty_prob = @exp(-(k * n) / m);
            return std.math.pow(f64, 1.0 - empty_prob, k);
        }

        /// Return the bit positions that `hash` probes in this salt domain.
        pub fn positions(self: Self, hash: u64) [hash_count]usize {
            var out: [hash_count]usize = undefined;
            const pair = doubleHash(hash, self.salt);

            for (&out, 0..) |*slot, i| {
                const probe = pair.h1 +% (@as(u64, @intCast(i)) *% pair.h2);
                slot.* = @as(usize, @intCast(probe % bit_count));
            }

            return out;
        }

        fn setBit(self: *Self, bit: usize) void {
            self.bits[bit / 64] |= @as(u64, 1) << @as(u6, @intCast(bit % 64));
        }

        fn isSet(self: Self, bit: usize) bool {
            return (self.bits[bit / 64] & (@as(u64, 1) << @as(u6, @intCast(bit % 64)))) != 0;
        }
    };
}

/// HyperLogLog cardinality estimator with fixed precision.
///
/// `precision` selects `2^precision` registers. Values from 4 through 18 are
/// supported here to keep standalone test instances practical.
pub fn HyperLogLog(comptime precision: usize) type {
    comptime {
        if (precision < 4) @compileError("HyperLogLog precision must be at least 4");
        if (precision > 18) @compileError("HyperLogLog precision must be at most 18");
    }

    const register_count: usize = @as(usize, 1) << precision;

    return struct {
        registers: [register_count]u8 = [_]u8{0} ** register_count,
        salt: u64,

        const Self = @This();

        /// Create an empty estimator for one domain-separated frame/epoch salt.
        pub fn init(salt: u64) Self {
            return .{ .salt = salt };
        }

        /// Remove all register state while keeping the same domain salt.
        pub fn clear(self: *Self) void {
            @memset(&self.registers, 0);
        }

        /// Add one caller-provided 64-bit hash to the estimator.
        pub fn add(self: *Self, hash: u64) void {
            const e = self.effect(hash);
            if (self.registers[e.index] < e.rank) self.registers[e.index] = e.rank;
        }

        /// Estimate cardinality using standard HLL alpha and range corrections.
        pub fn estimate(self: Self) f64 {
            const m: f64 = @floatFromInt(register_count);
            var harmonic: f64 = 0.0;
            var zero_count: usize = 0;

            for (self.registers) |rank| {
                harmonic += std.math.pow(f64, 2.0, -@as(f64, @floatFromInt(rank)));
                if (rank == 0) zero_count += 1;
            }

            const raw = alpha() * m * m / harmonic;
            if (raw <= 2.5 * m and zero_count != 0) {
                return m * @log(m / @as(f64, @floatFromInt(zero_count)));
            }

            const two_64 = 18_446_744_073_709_551_616.0;
            if (raw > two_64 / 30.0) {
                return -two_64 * @log(1.0 - (raw / two_64));
            }

            return raw;
        }

        /// Return the register update that `hash` would cause in this salt domain.
        pub fn effect(self: Self, hash: u64) RegisterEffect {
            const mixed = domainHash(hash, self.salt);
            const index = @as(usize, @intCast(mixed >> (64 - precision)));
            const shifted = mixed << precision;
            const max_rank = 64 - precision + 1;
            const rank = @min(@clz(shifted) + 1, max_rank);
            return .{ .index = index, .rank = @as(u8, @intCast(rank)) };
        }

        fn alpha() f64 {
            return switch (register_count) {
                16 => 0.673,
                32 => 0.697,
                64 => 0.709,
                else => 0.7213 / (1.0 + (1.079 / @as(f64, @floatFromInt(register_count)))),
            };
        }
    };
}

/// One HyperLogLog register mutation in a specific salt domain.
pub const RegisterEffect = struct {
    index: usize,
    rank: u8,
};

const HashPair = struct {
    h1: u64,
    h2: u64,
};

fn doubleHash(hash: u64, salt: u64) HashPair {
    const h1 = domainHash(hash, salt);
    const h2 = mix64(h1 ^ 0x9e37_79b9_7f4a_7c15) | 1;
    return .{ .h1 = h1, .h2 = h2 };
}

fn domainHash(hash: u64, salt: u64) u64 {
    return mix64(hash ^ mix64(salt +% 0xd6e8_feb8_6659_fd93));
}

fn mix64(input: u64) u64 {
    var x = input +% 0x9e37_79b9_7f4a_7c15;
    x = (x ^ (x >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    x = (x ^ (x >> 27)) *% 0x94d0_49bb_1331_11eb;
    return x ^ (x >> 31);
}

fn testHash(value: u64) u64 {
    return mix64(value ^ 0x517c_c1b7_2722_0a95);
}

test "bloom filter has no false negatives" {
    const Bloom = BloomFilter(.{ .bits = 4096, .hashes = 5 });
    var bloom = Bloom.init(0x1000_0000_0000_0001);

    for (0..512) |i| bloom.add(testHash(@intCast(i)));
    for (0..512) |i| {
        try std.testing.expect(bloom.mightContain(testHash(@intCast(i))));
    }
}

test "bloom filter false-positive rate is sane at known load" {
    const Bloom = BloomFilter(.{ .bits = 8192, .hashes = 4 });
    var bloom = Bloom.init(0x2000_0000_0000_0002);

    for (0..512) |i| bloom.add(testHash(@intCast(i)));

    var false_positives: usize = 0;
    const trials = 4096;
    for (10_000..10_000 + trials) |i| {
        if (bloom.mightContain(testHash(@intCast(i)))) false_positives += 1;
    }

    const observed = @as(f64, @floatFromInt(false_positives)) / @as(f64, @floatFromInt(trials));
    try std.testing.expect(bloom.estimatedFpp() > 0.001);
    try std.testing.expect(bloom.estimatedFpp() < 0.01);
    try std.testing.expect(observed < 0.02);
}

test "hyperloglog estimates distinct cardinality within tolerance" {
    const Hll = HyperLogLog(12);
    var hll = Hll.init(0x3000_0000_0000_0003);

    const n = 10_000;
    for (0..n) |i| hll.add(testHash(@intCast(i)));

    const estimate = hll.estimate();
    const target: f64 = @floatFromInt(n);
    const rel_err = @abs(estimate - target) / target;
    try std.testing.expect(rel_err < 0.08);
}

test "domain separation changes bloom bit positions" {
    const Bloom = BloomFilter(.{ .bits = 2048, .hashes = 6 });
    const key = testHash(42);
    const a = Bloom.init(0x4000_0000_0000_0004);
    const b = Bloom.init(0x5000_0000_0000_0005);

    const a_pos = a.positions(key);
    const b_pos = b.positions(key);
    try std.testing.expect(!std.mem.eql(usize, &a_pos, &b_pos));
}

test "domain separation changes hyperloglog register effects" {
    const Hll = HyperLogLog(10);
    const key = testHash(99);
    var a = Hll.init(0x6000_0000_0000_0006);
    var b = Hll.init(0x7000_0000_0000_0007);

    const a_effect = a.effect(key);
    const b_effect = b.effect(key);
    try std.testing.expect(a_effect.index != b_effect.index or a_effect.rank != b_effect.rank);

    a.add(key);
    b.add(key);
    try std.testing.expect(a.registers[a_effect.index] == a_effect.rank);
    try std.testing.expect(b.registers[b_effect.index] == b_effect.rank);
}
