//! Immutable xor filter for approximate membership over u64 keys.
//!
//! The builder uses a 3-wise segmented xor construction: each key maps into
//! three neighboring segments, the graph is peeled by degree-1 vertices, then
//! 8-bit fingerprints are assigned in reverse peel order. Queries have no
//! false negatives for keys present at build time and an expected false-positive
//! rate of about 1/256.
const std = @import("std");

pub const fingerprint_bits: usize = 8;
pub const default_seed: u64 = 0x4d_69_7a_75_58_4f_52;
pub const default_max_retries: usize = 64;

pub const BuildError = error{
    BuildFailed,
    TooManyKeys,
} || std.mem.Allocator.Error;

pub const Options = struct {
    seed: u64 = default_seed,
    max_retries: usize = default_max_retries,
};

pub const XorFilter = struct {
    allocator: std.mem.Allocator,
    seed: u64,
    fingerprints: []u8,
    len: usize,
    segment_length: usize,
    segment_count: usize,

    pub fn deinit(self: *XorFilter) void {
        if (self.fingerprints.len != 0) {
            self.allocator.free(self.fingerprints);
        }
        self.* = undefined;
    }

    pub fn contains(self: *const XorFilter, key: u64) bool {
        if (self.len == 0) return false;

        const h = edgeHash(key, self.seed);
        const idx = indexes(h, self.segment_length, self.segment_count);
        const got = self.fingerprints[idx[0]] ^ self.fingerprints[idx[1]] ^ self.fingerprints[idx[2]];
        return got == fingerprint(h);
    }

    pub fn bitsPerEntry(self: *const XorFilter) f64 {
        if (self.len == 0) return 0.0;
        const bits: f64 = @floatFromInt(self.fingerprints.len * fingerprint_bits);
        const entries: f64 = @floatFromInt(self.len);
        return bits / entries;
    }

    pub fn count(self: *const XorFilter) usize {
        return self.len;
    }

    pub fn byteSize(self: *const XorFilter) usize {
        return self.fingerprints.len;
    }
};

pub fn build(allocator: std.mem.Allocator, keys: []const u64) BuildError!XorFilter {
    return buildWithOptions(allocator, keys, .{});
}

pub fn buildWithSeed(allocator: std.mem.Allocator, keys: []const u64, seed: u64) BuildError!XorFilter {
    return buildWithOptions(allocator, keys, .{ .seed = seed });
}

pub fn buildWithOptions(allocator: std.mem.Allocator, keys: []const u64, options: Options) BuildError!XorFilter {
    var unique = std.ArrayList(u64).empty;
    defer unique.deinit(allocator);

    var seen = std.AutoHashMap(u64, void).init(allocator);
    defer seen.deinit();

    for (keys) |key| {
        const entry = try seen.getOrPut(key);
        if (!entry.found_existing) {
            try unique.append(allocator, key);
        }
    }

    const unique_keys = try unique.toOwnedSlice(allocator);
    defer allocator.free(unique_keys);

    if (unique_keys.len == 0) {
        return .{
            .allocator = allocator,
            .seed = options.seed,
            .fingerprints = &.{},
            .len = 0,
            .segment_length = 0,
            .segment_count = 0,
        };
    }

    const retries = @max(options.max_retries, 1);
    var seed_stream = SplitMix64.init(options.seed ^ 0x78_6f_72_66_69_6c_74);

    for (0..8) |growth_segments| {
        const layout = try chooseLayout(unique_keys.len, growth_segments);
        for (0..retries) |attempt| {
            const seed = if (attempt == 0 and growth_segments == 0) options.seed else seed_stream.next();
            if (try tryBuild(allocator, unique_keys, seed, layout)) |filter| {
                return filter;
            }
        }
    }

    return error.BuildFailed;
}

const Layout = struct {
    segment_length: usize,
    segment_count: usize,
    array_len: usize,
};

const Assignment = struct {
    hash: u64,
    index: usize,
};

fn tryBuild(allocator: std.mem.Allocator, keys: []const u64, seed: u64, layout: Layout) BuildError!?XorFilter {
    const m = layout.array_len;

    const counts = try allocator.alloc(u32, m);
    defer allocator.free(counts);
    @memset(counts, 0);

    const xors = try allocator.alloc(u64, m);
    defer allocator.free(xors);
    @memset(xors, 0);

    for (keys) |key| {
        const h = edgeHash(key, seed);
        const idx = indexes(h, layout.segment_length, layout.segment_count);
        inline for (0..3) |i| {
            counts[idx[i]] += 1;
            xors[idx[i]] ^= h;
        }
    }

    const stack = try allocator.alloc(usize, m);
    defer allocator.free(stack);

    var stack_len: usize = 0;
    for (counts, 0..) |count, idx| {
        if (count == 1) {
            stack[stack_len] = idx;
            stack_len += 1;
        }
    }

    const order = try allocator.alloc(Assignment, keys.len);
    errdefer allocator.free(order);

    var order_len: usize = 0;
    while (stack_len > 0) {
        stack_len -= 1;
        const slot = stack[stack_len];
        if (counts[slot] != 1) continue;

        const h = xors[slot];
        const idx = indexes(h, layout.segment_length, layout.segment_count);
        order[order_len] = .{ .hash = h, .index = slot };
        order_len += 1;

        inline for (0..3) |i| {
            const pos = idx[i];
            std.debug.assert(counts[pos] > 0);
            counts[pos] -= 1;
            xors[pos] ^= h;
            if (counts[pos] == 1) {
                stack[stack_len] = pos;
                stack_len += 1;
            }
        }
    }

    if (order_len != keys.len) {
        allocator.free(order);
        return null;
    }

    const fingerprints = try allocator.alloc(u8, m);
    errdefer allocator.free(fingerprints);
    @memset(fingerprints, 0);

    while (order_len > 0) {
        order_len -= 1;
        const assignment = order[order_len];
        const idx = indexes(assignment.hash, layout.segment_length, layout.segment_count);
        var value = fingerprint(assignment.hash);
        inline for (0..3) |i| {
            const pos = idx[i];
            if (pos != assignment.index) value ^= fingerprints[pos];
        }
        fingerprints[assignment.index] = value;
    }

    allocator.free(order);
    return .{
        .allocator = allocator,
        .seed = seed,
        .fingerprints = fingerprints,
        .len = keys.len,
        .segment_length = layout.segment_length,
        .segment_count = layout.segment_count,
    };
}

fn chooseLayout(key_count: usize, extra_segments: usize) BuildError!Layout {
    if (key_count > (std.math.maxInt(usize) / 9)) return error.TooManyKeys;

    const segment_length = chooseSegmentLength(key_count);
    const base_slots = divCeil(key_count * 9, 8);
    var total_segments = divCeil(base_slots, segment_length) + extra_segments;
    total_segments = @max(total_segments, 3);

    const segment_count = total_segments - 2;
    if (total_segments > std.math.maxInt(usize) / segment_length) return error.TooManyKeys;

    return .{
        .segment_length = segment_length,
        .segment_count = segment_count,
        .array_len = total_segments * segment_length,
    };
}

fn chooseSegmentLength(key_count: usize) usize {
    if (key_count <= 2) return 1;
    if (key_count <= 16) return 4;
    if (key_count <= 64) return 8;
    if (key_count <= 256) return 32;
    if (key_count <= 1024) return 128;
    if (key_count <= 4096) return 256;
    if (key_count <= 16_384) return 512;
    if (key_count <= 65_536) return 1024;
    if (key_count <= 262_144) return 2048;
    if (key_count <= 1_048_576) return 4096;
    return 8192;
}

fn indexes(hash: u64, segment_length: usize, segment_count: usize) [3]usize {
    const segment = reduce(mix64(hash ^ 0x73_65_67_6d_65_6e_74), segment_count);
    return .{
        segment * segment_length + reduce(mix64(hash ^ 0x69_6e_64_65_78_30), segment_length),
        (segment + 1) * segment_length + reduce(mix64(hash ^ 0x69_6e_64_65_78_31), segment_length),
        (segment + 2) * segment_length + reduce(mix64(hash ^ 0x69_6e_64_65_78_32), segment_length),
    };
}

fn edgeHash(key: u64, seed: u64) u64 {
    const h = mix64(key ^ seed ^ 0xa0_76_1d_64_78_bd_64_2f);
    if (h == 0) return 0xff51_afd7_ed55_8ccd;
    return h;
}

fn fingerprint(hash: u64) u8 {
    return @truncate(mix64(hash ^ 0x66_69_6e_67_65_72) >> 56);
}

fn reduce(hash: u64, upper: usize) usize {
    std.debug.assert(upper > 0);
    return @intCast(hash % @as(u64, @intCast(upper)));
}

fn divCeil(numerator: usize, denominator: usize) usize {
    return (numerator + denominator - 1) / denominator;
}

fn keyFor(prefix: u64, index: usize) u64 {
    return mix64(prefix ^ (@as(u64, @intCast(index)) *% 0x9e37_79b9_7f4a_7c15));
}

const SplitMix64 = struct {
    state: u64,

    fn init(seed: u64) SplitMix64 {
        return .{ .state = seed };
    }

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e37_79b9_7f4a_7c15;
        return mix64(self.state);
    }
};

fn mix64(value: u64) u64 {
    var z = value;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

test "empty and singleton filters behave correctly" {
    const allocator = std.testing.allocator;

    var empty = try build(allocator, &.{});
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.count());
    try std.testing.expectEqual(@as(f64, 0.0), empty.bitsPerEntry());
    try std.testing.expect(!empty.contains(0));
    try std.testing.expect(!empty.contains(1234));

    var single = try buildWithSeed(allocator, &.{0}, 7);
    defer single.deinit();
    try std.testing.expectEqual(@as(usize, 1), single.count());
    try std.testing.expect(single.contains(0));
    try std.testing.expect(single.bitsPerEntry() >= 8.0);
}

test "built keys have no false negatives" {
    const allocator = std.testing.allocator;
    var keys: [4096]u64 = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = keyFor(0xfeed_face_cafe_beef, i);
    }

    var filter = try buildWithSeed(allocator, &keys, 0x1234_5678_9abc_def0);
    defer filter.deinit();

    for (keys) |key| {
        try std.testing.expect(filter.contains(key));
    }

    try std.testing.expect(filter.bitsPerEntry() <= 12.0);
}

test "false-positive rate stays under a practical bound" {
    const allocator = std.testing.allocator;
    var keys: [2500]u64 = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = keyFor(0x11_22_33_44_55_66_77_88, i);
    }

    var filter = try buildWithSeed(allocator, &keys, 0x0f0e_0d0c_0b0a_0908);
    defer filter.deinit();

    var false_positives: usize = 0;
    const samples: usize = 50_000;
    for (0..samples) |i| {
        const candidate = keyFor(0x88_77_66_55_44_33_22_11, i);
        if (filter.contains(candidate)) false_positives += 1;
    }

    const observed: f64 = @as(f64, @floatFromInt(false_positives)) / @as(f64, @floatFromInt(samples));
    try std.testing.expect(observed < 0.015);
}

test "build succeeds across sizes with deterministic retry" {
    const allocator = std.testing.allocator;
    const sizes = [_]usize{ 0, 1, 2, 3, 7, 16, 31, 64, 257, 1024, 4097 };

    for (sizes) |size| {
        const keys = try allocator.alloc(u64, size);
        defer allocator.free(keys);

        for (keys, 0..) |*key, i| {
            key.* = keyFor(@as(u64, @intCast(size)) ^ 0xabcd_ef01, i);
        }

        var filter = try buildWithOptions(allocator, keys, .{
            .seed = 0xface_feed_dead_beef ^ @as(u64, @intCast(size)),
            .max_retries = 8,
        });
        defer filter.deinit();

        for (keys) |key| {
            try std.testing.expect(filter.contains(key));
        }
    }
}

test "duplicates are stored once without losing membership" {
    const allocator = std.testing.allocator;
    const keys = [_]u64{ 0, 1, 1, 2, 3, 3, 3, 4 };

    var filter = try buildWithSeed(allocator, &keys, 99);
    defer filter.deinit();

    try std.testing.expectEqual(@as(usize, 5), filter.count());
    for (keys) |key| {
        try std.testing.expect(filter.contains(key));
    }
}

test "same seed and keys produce identical filters" {
    const allocator = std.testing.allocator;
    var keys: [512]u64 = undefined;
    for (&keys, 0..) |*key, i| {
        key.* = keyFor(0x55aa_55aa_55aa_55aa, i);
    }

    var a = try buildWithSeed(allocator, &keys, 0x1357_9bdf_2468_ace0);
    defer a.deinit();
    var b = try buildWithSeed(allocator, &keys, 0x1357_9bdf_2468_ace0);
    defer b.deinit();

    try std.testing.expectEqual(a.seed, b.seed);
    try std.testing.expectEqual(a.segment_length, b.segment_length);
    try std.testing.expectEqual(a.segment_count, b.segment_count);
    try std.testing.expectEqual(a.len, b.len);
    try std.testing.expectEqualSlices(u8, a.fingerprints, b.fingerprints);
}
