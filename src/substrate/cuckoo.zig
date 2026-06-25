// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const Fingerprint = u16;
pub const empty_fingerprint: Fingerprint = 0;
pub const max_supported_kicks: usize = 4096;

const primary_hash_seed: u64 = 0x4d_69_7a_75_63_68_69_31;
const fingerprint_hash_seed: u64 = 0x43_75_63_6b_6f_6f_46_50;

pub const Options = struct {
    bucket_count: usize,
    bucket_size: usize = 4,
    max_kicks: usize = 500,
    seed: u64 = 0x9e37_79b9_7f4a_7c15,
};

pub const InitError = error{
    InvalidConfig,
    OutOfMemory,
};

pub const CuckooFilter = struct {
    allocator: std.mem.Allocator,
    buckets: []Fingerprint,
    bucket_count: usize,
    bucket_size: usize,
    len: usize,
    max_kicks: usize,
    rng: SplitMix64,

    const Move = struct {
        index: usize,
        slot: usize,
        previous: Fingerprint,
    };

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!CuckooFilter {
        if (options.bucket_count == 0 or
            options.bucket_size == 0 or
            !isPowerOfTwo(options.bucket_count) or
            options.max_kicks > max_supported_kicks)
        {
            return error.InvalidConfig;
        }

        if (options.bucket_count > std.math.maxInt(usize) / options.bucket_size) {
            return error.InvalidConfig;
        }

        const slot_count = options.bucket_count * options.bucket_size;
        const buckets = try allocator.alloc(Fingerprint, slot_count);
        @memset(buckets, empty_fingerprint);

        return .{
            .allocator = allocator,
            .buckets = buckets,
            .bucket_count = options.bucket_count,
            .bucket_size = options.bucket_size,
            .len = 0,
            .max_kicks = options.max_kicks,
            .rng = SplitMix64.init(options.seed),
        };
    }

    pub fn deinit(self: *CuckooFilter) void {
        self.allocator.free(self.buckets);
        self.* = undefined;
    }

    pub fn add(self: *CuckooFilter, bytes: []const u8) bool {
        const fp = makeFingerprint(bytes);
        const primary = self.primaryIndex(bytes);
        const alternate = self.alternateIndex(primary, fp);

        if (self.placeInBucket(primary, fp) or self.placeInBucket(alternate, fp)) {
            self.len += 1;
            return true;
        }

        var moves: [max_supported_kicks]Move = undefined;
        var move_count: usize = 0;
        var index = if (self.rng.bounded(2) == 0) primary else alternate;
        var moving = fp;

        for (0..self.max_kicks) |_| {
            const slot = self.rng.bounded(self.bucket_size);
            const offset = self.bucketStart(index) + slot;
            const evicted = self.buckets[offset];

            moves[move_count] = .{
                .index = index,
                .slot = slot,
                .previous = evicted,
            };
            move_count += 1;

            self.buckets[offset] = moving;
            moving = evicted;
            index = self.alternateIndex(index, moving);

            if (self.placeInBucket(index, moving)) {
                self.len += 1;
                return true;
            }
        }

        while (move_count > 0) {
            move_count -= 1;
            const move = moves[move_count];
            self.buckets[self.bucketStart(move.index) + move.slot] = move.previous;
        }

        return false;
    }

    pub fn contains(self: *const CuckooFilter, bytes: []const u8) bool {
        const fp = makeFingerprint(bytes);
        const primary = self.primaryIndex(bytes);
        const alternate = self.alternateIndex(primary, fp);
        return self.bucketContains(primary, fp) or self.bucketContains(alternate, fp);
    }

    pub fn remove(self: *CuckooFilter, bytes: []const u8) bool {
        const fp = makeFingerprint(bytes);
        const primary = self.primaryIndex(bytes);
        const alternate = self.alternateIndex(primary, fp);

        if (self.removeFromBucket(primary, fp) or self.removeFromBucket(alternate, fp)) {
            self.len -= 1;
            return true;
        }

        return false;
    }

    pub fn loadFactor(self: *const CuckooFilter) f64 {
        return @as(f64, @floatFromInt(self.len)) / @as(f64, @floatFromInt(self.capacity()));
    }

    pub fn count(self: *const CuckooFilter) usize {
        return self.len;
    }

    pub fn capacity(self: *const CuckooFilter) usize {
        return self.bucket_count * self.bucket_size;
    }

    fn primaryIndex(self: *const CuckooFilter, bytes: []const u8) usize {
        const mask: u64 = @intCast(self.bucket_count - 1);
        return @intCast(hashBytes(bytes, primary_hash_seed) & mask);
    }

    fn alternateIndex(self: *const CuckooFilter, index: usize, fp: Fingerprint) usize {
        if (self.bucket_count == 1) return 0;

        const mask: u64 = @intCast(self.bucket_count - 1);
        var delta = fingerprintHash(fp) & mask;
        if (delta == 0) delta = 1;
        return @intCast((@as(u64, @intCast(index)) ^ delta) & mask);
    }

    fn bucketStart(self: *const CuckooFilter, index: usize) usize {
        return index * self.bucket_size;
    }

    fn bucketContains(self: *const CuckooFilter, index: usize, fp: Fingerprint) bool {
        const start = self.bucketStart(index);
        for (self.buckets[start..][0..self.bucket_size]) |slot| {
            if (slot == fp) return true;
        }
        return false;
    }

    fn bucketHasEmpty(self: *const CuckooFilter, index: usize) bool {
        const start = self.bucketStart(index);
        for (self.buckets[start..][0..self.bucket_size]) |slot| {
            if (slot == empty_fingerprint) return true;
        }
        return false;
    }

    fn placeInBucket(self: *CuckooFilter, index: usize, fp: Fingerprint) bool {
        const start = self.bucketStart(index);
        for (self.buckets[start..][0..self.bucket_size]) |*slot| {
            if (slot.* == empty_fingerprint) {
                slot.* = fp;
                return true;
            }
        }
        return false;
    }

    fn removeFromBucket(self: *CuckooFilter, index: usize, fp: Fingerprint) bool {
        const start = self.bucketStart(index);
        for (self.buckets[start..][0..self.bucket_size]) |*slot| {
            if (slot.* == fp) {
                slot.* = empty_fingerprint;
                return true;
            }
        }
        return false;
    }
};

const SplitMix64 = struct {
    state: u64,

    fn init(seed: u64) SplitMix64 {
        return .{ .state = seed };
    }

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e37_79b9_7f4a_7c15;
        return mix64(self.state);
    }

    fn bounded(self: *SplitMix64, upper: usize) usize {
        std.debug.assert(upper > 0);
        return @intCast(self.next() % @as(u64, @intCast(upper)));
    }
};

fn isPowerOfTwo(value: usize) bool {
    return value != 0 and (value & (value - 1)) == 0;
}

fn makeFingerprint(bytes: []const u8) Fingerprint {
    const h = hashBytes(bytes, fingerprint_hash_seed);
    var fp: Fingerprint = @truncate(h ^ (h >> 16) ^ (h >> 32) ^ (h >> 48));
    if (fp == empty_fingerprint) fp = 1;
    return fp;
}

fn fingerprintHash(fp: Fingerprint) u64 {
    return mix64(@as(u64, fp) *% 0xa076_1d64_78bd_642f);
}

fn hashBytes(bytes: []const u8, seed: u64) u64 {
    var h = 0xcbf2_9ce4_8422_2325 ^ seed;
    for (bytes) |byte| {
        h ^= byte;
        h *%= 0x0000_0100_0000_01b3;
    }
    h ^= @as(u64, @intCast(bytes.len)) *% 0x9e37_79b9_7f4a_7c15;
    return mix64(h);
}

fn mix64(value: u64) u64 {
    var z = value;
    z ^= z >> 30;
    z *%= 0xbf58_476d_1ce4_e5b9;
    z ^= z >> 27;
    z *%= 0x94d0_49bb_1331_11eb;
    z ^= z >> 31;
    return z;
}

test "init rejects unusable configurations" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidConfig, CuckooFilter.init(allocator, .{
        .bucket_count = 0,
    }));
    try std.testing.expectError(error.InvalidConfig, CuckooFilter.init(allocator, .{
        .bucket_count = 3,
    }));
    try std.testing.expectError(error.InvalidConfig, CuckooFilter.init(allocator, .{
        .bucket_count = 4,
        .bucket_size = 0,
    }));
    try std.testing.expectError(error.InvalidConfig, CuckooFilter.init(allocator, .{
        .bucket_count = 4,
        .max_kicks = max_supported_kicks + 1,
    }));
}

test "add contains and load factor track inserted fingerprints" {
    var filter = try CuckooFilter.init(std.testing.allocator, .{
        .bucket_count = 16,
        .bucket_size = 4,
        .seed = 7,
    });
    defer filter.deinit();

    try std.testing.expectEqual(@as(usize, 64), filter.capacity());
    try std.testing.expectEqual(@as(usize, 0), filter.count());
    try std.testing.expectEqual(@as(f64, 0.0), filter.loadFactor());

    try std.testing.expect(filter.add("alpha"));
    try std.testing.expect(filter.add("bravo"));
    try std.testing.expect(filter.add("charlie"));

    try std.testing.expect(filter.contains("alpha"));
    try std.testing.expect(filter.contains("bravo"));
    try std.testing.expect(filter.contains("charlie"));
    try std.testing.expectEqual(@as(usize, 3), filter.count());
    try std.testing.expectApproxEqAbs(@as(f64, 3.0 / 64.0), filter.loadFactor(), 0.000001);
}

test "no false negatives before eviction overflow" {
    var filter = try CuckooFilter.init(std.testing.allocator, .{
        .bucket_count = 256,
        .bucket_size = 4,
        .max_kicks = 500,
        .seed = 0x1234_5678,
    });
    defer filter.deinit();

    var inserted: [512][32]u8 = undefined;
    var lengths: [512]usize = undefined;

    for (0..inserted.len) |i| {
        const key = try std.fmt.bufPrint(&inserted[i], "nf-key-{d}", .{i});
        lengths[i] = key.len;
        try std.testing.expect(filter.add(key));
    }

    for (0..inserted.len) |i| {
        try std.testing.expect(filter.contains(inserted[i][0..lengths[i]]));
    }
}

test "delete removes membership and reports misses" {
    var filter = try CuckooFilter.init(std.testing.allocator, .{
        .bucket_count = 8,
        .bucket_size = 2,
        .seed = 11,
    });
    defer filter.deinit();

    try std.testing.expect(filter.add("delete-me"));
    try std.testing.expect(filter.contains("delete-me"));
    try std.testing.expectEqual(@as(usize, 1), filter.count());

    try std.testing.expect(filter.remove("delete-me"));
    try std.testing.expect(!filter.contains("delete-me"));
    try std.testing.expectEqual(@as(usize, 0), filter.count());
    try std.testing.expect(!filter.remove("delete-me"));
}

test "insert fails gracefully when full after max kicks" {
    var filter = try CuckooFilter.init(std.testing.allocator, .{
        .bucket_count = 1,
        .bucket_size = 2,
        .max_kicks = 16,
        .seed = 99,
    });
    defer filter.deinit();

    try std.testing.expect(filter.add("first"));
    try std.testing.expect(filter.add("second"));

    const before0 = filter.buckets[0];
    const before1 = filter.buckets[1];
    try std.testing.expectEqual(@as(usize, 2), filter.count());
    try std.testing.expectEqual(@as(f64, 1.0), filter.loadFactor());

    try std.testing.expect(!filter.add("third"));
    try std.testing.expectEqual(before0, filter.buckets[0]);
    try std.testing.expectEqual(before1, filter.buckets[1]);
    try std.testing.expectEqual(@as(usize, 2), filter.count());
    try std.testing.expect(filter.contains("first"));
    try std.testing.expect(filter.contains("second"));
}

test "seeded kicks are deterministic" {
    var left = try CuckooFilter.init(std.testing.allocator, .{
        .bucket_count = 4,
        .bucket_size = 2,
        .max_kicks = 32,
        .seed = 0xa5a5_a5a5,
    });
    defer left.deinit();

    var right = try CuckooFilter.init(std.testing.allocator, .{
        .bucket_count = 4,
        .bucket_size = 2,
        .max_kicks = 32,
        .seed = 0xa5a5_a5a5,
    });
    defer right.deinit();

    var saw_eviction = false;
    var key_buf: [32]u8 = undefined;

    for (0..64) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "kick-key-{d}", .{i});
        const fp = makeFingerprint(key);
        const primary = left.primaryIndex(key);
        const alternate = left.alternateIndex(primary, fp);
        const direct_buckets_full = !left.bucketHasEmpty(primary) and !left.bucketHasEmpty(alternate);

        const left_added = left.add(key);
        const right_added = right.add(key);

        try std.testing.expectEqual(left_added, right_added);
        try std.testing.expectEqual(left.count(), right.count());
        try std.testing.expectEqualSlices(Fingerprint, left.buckets, right.buckets);

        if (left_added and direct_buckets_full) {
            saw_eviction = true;
        }
    }

    try std.testing.expect(saw_eviction);
}
