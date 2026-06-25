// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cuckoo filter — approximate set membership with deletion support.
//!
//! Unlike a Bloom filter, a cuckoo filter supports `remove`, which makes it a
//! natural fit for sets that shrink over time: seen-message dedup windows,
//! revocation/expiry sets, and short-lived nonce caches. It stores compact
//! 1-byte fingerprints in a flat bucket table (4 slots per bucket) and uses
//! partial-key cuckoo hashing: each item has two candidate buckets where the
//! second is derived from the first by XOR-ing in a hash of the fingerprint.
//! This lets `contains`/`remove` recompute the alternate bucket from the
//! fingerprint alone, without storing the full key.
//!
//! Tradeoffs versus Bloom:
//!   - Supports deletion (Bloom does not, absent counting variants).
//!   - Lower space overhead at the same false-positive rate for fpp < ~3%.
//!   - Bounded occupancy: inserts fail once the table is near-full after a
//!     capped number of evictions ("kicks"). `add` returns `false` rather than
//!     silently degrading.
//!
//! All hashing uses `std.hash.Wyhash` with fixed seeds, so behaviour is fully
//! deterministic for a given construction seed.

const std = @import("std");

/// 1-byte fingerprint. Zero is reserved to mark an empty slot.
pub const Fingerprint = u8;

const empty: Fingerprint = 0;

/// Slots per bucket. Four is the standard cuckoo-filter choice: it keeps the
/// achievable load factor high (~95%) while bounding per-bucket scan cost.
pub const slots_per_bucket: usize = 4;

/// Default cap on eviction chain length before an insert is declared failed.
pub const default_max_kicks: usize = 500;

const hash_seed: u64 = 0x4d_69_7a_75_63_68_69_00; // "Orochi\0"
const fingerprint_seed: u64 = 0x43_75_63_6b_6f_6f_5f_46; // "Cuckoo_F"

pub const InitError = error{
    /// Requested capacity rounds to zero buckets, or the bucket table would
    /// overflow `usize`.
    InvalidCapacity,
} || std.mem.Allocator.Error;

pub const CuckooFilter = struct {
    allocator: std.mem.Allocator,
    /// Flat table of `bucket_count * slots_per_bucket` fingerprints.
    slots: []Fingerprint,
    /// Always a power of two so the index masks are cheap.
    bucket_count: usize,
    /// Number of fingerprints currently stored.
    count: usize,
    max_kicks: usize,
    rng: SplitMix64,

    /// Create a filter able to hold roughly `capacity` items. The bucket count
    /// is rounded up to the next power of two of `ceil(capacity / slots)`, so
    /// real capacity is `bucket_count * slots_per_bucket` (see `cap`).
    pub fn init(allocator: std.mem.Allocator, capacity: usize) InitError!CuckooFilter {
        return initSeeded(allocator, capacity, 0x9e37_79b9_7f4a_7c15);
    }

    /// Like `init`, but with an explicit RNG seed for deterministic eviction.
    pub fn initSeeded(allocator: std.mem.Allocator, capacity: usize, seed: u64) InitError!CuckooFilter {
        if (capacity == 0) return error.InvalidCapacity;

        const wanted_buckets = (capacity + slots_per_bucket - 1) / slots_per_bucket;
        const bucket_count = std.math.ceilPowerOfTwo(usize, @max(wanted_buckets, 1)) catch
            return error.InvalidCapacity;

        if (bucket_count > std.math.maxInt(usize) / slots_per_bucket) {
            return error.InvalidCapacity;
        }

        const slots = try allocator.alloc(Fingerprint, bucket_count * slots_per_bucket);
        @memset(slots, empty);

        return .{
            .allocator = allocator,
            .slots = slots,
            .bucket_count = bucket_count,
            .count = 0,
            .max_kicks = default_max_kicks,
            .rng = SplitMix64.init(seed),
        };
    }

    pub fn deinit(self: *CuckooFilter) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    /// Total number of fingerprint slots (the effective capacity).
    pub fn cap(self: *const CuckooFilter) usize {
        return self.bucket_count * slots_per_bucket;
    }

    /// Fraction of slots in use, in [0, 1].
    pub fn loadFactor(self: *const CuckooFilter) f64 {
        return @as(f64, @floatFromInt(self.count)) / @as(f64, @floatFromInt(self.cap()));
    }

    /// Insert `item`. Returns `true` on success, `false` if the table is too
    /// full to place the item within `max_kicks` evictions. On failure the
    /// table is restored to its prior contents.
    pub fn add(self: *CuckooFilter, item: []const u8) !bool {
        const fp = fingerprintOf(item);
        const home = self.indexOf(item);
        const alt = self.altIndex(home, fp);

        if (self.tryPlace(home, fp) or self.tryPlace(alt, fp)) {
            self.count += 1;
            return true;
        }

        // Both candidate buckets are full: relocate via cuckoo eviction. Record
        // every move so a failed chain can be rolled back exactly.
        var trail: std.ArrayList(Move) = .empty;
        defer trail.deinit(self.allocator);

        var index = if (self.rng.boolean()) home else alt;
        var moving = fp;

        var kick: usize = 0;
        while (kick < self.max_kicks) : (kick += 1) {
            const slot = self.rng.below(slots_per_bucket);
            const offset = index * slots_per_bucket + slot;
            const evicted = self.slots[offset];

            trail.append(self.allocator, .{
                .offset = offset,
                .previous = evicted,
            }) catch {
                self.rollback(trail.items);
                return error.OutOfMemory;
            };

            self.slots[offset] = moving;
            moving = evicted;
            index = self.altIndex(index, moving);

            if (self.tryPlace(index, moving)) {
                self.count += 1;
                return true;
            }
        }

        // Exhausted the kick budget: undo the partial chain and report failure.
        self.rollback(trail.items);
        return false;
    }

    /// Report whether `item` is (probably) present. May return a false
    /// positive; never a false negative for items added and not removed.
    pub fn contains(self: *const CuckooFilter, item: []const u8) bool {
        const fp = fingerprintOf(item);
        const home = self.indexOf(item);
        const alt = self.altIndex(home, fp);
        return self.bucketHas(home, fp) or self.bucketHas(alt, fp);
    }

    /// Remove one occurrence of `item`. Returns `true` if a matching
    /// fingerprint was found and cleared, `false` otherwise. Removing an item
    /// never added is safe but may clear a colliding fingerprint (a rare
    /// consequence of the approximate representation).
    pub fn remove(self: *CuckooFilter, item: []const u8) bool {
        const fp = fingerprintOf(item);
        const home = self.indexOf(item);
        const alt = self.altIndex(home, fp);

        if (self.clearFrom(home, fp) or self.clearFrom(alt, fp)) {
            self.count -= 1;
            return true;
        }
        return false;
    }

    const Move = struct {
        offset: usize,
        previous: Fingerprint,
    };

    fn rollback(self: *CuckooFilter, moves: []const Move) void {
        // Undo in reverse so each slot lands on its original value.
        var i = moves.len;
        while (i > 0) {
            i -= 1;
            self.slots[moves[i].offset] = moves[i].previous;
        }
    }

    fn indexOf(self: *const CuckooFilter, item: []const u8) usize {
        const mask = self.bucket_count - 1;
        return @as(usize, @intCast(std.hash.Wyhash.hash(hash_seed, item))) & mask;
    }

    fn altIndex(self: *const CuckooFilter, index: usize, fp: Fingerprint) usize {
        if (self.bucket_count == 1) return 0;
        const mask = self.bucket_count - 1;
        // Partial-key cuckoo hashing: the alternate bucket is recoverable from
        // either bucket plus the fingerprint, so we never store the full key.
        const h: usize = @intCast(std.hash.Wyhash.hash(fingerprint_seed, &[_]u8{fp}));
        return (index ^ h) & mask;
    }

    fn bucketSlots(self: *const CuckooFilter, index: usize) []Fingerprint {
        const start = index * slots_per_bucket;
        return self.slots[start .. start + slots_per_bucket];
    }

    fn bucketHas(self: *const CuckooFilter, index: usize, fp: Fingerprint) bool {
        for (self.bucketSlots(index)) |slot| {
            if (slot == fp) return true;
        }
        return false;
    }

    fn tryPlace(self: *CuckooFilter, index: usize, fp: Fingerprint) bool {
        for (self.bucketSlots(index)) |*slot| {
            if (slot.* == empty) {
                slot.* = fp;
                return true;
            }
        }
        return false;
    }

    fn clearFrom(self: *CuckooFilter, index: usize, fp: Fingerprint) bool {
        for (self.bucketSlots(index)) |*slot| {
            if (slot.* == fp) {
                slot.* = empty;
                return true;
            }
        }
        return false;
    }
};

/// Derive a non-zero 1-byte fingerprint from an item. Zero is reserved for
/// empty slots, so collisions onto zero are remapped to 1.
fn fingerprintOf(item: []const u8) Fingerprint {
    const h = std.hash.Wyhash.hash(fingerprint_seed, item);
    const fp: Fingerprint = @truncate(h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24));
    return if (fp == empty) 1 else fp;
}

/// Small deterministic PRNG for eviction-slot selection.
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

    fn boolean(self: *SplitMix64) bool {
        return (self.next() & 1) == 1;
    }

    fn below(self: *SplitMix64, upper: usize) usize {
        std.debug.assert(upper > 0);
        return @intCast(self.next() % @as(u64, @intCast(upper)));
    }
};

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

fn keyBytes(buf: []u8, n: usize) []const u8 {
    return std.fmt.bufPrint(buf, "item-{d}", .{n}) catch unreachable;
}

test "init rejects zero capacity and rounds up to power-of-two buckets" {
    try testing.expectError(error.InvalidCapacity, CuckooFilter.init(testing.allocator, 0));

    var f = try CuckooFilter.init(testing.allocator, 10);
    defer f.deinit();

    // ceil(10/4) = 3 buckets -> rounded up to 4 -> 16 slots.
    try testing.expectEqual(@as(usize, 16), f.cap());
    try testing.expectEqual(@as(usize, 0), f.count);
    try testing.expectEqual(@as(f64, 0.0), f.loadFactor());
}

test "add then contains for inserted items" {
    var f = try CuckooFilter.init(testing.allocator, 64);
    defer f.deinit();

    try testing.expect(try f.add("alpha"));
    try testing.expect(try f.add("bravo"));
    try testing.expect(try f.add("charlie"));

    try testing.expect(f.contains("alpha"));
    try testing.expect(f.contains("bravo"));
    try testing.expect(f.contains("charlie"));
    try testing.expectEqual(@as(usize, 3), f.count);
}

test "no false negatives across many inserts below capacity" {
    var f = try CuckooFilter.initSeeded(testing.allocator, 1024, 0x1234_5678);
    defer f.deinit();

    const n: usize = 700; // comfortably under ~95% load of 1024 slots
    var buf: [32]u8 = undefined;
    for (0..n) |i| {
        try testing.expect(try f.add(keyBytes(&buf, i)));
    }
    for (0..n) |i| {
        try testing.expect(f.contains(keyBytes(&buf, i)));
    }
    try testing.expectEqual(n, f.count);
}

test "remove then item is absent and count drops" {
    var f = try CuckooFilter.initSeeded(testing.allocator, 32, 11);
    defer f.deinit();

    try testing.expect(try f.add("delete-me"));
    try testing.expect(try f.add("keep-me"));
    try testing.expect(f.contains("delete-me"));
    try testing.expectEqual(@as(usize, 2), f.count);

    try testing.expect(f.remove("delete-me"));
    try testing.expect(!f.contains("delete-me"));
    try testing.expect(f.contains("keep-me"));
    try testing.expectEqual(@as(usize, 1), f.count);

    // Removing again finds nothing.
    try testing.expect(!f.remove("delete-me"));
    try testing.expectEqual(@as(usize, 1), f.count);
}

test "false positive rate is bounded for a deterministic sample" {
    var f = try CuckooFilter.initSeeded(testing.allocator, 4096, 0xabcd_ef01);
    defer f.deinit();

    var buf: [32]u8 = undefined;
    const inserted: usize = 2000;
    for (0..inserted) |i| {
        try testing.expect(try f.add(keyBytes(&buf, i)));
    }

    // Query disjoint keys; count false positives.
    var false_positives: usize = 0;
    const samples: usize = 20_000;
    for (0..samples) |i| {
        const probe = std.fmt.bufPrint(&buf, "absent-{d}", .{i}) catch unreachable;
        if (f.contains(probe)) false_positives += 1;
    }

    const observed = @as(f64, @floatFromInt(false_positives)) / @as(f64, @floatFromInt(samples));
    // Theory: ~2 * slots_per_bucket / 2^8 = ~3.1%. Allow generous headroom.
    try testing.expect(observed < 0.05);
}

test "fills near capacity then add eventually returns false" {
    var f = try CuckooFilter.initSeeded(testing.allocator, 64, 0x99);
    defer f.deinit();

    var buf: [32]u8 = undefined;
    var added: usize = 0;
    var hit_full = false;

    // Push well past capacity; a healthy filter must refuse some insert.
    for (0..256) |i| {
        if (try f.add(keyBytes(&buf, i))) {
            added += 1;
        } else {
            hit_full = true;
            break;
        }
    }

    try testing.expect(hit_full);
    try testing.expectEqual(added, f.count);
    // Cuckoo filters reach high occupancy before failing.
    try testing.expect(f.loadFactor() > 0.80);

    // A failed add must not corrupt prior membership.
    for (0..added) |i| {
        try testing.expect(f.contains(keyBytes(&buf, i)));
    }
}

test "deterministic seed yields identical tables" {
    var a = try CuckooFilter.initSeeded(testing.allocator, 128, 0x5555_aaaa);
    defer a.deinit();
    var b = try CuckooFilter.initSeeded(testing.allocator, 128, 0x5555_aaaa);
    defer b.deinit();

    var buf: [32]u8 = undefined;
    for (0..100) |i| {
        const k = keyBytes(&buf, i);
        const ra = try a.add(k);
        const rb = try b.add(k);
        try testing.expectEqual(ra, rb);
    }

    try testing.expectEqual(a.count, b.count);
    try testing.expectEqualSlices(Fingerprint, a.slots, b.slots);
}
