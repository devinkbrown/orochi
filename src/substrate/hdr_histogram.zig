// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HDR (High Dynamic Range) histogram for latency recording with bounded relative error.
//!
//! Implements the HdrHistogram bucketing algorithm:
//!   - Values from 1 to `max_trackable_value` are recorded.
//!   - `significant_figures` controls the relative error guarantee:
//!     relative error <= 1 / (2 * sub_bucket_half_count).
//!   - Values outside the range are clamped to the boundary bucket.
//!
//! Reference: Gil Tene's HdrHistogram (https://github.com/HdrHistogram/HdrHistogram)
const std = @import("std");

/// Configuration for an HdrHistogram instance.
pub const Config = struct {
    /// Number of significant decimal figures of precision (1–5).
    significant_figures: u8,
    /// Highest value trackable without clamping (inclusive, must be >= 2).
    max_trackable_value: u64,
};

/// HDR histogram with allocator-managed bucket storage.
///
/// Bucket layout
/// -------------
/// Bucket 0 stores all values in [0, sub_bucket_count).
/// Bucket k>0 stores values whose leading bit is at position
///   (sub_bucket_half_count_magnitude + k).
/// Each bucket k>0 contributes exactly sub_bucket_half_count counters
/// (the upper half of the sub-bucket range; the lower half maps to bucket k-1).
///
/// Total counters = sub_bucket_count + bucket_count * sub_bucket_half_count.
pub const HdrHistogram = struct {
    allocator: std.mem.Allocator,

    /// sub_bucket_count = 2 * sub_bucket_half_count
    sub_bucket_half_count: u32,
    sub_bucket_count: u32,
    /// floor(log2(sub_bucket_half_count))
    sub_bucket_half_count_magnitude: u32,

    /// Number of exponent buckets beyond bucket 0.
    bucket_count: u32,
    /// Total number of counters in `counts`.
    counts_len: usize,

    counts: []u64,

    total_count: u64,
    min_value: u64,
    max_value: u64,

    /// Allocate and initialise an HDR histogram.
    pub fn init(allocator: std.mem.Allocator, cfg: Config) !HdrHistogram {
        if (cfg.significant_figures < 1 or cfg.significant_figures > 5)
            return error.InvalidSignificantFigures;
        if (cfg.max_trackable_value < 2)
            return error.InvalidMaxValue;

        // The smallest sub_bucket_half_count that is a power-of-two and gives
        // the required precision:  sub_bucket_count >= 2 * 10^significant_figures.
        const two_times_10_sf: u32 = @intCast(
            2 * std.math.pow(u64, 10, cfg.significant_figures),
        );
        const sub_bucket_count: u32 = nextPow2(two_times_10_sf);
        const sub_bucket_half_count: u32 = sub_bucket_count / 2;
        // magnitude = log2(sub_bucket_half_count)
        const sub_bucket_half_count_magnitude: u32 = @intCast(
            std.math.log2_int(u32, sub_bucket_half_count),
        );

        const bucket_count: u32 = computeBucketCount(
            cfg.max_trackable_value,
            sub_bucket_half_count_magnitude,
            sub_bucket_count,
        );

        // Bucket 0 uses sub_bucket_count slots.
        // Each subsequent bucket uses sub_bucket_half_count slots.
        const counts_len: usize = @as(usize, sub_bucket_count) +
            @as(usize, bucket_count) * @as(usize, sub_bucket_half_count);
        const counts = try allocator.alloc(u64, counts_len);
        @memset(counts, 0);

        return HdrHistogram{
            .allocator = allocator,
            .sub_bucket_half_count = sub_bucket_half_count,
            .sub_bucket_count = sub_bucket_count,
            .sub_bucket_half_count_magnitude = sub_bucket_half_count_magnitude,
            .bucket_count = bucket_count,
            .counts_len = counts_len,
            .counts = counts,
            .total_count = 0,
            .min_value = std.math.maxInt(u64),
            .max_value = 0,
        };
    }

    pub fn deinit(self: *HdrHistogram) void {
        self.allocator.free(self.counts);
    }

    /// Reset all counts to zero, preserving configuration.
    pub fn reset(self: *HdrHistogram) void {
        @memset(self.counts, 0);
        self.total_count = 0;
        self.min_value = std.math.maxInt(u64);
        self.max_value = 0;
    }

    /// Record one observation of `value`. Out-of-range values are clamped.
    pub fn recordValue(self: *HdrHistogram, value: u64) void {
        self.recordValueWithCount(value, 1);
    }

    /// Record `count` observations of `value`. Out-of-range values are clamped.
    pub fn recordValueWithCount(self: *HdrHistogram, value: u64, count: u64) void {
        if (count == 0) return;
        const clamped = self.clampValue(value);
        const idx = self.countsIndexFor(clamped);
        self.counts[idx] += count;
        self.total_count += count;
        if (clamped < self.min_value) self.min_value = clamped;
        if (clamped > self.max_value) self.max_value = clamped;
    }

    /// Value at or below which `percentile` percent of observations fall.
    /// `percentile` is in [0.0, 100.0].  Returns 0 when histogram is empty.
    pub fn valueAtPercentile(self: HdrHistogram, percentile: f64) u64 {
        if (self.total_count == 0) return 0;

        const pct = @max(0.0, @min(100.0, percentile));

        // Number of counts we must accumulate to reach the percentile.
        // Use ceiling so p100 returns the max occupied bucket.
        const count_at_pct: u64 = blk: {
            const raw: f64 = (pct / 100.0) * @as(f64, @floatFromInt(self.total_count));
            const ceiled: u64 = @intFromFloat(@ceil(raw));
            break :blk @min(ceiled, self.total_count);
        };

        var running: u64 = 0;

        // Iterate bucket 0 first (full sub_bucket_count slots).
        for (0..self.sub_bucket_count) |sub_idx| {
            running += self.counts[sub_idx];
            if (running >= count_at_pct) {
                const v = valueFromBucketSub(0, @intCast(sub_idx));
                return self.highestEquivalentValue(v);
            }
        }

        // Iterate buckets 1..bucket_count.
        for (1..@as(usize, self.bucket_count) + 1) |b| {
            const base: usize = @as(usize, self.sub_bucket_count) +
                (b - 1) * @as(usize, self.sub_bucket_half_count);
            for (0..self.sub_bucket_half_count) |slot| {
                running += self.counts[base + slot];
                const sub_idx: u32 = @intCast(self.sub_bucket_half_count + slot);
                if (running >= count_at_pct) {
                    const v = valueFromBucketSub(@intCast(b), sub_idx);
                    return self.highestEquivalentValue(v);
                }
            }
        }

        return self.max_value;
    }

    /// Minimum recorded value (`std.math.maxInt(u64)` when empty).
    pub fn minValue(self: HdrHistogram) u64 {
        return self.min_value;
    }

    /// Maximum recorded value (0 when empty).
    pub fn maxValue(self: HdrHistogram) u64 {
        return self.max_value;
    }

    /// Total number of recorded observations.
    pub fn totalCount(self: HdrHistogram) u64 {
        return self.total_count;
    }

    /// Arithmetic mean of all recorded values.  Returns 0.0 when empty.
    pub fn mean(self: HdrHistogram) f64 {
        if (self.total_count == 0) return 0.0;
        return self.iterateSum() / @as(f64, @floatFromInt(self.total_count));
    }

    /// Standard deviation of all recorded values.  Returns 0.0 when empty.
    pub fn stdDev(self: HdrHistogram) f64 {
        if (self.total_count == 0) return 0.0;
        const m = self.mean();
        var variance: f64 = 0.0;

        for (0..self.sub_bucket_count) |sub_idx| {
            const cnt = self.counts[sub_idx];
            if (cnt == 0) continue;
            const v = valueFromBucketSub(0, @intCast(sub_idx));
            const mid: f64 = @floatFromInt(self.medianEquivalentValue(v));
            const diff = mid - m;
            variance += diff * diff * @as(f64, @floatFromInt(cnt));
        }
        for (1..@as(usize, self.bucket_count) + 1) |b| {
            const base: usize = @as(usize, self.sub_bucket_count) +
                (b - 1) * @as(usize, self.sub_bucket_half_count);
            for (0..self.sub_bucket_half_count) |slot| {
                const cnt = self.counts[base + slot];
                if (cnt == 0) continue;
                const sub_idx: u32 = @intCast(self.sub_bucket_half_count + slot);
                const v = valueFromBucketSub(@intCast(b), sub_idx);
                const mid: f64 = @floatFromInt(self.medianEquivalentValue(v));
                const diff = mid - m;
                variance += diff * diff * @as(f64, @floatFromInt(cnt));
            }
        }

        return @sqrt(variance / @as(f64, @floatFromInt(self.total_count)));
    }

    /// Merge `other` into `self`, accumulating all counts.
    /// Both histograms must have been created with identical `Config` values.
    pub fn merge(self: *HdrHistogram, other: HdrHistogram) !void {
        if (self.counts_len != other.counts_len) return error.IncompatibleHistograms;
        for (self.counts, other.counts) |*dst, src| dst.* += src;
        self.total_count += other.total_count;
        if (other.total_count > 0) {
            if (other.min_value < self.min_value) self.min_value = other.min_value;
            if (other.max_value > self.max_value) self.max_value = other.max_value;
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn clampValue(self: HdrHistogram, value: u64) u64 {
        if (value < 1) return 1;
        const highest = self.highestRepresentableValue();
        if (value > highest) return highest;
        return value;
    }

    fn highestRepresentableValue(self: HdrHistogram) u64 {
        // Last slot: bucket = bucket_count, sub = sub_bucket_count - 1.
        const v = valueFromBucketSub(
            self.bucket_count,
            self.sub_bucket_count - 1,
        );
        return self.highestEquivalentValue(v);
    }

    /// Flat counter index for a (already clamped) value.
    fn countsIndexFor(self: HdrHistogram, value: u64) usize {
        const b = bucketIndexFor(value, self.sub_bucket_half_count_magnitude);
        const sub = subBucketIdxFor(value, b);
        return self.flatIndex(b, sub);
    }

    /// Flat array index from (bucket, sub-bucket) coordinates.
    fn flatIndex(self: HdrHistogram, bucket_idx: u32, sub_idx: u32) usize {
        if (bucket_idx == 0) {
            // Bucket 0: slots [0, sub_bucket_count).
            return @as(usize, sub_idx);
        }
        // Bucket k>0: slots start after sub_bucket_count (bucket 0) plus
        // (k-1)*sub_bucket_half_count earlier exponent buckets.
        const base: usize = @as(usize, self.sub_bucket_count) +
            @as(usize, bucket_idx - 1) * @as(usize, self.sub_bucket_half_count);
        const offset = sub_idx - self.sub_bucket_half_count;
        return base + @as(usize, offset);
    }

    fn highestEquivalentValue(self: HdrHistogram, value: u64) u64 {
        return self.nextNonEquivalentValue(value) - 1;
    }

    fn nextNonEquivalentValue(self: HdrHistogram, value: u64) u64 {
        const b = bucketIndexFor(value, self.sub_bucket_half_count_magnitude);
        const unit_magnitude: u6 = @intCast(b);
        return value + (@as(u64, 1) << unit_magnitude);
    }

    fn medianEquivalentValue(self: HdrHistogram, value: u64) u64 {
        const b = bucketIndexFor(value, self.sub_bucket_half_count_magnitude);
        const size_of_equivalent_range = @as(u64, 1) << @as(u6, @intCast(b));
        return value + (size_of_equivalent_range >> 1);
    }

    fn iterateSum(self: HdrHistogram) f64 {
        var sum: f64 = 0.0;
        for (0..self.sub_bucket_count) |sub_idx| {
            const cnt = self.counts[sub_idx];
            if (cnt == 0) continue;
            const v = valueFromBucketSub(0, @intCast(sub_idx));
            sum += @as(f64, @floatFromInt(self.medianEquivalentValue(v))) *
                @as(f64, @floatFromInt(cnt));
        }
        for (1..@as(usize, self.bucket_count) + 1) |b| {
            const base: usize = @as(usize, self.sub_bucket_count) +
                (b - 1) * @as(usize, self.sub_bucket_half_count);
            for (0..self.sub_bucket_half_count) |slot| {
                const cnt = self.counts[base + slot];
                if (cnt == 0) continue;
                const sub_idx: u32 = @intCast(self.sub_bucket_half_count + slot);
                const v = valueFromBucketSub(@intCast(b), sub_idx);
                sum += @as(f64, @floatFromInt(self.medianEquivalentValue(v))) *
                    @as(f64, @floatFromInt(cnt));
            }
        }
        return sum;
    }
};

// ---------------------------------------------------------------------------
// Pure helpers (module-private, no self parameter)
// ---------------------------------------------------------------------------

/// Which exponent bucket contains `value`.
///
/// We need the smallest bucket_index b such that
///   value < sub_bucket_count << b,
/// i.e. the top bit of value is at position >= sub_bucket_half_count_magnitude + b.
fn bucketIndexFor(value: u64, sub_bucket_half_count_magnitude: u32) u32 {
    if (value == 0) return 0;
    const bits_needed: u32 = 64 - @clz(value); // position of highest set bit + 1
    const base: u32 = sub_bucket_half_count_magnitude + 1;
    if (bits_needed <= base) return 0;
    return bits_needed - base;
}

/// Which sub-bucket within its exponent bucket contains `value`.
fn subBucketIdxFor(value: u64, bucket_idx: u32) u32 {
    const shift: u6 = @intCast(bucket_idx);
    return @intCast(value >> shift);
}

/// Lowest value that maps to (bucket_idx, sub_idx).
fn valueFromBucketSub(bucket_idx: u32, sub_idx: u32) u64 {
    return @as(u64, sub_idx) << @as(u6, @intCast(bucket_idx));
}

fn nextPow2(v: u32) u32 {
    if (v <= 1) return 1;
    return @as(u32, 1) << @intCast(32 - @clz(v - 1));
}

/// How many exponent buckets beyond bucket 0 are needed.
///
/// Bucket 0 covers [0, sub_bucket_count).  Each subsequent bucket k doubles
/// the range, so the first untrackable value after k extra buckets is
/// sub_bucket_count << k.  We count how many doublings are required so that
/// sub_bucket_count << bucket_count > max_value.
fn computeBucketCount(
    max_value: u64,
    sub_bucket_half_count_magnitude: u32,
    sub_bucket_count: u32,
) u32 {
    _ = sub_bucket_half_count_magnitude;
    // Start at sub_bucket_count (upper edge of bucket 0) and double until we
    // exceed max_value.
    var smallest_untrackable: u64 = @as(u64, sub_bucket_count);
    var buckets: u32 = 0;
    while (smallest_untrackable <= max_value) {
        if (smallest_untrackable > std.math.maxInt(u64) / 2) {
            return buckets + 1;
        }
        smallest_untrackable <<= 1;
        buckets += 1;
    }
    return buckets;
}

// ===========================================================================
// Tests
// ===========================================================================

test "basic record and total count" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 3,
        .max_trackable_value = 3_600_000_000,
    });
    defer h.deinit();

    h.recordValue(1);
    h.recordValue(100);
    h.recordValue(1000);
    try std.testing.expectEqual(@as(u64, 3), h.totalCount());
}

test "min and max track correctly" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 2,
        .max_trackable_value = 100_000,
    });
    defer h.deinit();

    h.recordValue(42);
    h.recordValue(7);
    h.recordValue(999);

    try std.testing.expectEqual(@as(u64, 7), h.minValue());
    try std.testing.expectEqual(@as(u64, 999), h.maxValue());
}

test "empty histogram returns safe sentinels" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 2,
        .max_trackable_value = 10_000,
    });
    defer h.deinit();

    try std.testing.expectEqual(@as(u64, 0), h.totalCount());
    try std.testing.expectEqual(@as(u64, 0), h.maxValue());
    try std.testing.expectEqual(@as(f64, 0.0), h.mean());
    try std.testing.expectEqual(@as(u64, 0), h.valueAtPercentile(50.0));
}

test "p50 and p99 on uniform 1..1000 within 1% relative error" {
    const allocator = std.testing.allocator;
    // 2 significant figures => relative error <= 1%.
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 2,
        .max_trackable_value = 3_600_000_000,
    });
    defer h.deinit();

    for (1..1001) |v| h.recordValue(@intCast(v));

    const p50 = h.valueAtPercentile(50.0);
    const p99 = h.valueAtPercentile(99.0);

    // True p50 ≈ 500, true p99 ≈ 990.  Allow 1% relative error.
    const p50_f: f64 = @floatFromInt(p50);
    const p99_f: f64 = @floatFromInt(p99);
    try std.testing.expect(@abs(p50_f - 500.0) / 500.0 <= 0.01);
    try std.testing.expect(@abs(p99_f - 990.0) / 990.0 <= 0.01);
}

test "p100 equals or exceeds recorded maximum" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 3,
        .max_trackable_value = 1_000_000,
    });
    defer h.deinit();

    for (1..101) |v| h.recordValue(@intCast(v));

    const p100 = h.valueAtPercentile(100.0);
    try std.testing.expect(p100 >= h.maxValue());
}

test "out-of-range values are clamped, not dropped" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 2,
        .max_trackable_value = 1000,
    });
    defer h.deinit();

    h.recordValue(0); // below minimum — clamped to 1
    h.recordValue(999_999_999); // above maximum — clamped to highest bucket
    try std.testing.expectEqual(@as(u64, 2), h.totalCount());
}

test "recordValueWithCount accumulates correctly" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 2,
        .max_trackable_value = 10_000,
    });
    defer h.deinit();

    h.recordValueWithCount(500, 100);
    h.recordValueWithCount(1000, 200);

    try std.testing.expectEqual(@as(u64, 300), h.totalCount());
    // p50 should be near 500 (100 counts at 500, 200 counts at 1000 → 33% at 500).
    // Actually p33 ≈ 500 and p100 ≈ 1000.  Check p99 ≈ 1000.
    const p99 = h.valueAtPercentile(99.0);
    const p99_f: f64 = @floatFromInt(p99);
    try std.testing.expect(@abs(p99_f - 1000.0) / 1000.0 <= 0.01);
}

test "mean and stddev on {1, 2, 3}" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 3,
        .max_trackable_value = 10_000,
    });
    defer h.deinit();

    h.recordValue(1);
    h.recordValue(2);
    h.recordValue(3);

    // True mean = 2.0.  Allow ±5% tolerance to account for bucket rounding.
    const m = h.mean();
    try std.testing.expect(@abs(m - 2.0) / 2.0 < 0.05);

    // True stddev ≈ 0.816.  Must be positive and well below the mean.
    const sd = h.stdDev();
    try std.testing.expect(sd > 0.0);
    try std.testing.expect(sd < 2.0);
}

test "merge sums counts and preserves percentiles" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .significant_figures = 2,
        .max_trackable_value = 3_600_000_000,
    };

    var a = try HdrHistogram.init(allocator, cfg);
    defer a.deinit();
    var b = try HdrHistogram.init(allocator, cfg);
    defer b.deinit();

    // a: 1..500, b: 501..1000 → merged uniform 1..1000.
    for (1..501) |v| a.recordValue(@intCast(v));
    for (501..1001) |v| b.recordValue(@intCast(v));

    try a.merge(b);

    try std.testing.expectEqual(@as(u64, 1000), a.totalCount());

    const p50 = a.valueAtPercentile(50.0);
    const p99 = a.valueAtPercentile(99.0);
    const p50_f: f64 = @floatFromInt(p50);
    const p99_f: f64 = @floatFromInt(p99);
    try std.testing.expect(@abs(p50_f - 500.0) / 500.0 <= 0.01);
    try std.testing.expect(@abs(p99_f - 990.0) / 990.0 <= 0.01);
}

test "merge preserves min and max" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .significant_figures = 2,
        .max_trackable_value = 100_000,
    };

    var a = try HdrHistogram.init(allocator, cfg);
    defer a.deinit();
    var b = try HdrHistogram.init(allocator, cfg);
    defer b.deinit();

    a.recordValue(100);
    b.recordValue(50);
    b.recordValue(200);

    try a.merge(b);

    try std.testing.expectEqual(@as(u64, 50), a.minValue());
    try std.testing.expectEqual(@as(u64, 200), a.maxValue());
}

test "reset clears all state" {
    const allocator = std.testing.allocator;
    var h = try HdrHistogram.init(allocator, .{
        .significant_figures = 2,
        .max_trackable_value = 10_000,
    });
    defer h.deinit();

    for (1..101) |v| h.recordValue(@intCast(v));
    h.reset();

    try std.testing.expectEqual(@as(u64, 0), h.totalCount());
    try std.testing.expectEqual(@as(f64, 0.0), h.mean());
    try std.testing.expectEqual(@as(u64, 0), h.valueAtPercentile(50.0));
}

test "deterministic: same inputs produce identical percentile results" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .significant_figures = 2,
        .max_trackable_value = 100_000,
    };

    var h1 = try HdrHistogram.init(allocator, cfg);
    defer h1.deinit();
    var h2 = try HdrHistogram.init(allocator, cfg);
    defer h2.deinit();

    for (1..1001) |v| {
        h1.recordValue(@intCast(v));
        h2.recordValue(@intCast(v));
    }

    try std.testing.expectEqual(h1.valueAtPercentile(25.0), h2.valueAtPercentile(25.0));
    try std.testing.expectEqual(h1.valueAtPercentile(50.0), h2.valueAtPercentile(50.0));
    try std.testing.expectEqual(h1.valueAtPercentile(75.0), h2.valueAtPercentile(75.0));
    try std.testing.expectEqual(h1.valueAtPercentile(99.0), h2.valueAtPercentile(99.0));
    try std.testing.expectEqual(h1.valueAtPercentile(100.0), h2.valueAtPercentile(100.0));
}

test "incompatible histograms return error on merge" {
    const allocator = std.testing.allocator;

    var a = try HdrHistogram.init(allocator, .{
        .significant_figures = 2,
        .max_trackable_value = 1_000,
    });
    defer a.deinit();
    var b = try HdrHistogram.init(allocator, .{
        .significant_figures = 3,
        .max_trackable_value = 1_000_000,
    });
    defer b.deinit();

    try std.testing.expectError(error.IncompatibleHistograms, a.merge(b));
}
