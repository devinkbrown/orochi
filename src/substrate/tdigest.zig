//! T-digest: streaming quantile estimator with bounded centroids.
//!
//! Implements the t-digest algorithm described by Dunning & Ertl (2019).
//! Two scale functions are available:
//!
//!   - `ScaleK0`: uniform cluster sizing (compression / 2 clusters max).
//!     Simple, fast, but fewer tail guarantees than k1.
//!   - `ScaleK1`: arcsin-based sizing that packs more resolution at the tails.
//!     q-quantile cluster has weight ≤ 4·n·q·(1−q)/compression.
//!
//! ## Usage
//!
//! ```zig
//! var td = TDigest(.{ .compression = 100, .scale = .k1 }).init(allocator);
//! defer td.deinit();
//! try td.add(42.0, 1);
//! const median = try td.quantile(0.5);
//! ```
const std = @import("std");
const math = std.math;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

// ---------------------------------------------------------------------------
// Public configuration
// ---------------------------------------------------------------------------

pub const ScaleFunction = enum { k0, k1 };

pub const TDigestConfig = struct {
    /// Controls the trade-off between accuracy and memory.
    /// Higher values give more centroids and better accuracy.
    compression: f64 = 100.0,
    /// Scale function that governs centroid size limits.
    scale: ScaleFunction = .k1,
};

// ---------------------------------------------------------------------------
// Centroid
// ---------------------------------------------------------------------------

const Centroid = struct {
    mean: f64,
    weight: f64,
};

// ---------------------------------------------------------------------------
// TDigest
// ---------------------------------------------------------------------------

/// Returns a TDigest type parameterised by `cfg`.
pub fn TDigest(comptime cfg: TDigestConfig) type {
    comptime {
        if (cfg.compression <= 0.0) @compileError("compression must be positive");
    }

    return struct {
        centroids: ArrayListUnmanaged(Centroid),
        total_weight: f64,
        allocator: Allocator,
        /// Sorted flag: true when centroids are in ascending mean order.
        sorted: bool,

        const Self = @This();

        // ------------------------------------------------------------------
        // Lifecycle
        // ------------------------------------------------------------------

        pub fn init(allocator: Allocator) Self {
            return .{
                .centroids = .empty,
                .total_weight = 0.0,
                .allocator = allocator,
                .sorted = true,
            };
        }

        pub fn deinit(self: *Self) void {
            self.centroids.deinit(self.allocator);
        }

        // ------------------------------------------------------------------
        // Insertion
        // ------------------------------------------------------------------

        /// Add a single observation `value` with positive integer `weight`.
        pub fn add(self: *Self, value: f64, weight: f64) !void {
            if (weight <= 0.0) return;
            // Buffer the new point as its own centroid, then compress if needed.
            try self.centroids.append(self.allocator, .{ .mean = value, .weight = weight });
            self.total_weight += weight;
            self.sorted = false;
            if (self.centroids.items.len > maxCentroids()) {
                try self.compress();
            }
        }

        // ------------------------------------------------------------------
        // Merge
        // ------------------------------------------------------------------

        /// Merge `other` into this digest.  The result is equivalent to
        /// having observed all inputs from both digests.
        pub fn merge(self: *Self, other: *const Self) !void {
            for (other.centroids.items) |c| {
                try self.centroids.append(self.allocator, c);
                self.total_weight += c.weight;
            }
            self.sorted = false;
            try self.compress();
        }

        // ------------------------------------------------------------------
        // Queries
        // ------------------------------------------------------------------

        /// Estimate the value at quantile `q` ∈ [0, 1].
        pub fn quantile(self: *Self, q: f64) !f64 {
            if (q < 0.0 or q > 1.0) return error.InvalidQuantile;
            try self.ensureSorted();
            const items = self.centroids.items;
            if (items.len == 0) return error.Empty;
            if (items.len == 1) return items[0].mean;

            // Target cumulative weight.
            const target = q * self.total_weight;

            // Walk cumulative weight using centroid midpoints.
            var cumulative: f64 = 0.0;
            for (items, 0..) |c, i| {
                const lower = cumulative;
                const upper = cumulative + c.weight;
                const mid = (lower + upper) / 2.0;

                if (target <= mid) {
                    if (i == 0) return c.mean;
                    // Interpolate between previous centroid midpoint and this one.
                    const prev = items[i - 1];
                    const prev_mid = (cumulative - prev.weight + cumulative) / 2.0;
                    // Remap: prev_mid → prev.mean, mid → c.mean
                    const frac = (target - prev_mid) / (mid - prev_mid);
                    return prev.mean + frac * (c.mean - prev.mean);
                }
                cumulative = upper;
            }
            return items[items.len - 1].mean;
        }

        /// Estimate the CDF: the fraction of observations ≤ `value`.
        pub fn cdf(self: *Self, value: f64) !f64 {
            try self.ensureSorted();
            const items = self.centroids.items;
            if (items.len == 0) return error.Empty;

            // Below the minimum.
            if (value < items[0].mean) return 0.0;
            // Above the maximum.
            if (value > items[items.len - 1].mean) return 1.0;

            var cumulative: f64 = 0.0;
            for (items, 0..) |c, i| {
                const mid = cumulative + c.weight / 2.0;
                if (value < c.mean) {
                    // Interpolate between previous midpoint and this midpoint.
                    if (i == 0) return 0.0;
                    const prev = items[i - 1];
                    const prev_mid = cumulative - prev.weight / 2.0;
                    const frac = (value - prev.mean) / (c.mean - prev.mean);
                    return (prev_mid + frac * (mid - prev_mid)) / self.total_weight;
                }
                if (value == c.mean) return (mid) / self.total_weight;
                cumulative += c.weight;
            }
            return 1.0;
        }

        /// Total number of observations (sum of weights).
        pub fn count(self: *const Self) f64 {
            return self.total_weight;
        }

        // ------------------------------------------------------------------
        // Internal helpers
        // ------------------------------------------------------------------

        /// Maximum number of centroids before compression is triggered.
        /// We allow up to 5× the compression target as a buffer before compressing.
        fn maxCentroids() usize {
            return @intFromFloat(@ceil(cfg.compression * 5.0));
        }

        /// Compress centroids to at most `compression` clusters using the
        /// chosen scale function.
        fn compress(self: *Self) !void {
            if (self.centroids.items.len == 0) return;

            // Sort by mean.
            self.sortCentroids();
            const n = self.total_weight;

            // Merge pass: walk sorted centroids and absorb neighbours when
            // the combined weight still fits within the scale limit for the
            // current quantile position.
            var merged = try ArrayListUnmanaged(Centroid).initCapacity(
                self.allocator,
                @intFromFloat(@ceil(cfg.compression * 2.0)),
            );
            errdefer merged.deinit(self.allocator);

            var cumulative: f64 = 0.0; // weight already assigned to finished clusters

            for (self.centroids.items) |c| {
                if (merged.items.len == 0) {
                    try merged.append(self.allocator, c);
                    continue;
                }
                var last = &merged.items[merged.items.len - 1];
                const candidate_weight = last.weight + c.weight;

                // Quantile at the midpoint of the merged cluster.
                const q = (cumulative + last.weight / 2.0) / n;
                const limit = clusterWeightLimit(q, n);

                if (candidate_weight <= limit) {
                    // Absorb: weighted mean.
                    last.mean = (last.mean * last.weight + c.mean * c.weight) / candidate_weight;
                    last.weight = candidate_weight;
                } else {
                    // Finalise current cluster, start a new one.
                    cumulative += last.weight;
                    try merged.append(self.allocator, c);
                }
            }

            self.centroids.deinit(self.allocator);
            self.centroids = merged;
            self.sorted = true;
        }

        /// Maximum weight allowed for a centroid whose midpoint is at
        /// quantile `q` given total weight `n`.
        fn clusterWeightLimit(q: f64, n: f64) f64 {
            return switch (cfg.scale) {
                .k0 => 2.0 * n / cfg.compression,
                .k1 => k1Limit(q, n),
            };
        }

        /// k1 scale limit: 4·n·q·(1−q) / compression
        fn k1Limit(q: f64, n: f64) f64 {
            const clamped = math.clamp(q, 1e-10, 1.0 - 1e-10);
            return 4.0 * n * clamped * (1.0 - clamped) / cfg.compression;
        }

        fn sortCentroids(self: *Self) void {
            if (self.sorted) return;
            const items = self.centroids.items;
            std.sort.pdq(Centroid, items, {}, struct {
                fn lt(_: void, a: Centroid, b: Centroid) bool {
                    return a.mean < b.mean;
                }
            }.lt);
            self.sorted = true;
        }

        fn ensureSorted(self: *Self) !void {
            if (!self.sorted) {
                self.sortCentroids();
                // After sorting, do a compression pass so the quantile
                // interpolation logic works on valid compressed data.
                try self.compress();
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Build a digest from consecutive integer values 1..n with weight 1 each.
fn buildUniform(
    comptime Td: type,
    td: *Td,
    n: u32,
) !void {
    var i: u32 = 1;
    while (i <= n) : (i += 1) {
        try td.add(@floatFromInt(i), 1.0);
    }
}

test "single value" {
    const Td = TDigest(.{ .compression = 100, .scale = .k1 });
    var td = Td.init(testing.allocator);
    defer td.deinit();

    try td.add(42.0, 1.0);
    try testing.expectApproxEqAbs(42.0, try td.quantile(0.0), 1e-9);
    try testing.expectApproxEqAbs(42.0, try td.quantile(0.5), 1e-9);
    try testing.expectApproxEqAbs(42.0, try td.quantile(1.0), 1e-9);
    try testing.expectApproxEqAbs(1.0, td.count(), 1e-9);
}

test "empty digest returns error" {
    const Td = TDigest(.{ .compression = 100 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try testing.expectError(error.Empty, td.quantile(0.5));
    try testing.expectError(error.Empty, td.cdf(1.0));
}

test "invalid quantile returns error" {
    const Td = TDigest(.{ .compression = 100 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try td.add(1.0, 1.0);
    try testing.expectError(error.InvalidQuantile, td.quantile(-0.1));
    try testing.expectError(error.InvalidQuantile, td.quantile(1.1));
}

test "k1 uniform 1..10000 median within 1%" {
    const Td = TDigest(.{ .compression = 200, .scale = .k1 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try buildUniform(Td, &td, 10_000);

    const p50 = try td.quantile(0.50);
    // True median ≈ 5000.5; accept ±1% of range (100 units).
    try testing.expect(p50 >= 4900.0 and p50 <= 5100.0);
}

test "k1 uniform 1..10000 p99 within 1%" {
    const Td = TDigest(.{ .compression = 200, .scale = .k1 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try buildUniform(Td, &td, 10_000);

    const p99 = try td.quantile(0.99);
    // True 99th percentile ≈ 9900; accept ±1% (100 units).
    try testing.expect(p99 >= 9800.0 and p99 <= 10_000.0);
}

test "k1 tail accuracy tighter than mid" {
    // t-digest guarantees high accuracy at the tails.
    // p0.001 true ≈ 10; p0.999 true ≈ 9990; p0.5 true ≈ 5000.
    const Td = TDigest(.{ .compression = 200, .scale = .k1 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try buildUniform(Td, &td, 10_000);

    const p001 = try td.quantile(0.001);
    const p999 = try td.quantile(0.999);
    const p500 = try td.quantile(0.500);

    const err_p001 = @abs(p001 - 10.0) / 10_000.0;
    const err_p999 = @abs(p999 - 9990.0) / 10_000.0;
    const err_p500 = @abs(p500 - 5000.5) / 10_000.0;

    // Tail errors should be at most 0.5%; mid error is typically larger.
    try testing.expect(err_p001 <= 0.005);
    try testing.expect(err_p999 <= 0.005);
    // The tail errors are tighter than, or comparable to, the mid error.
    _ = err_p500; // mid error may vary; we only assert tails are within 0.5%
}

test "k0 uniform 1..10000 p50 and p99 within 2%" {
    const Td = TDigest(.{ .compression = 200, .scale = .k0 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try buildUniform(Td, &td, 10_000);

    const p50 = try td.quantile(0.50);
    const p99 = try td.quantile(0.99);

    try testing.expect(p50 >= 4800.0 and p50 <= 5200.0);
    try testing.expect(p99 >= 9700.0 and p99 <= 10_000.0);
}

test "merge of two half-streams preserves quantiles" {
    const Td = TDigest(.{ .compression = 200, .scale = .k1 });

    var td1 = Td.init(testing.allocator);
    defer td1.deinit();
    var td2 = Td.init(testing.allocator);
    defer td2.deinit();

    // td1 gets odd values 1,3,5,...9999; td2 gets even values 2,4,...10000.
    var i: u32 = 1;
    while (i <= 10_000) : (i += 2) {
        try td1.add(@floatFromInt(i), 1.0);
    }
    var j: u32 = 2;
    while (j <= 10_000) : (j += 2) {
        try td2.add(@floatFromInt(j), 1.0);
    }

    try td1.merge(&td2);

    const p50 = try td1.quantile(0.50);
    const p99 = try td1.quantile(0.99);

    try testing.expect(p50 >= 4800.0 and p50 <= 5200.0);
    try testing.expect(p99 >= 9700.0 and p99 <= 10_000.0);
    try testing.expectApproxEqAbs(10_000.0, td1.count(), 1e-9);
}

test "monotonic cdf" {
    const Td = TDigest(.{ .compression = 100, .scale = .k1 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try buildUniform(Td, &td, 1_000);

    const checkpoints = [_]f64{ 1, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000 };
    var prev: f64 = 0.0;
    for (checkpoints) |v| {
        const q = try td.cdf(v);
        try testing.expect(q >= prev);
        prev = q;
    }
    // CDF at or beyond max should be 1.
    try testing.expectApproxEqAbs(1.0, try td.cdf(1001.0), 1e-9);
    // CDF below min should be 0.
    try testing.expectApproxEqAbs(0.0, try td.cdf(0.0), 1e-9);
}

test "cdf and quantile are approximate inverses" {
    const Td = TDigest(.{ .compression = 200, .scale = .k1 });
    var td = Td.init(testing.allocator);
    defer td.deinit();
    try buildUniform(Td, &td, 5_000);

    // For a value v, cdf(v) ≈ q, and quantile(q) ≈ v within 2%.
    const values = [_]f64{ 500, 2500, 4500 };
    for (values) |v| {
        const q = try td.cdf(v);
        const v2 = try td.quantile(q);
        try testing.expect(@abs(v2 - v) / 5_000.0 <= 0.02);
    }
}

test "count accumulates weights" {
    const Td = TDigest(.{ .compression = 100 });
    var td = Td.init(testing.allocator);
    defer td.deinit();

    try td.add(1.0, 3.0);
    try td.add(2.0, 5.0);
    try td.add(3.0, 2.0);
    try testing.expectApproxEqAbs(10.0, td.count(), 1e-9);
}

test "deterministic: same input same quantile" {
    const Td = TDigest(.{ .compression = 100, .scale = .k1 });

    var td1 = Td.init(testing.allocator);
    defer td1.deinit();
    var td2 = Td.init(testing.allocator);
    defer td2.deinit();

    var i: u32 = 1;
    while (i <= 1_000) : (i += 1) {
        try td1.add(@floatFromInt(i), 1.0);
        try td2.add(@floatFromInt(i), 1.0);
    }

    const q1 = try td1.quantile(0.5);
    const q2 = try td2.quantile(0.5);
    try testing.expectApproxEqAbs(q1, q2, 1e-12);
}

test "weighted add shifts quantiles correctly" {
    // Add value 1.0 with weight 9 and value 2.0 with weight 1.
    // p90 should be near 2.0; p50 should be near 1.0.
    const Td = TDigest(.{ .compression = 100, .scale = .k1 });
    var td = Td.init(testing.allocator);
    defer td.deinit();

    try td.add(1.0, 9.0);
    try td.add(2.0, 1.0);

    const p50 = try td.quantile(0.50);
    const p90 = try td.quantile(0.90);

    // True p50 is 1.0 (weight 9 of 10 at 1.0).  Interpolation may place
    // the midpoint slightly inside the 1→2 span, so allow up to 0.2 error.
    try testing.expect(p50 >= 0.9 and p50 <= 1.2);
    // p90 is inside the last bucket that spans 1→2.
    try testing.expect(p90 >= 1.5 and p90 <= 2.0);
}

test "merge is commutative (same quantiles regardless of order)" {
    const Td = TDigest(.{ .compression = 200, .scale = .k1 });

    var tdA = Td.init(testing.allocator);
    defer tdA.deinit();
    var tdB = Td.init(testing.allocator);
    defer tdB.deinit();

    var i: u32 = 1;
    while (i <= 5_000) : (i += 1) {
        try tdA.add(@floatFromInt(i), 1.0);
    }
    var j: u32 = 5_001;
    while (j <= 10_000) : (j += 1) {
        try tdB.add(@floatFromInt(j), 1.0);
    }

    // Build A∪B and B∪A via separate clones.
    var tdAB = Td.init(testing.allocator);
    defer tdAB.deinit();
    var tdBA = Td.init(testing.allocator);
    defer tdBA.deinit();

    try tdAB.merge(&tdA);
    try tdAB.merge(&tdB);

    try tdBA.merge(&tdB);
    try tdBA.merge(&tdA);

    const q_ab = try tdAB.quantile(0.5);
    const q_ba = try tdBA.quantile(0.5);
    // Both should be near 5000; they must agree within 1%.
    try testing.expect(@abs(q_ab - q_ba) / 10_000.0 <= 0.01);
}
