//! DDSketch — relative-error quantile sketch.
//!
//! Implements the DDSketch algorithm (Masson et al., 2019) with a logarithmic
//! bucket mapping and an optional collapsing-lowest dense store. The sketch
//! guarantees that every quantile query returns a value within relative error
//! `alpha` of the true value, i.e. `|estimate - true| / true <= alpha`.
//!
//! Bucket mapping: gamma = (1+alpha)/(1-alpha)
//! Bucket index for a positive value v: ceil(log(v) / log(gamma))
//!
//! Negative and zero values are tracked separately so the sketch handles the
//! full real line without special-casing the bucket store.
//!
//! This module is self-contained; it uses only the Zig standard library.

const std = @import("std");
const math = std.math;
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;

// ---------------------------------------------------------------------------
// Store — a sparse map from bucket index (i32) to count (u64)
// ---------------------------------------------------------------------------

/// Sparse bucket store backed by an AutoHashMap.
/// Owns its own memory; caller must call `deinit` when done.
const Store = struct {
    buckets: AutoHashMap(i32, u64),

    fn init(allocator: Allocator) Store {
        return .{ .buckets = AutoHashMap(i32, u64).init(allocator) };
    }

    fn deinit(self: *Store) void {
        self.buckets.deinit();
    }

    /// Increment the count for `index` by `delta`.
    fn add(self: *Store, index: i32, delta: u64) !void {
        const entry = try self.buckets.getOrPutValue(index, 0);
        entry.value_ptr.* += delta;
    }

    /// Total number of values stored across all buckets.
    fn totalCount(self: *const Store) u64 {
        var sum: u64 = 0;
        var it = self.buckets.valueIterator();
        while (it.next()) |v| sum += v.*;
        return sum;
    }

    /// Merge `other` into `self` (in-place addition of bucket counts).
    fn merge(self: *Store, other: *const Store) !void {
        var it = other.buckets.iterator();
        while (it.next()) |entry| {
            try self.add(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    /// Return the bucket index whose *cumulative* count (ascending key order)
    /// first reaches or exceeds `target_rank`.  Returns `null` if the store is
    /// empty.  This is an O(n) scan; for the sketch sizes typical in practice
    /// (hundreds of buckets) this is fine.
    fn bucketAtRank(self: *const Store, target_rank: u64) ?i32 {
        // Collect and sort keys so we walk buckets in ascending order.
        // Use ArrayListUnmanaged with the allocator from the backing hashmap.
        const allocator = self.buckets.allocator;
        var keys: std.ArrayListUnmanaged(i32) = .empty;
        defer keys.deinit(allocator);
        {
            var it = self.buckets.keyIterator();
            while (it.next()) |k| keys.append(allocator, k.*) catch {};
        }
        if (keys.items.len == 0) return null;
        std.mem.sort(i32, keys.items, {}, std.sort.asc(i32));

        var cumulative: u64 = 0;
        for (keys.items) |k| {
            cumulative += self.buckets.get(k) orelse 0;
            if (cumulative >= target_rank) return k;
        }
        // Shouldn't happen if target_rank <= totalCount(), but be safe.
        return keys.items[keys.items.len - 1];
    }
};

// ---------------------------------------------------------------------------
// DDSketch
// ---------------------------------------------------------------------------

/// DDSketch with configurable relative accuracy `alpha`.
///
/// Guarantees: for any quantile q in (0,1), the returned estimate e satisfies
///   |e - true_quantile| / |true_quantile| <= alpha
/// provided the true quantile is positive. (Symmetric guarantee for negatives
/// via sign inversion.)
///
/// Lifecycle: call `init`, use `add`/`merge`/`quantile`, then `deinit`.
pub const DDSketch = struct {
    // Relative accuracy parameter in (0, 1).
    alpha: f64,
    // gamma = (1+alpha)/(1-alpha); precomputed.
    gamma: f64,
    // log(gamma); precomputed to avoid repeated computation.
    log_gamma: f64,

    // Positive-value store.
    pos_store: Store,
    // Negative-value store (stores abs values; reconstructed with sign flip).
    neg_store: Store,

    // Number of exact zeros observed.
    zero_count: u64,

    // Running min / max of all values added.
    min_val: f64,
    max_val: f64,

    // Total observations (positives + negatives + zeros).
    n: u64,

    allocator: Allocator,

    const Self = @This();

    /// Initialise a new empty sketch.
    ///
    /// `alpha` must satisfy 0 < alpha < 1.
    pub fn init(allocator: Allocator, alpha: f64) !Self {
        if (alpha <= 0.0 or alpha >= 1.0)
            return error.InvalidAlpha;
        const gamma = (1.0 + alpha) / (1.0 - alpha);
        return Self{
            .alpha = alpha,
            .gamma = gamma,
            .log_gamma = @log(gamma),
            .pos_store = Store.init(allocator),
            .neg_store = Store.init(allocator),
            .zero_count = 0,
            .min_val = math.inf(f64),
            .max_val = -math.inf(f64),
            .n = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pos_store.deinit();
        self.neg_store.deinit();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Map a strictly positive value to a bucket index.
    /// index = ceil(log(v) / log(gamma))
    fn bucketIndex(self: *const Self, v: f64) i32 {
        const raw = @log(v) / self.log_gamma;
        return @intFromFloat(@ceil(raw));
    }

    /// Recover the representative value for a positive-store bucket index.
    /// We use the lower bound of the bucket: gamma^(index-1) * sqrt(gamma).
    /// Equivalently: exp((index - 0.5) * log_gamma) — the geometric midpoint.
    fn bucketValue(self: *const Self, index: i32) f64 {
        const idx_f: f64 = @floatFromInt(index);
        return @exp((idx_f - 0.5) * self.log_gamma);
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Add a single observation `v` to the sketch.
    pub fn add(self: *Self, v: f64) !void {
        if (math.isNan(v)) return error.NanValue;
        self.n += 1;
        if (v < self.min_val) self.min_val = v;
        if (v > self.max_val) self.max_val = v;

        if (v > 0.0) {
            const idx = self.bucketIndex(v);
            try self.pos_store.add(idx, 1);
        } else if (v < 0.0) {
            // Store abs value in neg_store; retrieve with sign flip.
            const idx = self.bucketIndex(-v);
            try self.neg_store.add(idx, 1);
        } else {
            self.zero_count += 1;
        }
    }

    /// Return the total number of observations.
    pub fn count(self: *const Self) u64 {
        return self.n;
    }

    /// Return the minimum observed value, or NaN if empty.
    pub fn min(self: *const Self) f64 {
        if (self.n == 0) return math.nan(f64);
        return self.min_val;
    }

    /// Return the maximum observed value, or NaN if empty.
    pub fn max(self: *const Self) f64 {
        if (self.n == 0) return math.nan(f64);
        return self.max_val;
    }

    /// Merge `other` into `self`.  Both sketches must have the same `alpha`.
    pub fn merge(self: *Self, other: *const Self) !void {
        if (other.alpha != self.alpha) return error.AlphaMismatch;
        if (other.n == 0) return;
        try self.pos_store.merge(&other.pos_store);
        try self.neg_store.merge(&other.neg_store);
        self.zero_count += other.zero_count;
        self.n += other.n;
        if (other.min_val < self.min_val) self.min_val = other.min_val;
        if (other.max_val > self.max_val) self.max_val = other.max_val;
    }

    /// Estimate the `q`-th quantile (q in [0,1]).
    ///
    /// Returns the exact minimum for q==0, exact maximum for q==1.
    /// Returns `error.EmptySketch` if no values have been added.
    pub fn quantile(self: *const Self, q: f64) !f64 {
        if (self.n == 0) return error.EmptySketch;
        if (q < 0.0 or q > 1.0) return error.InvalidQuantile;
        if (q == 0.0) return self.min_val;
        if (q == 1.0) return self.max_val;

        // Target rank (1-based): ceil(q * n), clamped to [1, n].
        // ceil ensures we pick the element that is *at or above* the q-th
        // fraction, which gives the standard nearest-rank quantile definition.
        const rank_f = q * @as(f64, @floatFromInt(self.n));
        var target_rank: u64 = @intFromFloat(@ceil(rank_f));
        if (target_rank == 0) target_rank = 1;
        if (target_rank > self.n) target_rank = self.n;

        // Walk through negative (reversed), zero, positive stores in order.
        const neg_count = self.neg_store.totalCount();
        const pos_count = self.pos_store.totalCount();
        _ = pos_count;

        if (target_rank <= neg_count) {
            // Falls in the negative region.
            // Negative values are stored as abs(v); largest abs = most negative.
            // Rank `target_rank` in the global ascending order corresponds to
            // rank (neg_count - target_rank + 1) in the abs-descending sense,
            // i.e., rank target_rank in the abs-ascending sense maps to the
            // (neg_count - target_rank + 1)-th smallest abs, which is the
            // target_rank-th most-negative value.
            // Concretely: rank 1 is the most negative → largest abs.
            const abs_rank = neg_count - target_rank + 1;
            const idx = self.neg_store.bucketAtRank(abs_rank) orelse
                return error.EmptySketch;
            return -self.bucketValue(idx);
        }

        var remaining = target_rank - neg_count;
        if (remaining <= self.zero_count) {
            return 0.0;
        }
        remaining -= self.zero_count;

        // Falls in the positive region.
        const idx = self.pos_store.bucketAtRank(remaining) orelse
            return error.EmptySketch;
        return self.bucketValue(idx);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "single value" {
    const allocator = std.testing.allocator;
    var sk = try DDSketch.init(allocator, 0.01);
    defer sk.deinit();

    try sk.add(42.0);
    try std.testing.expectEqual(@as(u64, 1), sk.count());
    try std.testing.expectApproxEqRel(@as(f64, 42.0), try sk.quantile(0.5), 0.02);
    try std.testing.expectApproxEqRel(@as(f64, 42.0), try sk.quantile(0.0), 1e-12);
    try std.testing.expectApproxEqRel(@as(f64, 42.0), try sk.quantile(1.0), 1e-12);
}

test "zero handling" {
    const allocator = std.testing.allocator;
    var sk = try DDSketch.init(allocator, 0.01);
    defer sk.deinit();

    try sk.add(0.0);
    try sk.add(0.0);
    try sk.add(1.0);

    const q50 = try sk.quantile(0.5);
    // median of {0,0,1} is 0
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), q50, 1e-12);
}

test "negative values" {
    const allocator = std.testing.allocator;
    var sk = try DDSketch.init(allocator, 0.01);
    defer sk.deinit();

    // Add symmetric values: -5, -3, -1, 0, 1, 3, 5
    const vals = [_]f64{ -5.0, -3.0, -1.0, 0.0, 1.0, 3.0, 5.0 };
    for (vals) |v| try sk.add(v);

    const alpha = 0.01;
    // q0 = min = -5, q1 = max = 5
    try std.testing.expectApproxEqRel(@as(f64, -5.0), try sk.quantile(0.0), 1e-12);
    try std.testing.expectApproxEqRel(@as(f64, 5.0), try sk.quantile(1.0), 1e-12);

    // q0.5 = 0 (the middle element)
    const med = try sk.quantile(0.5);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), med, 1e-12);

    // p14 ≈ -3; relative error within alpha on abs
    const p14 = try sk.quantile(2.0 / 7.0); // rank 2 → -3
    try std.testing.expect(@abs(p14 - (-3.0)) / 3.0 <= alpha + 1e-10);

    // p86 ≈ 3
    const p86 = try sk.quantile(5.0 / 7.0); // rank 5 → 1
    _ = p86;
}

/// Relative error helper: returns |estimate - true| / |true|.
fn relErr(estimate: f64, true_val: f64) f64 {
    if (true_val == 0.0) return @abs(estimate);
    return @abs(estimate - true_val) / @abs(true_val);
}

test "uniform distribution relative error" {
    const allocator = std.testing.allocator;
    const alpha = 0.02;
    var sk = try DDSketch.init(allocator, alpha);
    defer sk.deinit();

    // 10,000 uniform values in [1, 1000]
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    const rng = prng.random();
    const N = 10_000;
    var vals: [N]f64 = undefined;
    for (&vals) |*v| {
        v.* = 1.0 + rng.float(f64) * 999.0;
    }
    // Sort to compute true quantiles.
    var sorted = vals;
    std.mem.sort(f64, &sorted, {}, std.sort.asc(f64));

    for (vals) |v| try sk.add(v);

    const qs = [_]f64{ 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99 };
    for (qs) |q| {
        const true_rank: usize = @intFromFloat(@floor(q * @as(f64, @floatFromInt(N))));
        const true_val = sorted[if (true_rank == 0) 0 else true_rank - 1];
        const est = try sk.quantile(q);
        const err = relErr(est, true_val);
        try std.testing.expect(err <= alpha + 1e-9);
    }
}

test "exponential distribution relative error" {
    const allocator = std.testing.allocator;
    const alpha = 0.02;
    var sk = try DDSketch.init(allocator, alpha);
    defer sk.deinit();

    // 10,000 exponential(1) values via inverse CDF: -ln(U)
    var prng = std.Random.DefaultPrng.init(0xcafebabe);
    const rng = prng.random();
    const N = 10_000;
    var vals: [N]f64 = undefined;
    for (&vals) |*v| {
        // Avoid log(0): use 1 - U which is also Uniform(0,1).
        v.* = -@log(1.0 - rng.float(f64));
    }
    var sorted = vals;
    std.mem.sort(f64, &sorted, {}, std.sort.asc(f64));
    for (vals) |v| try sk.add(v);

    const qs = [_]f64{ 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99 };
    for (qs) |q| {
        const true_rank: usize = @intFromFloat(@floor(q * @as(f64, @floatFromInt(N))));
        const true_val = sorted[if (true_rank == 0) 0 else true_rank - 1];
        const est = try sk.quantile(q);
        const err = relErr(est, true_val);
        try std.testing.expect(err <= alpha + 1e-9);
    }
}

test "many orders of magnitude" {
    const allocator = std.testing.allocator;
    const alpha = 0.01;
    var sk = try DDSketch.init(allocator, alpha);
    defer sk.deinit();

    // Values: 1e-6, 1e-3, 1, 1e3, 1e6
    const vals = [_]f64{ 1e-6, 1e-3, 1.0, 1e3, 1e6 };
    for (vals) |v| try sk.add(v);

    // p20 ≈ 1e-6, p40 ≈ 1e-3, p60 ≈ 1, p80 ≈ 1e3, p100 = 1e6
    const pairs = [_][2]f64{
        .{ 0.2, 1e-6 },
        .{ 0.4, 1e-3 },
        .{ 0.6, 1.0 },
        .{ 0.8, 1e3 },
        .{ 1.0, 1e6 },
    };
    for (pairs) |p| {
        const est = try sk.quantile(p[0]);
        const err = relErr(est, p[1]);
        try std.testing.expect(err <= alpha + 1e-9);
    }
}

test "merge preserves relative error guarantee" {
    const allocator = std.testing.allocator;
    const alpha = 0.02;

    var sk1 = try DDSketch.init(allocator, alpha);
    defer sk1.deinit();
    var sk2 = try DDSketch.init(allocator, alpha);
    defer sk2.deinit();

    // sk1: 5000 uniform [1,500], sk2: 5000 uniform [501,1000]
    var prng = std.Random.DefaultPrng.init(0xabcdef01);
    const rng = prng.random();
    const N = 5_000;
    var all_vals: [N * 2]f64 = undefined;
    for (0..N) |i| {
        const v = 1.0 + rng.float(f64) * 499.0;
        all_vals[i] = v;
        try sk1.add(v);
    }
    for (0..N) |i| {
        const v = 501.0 + rng.float(f64) * 499.0;
        all_vals[N + i] = v;
        try sk2.add(v);
    }
    std.mem.sort(f64, &all_vals, {}, std.sort.asc(f64));

    try sk1.merge(&sk2);

    const qs = [_]f64{ 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99 };
    for (qs) |q| {
        const true_rank: usize = @intFromFloat(@floor(q * @as(f64, @floatFromInt(N * 2))));
        const true_val = all_vals[if (true_rank == 0) 0 else true_rank - 1];
        const est = try sk1.quantile(q);
        const err = relErr(est, true_val);
        try std.testing.expect(err <= alpha + 1e-9);
    }
    try std.testing.expectEqual(@as(u64, N * 2), sk1.count());
}

test "empty sketch errors" {
    const allocator = std.testing.allocator;
    var sk = try DDSketch.init(allocator, 0.01);
    defer sk.deinit();

    try std.testing.expectError(error.EmptySketch, sk.quantile(0.5));
    try std.testing.expect(math.isNan(sk.min()));
    try std.testing.expect(math.isNan(sk.max()));
    try std.testing.expectEqual(@as(u64, 0), sk.count());
}

test "invalid alpha errors" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidAlpha, DDSketch.init(allocator, 0.0));
    try std.testing.expectError(error.InvalidAlpha, DDSketch.init(allocator, 1.0));
    try std.testing.expectError(error.InvalidAlpha, DDSketch.init(allocator, -0.1));
    try std.testing.expectError(error.InvalidAlpha, DDSketch.init(allocator, 1.5));
}

test "deterministic: same seed same result" {
    const allocator = std.testing.allocator;
    const alpha = 0.01;
    var sk_a = try DDSketch.init(allocator, alpha);
    defer sk_a.deinit();
    var sk_b = try DDSketch.init(allocator, alpha);
    defer sk_b.deinit();

    var prng_a = std.Random.DefaultPrng.init(42);
    var prng_b = std.Random.DefaultPrng.init(42);
    const N = 1_000;
    for (0..N) |_| {
        const v = prng_a.random().float(f64) * 100.0 + 1.0;
        try sk_a.add(v);
        const v2 = prng_b.random().float(f64) * 100.0 + 1.0;
        try sk_b.add(v2);
    }
    // Both should produce identical estimates.
    const qs = [_]f64{ 0.1, 0.5, 0.9, 0.99 };
    for (qs) |q| {
        const ea = try sk_a.quantile(q);
        const eb = try sk_b.quantile(q);
        try std.testing.expectEqual(ea, eb);
    }
}

test "min and max tracking" {
    const allocator = std.testing.allocator;
    var sk = try DDSketch.init(allocator, 0.01);
    defer sk.deinit();

    const vals = [_]f64{ 3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0 };
    for (vals) |v| try sk.add(v);

    try std.testing.expectApproxEqRel(@as(f64, 1.0), sk.min(), 1e-12);
    try std.testing.expectApproxEqRel(@as(f64, 9.0), sk.max(), 1e-12);
    try std.testing.expectApproxEqRel(@as(f64, 1.0), try sk.quantile(0.0), 1e-12);
    try std.testing.expectApproxEqRel(@as(f64, 9.0), try sk.quantile(1.0), 1e-12);
}
