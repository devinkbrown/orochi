//! Count-Min Sketch frequency estimation.
//!
//! The sketch stores a `depth x width` counter matrix and uses one
//! pairwise-independent hash per row. Standard updates increment each touched
//! counter; conservative updates only raise touched counters to the new
//! estimated count, which reduces positive bias while preserving the Count-Min
//! no-underestimate property.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Count = u64;

const default_seed: u64 = 0x6d697a7563686921;
const mersenne_prime_u64: u64 = 0x1fff_ffff_ffff_ffff; // 2^61 - 1
const mersenne_prime: u128 = mersenne_prime_u64;
const e_value = 2.71828182845904523536;

/// Errors produced by sketch construction and updates.
pub const Error = error{
    CountOverflow,
    IncompatibleSketch,
    InvalidBounds,
    InvalidDimensions,
};

/// Count-Min error bound for a configured sketch.
pub const ErrorBounds = struct {
    /// Additive error factor. With standard sizing this is about `e / width`.
    epsilon: f64,
    /// Probability that the estimate exceeds `true_count + epsilon * total`.
    delta: f64,
    /// Total count inserted into the sketch.
    total: Count,
    /// Additive count error corresponding to `epsilon * total`.
    max_overestimate: f64,
};

/// Recommended dimensions for a requested Count-Min error target.
pub const Dimensions = struct {
    width: usize,
    depth: usize,
};

const HashSeed = struct {
    a: u64,
    b: u64,
};

/// Return dimensions satisfying `epsilon` and `delta` for Count-Min bounds.
///
/// The returned values follow the usual `width = ceil(e / epsilon)` and
/// `depth = ceil(ln(1 / delta))` construction.
pub fn dimensionsFor(epsilon: f64, delta: f64) Error!Dimensions {
    if (!std.math.isFinite(epsilon) or !std.math.isFinite(delta)) return error.InvalidBounds;
    if (epsilon <= 0.0 or delta <= 0.0 or delta >= 1.0) return error.InvalidBounds;

    return .{
        .width = @intFromFloat(@ceil(e_value / epsilon)),
        .depth = @intFromFloat(@ceil(@log(1.0 / delta))),
    };
}

/// Return the Count-Min error bound implied by `width`, `depth`, and `total`.
pub fn errorBounds(width: usize, depth: usize, total: Count) Error!ErrorBounds {
    if (width == 0 or depth == 0) return error.InvalidDimensions;

    const epsilon = e_value / @as(f64, @floatFromInt(width));
    const delta = @exp(-@as(f64, @floatFromInt(depth)));
    const max_overestimate = epsilon * @as(f64, @floatFromInt(total));
    return .{
        .epsilon = epsilon,
        .delta = delta,
        .total = total,
        .max_overestimate = max_overestimate,
    };
}

/// Compact Count-Min Sketch for byte-slice items.
pub const CountMinSketch = struct {
    allocator: Allocator,
    width: usize,
    depth: usize,
    total: Count,
    cells: []Count,
    seeds: []HashSeed,

    /// Initialize a deterministic sketch using a stable module seed.
    pub fn init(allocator: Allocator, width: usize, depth: usize) !CountMinSketch {
        return initSeeded(allocator, width, depth, default_seed);
    }

    /// Initialize a deterministic sketch using caller-provided seed material.
    pub fn initSeeded(allocator: Allocator, width: usize, depth: usize, seed: u64) !CountMinSketch {
        if (width == 0 or depth == 0) return error.InvalidDimensions;
        const cell_count = std.math.mul(usize, width, depth) catch return error.InvalidDimensions;

        const cells = try allocator.alloc(Count, cell_count);
        errdefer allocator.free(cells);
        @memset(cells, 0);

        const seeds = try allocator.alloc(HashSeed, depth);
        errdefer allocator.free(seeds);
        fillSeeds(seeds, seed);

        return .{
            .allocator = allocator,
            .width = width,
            .depth = depth,
            .total = 0,
            .cells = cells,
            .seeds = seeds,
        };
    }

    /// Release sketch storage.
    pub fn deinit(self: *CountMinSketch) void {
        self.allocator.free(self.cells);
        self.allocator.free(self.seeds);
        self.* = undefined;
    }

    /// Insert `count` occurrences of `item` with the standard Count-Min update.
    pub fn add(self: *CountMinSketch, item: []const u8, count: Count) !void {
        if (count == 0) return;
        const new_total = try checkedAdd(self.total, count);

        for (0..self.depth) |row| {
            const idx = self.cellIndex(row, item);
            self.cells[idx] = try checkedAdd(self.cells[idx], count);
        }
        self.total = new_total;
    }

    /// Insert `count` occurrences using conservative update.
    ///
    /// Conservative update computes the current estimate first, then raises only
    /// touched counters below `estimate + count` to that target value.
    pub fn addConservative(self: *CountMinSketch, item: []const u8, count: Count) !void {
        if (count == 0) return;
        const new_total = try checkedAdd(self.total, count);
        const target = try checkedAdd(self.estimate(item), count);

        for (0..self.depth) |row| {
            const idx = self.cellIndex(row, item);
            if (self.cells[idx] < target) self.cells[idx] = target;
        }
        self.total = new_total;
    }

    /// Return the Count-Min estimate for `item`, the minimum touched counter.
    pub fn estimate(self: *const CountMinSketch, item: []const u8) Count {
        var best: Count = std.math.maxInt(Count);
        for (0..self.depth) |row| {
            const value = self.cells[self.cellIndex(row, item)];
            if (value < best) best = value;
        }
        return best;
    }

    /// Merge another sketch into this one.
    ///
    /// Sketches must have identical dimensions and row hash seeds.
    pub fn merge(self: *CountMinSketch, other: *const CountMinSketch) !void {
        if (!self.compatibleWith(other)) return error.IncompatibleSketch;
        _ = try checkedAdd(self.total, other.total);
        for (self.cells, other.cells) |a, b| {
            _ = try checkedAdd(a, b);
        }

        for (self.cells, other.cells) |*a, b| {
            a.* += b;
        }
        self.total += other.total;
    }

    /// Return error bounds for the current sketch and inserted total.
    pub fn bounds(self: *const CountMinSketch) Error!ErrorBounds {
        return errorBounds(self.width, self.depth, self.total);
    }

    /// Return true when dimensions and row hash seeds match.
    pub fn compatibleWith(self: *const CountMinSketch, other: *const CountMinSketch) bool {
        if (self.width != other.width or self.depth != other.depth) return false;
        for (self.seeds, other.seeds) |a, b| {
            if (a.a != b.a or a.b != b.b) return false;
        }
        return true;
    }

    fn cellIndex(self: *const CountMinSketch, row: usize, item: []const u8) usize {
        return row * self.width + rowOffset(self.seeds[row], item, self.width);
    }
};

/// Heavy-hitter tracker paired with a conservatively updated Count-Min Sketch.
///
/// Items are copied into an owned candidate set once their estimated count
/// reaches the configured absolute threshold. Returned entries borrow those
/// owned keys; they remain valid until `deinit` or further candidate mutation.
pub const HeavyHitters = struct {
    pub const Entry = struct {
        item: []const u8,
        estimate: Count,
    };

    allocator: Allocator,
    sketch: CountMinSketch,
    threshold: Count,
    candidates: std.StringHashMap(void),

    /// Initialize a heavy-hitter tracker with deterministic sketch hashes.
    pub fn init(allocator: Allocator, width: usize, depth: usize, threshold: Count) !HeavyHitters {
        return initSeeded(allocator, width, depth, default_seed, threshold);
    }

    /// Initialize a heavy-hitter tracker with caller-provided seed material.
    pub fn initSeeded(
        allocator: Allocator,
        width: usize,
        depth: usize,
        seed: u64,
        threshold: Count,
    ) !HeavyHitters {
        var sketch = try CountMinSketch.initSeeded(allocator, width, depth, seed);
        errdefer sketch.deinit();
        return .{
            .allocator = allocator,
            .sketch = sketch,
            .threshold = threshold,
            .candidates = std.StringHashMap(void).init(allocator),
        };
    }

    /// Release candidate key copies and sketch storage.
    pub fn deinit(self: *HeavyHitters) void {
        var it = self.candidates.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.candidates.deinit();
        self.sketch.deinit();
        self.* = undefined;
    }

    /// Add occurrences using conservative update and track threshold crossings.
    pub fn add(self: *HeavyHitters, item: []const u8, count: Count) !void {
        try self.sketch.addConservative(item, count);
        if (self.sketch.estimate(item) < self.threshold) return;
        if (self.candidates.contains(item)) return;

        const owned = try self.allocator.dupe(u8, item);
        errdefer self.allocator.free(owned);
        try self.candidates.put(owned, {});
    }

    /// Estimate `item` using the paired sketch.
    pub fn estimate(self: *const HeavyHitters, item: []const u8) Count {
        return self.sketch.estimate(item);
    }

    /// Return tracked candidates whose current estimate is at least threshold.
    pub fn heavyHitters(self: *const HeavyHitters, allocator: Allocator) ![]Entry {
        var entries: std.ArrayList(Entry) = .empty;
        errdefer entries.deinit(allocator);

        var it = self.candidates.iterator();
        while (it.next()) |candidate| {
            const item = candidate.key_ptr.*;
            const estimate_value = self.sketch.estimate(item);
            if (estimate_value >= self.threshold) {
                try entries.append(allocator, .{
                    .item = item,
                    .estimate = estimate_value,
                });
            }
        }

        sortEntries(entries.items);
        return entries.toOwnedSlice(allocator);
    }
};

fn checkedAdd(a: Count, b: Count) Error!Count {
    if (b > std.math.maxInt(Count) - a) return error.CountOverflow;
    return a + b;
}

fn fillSeeds(seeds: []HashSeed, seed: u64) void {
    var state = seed ^ 0x9e37_79b9_7f4a_7c15;
    for (seeds) |*row_seed| {
        const a = splitMix64(&state) % (mersenne_prime_u64 - 1) + 1;
        const b = splitMix64(&state) % mersenne_prime_u64;
        row_seed.* = .{ .a = a, .b = b };
    }
}

fn splitMix64(state: *u64) u64 {
    state.* +%= 0x9e37_79b9_7f4a_7c15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

fn rowOffset(seed: HashSeed, item: []const u8, width: usize) usize {
    const item_hash = std.hash.Wyhash.hash(0, item) % mersenne_prime_u64;
    const mixed = (@as(u128, seed.a) * @as(u128, item_hash) + @as(u128, seed.b)) % mersenne_prime;
    return @intCast(mixed % @as(u128, width));
}

fn sortEntries(items: []HeavyHitters.Entry) void {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        const value = items[i];
        var j = i;
        while (j > 0 and entryBefore(value, items[j - 1])) : (j -= 1) {
            items[j] = items[j - 1];
        }
        items[j] = value;
    }
}

fn entryBefore(a: HeavyHitters.Entry, b: HeavyHitters.Entry) bool {
    if (a.estimate != b.estimate) return a.estimate > b.estimate;
    return std.mem.lessThan(u8, a.item, b.item);
}

fn writeU64Big(out: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, out, value, .big);
}

test "init rejects invalid dimensions" {
    try std.testing.expectError(error.InvalidDimensions, CountMinSketch.init(std.testing.allocator, 0, 3));
    try std.testing.expectError(error.InvalidDimensions, CountMinSketch.init(std.testing.allocator, 8, 0));
}

test "deterministic seeded sketches produce identical counters" {
    var a = try CountMinSketch.initSeeded(std.testing.allocator, 32, 4, 12345);
    defer a.deinit();
    var b = try CountMinSketch.initSeeded(std.testing.allocator, 32, 4, 12345);
    defer b.deinit();

    try a.add("alpha", 3);
    try a.add("beta", 7);
    try a.addConservative("alpha", 2);

    try b.add("alpha", 3);
    try b.add("beta", 7);
    try b.addConservative("alpha", 2);

    try std.testing.expectEqual(@as(Count, 5), a.estimate("alpha"));
    try std.testing.expectEqual(@as(Count, 7), a.estimate("beta"));
    try std.testing.expectEqual(@as(Count, 0), a.estimate("missing"));
    try std.testing.expectEqualSlices(Count, a.cells, b.cells);
}

test "estimates never undercount true frequencies" {
    var sketch = try CountMinSketch.initSeeded(std.testing.allocator, 64, 5, 0xabc);
    defer sketch.deinit();

    var true_counts = [_]Count{0} ** 80;
    for (&true_counts, 0..) |*count, i| {
        var key: [8]u8 = undefined;
        writeU64Big(&key, @intCast(i));
        const amount: Count = @intCast(i % 11 + 1);
        count.* += amount;
        try sketch.add(&key, amount);
    }

    for (true_counts, 0..) |actual, i| {
        var key: [8]u8 = undefined;
        writeU64Big(&key, @intCast(i));
        try std.testing.expect(sketch.estimate(&key) >= actual);
    }
}

test "overestimate stays within epsilon total on deterministic sample" {
    var sketch = try CountMinSketch.initSeeded(std.testing.allocator, 256, 6, 0x5555);
    defer sketch.deinit();

    var true_counts = [_]Count{0} ** 120;
    for (&true_counts, 0..) |*actual, i| {
        var key: [8]u8 = undefined;
        writeU64Big(&key, @intCast(i));
        const amount: Count = @intCast(i % 17 + 1);
        actual.* += amount;
        try sketch.add(&key, amount);
    }

    const bounds = try sketch.bounds();
    for (true_counts, 0..) |actual, i| {
        var key: [8]u8 = undefined;
        writeU64Big(&key, @intCast(i));
        const estimate_value = sketch.estimate(&key);
        try std.testing.expect(estimate_value >= actual);
        const over = @as(f64, @floatFromInt(estimate_value - actual));
        try std.testing.expect(over <= @ceil(bounds.max_overestimate));
    }
}

test "conservative update reduces aggregate overestimate" {
    var standard = try CountMinSketch.initSeeded(std.testing.allocator, 12, 4, 0x7777);
    defer standard.deinit();
    var conservative = try CountMinSketch.initSeeded(std.testing.allocator, 12, 4, 0x7777);
    defer conservative.deinit();

    var true_counts = [_]Count{0} ** 64;
    for (0..400) |n| {
        const item_index = (n * 17 + n / 3) % true_counts.len;
        const amount: Count = if (item_index < 4) 5 else 1;
        var key: [8]u8 = undefined;
        writeU64Big(&key, @intCast(item_index));
        true_counts[item_index] += amount;
        try standard.add(&key, amount);
        try conservative.addConservative(&key, amount);
    }

    var standard_error: Count = 0;
    var conservative_error: Count = 0;
    for (true_counts, 0..) |actual, i| {
        var key: [8]u8 = undefined;
        writeU64Big(&key, @intCast(i));
        standard_error += standard.estimate(&key) - actual;
        conservative_error += conservative.estimate(&key) - actual;
    }

    try std.testing.expect(conservative_error < standard_error);
}

test "merge sums sketches with matching dimensions and seeds" {
    var left = try CountMinSketch.initSeeded(std.testing.allocator, 48, 5, 0x9999);
    defer left.deinit();
    var right = try CountMinSketch.initSeeded(std.testing.allocator, 48, 5, 0x9999);
    defer right.deinit();
    var combined = try CountMinSketch.initSeeded(std.testing.allocator, 48, 5, 0x9999);
    defer combined.deinit();

    try left.add("alpha", 4);
    try left.add("beta", 9);
    try right.add("alpha", 6);
    try right.add("gamma", 3);

    try combined.add("alpha", 10);
    try combined.add("beta", 9);
    try combined.add("gamma", 3);

    try left.merge(&right);
    try std.testing.expectEqual(@as(Count, 22), left.total);
    try std.testing.expectEqualSlices(Count, combined.cells, left.cells);
    try std.testing.expectEqual(@as(Count, 10), left.estimate("alpha"));

    var incompatible = try CountMinSketch.initSeeded(std.testing.allocator, 48, 5, 0xaaaa);
    defer incompatible.deinit();
    try std.testing.expectError(error.IncompatibleSketch, left.merge(&incompatible));
}

test "heavy hitters tracks threshold crossings with conservative update" {
    var tracker = try HeavyHitters.initSeeded(std.testing.allocator, 64, 5, 0x1234, 10);
    defer tracker.deinit();

    try tracker.add("apple", 4);
    try tracker.add("banana", 7);
    try tracker.add("apple", 6);
    try tracker.add("cherry", 11);
    try tracker.add("date", 1);

    const hitters = try tracker.heavyHitters(std.testing.allocator);
    defer std.testing.allocator.free(hitters);

    try std.testing.expectEqual(@as(usize, 2), hitters.len);
    try std.testing.expectEqualStrings("cherry", hitters[0].item);
    try std.testing.expectEqual(@as(Count, 11), hitters[0].estimate);
    try std.testing.expectEqualStrings("apple", hitters[1].item);
    try std.testing.expectEqual(@as(Count, 10), hitters[1].estimate);
    try std.testing.expect(tracker.estimate("banana") < 10);
}

test "error bounds and recommended dimensions are coherent" {
    const dims = try dimensionsFor(0.01, 0.001);
    try std.testing.expect(dims.width >= 272);
    try std.testing.expect(dims.depth >= 7);

    const bounds = try errorBounds(dims.width, dims.depth, 1000);
    try std.testing.expect(bounds.epsilon <= 0.01);
    try std.testing.expect(bounds.delta <= 0.001);
    try std.testing.expect(bounds.max_overestimate <= 10.0);
}
