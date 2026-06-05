//! Fenwick tree / Binary Indexed Tree over i64 values.
//!
//! Public indexes are zero-based. `prefixSum(index)` and `rangeSum(left, right)`
//! are inclusive. `findByPrefix(target)` returns the first zero-based index
//! whose cumulative prefix sum is at least `target`; as with the standard
//! Fenwick order-statistics search, stored point values must be nonnegative for
//! that lower-bound query to be meaningful.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    InvalidIndex,
    InvalidRange,
};

pub const Fenwick = struct {
    const Self = @This();

    allocator: Allocator,
    /// 1-based internal tree. `tree.len - 1` is the public element count.
    tree: []i64,

    /// Allocate a Fenwick tree with `len` zero-initialized elements.
    pub fn init(allocator: Allocator, len_: usize) !Self {
        const tree = try allocator.alloc(i64, len_ + 1);
        @memset(tree, 0);
        return .{ .allocator = allocator, .tree = tree };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.tree);
        self.tree = &.{};
    }

    /// Number of addressable point values.
    pub fn len(self: *const Self) usize {
        return self.tree.len - 1;
    }

    /// Add `delta` to the point at zero-based `index`.
    pub fn pointUpdate(self: *Self, index: usize, delta: i64) Error!void {
        if (index >= self.len()) return error.InvalidIndex;

        var i = index + 1;
        while (i < self.tree.len) : (i += lowbit(i)) {
            self.tree[i] += delta;
        }
    }

    /// Inclusive prefix sum from index 0 through `index`.
    pub fn prefixSum(self: *const Self, index: usize) Error!i64 {
        if (index >= self.len()) return error.InvalidIndex;

        var sum: i64 = 0;
        var i = index + 1;
        while (i != 0) : (i -= lowbit(i)) {
            sum += self.tree[i];
        }
        return sum;
    }

    /// Inclusive range sum from `left` through `right`.
    pub fn rangeSum(self: *const Self, left: usize, right: usize) Error!i64 {
        if (left > right) return error.InvalidRange;
        if (right >= self.len()) return error.InvalidIndex;

        const right_sum = try self.prefixSum(right);
        if (left == 0) return right_sum;
        return right_sum - try self.prefixSum(left - 1);
    }

    /// Sum of all point values.
    pub fn totalSum(self: *const Self) i64 {
        if (self.len() == 0) return 0;
        return self.prefixSum(self.len() - 1) catch unreachable;
    }

    /// Return the first index whose prefix sum is >= `target`, or null if no
    /// such index exists. For order-statistics use, all point values must be
    /// nonnegative so prefix sums are monotonic.
    pub fn findByPrefix(self: *const Self, target: i64) ?usize {
        const n = self.len();
        if (n == 0) return null;
        if (target <= 0) return 0;
        if (self.totalSum() < target) return null;

        var idx: usize = 0;
        var bit = highestPowerOfTwo(n);
        var remaining = target;

        while (bit != 0) : (bit >>= 1) {
            const next = idx + bit;
            if (next <= n and self.tree[next] < remaining) {
                idx = next;
                remaining -= self.tree[next];
            }
        }

        if (idx >= n) return null;
        return idx;
    }

    fn lowbit(value: usize) usize {
        return value & (0 -% value);
    }

    fn highestPowerOfTwo(value: usize) usize {
        std.debug.assert(value > 0);

        var bit: usize = 1;
        while (bit <= value / 2) {
            bit <<= 1;
        }
        return bit;
    }
};

fn expectPrefixMatches(values: []const i64, tree: *const Fenwick) !void {
    var running: i64 = 0;
    for (values, 0..) |value, i| {
        running += value;
        try std.testing.expectEqual(running, try tree.prefixSum(i));
    }
}

fn bruteRange(values: []const i64, left: usize, right: usize) i64 {
    var sum: i64 = 0;
    for (values[left .. right + 1]) |value| {
        sum += value;
    }
    return sum;
}

fn bruteFindByPrefix(values: []const i64, target: i64) ?usize {
    if (values.len == 0) return null;
    if (target <= 0) return 0;

    var running: i64 = 0;
    for (values, 0..) |value, i| {
        running += value;
        if (running >= target) return i;
    }
    return null;
}

test "point updates are reflected in prefix and range sums" {
    const allocator = std.testing.allocator;
    var tree = try Fenwick.init(allocator, 8);
    defer tree.deinit();

    var values = [_]i64{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const updates = [_]struct { index: usize, delta: i64 }{
        .{ .index = 0, .delta = 5 },
        .{ .index = 3, .delta = 7 },
        .{ .index = 7, .delta = 11 },
        .{ .index = 3, .delta = -2 },
        .{ .index = 1, .delta = 4 },
    };

    for (updates) |update| {
        try tree.pointUpdate(update.index, update.delta);
        values[update.index] += update.delta;
        try expectPrefixMatches(&values, &tree);
    }

    for (0..values.len) |left| {
        for (left..values.len) |right| {
            try std.testing.expectEqual(bruteRange(&values, left, right), try tree.rangeSum(left, right));
        }
    }
}

test "deterministic random point updates match brute force" {
    const allocator = std.testing.allocator;
    const n = 128;
    var tree = try Fenwick.init(allocator, n);
    defer tree.deinit();

    var values = try allocator.alloc(i64, n);
    defer allocator.free(values);
    @memset(values, 0);

    var prng = std.Random.DefaultPrng.init(0x4d495a5543484955);
    const random = prng.random();

    for (0..1000) |_| {
        const index = random.uintLessThan(usize, n);
        const delta = @as(i64, random.intRangeAtMost(i8, -25, 25));
        try tree.pointUpdate(index, delta);
        values[index] += delta;

        try expectPrefixMatches(values, &tree);

        for (0..12) |_| {
            const a = random.uintLessThan(usize, n);
            const b = random.uintLessThan(usize, n);
            const left = @min(a, b);
            const right = @max(a, b);
            try std.testing.expectEqual(bruteRange(values, left, right), try tree.rangeSum(left, right));
        }
    }
}

test "negative deltas update sums correctly" {
    const allocator = std.testing.allocator;
    var tree = try Fenwick.init(allocator, 5);
    defer tree.deinit();

    var values = [_]i64{ 10, 20, 30, 40, 50 };
    for (values, 0..) |value, index| {
        try tree.pointUpdate(index, value);
    }

    try tree.pointUpdate(2, -45);
    values[2] -= 45;
    try tree.pointUpdate(4, -75);
    values[4] -= 75;

    try expectPrefixMatches(&values, &tree);
    try std.testing.expectEqual(bruteRange(&values, 2, 4), try tree.rangeSum(2, 4));
    try std.testing.expectEqual(bruteRange(&values, 0, values.len - 1), tree.totalSum());
}

test "findByPrefix returns lower bound index for cumulative weights" {
    const allocator = std.testing.allocator;
    var tree = try Fenwick.init(allocator, 7);
    defer tree.deinit();

    const weights = [_]i64{ 0, 3, 0, 4, 2, 0, 5 };
    for (weights, 0..) |weight, index| {
        try tree.pointUpdate(index, weight);
    }

    try std.testing.expectEqual(@as(?usize, 0), tree.findByPrefix(0));
    try std.testing.expectEqual(@as(?usize, 1), tree.findByPrefix(1));
    try std.testing.expectEqual(@as(?usize, 1), tree.findByPrefix(3));
    try std.testing.expectEqual(@as(?usize, 3), tree.findByPrefix(4));
    try std.testing.expectEqual(@as(?usize, 3), tree.findByPrefix(7));
    try std.testing.expectEqual(@as(?usize, 4), tree.findByPrefix(8));
    try std.testing.expectEqual(@as(?usize, 6), tree.findByPrefix(10));
    try std.testing.expectEqual(@as(?usize, 6), tree.findByPrefix(14));
    try std.testing.expectEqual(@as(?usize, null), tree.findByPrefix(15));

    for (1..15) |target| {
        const signed_target: i64 = @intCast(target);
        try std.testing.expectEqual(bruteFindByPrefix(&weights, signed_target), tree.findByPrefix(signed_target));
    }
}

test "size one tree handles sums and prefix search" {
    const allocator = std.testing.allocator;
    var tree = try Fenwick.init(allocator, 1);
    defer tree.deinit();

    try std.testing.expectEqual(@as(i64, 0), try tree.prefixSum(0));
    try std.testing.expectEqual(@as(i64, 0), try tree.rangeSum(0, 0));
    try std.testing.expectEqual(@as(?usize, 0), tree.findByPrefix(0));
    try std.testing.expectEqual(@as(?usize, null), tree.findByPrefix(1));

    try tree.pointUpdate(0, 9);
    try std.testing.expectEqual(@as(i64, 9), try tree.prefixSum(0));
    try std.testing.expectEqual(@as(i64, 9), try tree.rangeSum(0, 0));
    try std.testing.expectEqual(@as(?usize, 0), tree.findByPrefix(1));
    try std.testing.expectEqual(@as(?usize, 0), tree.findByPrefix(9));
    try std.testing.expectEqual(@as(?usize, null), tree.findByPrefix(10));

    try tree.pointUpdate(0, -4);
    try std.testing.expectEqual(@as(i64, 5), tree.totalSum());
}

test "large deterministic tree remains logarithmic and exact" {
    const allocator = std.testing.allocator;
    const n = 4096;
    var tree = try Fenwick.init(allocator, n);
    defer tree.deinit();

    var total: i64 = 0;
    for (0..n) |index| {
        const value: i64 = @intCast((index * 17 + 3) % 29);
        total += value;
        try tree.pointUpdate(index, value);
    }

    try std.testing.expectEqual(total, tree.totalSum());
    try std.testing.expectEqual(total, try tree.prefixSum(n - 1));
    try std.testing.expectEqual(@as(i64, 3), try tree.rangeSum(0, 0));

    const middle_sum = try tree.rangeSum(123, 2345);
    var expected_middle: i64 = 0;
    for (123..2346) |index| {
        expected_middle += @intCast((index * 17 + 3) % 29);
    }
    try std.testing.expectEqual(expected_middle, middle_sum);

    const half_target = @divTrunc(total, 2);
    try std.testing.expectEqual(bruteFindByPrefixLarge(n, half_target), tree.findByPrefix(half_target));
}

fn bruteFindByPrefixLarge(n: usize, target: i64) ?usize {
    if (target <= 0) return 0;

    var running: i64 = 0;
    for (0..n) |index| {
        running += @intCast((index * 17 + 3) % 29);
        if (running >= target) return index;
    }
    return null;
}

test "invalid indexes and ranges return errors" {
    const allocator = std.testing.allocator;
    var tree = try Fenwick.init(allocator, 3);
    defer tree.deinit();

    try std.testing.expectError(error.InvalidIndex, tree.pointUpdate(3, 1));
    try std.testing.expectError(error.InvalidIndex, tree.prefixSum(3));
    try std.testing.expectError(error.InvalidIndex, tree.rangeSum(0, 3));
    try std.testing.expectError(error.InvalidRange, tree.rangeSum(2, 1));
}
