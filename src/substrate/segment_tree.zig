// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    EmptyTree,
    EmptyRange,
    IndexOutOfBounds,
};

pub const SegmentTree = struct {
    allocator: Allocator,
    len: usize,
    sums: []i64,
    mins: []i64,
    lazy: []i64,

    pub fn build(allocator: Allocator, values: []const i64) !SegmentTree {
        const cap = if (values.len == 0) 0 else values.len * 4;
        var self = SegmentTree{
            .allocator = allocator,
            .len = values.len,
            .sums = try allocator.alloc(i64, cap),
            .mins = undefined,
            .lazy = undefined,
        };
        errdefer allocator.free(self.sums);

        self.mins = try allocator.alloc(i64, cap);
        errdefer allocator.free(self.mins);

        self.lazy = try allocator.alloc(i64, cap);
        errdefer allocator.free(self.lazy);

        @memset(self.sums, 0);
        @memset(self.mins, 0);
        @memset(self.lazy, 0);

        if (values.len > 0) {
            self.buildNode(1, 0, values.len, values);
        }

        return self;
    }

    pub fn deinit(self: *SegmentTree) void {
        self.allocator.free(self.sums);
        self.allocator.free(self.mins);
        self.allocator.free(self.lazy);
        self.* = undefined;
    }

    pub fn rangeAdd(self: *SegmentTree, l: usize, r: usize, delta: i64) Error!void {
        try self.validateRange(l, r);
        self.addNode(1, 0, self.len, l, r, delta);
    }

    pub fn rangeSum(self: *SegmentTree, l: usize, r: usize) Error!i64 {
        try self.validateRange(l, r);
        return self.sumNode(1, 0, self.len, l, r);
    }

    pub fn rangeMin(self: *SegmentTree, l: usize, r: usize) Error!i64 {
        try self.validateRange(l, r);
        return self.minNode(1, 0, self.len, l, r);
    }

    fn validateRange(self: SegmentTree, l: usize, r: usize) Error!void {
        if (self.len == 0) return Error.EmptyTree;
        if (l >= r) return Error.EmptyRange;
        if (r > self.len) return Error.IndexOutOfBounds;
    }

    fn buildNode(self: *SegmentTree, node: usize, left: usize, right: usize, values: []const i64) void {
        if (right - left == 1) {
            self.sums[node] = values[left];
            self.mins[node] = values[left];
            return;
        }

        const mid = left + (right - left) / 2;
        self.buildNode(node * 2, left, mid, values);
        self.buildNode(node * 2 + 1, mid, right, values);
        self.pull(node);
    }

    fn addNode(
        self: *SegmentTree,
        node: usize,
        left: usize,
        right: usize,
        ql: usize,
        qr: usize,
        delta: i64,
    ) void {
        if (ql <= left and right <= qr) {
            self.apply(node, right - left, delta);
            return;
        }

        self.push(node, left, right);

        const mid = left + (right - left) / 2;
        if (ql < mid) {
            self.addNode(node * 2, left, mid, ql, qr, delta);
        }
        if (mid < qr) {
            self.addNode(node * 2 + 1, mid, right, ql, qr, delta);
        }
        self.pull(node);
    }

    fn sumNode(
        self: *SegmentTree,
        node: usize,
        left: usize,
        right: usize,
        ql: usize,
        qr: usize,
    ) i64 {
        if (ql <= left and right <= qr) {
            return self.sums[node];
        }

        self.push(node, left, right);

        const mid = left + (right - left) / 2;
        var total: i64 = 0;
        if (ql < mid) {
            total += self.sumNode(node * 2, left, mid, ql, qr);
        }
        if (mid < qr) {
            total += self.sumNode(node * 2 + 1, mid, right, ql, qr);
        }
        return total;
    }

    fn minNode(
        self: *SegmentTree,
        node: usize,
        left: usize,
        right: usize,
        ql: usize,
        qr: usize,
    ) i64 {
        if (ql <= left and right <= qr) {
            return self.mins[node];
        }

        self.push(node, left, right);

        const mid = left + (right - left) / 2;
        var best: ?i64 = null;
        if (ql < mid) {
            best = self.minNode(node * 2, left, mid, ql, qr);
        }
        if (mid < qr) {
            const right_min = self.minNode(node * 2 + 1, mid, right, ql, qr);
            best = if (best) |left_min| @min(left_min, right_min) else right_min;
        }
        return best.?;
    }

    fn apply(self: *SegmentTree, node: usize, width: usize, delta: i64) void {
        self.sums[node] += delta * @as(i64, @intCast(width));
        self.mins[node] += delta;
        self.lazy[node] += delta;
    }

    fn push(self: *SegmentTree, node: usize, left: usize, right: usize) void {
        const delta = self.lazy[node];
        if (delta == 0 or right - left == 1) return;

        const mid = left + (right - left) / 2;
        self.apply(node * 2, mid - left, delta);
        self.apply(node * 2 + 1, right - mid, delta);
        self.lazy[node] = 0;
    }

    fn pull(self: *SegmentTree, node: usize) void {
        const left = node * 2;
        const right = left + 1;
        self.sums[node] = self.sums[left] + self.sums[right];
        self.mins[node] = @min(self.mins[left], self.mins[right]);
    }
};

pub fn build(allocator: Allocator, values: []const i64) !SegmentTree {
    return SegmentTree.build(allocator, values);
}

fn bruteSum(values: []const i64, l: usize, r: usize) i64 {
    var total: i64 = 0;
    for (values[l..r]) |value| {
        total += value;
    }
    return total;
}

fn bruteMin(values: []const i64, l: usize, r: usize) i64 {
    var best = values[l];
    for (values[l + 1 .. r]) |value| {
        best = @min(best, value);
    }
    return best;
}

fn bruteAdd(values: []i64, l: usize, r: usize, delta: i64) void {
    for (values[l..r]) |*value| {
        value.* += delta;
    }
}

test "single element supports add sum and min" {
    const allocator = std.testing.allocator;
    const values = [_]i64{41};

    var tree = try SegmentTree.build(allocator, &values);
    defer tree.deinit();

    try std.testing.expectEqual(@as(i64, 41), try tree.rangeSum(0, 1));
    try std.testing.expectEqual(@as(i64, 41), try tree.rangeMin(0, 1));

    try tree.rangeAdd(0, 1, -9);
    try std.testing.expectEqual(@as(i64, 32), try tree.rangeSum(0, 1));
    try std.testing.expectEqual(@as(i64, 32), try tree.rangeMin(0, 1));
}

test "full range update and queries" {
    const allocator = std.testing.allocator;
    const values = [_]i64{ 5, -2, 7, 0, 3, -4 };

    var tree = try build(allocator, &values);
    defer tree.deinit();

    try std.testing.expectEqual(@as(i64, 9), try tree.rangeSum(0, values.len));
    try std.testing.expectEqual(@as(i64, -4), try tree.rangeMin(0, values.len));

    try tree.rangeAdd(0, values.len, 6);
    try std.testing.expectEqual(@as(i64, 45), try tree.rangeSum(0, values.len));
    try std.testing.expectEqual(@as(i64, 2), try tree.rangeMin(0, values.len));
}

test "overlapping updates compose" {
    const allocator = std.testing.allocator;
    var values = [_]i64{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var tree = try SegmentTree.build(allocator, &values);
    defer tree.deinit();

    try tree.rangeAdd(1, 6, 10);
    bruteAdd(&values, 1, 6, 10);
    try tree.rangeAdd(3, 8, -4);
    bruteAdd(&values, 3, 8, -4);
    try tree.rangeAdd(0, 4, 2);
    bruteAdd(&values, 0, 4, 2);

    try std.testing.expectEqual(bruteSum(&values, 0, values.len), try tree.rangeSum(0, values.len));
    try std.testing.expectEqual(bruteMin(&values, 0, values.len), try tree.rangeMin(0, values.len));
    try std.testing.expectEqual(bruteSum(&values, 2, 7), try tree.rangeSum(2, 7));
    try std.testing.expectEqual(bruteMin(&values, 2, 7), try tree.rangeMin(2, 7));
    try std.testing.expectEqualSlices(i64, &[_]i64{ 3, 14, 15, 12, 11, 12, 3, 4 }, &values);
}

test "invalid ranges are rejected" {
    const allocator = std.testing.allocator;
    const values = [_]i64{ 1, 2, 3 };

    var tree = try SegmentTree.build(allocator, &values);
    defer tree.deinit();

    try std.testing.expectError(Error.EmptyRange, tree.rangeAdd(1, 1, 1));
    try std.testing.expectError(Error.EmptyRange, tree.rangeSum(2, 2));
    try std.testing.expectError(Error.IndexOutOfBounds, tree.rangeMin(0, 4));

    var empty = try SegmentTree.build(allocator, &[_]i64{});
    defer empty.deinit();
    try std.testing.expectError(Error.EmptyTree, empty.rangeSum(0, 1));
}

test "range sum and min match brute force after random range adds" {
    const allocator = std.testing.allocator;
    const initial = [_]i64{
        7, -3, 12, 0, -8, 4, 11, -1, 6, -5, 9, 2, -7, 13, -2, 5,
    };
    const brute = try allocator.dupe(i64, &initial);
    defer allocator.free(brute);

    var tree = try SegmentTree.build(allocator, &initial);
    defer tree.deinit();

    var prng = std.Random.DefaultPrng.init(0x5eed_f00d_cafe_babe);
    const random = prng.random();

    var step: usize = 0;
    while (step < 400) : (step += 1) {
        const l = random.intRangeLessThan(usize, 0, initial.len);
        const r = random.intRangeAtMost(usize, l + 1, initial.len);
        const delta = random.intRangeAtMost(i64, -25, 25);

        try tree.rangeAdd(l, r, delta);
        bruteAdd(brute, l, r, delta);

        const ql = random.intRangeLessThan(usize, 0, initial.len);
        const qr = random.intRangeAtMost(usize, ql + 1, initial.len);
        try std.testing.expectEqual(bruteSum(brute, ql, qr), try tree.rangeSum(ql, qr));
        try std.testing.expectEqual(bruteMin(brute, ql, qr), try tree.rangeMin(ql, qr));
    }

    try std.testing.expectEqual(bruteSum(brute, 0, brute.len), try tree.rangeSum(0, brute.len));
    try std.testing.expectEqual(bruteMin(brute, 0, brute.len), try tree.rangeMin(0, brute.len));
}

test "deterministic stress covers every range repeatedly" {
    const allocator = std.testing.allocator;
    const values = [_]i64{
        -15, 4,  0,  23, -8, 16, -3, 9,  11, -20, 5,  14, -1, 7,  -6, 18,
        2,   -9, 12, 3,  -4, 6,  21, -7, 10, 1,   -2, 8,  13, -5, 17, -11,
    };
    const brute = try allocator.dupe(i64, &values);
    defer allocator.free(brute);

    var tree = try SegmentTree.build(allocator, &values);
    defer tree.deinit();

    var round: usize = 0;
    while (round < 12) : (round += 1) {
        var l: usize = 0;
        while (l < values.len) : (l += 1) {
            var r = l + 1;
            while (r <= values.len) : (r += 1) {
                const width: i64 = @intCast(r - l);
                const delta = @as(i64, @intCast((round + l + r) % 17)) - 8;
                try tree.rangeAdd(l, r, delta);
                bruteAdd(brute, l, r, delta);

                const ql = (l + round) % values.len;
                const remaining = values.len - ql;
                const qr = ql + @as(usize, @intCast(@mod(width, @as(i64, @intCast(remaining))) + 1));
                try std.testing.expectEqual(bruteSum(brute, ql, qr), try tree.rangeSum(ql, qr));
                try std.testing.expectEqual(bruteMin(brute, ql, qr), try tree.rangeMin(ql, qr));
            }
        }
    }
}
