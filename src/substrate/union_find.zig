// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    IndexOutOfBounds,
};

pub const UnionFind = struct {
    parents: []usize,
    ranks: []u8,
    sizes: []usize,
    components: usize,

    pub fn makeSet(allocator: Allocator, n: usize) Allocator.Error!UnionFind {
        const parents = try allocator.alloc(usize, n);
        errdefer allocator.free(parents);

        const ranks = try allocator.alloc(u8, n);
        errdefer allocator.free(ranks);

        const sizes = try allocator.alloc(usize, n);
        errdefer allocator.free(sizes);

        for (parents, 0..) |*parent, i| {
            parent.* = i;
        }
        @memset(ranks, 0);
        @memset(sizes, 1);

        return .{
            .parents = parents,
            .ranks = ranks,
            .sizes = sizes,
            .components = n,
        };
    }

    pub fn deinit(self: *UnionFind, allocator: Allocator) void {
        allocator.free(self.parents);
        allocator.free(self.ranks);
        allocator.free(self.sizes);
        self.* = .{
            .parents = &.{},
            .ranks = &.{},
            .sizes = &.{},
            .components = 0,
        };
    }

    pub fn find(self: *UnionFind, x: usize) Error!usize {
        try self.checkIndex(x);

        var root = x;
        while (self.parents[root] != root) {
            root = self.parents[root];
        }

        var node = x;
        while (self.parents[node] != node) {
            const next = self.parents[node];
            self.parents[node] = root;
            node = next;
        }

        return root;
    }

    pub fn @"union"(self: *UnionFind, a: usize, b: usize) Error!bool {
        var root_a = try self.find(a);
        var root_b = try self.find(b);

        if (root_a == root_b) {
            return false;
        }

        if (self.ranks[root_a] < self.ranks[root_b]) {
            std.mem.swap(usize, &root_a, &root_b);
        }

        self.parents[root_b] = root_a;
        self.sizes[root_a] += self.sizes[root_b];
        self.sizes[root_b] = 0;

        if (self.ranks[root_a] == self.ranks[root_b]) {
            self.ranks[root_a] += 1;
        }

        self.components -= 1;
        return true;
    }

    pub fn connected(self: *UnionFind, a: usize, b: usize) Error!bool {
        return try self.find(a) == try self.find(b);
    }

    pub fn componentCount(self: *const UnionFind) usize {
        return self.components;
    }

    pub fn componentSize(self: *UnionFind, x: usize) Error!usize {
        const root = try self.find(x);
        return self.sizes[root];
    }

    fn checkIndex(self: *const UnionFind, x: usize) Error!void {
        if (x >= self.parents.len) {
            return Error.IndexOutOfBounds;
        }
    }
};

pub const DisjointSetUnion = UnionFind;

pub fn makeSet(allocator: Allocator, n: usize) Allocator.Error!UnionFind {
    return UnionFind.makeSet(allocator, n);
}

const Lcg = struct {
    state: u64,

    fn next(self: *Lcg) u64 {
        self.state = self.state *% 6364136223846793005 +% 1442695040888963407;
        return self.state;
    }

    fn index(self: *Lcg, n: usize) usize {
        const limit: u64 = @intCast(n);
        return @intCast(self.next() % limit);
    }
};

const BruteForceOracle = struct {
    labels: []usize,

    fn init(allocator: Allocator, n: usize) Allocator.Error!BruteForceOracle {
        const labels = try allocator.alloc(usize, n);
        for (labels, 0..) |*label, i| {
            label.* = i;
        }
        return .{ .labels = labels };
    }

    fn deinit(self: *BruteForceOracle, allocator: Allocator) void {
        allocator.free(self.labels);
        self.labels = &.{};
    }

    fn connected(self: *const BruteForceOracle, a: usize, b: usize) bool {
        return self.labels[a] == self.labels[b];
    }

    fn @"union"(self: *BruteForceOracle, a: usize, b: usize) bool {
        const label_a = self.labels[a];
        const label_b = self.labels[b];
        if (label_a == label_b) {
            return false;
        }

        for (self.labels) |*label| {
            if (label.* == label_b) {
                label.* = label_a;
            }
        }
        return true;
    }

    fn componentCount(self: *const BruteForceOracle) usize {
        var count: usize = 0;
        for (self.labels, 0..) |label, i| {
            var seen = false;
            for (self.labels[0..i]) |previous| {
                if (previous == label) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                count += 1;
            }
        }
        return count;
    }

    fn componentSize(self: *const BruteForceOracle, x: usize) usize {
        const label = self.labels[x];
        var count: usize = 0;
        for (self.labels) |candidate| {
            if (candidate == label) {
                count += 1;
            }
        }
        return count;
    }
};

test "union merges components and connected reflects it" {
    const allocator = std.testing.allocator;
    var uf = try makeSet(allocator, 6);
    defer uf.deinit(allocator);

    try std.testing.expect(!try uf.connected(1, 2));
    try std.testing.expect(try uf.@"union"(1, 2));
    try std.testing.expect(try uf.connected(1, 2));

    try std.testing.expect(try uf.@"union"(2, 3));
    try std.testing.expect(try uf.connected(1, 3));
    try std.testing.expect(!try uf.connected(1, 4));
    try std.testing.expect(!try uf.connected(0, 5));
}

test "component count decreases only on real merges" {
    const allocator = std.testing.allocator;
    var uf = try UnionFind.makeSet(allocator, 5);
    defer uf.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 5), uf.componentCount());

    try std.testing.expect(try uf.@"union"(0, 1));
    try std.testing.expectEqual(@as(usize, 4), uf.componentCount());

    try std.testing.expect(!try uf.@"union"(1, 0));
    try std.testing.expectEqual(@as(usize, 4), uf.componentCount());

    try std.testing.expect(try uf.@"union"(2, 3));
    try std.testing.expectEqual(@as(usize, 3), uf.componentCount());

    try std.testing.expect(try uf.@"union"(1, 2));
    try std.testing.expectEqual(@as(usize, 2), uf.componentCount());
}

test "component size tracking follows merges" {
    const allocator = std.testing.allocator;
    var uf = try makeSet(allocator, 7);
    defer uf.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), try uf.componentSize(0));
    try std.testing.expectEqual(@as(usize, 1), try uf.componentSize(6));

    try std.testing.expect(try uf.@"union"(0, 1));
    try std.testing.expectEqual(@as(usize, 2), try uf.componentSize(0));
    try std.testing.expectEqual(@as(usize, 2), try uf.componentSize(1));

    try std.testing.expect(try uf.@"union"(2, 3));
    try std.testing.expect(try uf.@"union"(3, 4));
    try std.testing.expectEqual(@as(usize, 3), try uf.componentSize(2));
    try std.testing.expectEqual(@as(usize, 3), try uf.componentSize(4));

    try std.testing.expect(try uf.@"union"(1, 4));
    try std.testing.expectEqual(@as(usize, 5), try uf.componentSize(0));
    try std.testing.expectEqual(@as(usize, 5), try uf.componentSize(3));
    try std.testing.expectEqual(@as(usize, 1), try uf.componentSize(5));
    try std.testing.expectEqual(@as(usize, 1), try uf.componentSize(6));
}

test "self-union is a no-op" {
    const allocator = std.testing.allocator;
    var uf = try makeSet(allocator, 4);
    defer uf.deinit(allocator);

    try std.testing.expect(!try uf.@"union"(2, 2));
    try std.testing.expectEqual(@as(usize, 4), uf.componentCount());
    try std.testing.expectEqual(@as(usize, 1), try uf.componentSize(2));

    try std.testing.expect(try uf.@"union"(1, 2));
    try std.testing.expect(!try uf.@"union"(2, 2));
    try std.testing.expectEqual(@as(usize, 3), uf.componentCount());
    try std.testing.expectEqual(@as(usize, 2), try uf.componentSize(1));
}

test "path compression preserves roots on an explicit chain" {
    const allocator = std.testing.allocator;
    var uf = try makeSet(allocator, 8);
    defer uf.deinit(allocator);

    for (uf.parents[1..], 1..) |*parent, i| {
        parent.* = i - 1;
    }
    uf.sizes[0] = 8;
    for (uf.sizes[1..]) |*size| {
        size.* = 0;
    }
    uf.components = 1;

    try std.testing.expectEqual(@as(usize, 0), try uf.find(7));
    for (uf.parents, 0..) |parent, i| {
        if (i == 0) {
            try std.testing.expectEqual(@as(usize, 0), parent);
        } else {
            try std.testing.expectEqual(@as(usize, 0), parent);
        }
    }
    try std.testing.expectEqual(@as(usize, 8), try uf.componentSize(6));
}

test "random unions match a brute-force oracle while find compresses paths" {
    const allocator = std.testing.allocator;
    const n = 32;

    var uf = try makeSet(allocator, n);
    defer uf.deinit(allocator);

    var oracle = try BruteForceOracle.init(allocator, n);
    defer oracle.deinit(allocator);

    var rng = Lcg{ .state = 0x1f2e_3d4c_5b6a_7988 };

    for (0..256) |_| {
        const a = rng.index(n);
        const b = rng.index(n);

        const expected_merge = oracle.@"union"(a, b);
        try std.testing.expectEqual(expected_merge, try uf.@"union"(a, b));
        try std.testing.expectEqual(oracle.componentCount(), uf.componentCount());

        for (0..n) |i| {
            _ = try uf.find(i);
        }

        for (0..n) |i| {
            try std.testing.expectEqual(oracle.componentSize(i), try uf.componentSize(i));
            for (0..n) |j| {
                try std.testing.expectEqual(oracle.connected(i, j), try uf.connected(i, j));
            }
        }
    }
}

test "out-of-bounds operations report index errors" {
    const allocator = std.testing.allocator;
    var uf = try makeSet(allocator, 3);
    defer uf.deinit(allocator);

    try std.testing.expectError(Error.IndexOutOfBounds, uf.find(3));
    try std.testing.expectError(Error.IndexOutOfBounds, uf.@"union"(0, 3));
    try std.testing.expectError(Error.IndexOutOfBounds, uf.connected(3, 0));
    try std.testing.expectError(Error.IndexOutOfBounds, uf.componentSize(99));
}
