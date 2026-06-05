//! Rendezvous hashing, also known as Highest-Random-Weight hashing.
//!
//! The module is self-contained and operates on caller-owned node identifiers.
//! It does not retain or duplicate node memory.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{
    InvalidWeight,
};

pub const WeightedNode = struct {
    id: []const u8,
    weight: f64,
};

pub const RendezvousHash = struct {
    nodes: []const []const u8,

    pub fn init(nodes: []const []const u8) RendezvousHash {
        return .{ .nodes = nodes };
    }

    pub fn pick(self: RendezvousHash, key: []const u8) ?[]const u8 {
        return selectOne(self.nodes, key);
    }

    pub fn pickN(self: RendezvousHash, allocator: Allocator, key: []const u8, n: usize) ![][]const u8 {
        return selectMany(allocator, self.nodes, key, n);
    }
};

pub const WeightedRendezvousHash = struct {
    nodes: []const WeightedNode,

    pub fn init(nodes: []const WeightedNode) WeightedRendezvousHash {
        return .{ .nodes = nodes };
    }

    pub fn pick(self: WeightedRendezvousHash, key: []const u8) Error!?[]const u8 {
        return selectOneWeighted(self.nodes, key);
    }

    pub fn pickN(self: WeightedRendezvousHash, allocator: Allocator, key: []const u8, n: usize) ![][]const u8 {
        return selectManyWeighted(allocator, self.nodes, key, n);
    }
};

pub fn pick(nodes: []const []const u8, key: []const u8) ?[]const u8 {
    return selectOne(nodes, key);
}

pub fn pickN(allocator: Allocator, nodes: []const []const u8, key: []const u8, n: usize) ![][]const u8 {
    return selectMany(allocator, nodes, key, n);
}

pub fn pickWeighted(nodes: []const WeightedNode, key: []const u8) Error!?[]const u8 {
    return selectOneWeighted(nodes, key);
}

pub fn pickNWeighted(allocator: Allocator, nodes: []const WeightedNode, key: []const u8, n: usize) ![][]const u8 {
    return selectManyWeighted(allocator, nodes, key, n);
}

pub fn score(node: []const u8, key: []const u8) u64 {
    return hashNodeKey(node, key);
}

pub fn weightedScore(node: WeightedNode, key: []const u8) Error!f64 {
    try validateWeight(node.weight);
    const u = unitOpen(score(node.id, key));
    return -node.weight / @log(u);
}

fn selectOne(nodes: []const []const u8, key: []const u8) ?[]const u8 {
    if (nodes.len == 0) return null;

    var best = Ranked{
        .id = nodes[0],
        .score = score(nodes[0], key),
    };

    for (nodes[1..]) |node| {
        const candidate = Ranked{
            .id = node,
            .score = score(node, key),
        };
        if (rankedBefore(candidate, best)) best = candidate;
    }

    return best.id;
}

fn selectMany(allocator: Allocator, nodes: []const []const u8, key: []const u8, n: usize) ![][]const u8 {
    const count = @min(n, nodes.len);
    if (count == 0) return allocator.alloc([]const u8, 0);

    var ranked = try allocator.alloc(Ranked, nodes.len);
    defer allocator.free(ranked);

    for (nodes, ranked) |node, *dst| {
        dst.* = .{
            .id = node,
            .score = score(node, key),
        };
    }

    std.mem.sort(Ranked, ranked, {}, rankedLessThan);

    const out = try allocator.alloc([]const u8, count);
    for (out, ranked[0..count]) |*dst, item| {
        dst.* = item.id;
    }
    return out;
}

fn selectOneWeighted(nodes: []const WeightedNode, key: []const u8) Error!?[]const u8 {
    if (nodes.len == 0) return null;

    var best = WeightedRanked{
        .id = nodes[0].id,
        .score = try weightedScore(nodes[0], key),
    };

    for (nodes[1..]) |node| {
        const candidate = WeightedRanked{
            .id = node.id,
            .score = try weightedScore(node, key),
        };
        if (weightedRankedBefore(candidate, best)) best = candidate;
    }

    return best.id;
}

fn selectManyWeighted(allocator: Allocator, nodes: []const WeightedNode, key: []const u8, n: usize) ![][]const u8 {
    const count = @min(n, nodes.len);
    if (count == 0) return allocator.alloc([]const u8, 0);

    var ranked = try allocator.alloc(WeightedRanked, nodes.len);
    defer allocator.free(ranked);

    for (nodes, ranked) |node, *dst| {
        dst.* = .{
            .id = node.id,
            .score = try weightedScore(node, key),
        };
    }

    std.mem.sort(WeightedRanked, ranked, {}, weightedRankedLessThan);

    const out = try allocator.alloc([]const u8, count);
    for (out, ranked[0..count]) |*dst, item| {
        dst.* = item.id;
    }
    return out;
}

const Ranked = struct {
    id: []const u8,
    score: u64,
};

const WeightedRanked = struct {
    id: []const u8,
    score: f64,
};

fn rankedLessThan(_: void, a: Ranked, b: Ranked) bool {
    return rankedBefore(a, b);
}

fn rankedBefore(a: Ranked, b: Ranked) bool {
    if (a.score != b.score) return a.score > b.score;
    return std.mem.lessThan(u8, a.id, b.id);
}

fn weightedRankedLessThan(_: void, a: WeightedRanked, b: WeightedRanked) bool {
    return weightedRankedBefore(a, b);
}

fn weightedRankedBefore(a: WeightedRanked, b: WeightedRanked) bool {
    if (a.score != b.score) return a.score > b.score;
    return std.mem.lessThan(u8, a.id, b.id);
}

fn validateWeight(weight: f64) Error!void {
    if (!(weight > 0.0) or weight > std.math.floatMax(f64)) return Error.InvalidWeight;
}

fn unitOpen(hash: u64) f64 {
    const mantissa = (hash >> 11) + 1;
    const denominator = (@as(u64, 1) << 53) + 1;
    return @as(f64, @floatFromInt(mantissa)) / @as(f64, @floatFromInt(denominator));
}

const fnv_offset: u64 = 0xcbf2_9ce4_8422_2325;
const fnv_prime: u64 = 0x0000_0100_0000_01b3;

fn hashNodeKey(node: []const u8, key: []const u8) u64 {
    var h = fnv_offset;
    updateByte(&h, 0x4d);
    updateWithLen(&h, node);
    updateByte(&h, 0x52);
    updateWithLen(&h, key);
    return mix64(h);
}

fn updateWithLen(hash: *u64, bytes: []const u8) void {
    updateInt(hash, @intCast(bytes.len));
    for (bytes) |b| updateByte(hash, b);
}

fn updateInt(hash: *u64, value: u64) void {
    var remaining = value;
    for (0..8) |_| {
        updateByte(hash, @truncate(remaining));
        remaining >>= 8;
    }
}

fn updateByte(hash: *u64, byte: u8) void {
    hash.* ^= byte;
    hash.* *%= fnv_prime;
}

fn mix64(input: u64) u64 {
    var x = input;
    x = (x ^ (x >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    x = (x ^ (x >> 27)) *% 0x94d0_49bb_1331_11eb;
    return x ^ (x >> 31);
}

fn makeKey(buf: []u8, prefix: []const u8, n: usize) []const u8 {
    return std.fmt.bufPrint(buf, "{s}-{d}", .{ prefix, n }) catch unreachable;
}

fn findIndex(nodes: []const []const u8, id: []const u8) ?usize {
    for (nodes, 0..) |node, i| {
        if (std.mem.eql(u8, node, id)) return i;
    }
    return null;
}

test "deterministic selection is stable and order independent" {
    const nodes = [_][]const u8{ "alpha", "beta", "gamma", "delta" };
    const reordered = [_][]const u8{ "gamma", "alpha", "delta", "beta" };
    const ring = RendezvousHash.init(&nodes);

    const direct = pick(&nodes, "user:42").?;
    try std.testing.expectEqualStrings(direct, ring.pick("user:42").?);
    try std.testing.expectEqualStrings(direct, pick(&reordered, "user:42").?);

    try std.testing.expectEqualStrings(direct, pick(&nodes, "user:42").?);
    try std.testing.expect(!std.mem.eql(u8, direct, pick(&nodes, "user:43").?));
}

test "selection distributes evenly across equal-weight nodes" {
    const nodes = [_][]const u8{ "a", "b", "c", "d", "e" };
    var counts = [_]usize{ 0, 0, 0, 0, 0 };
    var buf: [64]u8 = undefined;

    const samples: usize = 50_000;
    for (0..samples) |i| {
        const owner = pick(&nodes, makeKey(&buf, "key", i)).?;
        counts[findIndex(&nodes, owner).?] += 1;
    }

    const expected = samples / nodes.len;
    for (counts) |count| {
        try std.testing.expect(count > expected * 85 / 100);
        try std.testing.expect(count < expected * 115 / 100);
    }
}

test "node add and remove only move keys affected by the changed owner" {
    const base = [_][]const u8{ "a", "b", "c", "d" };
    const added = [_][]const u8{ "a", "b", "c", "d", "e" };
    const removed = [_][]const u8{ "a", "b", "d" };
    var buf: [64]u8 = undefined;

    var moved_to_added: usize = 0;
    var moved_from_removed: usize = 0;

    for (0..20_000) |i| {
        const k = makeKey(&buf, "session", i);
        const before = pick(&base, k).?;

        const after_add = pick(&added, k).?;
        if (!std.mem.eql(u8, before, after_add)) {
            moved_to_added += 1;
            try std.testing.expectEqualStrings("e", after_add);
        }

        const after_remove = pick(&removed, k).?;
        if (std.mem.eql(u8, before, "c")) {
            if (!std.mem.eql(u8, before, after_remove)) moved_from_removed += 1;
        } else {
            try std.testing.expectEqualStrings(before, after_remove);
        }
    }

    try std.testing.expect(moved_to_added > 0);
    try std.testing.expect(moved_from_removed > 0);
}

test "pickN returns top nodes in descending rendezvous score order" {
    const allocator = std.testing.allocator;
    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };

    const chosen = try pickN(allocator, &nodes, "object:9001", 4);
    defer allocator.free(chosen);

    try std.testing.expectEqual(@as(usize, 4), chosen.len);
    try std.testing.expectEqualStrings(pick(&nodes, "object:9001").?, chosen[0]);

    for (chosen[0 .. chosen.len - 1], chosen[1..]) |left, right| {
        const ls = score(left, "object:9001");
        const rs = score(right, "object:9001");
        try std.testing.expect(ls > rs or (ls == rs and std.mem.lessThan(u8, left, right)));
    }

    for (chosen, 0..) |left, i| {
        for (chosen[i + 1 ..]) |right| {
            try std.testing.expect(!std.mem.eql(u8, left, right));
        }
    }

    const all = try pickN(allocator, &nodes, "object:9001", 99);
    defer allocator.free(all);
    try std.testing.expectEqual(nodes.len, all.len);
}

test "weighted variant picks in proportion to positive weights" {
    const weighted = [_]WeightedNode{
        .{ .id = "small", .weight = 1.0 },
        .{ .id = "large", .weight = 4.0 },
    };
    var counts = [_]usize{ 0, 0 };
    var buf: [64]u8 = undefined;

    for (0..60_000) |i| {
        const owner = try pickWeighted(&weighted, makeKey(&buf, "weighted", i));
        if (std.mem.eql(u8, owner.?, "small")) {
            counts[0] += 1;
        } else {
            try std.testing.expectEqualStrings("large", owner.?);
            counts[1] += 1;
        }
    }

    const ratio = @as(f64, @floatFromInt(counts[1])) / @as(f64, @floatFromInt(counts[0]));
    try std.testing.expect(ratio > 3.6);
    try std.testing.expect(ratio < 4.4);
}

test "weighted topN orders by weighted score and validates weights" {
    const allocator = std.testing.allocator;
    const nodes = [_]WeightedNode{
        .{ .id = "thin", .weight = 0.5 },
        .{ .id = "normal", .weight = 1.0 },
        .{ .id = "heavy", .weight = 3.0 },
    };

    const chosen = try pickNWeighted(allocator, &nodes, "replica-key", 3);
    defer allocator.free(chosen);

    try std.testing.expectEqual(@as(usize, 3), chosen.len);
    try std.testing.expectEqualStrings((try pickWeighted(&nodes, "replica-key")).?, chosen[0]);

    for (chosen[0 .. chosen.len - 1], chosen[1..]) |left, right| {
        var left_node: ?WeightedNode = null;
        var right_node: ?WeightedNode = null;
        for (nodes) |node| {
            if (std.mem.eql(u8, node.id, left)) left_node = node;
            if (std.mem.eql(u8, node.id, right)) right_node = node;
        }
        const ls = try weightedScore(left_node.?, "replica-key");
        const rs = try weightedScore(right_node.?, "replica-key");
        try std.testing.expect(ls > rs or (ls == rs and std.mem.lessThan(u8, left, right)));
    }

    const bad = [_]WeightedNode{.{ .id = "bad", .weight = 0.0 }};
    try std.testing.expectError(Error.InvalidWeight, pickWeighted(&bad, "x"));
    try std.testing.expectError(Error.InvalidWeight, pickNWeighted(allocator, &bad, "x", 1));
}

test "empty node sets return no selection and owned empty topN slices" {
    const allocator = std.testing.allocator;
    const nodes = [_][]const u8{};
    const weighted = [_]WeightedNode{};

    try std.testing.expectEqual(@as(?[]const u8, null), pick(&nodes, "k"));
    try std.testing.expectEqual(@as(?[]const u8, null), try pickWeighted(&weighted, "k"));

    const top = try pickN(allocator, &nodes, "k", 3);
    defer allocator.free(top);
    try std.testing.expectEqual(@as(usize, 0), top.len);

    const weighted_top = try pickNWeighted(allocator, &weighted, "k", 3);
    defer allocator.free(weighted_top);
    try std.testing.expectEqual(@as(usize, 0), weighted_top.len);
}
