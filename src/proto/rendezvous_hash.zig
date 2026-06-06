//! Allocation-free rendezvous hashing over caller-owned node slices.
//!
//! Highest-random-weight hashing chooses the node with the greatest
//! deterministic score for a key. Removing a node only changes assignments for
//! keys that previously chose that node, because all remaining node scores are
//! independent and stable.

const std = @import("std");

/// Tunable validation and hash parameters for rendezvous hashing.
pub const Params = struct {
    /// Maximum number of nodes accepted by `pick` or `topN`.
    max_nodes: usize = 4096,
    /// Maximum byte length for a node id.
    max_node_id_bytes: usize = 255,
    /// Seed used by the deterministic pair hash.
    seed: u64 = 0x6d69_7a75_6368_6950,
    /// Whether duplicate node ids are rejected with `error.DuplicateNode`.
    reject_duplicate_ids: bool = true,
};

/// Errors returned by rendezvous hashing operations.
pub const HashError = error{
    NoNodes,
    TooManyNodes,
    EmptyNodeId,
    NodeIdTooLong,
    InvalidWeight,
    DuplicateNode,
    OutputTooSmall,
};

/// A caller-owned rendezvous node.
pub const Node = struct {
    /// Stable node identity. The bytes are borrowed and never copied.
    id: []const u8,
    /// Relative node weight. Larger weights increase the chance of selection.
    weight: u64 = 1,
};

/// A node paired with its weighted rendezvous score for a specific key.
pub const RankedNode = struct {
    /// Borrowed pointer to the selected node in the caller's node slice.
    node: *const Node,
    /// Weighted score used for descending rank order.
    score: u128,

    /// Return true when this rank should appear before `other`.
    pub fn precedes(self: RankedNode, other: RankedNode) bool {
        return rankedBetter(self, other);
    }
};

/// Default rendezvous hash type using `Params{}`.
pub const Default = RendezvousHash(.{});

/// Build a stateless rendezvous hasher specialized for `params`.
pub fn RendezvousHash(comptime params: Params) type {
    comptime {
        if (params.max_nodes == 0) @compileError("rendezvous hashing needs node storage");
        if (params.max_node_id_bytes == 0) @compileError("rendezvous node ids need storage");
    }

    return struct {
        const Self = @This();

        /// Initialize a stateless rendezvous hasher.
        pub fn init() Self {
            return .{};
        }

        /// Release hasher resources. This type owns no memory.
        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Return the node with the highest weighted score for `key`.
        pub fn pick(self: *const Self, key: []const u8, nodes: []const Node) HashError!*const Node {
            try validateNodes(nodes);

            var best = RankedNode{
                .node = &nodes[0],
                .score = self.score(key, nodes[0]) catch unreachable,
            };

            for (nodes[1..]) |*node| {
                const candidate = RankedNode{
                    .node = node,
                    .score = self.score(key, node.*) catch unreachable,
                };
                if (rankedBetter(candidate, best)) best = candidate;
            }

            return best.node;
        }

        /// Fill `out` with up to `count` top-ranked nodes for `key`.
        ///
        /// The returned slice aliases `out`; each `RankedNode.node` points into
        /// `nodes`. If `count` exceeds `nodes.len`, all nodes are returned.
        pub fn topN(
            self: *const Self,
            key: []const u8,
            nodes: []const Node,
            count: usize,
            out: []RankedNode,
        ) HashError![]const RankedNode {
            if (count == 0) return out[0..0];
            try validateNodes(nodes);

            const wanted = @min(count, nodes.len);
            if (out.len < wanted) return error.OutputTooSmall;

            var used: usize = 0;
            for (nodes) |*node| {
                const candidate = RankedNode{
                    .node = node,
                    .score = self.score(key, node.*) catch unreachable,
                };
                insertRanked(out, &used, wanted, candidate);
            }

            return out[0..used];
        }

        /// Calculate the deterministic weighted score for one node and key.
        pub fn score(self: *const Self, key: []const u8, node: Node) HashError!u128 {
            _ = self;
            try validateNode(node);
            const raw = hashPair(params.seed, key, node.id);
            return @as(u128, raw) * @as(u128, node.weight);
        }

        fn validateNodes(nodes: []const Node) HashError!void {
            if (nodes.len == 0) return error.NoNodes;
            if (nodes.len > params.max_nodes) return error.TooManyNodes;

            for (nodes, 0..) |node, index| {
                try validateNode(node);
                if (params.reject_duplicate_ids) {
                    for (nodes[0..index]) |previous| {
                        if (std.mem.eql(u8, previous.id, node.id)) return error.DuplicateNode;
                    }
                }
            }
        }

        fn validateNode(node: Node) HashError!void {
            if (node.id.len == 0) return error.EmptyNodeId;
            if (node.id.len > params.max_node_id_bytes) return error.NodeIdTooLong;
            if (node.weight == 0) return error.InvalidWeight;
        }
    };
}

fn insertRanked(out: []RankedNode, used: *usize, wanted: usize, candidate: RankedNode) void {
    var pos: usize = 0;
    while (pos < used.* and !rankedBetter(candidate, out[pos])) : (pos += 1) {}
    if (pos >= wanted) return;

    if (used.* < wanted) used.* += 1;

    var index = used.* - 1;
    while (index > pos) : (index -= 1) {
        out[index] = out[index - 1];
    }
    out[pos] = candidate;
}

fn rankedBetter(left: RankedNode, right: RankedNode) bool {
    if (left.score != right.score) return left.score > right.score;
    return std.mem.order(u8, left.node.id, right.node.id) == .lt;
}

fn hashPair(seed: u64, key: []const u8, node_id: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(seed);
    updateLength(&hasher, key.len);
    hasher.update(key);
    updateLength(&hasher, node_id.len);
    hasher.update(node_id);
    return hasher.final();
}

fn updateLength(hasher: *std.hash.Wyhash, len: usize) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, @intCast(len), .little);
    hasher.update(&buf);
}

test "rendezvous pick is deterministic for the same key and nodes" {
    // Arrange.
    const allocator = std.testing.allocator;
    const nodes = try allocator.dupe(Node, &.{
        .{ .id = "alpha", .weight = 1 },
        .{ .id = "bravo", .weight = 2 },
        .{ .id = "charlie", .weight = 1 },
        .{ .id = "delta", .weight = 3 },
    });
    defer allocator.free(nodes);

    var hasher = Default.init();
    defer hasher.deinit();

    // Act.
    const first = try hasher.pick("channel:#zig", nodes);
    const second = try hasher.pick("channel:#zig", nodes);

    // Assert.
    try std.testing.expectEqualStrings(first.id, second.id);
    try std.testing.expectEqual(first.weight, second.weight);
}

test "rendezvous removal only reassigns keys owned by the removed node" {
    // Arrange.
    const allocator = std.testing.allocator;
    const full = try allocator.dupe(Node, &.{
        .{ .id = "alpha", .weight = 1 },
        .{ .id = "bravo", .weight = 1 },
        .{ .id = "charlie", .weight = 1 },
        .{ .id = "delta", .weight = 1 },
    });
    defer allocator.free(full);

    const reduced = try allocator.dupe(Node, &.{
        .{ .id = "alpha", .weight = 1 },
        .{ .id = "charlie", .weight = 1 },
        .{ .id = "delta", .weight = 1 },
    });
    defer allocator.free(reduced);

    var hasher = Default.init();
    defer hasher.deinit();

    // Act and assert.
    var affected: usize = 0;
    var key_buf: [32]u8 = undefined;
    for (0..256) |index| {
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{index});
        const before = try hasher.pick(key, full);
        const after = try hasher.pick(key, reduced);

        if (std.mem.eql(u8, before.id, "bravo")) {
            affected += 1;
        } else {
            try std.testing.expectEqualStrings(before.id, after.id);
        }
    }
    try std.testing.expect(affected > 0);
}

test "rendezvous topN returns descending scores with pick first" {
    // Arrange.
    const allocator = std.testing.allocator;
    const nodes = try allocator.dupe(Node, &.{
        .{ .id = "alpha", .weight = 1 },
        .{ .id = "bravo", .weight = 5 },
        .{ .id = "charlie", .weight = 2 },
        .{ .id = "delta", .weight = 3 },
        .{ .id = "echo", .weight = 1 },
    });
    defer allocator.free(nodes);

    const ranked_storage = try allocator.alloc(RankedNode, 3);
    defer allocator.free(ranked_storage);

    var hasher = Default.init();
    defer hasher.deinit();

    // Act.
    const picked = try hasher.pick("user:kain", nodes);
    const ranked = try hasher.topN("user:kain", nodes, 3, ranked_storage);

    // Assert.
    try std.testing.expectEqual(@as(usize, 3), ranked.len);
    try std.testing.expectEqualStrings(picked.id, ranked[0].node.id);
    try std.testing.expect(ranked[0].precedes(ranked[1]));
    try std.testing.expect(ranked[1].precedes(ranked[2]));
    try std.testing.expect(!std.mem.eql(u8, ranked[0].node.id, ranked[1].node.id));
    try std.testing.expect(!std.mem.eql(u8, ranked[1].node.id, ranked[2].node.id));
}

test "rendezvous topN truncates count to available nodes" {
    // Arrange.
    const allocator = std.testing.allocator;
    const nodes = try allocator.dupe(Node, &.{
        .{ .id = "alpha", .weight = 1 },
        .{ .id = "bravo", .weight = 1 },
    });
    defer allocator.free(nodes);

    const ranked_storage = try allocator.alloc(RankedNode, 4);
    defer allocator.free(ranked_storage);

    var hasher = Default.init();
    defer hasher.deinit();

    // Act.
    const ranked = try hasher.topN("small-ring", nodes, 4, ranked_storage);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), ranked.len);
    try std.testing.expect(ranked[0].precedes(ranked[1]));
}

test "rendezvous validation rejects unusable inputs" {
    // Arrange.
    var hasher = Default.init();
    defer hasher.deinit();

    const empty_nodes: []const Node = &.{};
    const bad_weight = [_]Node{.{ .id = "alpha", .weight = 0 }};
    const duplicate_ids = [_]Node{
        .{ .id = "alpha", .weight = 1 },
        .{ .id = "alpha", .weight = 2 },
    };
    const nodes = [_]Node{
        .{ .id = "alpha", .weight = 1 },
        .{ .id = "bravo", .weight = 1 },
    };
    var one_slot: [1]RankedNode = undefined;

    // Act and assert.
    try std.testing.expectError(error.NoNodes, hasher.pick("k", empty_nodes));
    try std.testing.expectError(error.InvalidWeight, hasher.pick("k", &bad_weight));
    try std.testing.expectError(error.DuplicateNode, hasher.pick("k", &duplicate_ids));
    try std.testing.expectError(error.OutputTooSmall, hasher.topN("k", &nodes, 2, &one_slot));
}
