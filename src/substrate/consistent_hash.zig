const std = @import("std");

pub const Ring = struct {
    allocator: std.mem.Allocator,
    vnodes_per_weight: usize,
    nodes: std.StringHashMap(usize),
    points: std.ArrayList(VNode) = .empty,

    const Self = @This();

    const VNode = struct {
        hash: u64,
        node_id: []const u8,
        replica: usize,
    };

    pub const Error = error{
        InvalidWeight,
        NodeExists,
        NotEnoughNodes,
    };

    pub fn init(allocator: std.mem.Allocator, vnodes_per_weight: usize) Self {
        return .{
            .allocator = allocator,
            .vnodes_per_weight = vnodes_per_weight,
            .nodes = std.StringHashMap(usize).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.nodes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.nodes.deinit();
        self.points.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn nodeCount(self: Self) usize {
        return self.nodes.count();
    }

    pub fn vnodeCount(self: Self) usize {
        return self.points.items.len;
    }

    pub fn addNode(self: *Self, id: []const u8, weight: usize) !void {
        if (weight == 0 or self.vnodes_per_weight == 0) return Error.InvalidWeight;
        if (self.nodes.contains(id)) return Error.NodeExists;

        const point_count = std.math.mul(usize, weight, self.vnodes_per_weight) catch
            return Error.InvalidWeight;

        const owned_id = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(owned_id);

        try self.points.ensureUnusedCapacity(self.allocator, point_count);
        try self.nodes.put(owned_id, weight);
        errdefer _ = self.nodes.remove(owned_id);

        for (0..point_count) |replica| {
            self.points.appendAssumeCapacity(.{
                .hash = vnodeHash(owned_id, replica),
                .node_id = owned_id,
                .replica = replica,
            });
        }

        self.sortPoints();
    }

    pub fn removeNode(self: *Self, id: []const u8) bool {
        const removed = self.nodes.fetchRemove(id) orelse return false;
        const owned_id = removed.key;

        var write_index: usize = 0;
        for (self.points.items) |point| {
            if (!std.mem.eql(u8, point.node_id, owned_id)) {
                self.points.items[write_index] = point;
                write_index += 1;
            }
        }
        self.points.shrinkRetainingCapacity(write_index);

        self.allocator.free(owned_id);
        return true;
    }

    pub fn locate(self: Self, key: []const u8) ?[]const u8 {
        if (self.points.items.len == 0) return null;
        return self.points.items[self.clockwiseIndex(keyHash(key))].node_id;
    }

    pub fn locateN(self: Self, allocator: std.mem.Allocator, key: []const u8, n: usize) ![][]const u8 {
        if (n > self.nodes.count()) return Error.NotEnoughNodes;

        const result = try allocator.alloc([]const u8, n);
        errdefer allocator.free(result);
        if (n == 0) return result;

        var found: usize = 0;
        var index = self.clockwiseIndex(keyHash(key));
        var steps: usize = 0;
        while (steps < self.points.items.len and found < n) : (steps += 1) {
            const node_id = self.points.items[index].node_id;
            if (!containsNode(result[0..found], node_id)) {
                result[found] = node_id;
                found += 1;
            }
            index = (index + 1) % self.points.items.len;
        }

        if (found != n) return Error.NotEnoughNodes;
        return result;
    }

    fn sortPoints(self: *Self) void {
        std.sort.heap(VNode, self.points.items, {}, vnodeLessThan);
    }

    fn clockwiseIndex(self: Self, hash: u64) usize {
        var low: usize = 0;
        var high: usize = self.points.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.points.items[mid].hash < hash) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if (low == self.points.items.len) return 0;
        return low;
    }
};

fn containsNode(nodes: []const []const u8, needle: []const u8) bool {
    for (nodes) |node| {
        if (std.mem.eql(u8, node, needle)) return true;
    }
    return false;
}

fn keyHash(key: []const u8) u64 {
    var wy = std.hash.Wyhash.init(0);
    wy.update(key);
    return wy.final();
}

fn vnodeHash(node_id: []const u8, replica: usize) u64 {
    var replica_buf: [8]u8 = undefined;
    const replica64: u64 = @intCast(replica);
    std.mem.writeInt(u64, &replica_buf, replica64, .big);

    var wy = std.hash.Wyhash.init(0);
    wy.update(node_id);
    wy.update(&replica_buf);
    return wy.final();
}

fn vnodeLessThan(_: void, a: Ring.VNode, b: Ring.VNode) bool {
    if (a.hash != b.hash) return a.hash < b.hash;

    return switch (std.mem.order(u8, a.node_id, b.node_id)) {
        .lt => true,
        .gt => false,
        .eq => a.replica < b.replica,
    };
}

fn expectNodeIndex(node_id: []const u8) !usize {
    if (std.mem.eql(u8, node_id, "node-a")) return 0;
    if (std.mem.eql(u8, node_id, "node-b")) return 1;
    if (std.mem.eql(u8, node_id, "node-c")) return 2;
    return error.UnknownNode;
}

test "single node owns all keys" {
    const allocator = std.testing.allocator;
    var ring = Ring.init(allocator, 64);
    defer ring.deinit();

    try ring.addNode("solo", 1);
    try std.testing.expectEqual(@as(usize, 1), ring.nodeCount());
    try std.testing.expectEqual(@as(usize, 64), ring.vnodeCount());

    for (0..1000) |i| {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{i});
        try std.testing.expectEqualStrings("solo", ring.locate(key).?);
    }
}

test "keys distribute roughly evenly across equal weight nodes" {
    const allocator = std.testing.allocator;
    var ring = Ring.init(allocator, 256);
    defer ring.deinit();

    try ring.addNode("node-a", 1);
    try ring.addNode("node-b", 1);
    try ring.addNode("node-c", 1);

    var counts = [_]usize{ 0, 0, 0 };
    const samples: usize = 12000;
    for (0..samples) |i| {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "route-{d}", .{i});
        const index = try expectNodeIndex(ring.locate(key).?);
        counts[index] += 1;
    }

    const ideal = samples / counts.len;
    const tolerance = ideal / 4;
    for (counts) |count| {
        try std.testing.expect(count >= ideal - tolerance);
        try std.testing.expect(count <= ideal + tolerance);
    }
}

test "removing a node only remaps keys owned by that node" {
    const allocator = std.testing.allocator;
    var ring = Ring.init(allocator, 128);
    defer ring.deinit();

    try ring.addNode("node-a", 1);
    try ring.addNode("node-b", 1);
    try ring.addNode("node-c", 1);

    const samples: usize = 5000;
    var original_owners: [samples]usize = undefined;
    for (0..samples) |i| {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "stable-key-{d}", .{i});
        original_owners[i] = try expectNodeIndex(ring.locate(key).?);
    }

    try std.testing.expect(ring.removeNode("node-b"));
    try std.testing.expectEqual(@as(usize, 2), ring.nodeCount());

    var removed_node_keys: usize = 0;
    var unaffected_keys: usize = 0;
    var moved_from_survivors: usize = 0;
    for (0..samples) |i| {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "stable-key-{d}", .{i});
        const new_owner = try expectNodeIndex(ring.locate(key).?);

        if (original_owners[i] == 1) {
            removed_node_keys += 1;
            try std.testing.expect(new_owner != 1);
        } else if (original_owners[i] == new_owner) {
            unaffected_keys += 1;
        } else {
            moved_from_survivors += 1;
        }
    }

    try std.testing.expect(removed_node_keys > 0);
    try std.testing.expect(unaffected_keys > 0);
    try std.testing.expectEqual(@as(usize, 0), moved_from_survivors);
}

test "locateN returns requested distinct nodes in ring order" {
    const allocator = std.testing.allocator;
    var ring = Ring.init(allocator, 64);
    defer ring.deinit();

    try ring.addNode("node-a", 1);
    try ring.addNode("node-b", 1);
    try ring.addNode("node-c", 1);

    const nodes = try ring.locateN(allocator, "replicated-route", 3);
    defer allocator.free(nodes);

    try std.testing.expectEqual(@as(usize, 3), nodes.len);
    try std.testing.expect(!std.mem.eql(u8, nodes[0], nodes[1]));
    try std.testing.expect(!std.mem.eql(u8, nodes[0], nodes[2]));
    try std.testing.expect(!std.mem.eql(u8, nodes[1], nodes[2]));

    const too_many = ring.locateN(allocator, "replicated-route", 4);
    try std.testing.expectError(Ring.Error.NotEnoughNodes, too_many);
}

test "ring lookups are deterministic" {
    const allocator = std.testing.allocator;
    var first = Ring.init(allocator, 96);
    defer first.deinit();
    var second = Ring.init(allocator, 96);
    defer second.deinit();

    try first.addNode("node-a", 1);
    try first.addNode("node-b", 2);
    try first.addNode("node-c", 1);

    try second.addNode("node-c", 1);
    try second.addNode("node-a", 1);
    try second.addNode("node-b", 2);

    for (0..1000) |i| {
        var key_buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "det-key-{d}", .{i});
        try std.testing.expectEqualStrings(first.locate(key).?, second.locate(key).?);

        const first_nodes = try first.locateN(allocator, key, 3);
        defer allocator.free(first_nodes);
        const second_nodes = try second.locateN(allocator, key, 3);
        defer allocator.free(second_nodes);

        for (first_nodes, second_nodes) |first_node, second_node| {
            try std.testing.expectEqualStrings(first_node, second_node);
        }
    }
}

test "invalid and duplicate node operations are rejected" {
    const allocator = std.testing.allocator;
    var ring = Ring.init(allocator, 16);
    defer ring.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), ring.locate("missing"));
    try std.testing.expectError(Ring.Error.InvalidWeight, ring.addNode("node-a", 0));

    try ring.addNode("node-a", 1);
    try std.testing.expectError(Ring.Error.NodeExists, ring.addNode("node-a", 1));
    try std.testing.expect(!ring.removeNode("node-b"));
    try std.testing.expect(ring.removeNode("node-a"));
    try std.testing.expectEqual(@as(?[]const u8, null), ring.locate("missing"));
}
