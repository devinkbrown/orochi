// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Multi-hop mesh topology view for the Suimyaku peer graph.
//!
//! This module is pure graph state: callers provide the peer links, choose the
//! local node, and own all transport decisions. The topology stores sorted
//! undirected adjacency and a BFS closure rooted at the local node so routing
//! queries are deterministic and allocation-free after initialization.

const std = @import("std");
const route_table = @import("route_table.zig");

pub const NodeId = route_table.NodeId;

/// One undirected peer link.
pub const Edge = struct {
    a: NodeId,
    b: NodeId,
};

pub const Error = std.mem.Allocator.Error || error{
    DistanceOverflow,
};

const Route = struct {
    distance: u32,
    next_hop: ?NodeId,
};

/// Immutable topology snapshot rooted at one local node.
pub const Topology = struct {
    local: NodeId,
    adjacency: std.AutoHashMapUnmanaged(NodeId, std.ArrayListUnmanaged(NodeId)) = .empty,
    routes: std.AutoHashMapUnmanaged(NodeId, Route) = .empty,
    reachable_nodes: std.ArrayListUnmanaged(NodeId) = .empty,

    /// Build a topology snapshot from undirected edges and the local node id.
    pub fn init(allocator: std.mem.Allocator, local: NodeId, edges: []const Edge) Error!Topology {
        var self = Topology{ .local = local };
        errdefer self.deinit(allocator);

        try self.ensureNode(allocator, local);
        for (edges) |edge| try self.addEdge(allocator, edge);
        self.sortAdjacency();
        try self.computeRoutes(allocator);

        return self;
    }

    /// Release all storage owned by this snapshot.
    pub fn deinit(self: *Topology, allocator: std.mem.Allocator) void {
        var it = self.adjacency.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        self.adjacency.deinit(allocator);
        self.routes.deinit(allocator);
        self.reachable_nodes.deinit(allocator);
        self.* = undefined;
    }

    /// Return the first hop toward `dest`, or null for local/unreachable nodes.
    pub fn nextHop(self: *const Topology, dest: NodeId) ?NodeId {
        const route = self.routes.get(dest) orelse return null;
        return route.next_hop;
    }

    /// Return the shortest-path hop count from the local node to `dest`.
    pub fn distance(self: *const Topology, dest: NodeId) ?u32 {
        const route = self.routes.get(dest) orelse return null;
        return route.distance;
    }

    /// Return the local partition in deterministic BFS order.
    pub fn reachable(self: *const Topology) []const NodeId {
        return self.reachable_nodes.items;
    }

    /// Return whether `other` is outside the local partition.
    pub fn partitioned(self: *const Topology, other: NodeId) bool {
        return !self.routes.contains(other);
    }

    fn addEdge(self: *Topology, allocator: std.mem.Allocator, edge: Edge) Error!void {
        try self.ensureNode(allocator, edge.a);
        try self.ensureNode(allocator, edge.b);

        if (edge.a == edge.b) return;
        try self.addNeighbor(allocator, edge.a, edge.b);
        try self.addNeighbor(allocator, edge.b, edge.a);
    }

    fn ensureNode(self: *Topology, allocator: std.mem.Allocator, node: NodeId) Error!void {
        if (self.adjacency.contains(node)) return;
        try self.adjacency.put(allocator, node, .empty);
    }

    fn addNeighbor(
        self: *Topology,
        allocator: std.mem.Allocator,
        from: NodeId,
        to: NodeId,
    ) Error!void {
        const neighbors = self.adjacency.getPtr(from).?;
        for (neighbors.items) |existing| {
            if (existing == to) return;
        }
        try neighbors.append(allocator, to);
    }

    fn sortAdjacency(self: *Topology) void {
        var it = self.adjacency.iterator();
        while (it.next()) |entry| {
            std.mem.sort(NodeId, entry.value_ptr.items, {}, lessNode);
        }
    }

    fn computeRoutes(self: *Topology, allocator: std.mem.Allocator) Error!void {
        self.routes.clearRetainingCapacity();
        self.reachable_nodes.clearRetainingCapacity();

        var queue: std.ArrayListUnmanaged(NodeId) = .empty;
        defer queue.deinit(allocator);

        try self.routes.put(allocator, self.local, .{
            .distance = 0,
            .next_hop = null,
        });
        try self.reachable_nodes.append(allocator, self.local);
        try queue.append(allocator, self.local);

        var head: usize = 0;
        while (head < queue.items.len) : (head += 1) {
            const current = queue.items[head];
            const current_route = self.routes.get(current).?;
            const neighbors = self.adjacency.get(current) orelse continue;

            for (neighbors.items) |neighbor| {
                if (self.routes.contains(neighbor)) continue;
                if (current_route.distance == std.math.maxInt(u32)) return error.DistanceOverflow;

                const next_hop = if (current == self.local) neighbor else current_route.next_hop.?;
                const next_distance = current_route.distance + 1;
                try self.routes.put(allocator, neighbor, .{
                    .distance = next_distance,
                    .next_hop = next_hop,
                });
                try self.reachable_nodes.append(allocator, neighbor);
                try queue.append(allocator, neighbor);
            }
        }
    }
};

fn lessNode(_: void, a: NodeId, b: NodeId) bool {
    return a < b;
}

test "linear chain next hop and distance" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
        .{ .a = 3, .b = 4 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(2));
    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(3));
    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(4));
    try std.testing.expectEqual(@as(?u32, 0), topo.distance(1));
    try std.testing.expectEqual(@as(?u32, 1), topo.distance(2));
    try std.testing.expectEqual(@as(?u32, 2), topo.distance(3));
    try std.testing.expectEqual(@as(?u32, 3), topo.distance(4));
    try std.testing.expectEqualSlices(NodeId, &.{ 1, 2, 3, 4 }, topo.reachable());
}

test "partitioned component is detected" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 10, .b = 11 },
        .{ .a = 20, .b = 21 },
    };

    var topo = try Topology.init(allocator, 10, &edges);
    defer topo.deinit(allocator);

    try std.testing.expect(!topo.partitioned(10));
    try std.testing.expect(!topo.partitioned(11));
    try std.testing.expect(topo.partitioned(20));
    try std.testing.expect(topo.partitioned(21));
    try std.testing.expectEqualSlices(NodeId, &.{ 10, 11 }, topo.reachable());
}

test "tie break chooses lowest next hop deterministically" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 3 },
        .{ .a = 4, .b = 8 },
        .{ .a = 1, .b = 2 },
        .{ .a = 3, .b = 8 },
        .{ .a = 2, .b = 8 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, 2), topo.nextHop(8));
    try std.testing.expectEqual(@as(?u32, 2), topo.distance(8));
    try std.testing.expectEqualSlices(NodeId, &.{ 1, 2, 3, 8, 4 }, topo.reachable());
}

test "unreachable destination returns null" {
    const allocator = std.testing.allocator;
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 3, .b = 4 },
    };

    var topo = try Topology.init(allocator, 1, &edges);
    defer topo.deinit(allocator);

    try std.testing.expectEqual(@as(?NodeId, null), topo.nextHop(4));
    try std.testing.expectEqual(@as(?u32, null), topo.distance(4));
    try std.testing.expect(topo.partitioned(4));
}
