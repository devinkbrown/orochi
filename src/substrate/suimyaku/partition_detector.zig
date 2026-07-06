// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mesh partition + quorum detector over the Suimyaku peer graph.
//!
//! Pure graph logic: callers supply the current mesh view (the set of known
//! nodes with per-node liveness, plus the undirected edge set linking them) and
//! the detector answers reachability, partition, connected-component, and quorum
//! questions from the perspective of the local node. There are NO sockets, NO
//! daemon types, and NO I/O — only a deterministic, allocation-free closure over
//! the supplied topology.
//!
//! Liveness semantics: only non-`dead` nodes participate in the graph. A `dead`
//! node is excluded from node counts, component counts, reachability, and quorum
//! math entirely (as if it were never in the mesh). `suspect` nodes still count
//! and still relay — they are merely flagged unhealthy upstream, not removed.
//!
//! Edges referencing an unknown or dead endpoint are ignored, so a stale edge to
//! a node that just died cannot keep a partition artificially "connected".

const std = @import("std");

/// Mesh node identifier. Defined locally so this module imports only `std`.
pub const NodeId = u64;

/// Maximum number of distinct known nodes a single view may hold.
pub const max_nodes: usize = 256;

/// One undirected mesh link between two nodes.
pub const Edge = struct {
    a: NodeId,
    b: NodeId,
};

/// Per-node health classification. Only non-`dead` nodes form the live graph.
pub const Liveness = enum {
    alive,
    suspect,
    dead,
};

/// Transition reported by `step` when the reachable-from-local set changes in a
/// way that crosses a partition boundary.
///
/// * `none`  — no partition-relevant change since the previous snapshot.
/// * `split` — one or more previously-reachable (or newly-known) live nodes are
///             now unreachable from local; payload is the unreachable live set.
/// * `heal`  — local was partitioned on the previous snapshot and now reaches
///             every live known node again.
pub const PartitionEvent = union(enum) {
    none,
    split: []const NodeId,
    heal,
};

pub const Error = error{
    TooManyNodes,
    LengthMismatch,
    DuplicateNode,
};

/// Stateful partition detector over a fixed-capacity mesh view.
///
/// Usage: call `update` (or `setNodes` + `setEdges`) with the current view, then
/// query `reachableFrom` / `isPartitioned` / `componentCount` / `hasQuorum`. For
/// transition events across successive views, call `step` after each `update`.
pub const Detector = struct {
    /// Known node ids, in insertion order. Length is `node_count`.
    nodes: [max_nodes]NodeId = undefined,
    /// Liveness parallel to `nodes`.
    live: [max_nodes]Liveness = undefined,
    node_count: usize = 0,

    /// Adjacency over node *indices* (into `nodes`), restricted to live nodes.
    /// `adj[i]` lists indices reachable in one hop from node index `i`.
    adj: [max_nodes][max_nodes]u16 = undefined,
    adj_len: [max_nodes]usize = @splat(0),

    /// Previous reachable-from-local set (sorted node ids) and whether the
    /// previous snapshot considered local partitioned. Used by `step`.
    prev_reachable: [max_nodes]NodeId = undefined,
    prev_reachable_len: usize = 0,
    prev_partitioned: bool = false,
    have_prev: bool = false,

    /// Scratch buffer for the most recent split payload, so `step` can return a
    /// stable slice owned by the detector.
    split_buf: [max_nodes]NodeId = undefined,

    /// Create an empty detector. No allocation is performed; the detector is a
    /// plain value and needs no `deinit`.
    pub fn init() Detector {
        return .{};
    }

    // ---- view loading -----------------------------------------------------

    /// Replace the known-node set and per-node liveness. `ids` and `liveness`
    /// must be the same length, hold no duplicate ids, and fit within
    /// `max_nodes`. Clears any previously-loaded edges.
    pub fn setNodes(self: *Detector, ids: []const NodeId, liveness: []const Liveness) Error!void {
        if (ids.len != liveness.len) return Error.LengthMismatch;
        if (ids.len > max_nodes) return Error.TooManyNodes;

        // Reject duplicates: a duplicate id would make index lookup ambiguous.
        for (ids, 0..) |id, i| {
            for (ids[0..i]) |prev| {
                if (prev == id) return Error.DuplicateNode;
            }
        }

        self.node_count = ids.len;
        for (ids, 0..) |id, i| {
            self.nodes[i] = id;
            self.live[i] = liveness[i];
        }
        // Edges depend on node indices, so a node change invalidates them.
        for (0..self.node_count) |i| self.adj_len[i] = 0;
    }

    /// Replace the edge set. Edges with an unknown, dead, or self endpoint are
    /// silently ignored. Must be called after `setNodes` for a given view.
    pub fn setEdges(self: *Detector, edges: []const Edge) void {
        for (0..self.node_count) |i| self.adj_len[i] = 0;
        for (edges) |edge| {
            if (edge.a == edge.b) continue;
            const ia = self.indexOfLive(edge.a) orelse continue;
            const ib = self.indexOfLive(edge.b) orelse continue;
            self.addDirected(ia, ib);
            self.addDirected(ib, ia);
        }
    }

    /// Convenience: load nodes and edges in one call.
    pub fn update(
        self: *Detector,
        ids: []const NodeId,
        liveness: []const Liveness,
        edges: []const Edge,
    ) Error!void {
        try self.setNodes(ids, liveness);
        self.setEdges(edges);
    }

    // ---- queries ----------------------------------------------------------

    /// Fill `out` with the node ids reachable from `local` over live edges
    /// (including `local` itself when live), returning the count written. Result
    /// is sorted ascending for determinism. If `local` is unknown or dead the
    /// result is empty. Caller must size `out` to at least the live-node count
    /// (`max_nodes` is always safe).
    pub fn reachableFrom(self: *const Detector, local: NodeId, out: []NodeId) usize {
        const start = self.indexOfLive(local) orelse return 0;

        var seen = @as([max_nodes]bool, @splat(false));
        var queue: [max_nodes]u16 = undefined;
        var head: usize = 0;
        var tail: usize = 0;

        seen[start] = true;
        queue[tail] = @intCast(start);
        tail += 1;

        var count: usize = 0;
        while (head < tail) {
            const cur = queue[head];
            head += 1;
            if (count < out.len) out[count] = self.nodes[cur];
            count += 1;
            for (self.adj[cur][0..self.adj_len[cur]]) |nb| {
                if (!seen[nb]) {
                    seen[nb] = true;
                    queue[tail] = nb;
                    tail += 1;
                }
            }
        }

        std.mem.sort(NodeId, out[0..@min(count, out.len)], {}, std.sort.asc(NodeId));
        return count;
    }

    /// Number of live known nodes (liveness != dead).
    pub fn liveCount(self: *const Detector) usize {
        var n: usize = 0;
        for (0..self.node_count) |i| {
            if (self.live[i] != .dead) n += 1;
        }
        return n;
    }

    /// True if any live known node is NOT reachable from `local`. An unknown or
    /// dead `local` with at least one live node counts as partitioned (local
    /// cannot see the mesh). A mesh with no live nodes is not partitioned.
    pub fn isPartitioned(self: *const Detector, local: NodeId) bool {
        const live = self.liveCount();
        if (live == 0) return false;
        var buf: [max_nodes]NodeId = undefined;
        const reached = self.reachableFrom(local, &buf);
        return reached < live;
    }

    /// Number of connected components among live nodes (dead nodes ignored).
    pub fn componentCount(self: *const Detector) usize {
        var seen = @as([max_nodes]bool, @splat(false));
        var components: usize = 0;
        for (0..self.node_count) |i| {
            if (self.live[i] == .dead) continue;
            if (seen[i]) continue;
            components += 1;
            self.markComponent(@intCast(i), &seen);
        }
        return components;
    }

    /// True if local's reachable component holds a strict majority (> half) of
    /// all live known nodes. With zero live nodes there is no quorum.
    pub fn hasQuorum(self: *const Detector, local: NodeId) bool {
        const live = self.liveCount();
        if (live == 0) return false;
        var buf: [max_nodes]NodeId = undefined;
        const reached = self.reachableFrom(local, &buf);
        // Strict majority: reached * 2 > live.
        return reached * 2 > live;
    }

    // ---- transition tracking ---------------------------------------------

    /// Compare the current view against the previously-recorded snapshot and
    /// report a split/heal transition, then record the current snapshot as the
    /// new baseline. The first call after construction establishes a baseline
    /// and reports `none`.
    ///
    /// A returned `split` payload is a slice into detector-owned storage; it is
    /// valid until the next `step` call.
    pub fn step(self: *Detector, local: NodeId) PartitionEvent {
        var now_buf: [max_nodes]NodeId = undefined;
        const now_len = self.reachableFrom(local, &now_buf);
        const now_reach = now_buf[0..now_len];
        const partitioned_now = self.isPartitioned(local);

        var event: PartitionEvent = .none;

        if (self.have_prev) {
            // Heal: previously partitioned, now fully connected.
            if (self.prev_partitioned and !partitioned_now) {
                event = .heal;
            } else if (partitioned_now) {
                // Split: collect live nodes not currently reachable from local.
                // Report when we just became partitioned, or while remaining
                // partitioned the reachable membership changed (deepened or
                // shifted split). A steady-state partition reports nothing.
                const split_len = self.collectUnreachableLive(now_reach, &self.split_buf);
                if (split_len > 0) {
                    const transitioned_into = !self.prev_partitioned;
                    const set_changed = !slicesEqual(
                        self.prev_reachable[0..self.prev_reachable_len],
                        now_reach,
                    );
                    if (transitioned_into or set_changed) {
                        event = .{ .split = self.split_buf[0..split_len] };
                    }
                }
            }
        }

        // Record baseline.
        @memcpy(self.prev_reachable[0..now_len], now_reach);
        self.prev_reachable_len = now_len;
        self.prev_partitioned = partitioned_now;
        self.have_prev = true;

        return event;
    }

    /// Stateless variant: given the caller's own previous reachable set, report
    /// the transition implied by the current view without mutating detector
    /// state. The returned `split` slice points into `scratch`, which the caller
    /// supplies and must keep alive while the event is used.
    pub fn diff(
        self: *const Detector,
        local: NodeId,
        prev_reachable: []const NodeId,
        scratch: []NodeId,
    ) PartitionEvent {
        var now_buf: [max_nodes]NodeId = undefined;
        const now_len = self.reachableFrom(local, &now_buf);
        const now_reach = now_buf[0..now_len];
        const live = self.liveCount();

        const prev_partitioned = prev_reachable.len < live and live > 0;
        const now_partitioned = now_len < live and live > 0;

        if (prev_partitioned and !now_partitioned) return .heal;
        if (now_partitioned) {
            const split_len = self.collectUnreachableLive(now_reach, scratch);
            if (split_len > 0 and (!prev_partitioned or
                !slicesEqual(prev_reachable, now_reach)))
            {
                return .{ .split = scratch[0..split_len] };
            }
        }
        return .none;
    }

    // ---- internals --------------------------------------------------------

    fn indexOfLive(self: *const Detector, id: NodeId) ?usize {
        for (0..self.node_count) |i| {
            if (self.nodes[i] == id) {
                return if (self.live[i] == .dead) null else i;
            }
        }
        return null;
    }

    fn addDirected(self: *Detector, from: usize, to: usize) void {
        // Skip if edge already present (idempotent against duplicate inputs).
        for (self.adj[from][0..self.adj_len[from]]) |existing| {
            if (existing == @as(u16, @intCast(to))) return;
        }
        self.adj[from][self.adj_len[from]] = @intCast(to);
        self.adj_len[from] += 1;
    }

    fn markComponent(self: *const Detector, start: u16, seen: *[max_nodes]bool) void {
        var queue: [max_nodes]u16 = undefined;
        var head: usize = 0;
        var tail: usize = 0;
        seen[start] = true;
        queue[tail] = start;
        tail += 1;
        while (head < tail) {
            const cur = queue[head];
            head += 1;
            for (self.adj[cur][0..self.adj_len[cur]]) |nb| {
                if (!seen[nb]) {
                    seen[nb] = true;
                    queue[tail] = nb;
                    tail += 1;
                }
            }
        }
    }

    /// Fill `out` with live node ids that are NOT in the sorted `reachable` set,
    /// returning the count. `out` must hold at least `liveCount` ids.
    fn collectUnreachableLive(
        self: *const Detector,
        reachable: []const NodeId,
        out: []NodeId,
    ) usize {
        var n: usize = 0;
        for (0..self.node_count) |i| {
            if (self.live[i] == .dead) continue;
            const id = self.nodes[i];
            if (!sortedContains(reachable, id)) {
                if (n < out.len) out[n] = id;
                n += 1;
            }
        }
        return n;
    }
};

fn sortedContains(sorted: []const NodeId, id: NodeId) bool {
    return std.sort.binarySearch(NodeId, sorted, id, orderNode) != null;
}

fn orderNode(target: NodeId, item: NodeId) std.math.Order {
    return std.math.order(target, item);
}

fn slicesEqual(a: []const NodeId, b: []const NodeId) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

// ===========================================================================
// One-shot snapshot analysis
// ===========================================================================

/// One node in an assembled mesh topology: a node id and the parent it is
/// reachable through (its uplink). A null uplink contributes no edge.
pub const TopoNode = struct {
    node_id: NodeId,
    uplink: ?NodeId = null,
};

/// Point-in-time partition statistics from the local node's perspective.
pub const Stats = struct {
    /// Distinct known nodes (local plus every node id / uplink in the topology).
    known: usize,
    /// Nodes reachable from local over the current edges (includes local).
    reachable: usize,
    /// Known nodes NOT reachable from local (`known - reachable`).
    partitioned: usize,
    /// Connected components among the known nodes.
    components: usize,
    /// True when at least one known node is unreachable from local.
    is_partitioned: bool,
};

/// Analyze a mesh topology from `local`'s perspective. `topo` lists known nodes
/// with their uplink (parent) edges; `local` is always treated as a known live
/// node even if absent from `topo`. Each (node_id, uplink) pair contributes an
/// undirected edge. All nodes are treated as live. Nodes beyond `max_nodes` are
/// ignored. Allocation-free.
pub fn analyze(local: NodeId, topo: []const TopoNode) Stats {
    var ids: [max_nodes]NodeId = undefined;
    var n: usize = 0;
    ids[0] = local;
    n = 1;
    for (topo) |t| {
        n = appendUnique(&ids, n, t.node_id);
        if (t.uplink) |up| n = appendUnique(&ids, n, up);
    }

    var edges: [max_nodes]Edge = undefined;
    var en: usize = 0;
    for (topo) |t| {
        if (t.uplink) |up| {
            if (up == t.node_id) continue;
            if (en < edges.len) {
                edges[en] = .{ .a = t.node_id, .b = up };
                en += 1;
            }
        }
    }

    var live: [max_nodes]Liveness = undefined;
    for (0..n) |i| live[i] = .alive;

    var det = Detector.init();
    det.update(ids[0..n], live[0..n], edges[0..en]) catch {
        return .{ .known = n, .reachable = n, .partitioned = 0, .components = 1, .is_partitioned = false };
    };

    var rbuf: [max_nodes]NodeId = undefined;
    const reached = @min(det.reachableFrom(local, &rbuf), n);
    return .{
        .known = n,
        .reachable = reached,
        .partitioned = n - reached,
        .components = det.componentCount(),
        .is_partitioned = det.isPartitioned(local),
    };
}

fn appendUnique(buf: []NodeId, len: usize, id: NodeId) usize {
    for (buf[0..len]) |existing| {
        if (existing == id) return len;
    }
    if (len < buf.len) {
        buf[len] = id;
        return len + 1;
    }
    return len;
}

/// Persistent "expected membership" set for partition transition detection.
///
/// A live mesh view (assembled from peer registries) self-heals: when a link
/// drops, the nodes reachable only through it vanish from the current topology,
/// so a snapshot can never tell a partition apart from a graceful departure.
/// `SeenSet` remembers every node id observed, with the time it was last seen,
/// so a node that disappears stays "expected" — and therefore shows up as
/// unreachable (a split) — until it ages out past a TTL, at which point its
/// removal heals the view. Fixed-capacity, allocation-free.
pub fn SeenSet(comptime cap: usize) type {
    return struct {
        const Self = @This();
        const Entry = struct { node_id: NodeId, last_seen_ms: u64 };

        entries: [cap]Entry = undefined,
        len: usize = 0,

        /// Record `id` as seen at `now_ms`, refreshing an existing entry or
        /// inserting a new one (dropped silently when at capacity).
        pub fn observe(self: *Self, id: NodeId, now_ms: u64) void {
            for (self.entries[0..self.len]) |*e| {
                if (e.node_id == id) {
                    e.last_seen_ms = now_ms;
                    return;
                }
            }
            if (self.len < cap) {
                self.entries[self.len] = .{ .node_id = id, .last_seen_ms = now_ms };
                self.len += 1;
            }
        }

        /// Drop entries not seen within `ttl_ms` of `now_ms`, returning the count
        /// removed. Order is not preserved (swap-remove).
        pub fn prune(self: *Self, now_ms: u64, ttl_ms: u64) usize {
            var removed: usize = 0;
            var i: usize = 0;
            while (i < self.len) {
                if (now_ms >= self.entries[i].last_seen_ms +| ttl_ms) {
                    self.entries[i] = self.entries[self.len - 1];
                    self.len -= 1;
                    removed += 1;
                } else {
                    i += 1;
                }
            }
            return removed;
        }

        /// Copy the current node ids into `out`, returning the count written.
        pub fn ids(self: *const Self, out: []NodeId) usize {
            var n: usize = 0;
            for (self.entries[0..self.len]) |e| {
                if (n == out.len) break;
                out[n] = e.node_id;
                n += 1;
            }
            return n;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }
    };
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "SeenSet: observe inserts, refreshes, and dedupes" {
    var s = SeenSet(8){};
    s.observe(10, 100);
    s.observe(20, 100);
    s.observe(10, 200); // refresh, not a new entry
    try testing.expectEqual(@as(usize, 2), s.count());

    var buf: [8]NodeId = undefined;
    const n = s.ids(&buf);
    try testing.expectEqual(@as(usize, 2), n);
}

test "SeenSet: prune drops entries past the TTL, keeps fresh ones" {
    var s = SeenSet(8){};
    s.observe(10, 1_000); // stale at now=10_000 with ttl=5_000
    s.observe(20, 8_000); // fresh
    const removed = s.prune(10_000, 5_000);
    try testing.expectEqual(@as(usize, 1), removed);
    try testing.expectEqual(@as(usize, 1), s.count());

    var buf: [8]NodeId = undefined;
    const n = s.ids(&buf);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(NodeId, 20), buf[0]);
}

test "SeenSet: a dropped node stays known until it ages out, then heals" {
    // Model the split/heal lifecycle: node 1 (local) stays live and is
    // re-observed each refresh; node 2 was last seen at t=1000, then dropped.
    var s = SeenSet(8){};
    s.observe(1, 1_000);
    s.observe(2, 1_000);
    // At t=2000 node 2 is still within TTL -> still "expected" (would be a split
    // if it is now unreachable). Local node 1 is refreshed as it stays live.
    s.observe(1, 2_000);
    try testing.expectEqual(@as(usize, 0), s.prune(2_000, 5_000));
    try testing.expectEqual(@as(usize, 2), s.count());
    // Local keeps being refreshed; node 2 is not. At t=7000 node 2 has aged out
    // (last seen 1000, 7000 >= 6000) -> forgotten, healing the view; node 1
    // (last seen 6000) survives.
    s.observe(1, 6_000);
    try testing.expectEqual(@as(usize, 1), s.prune(7_000, 5_000));
    try testing.expectEqual(@as(usize, 1), s.count());
    var buf: [8]NodeId = undefined;
    try testing.expectEqual(@as(usize, 1), s.ids(&buf));
    try testing.expectEqual(@as(NodeId, 1), buf[0]);
}

test "analyze: lone node is fully reachable, no partition" {
    const stats = analyze(1, &.{});
    try testing.expectEqual(@as(usize, 1), stats.known);
    try testing.expectEqual(@as(usize, 1), stats.reachable);
    try testing.expectEqual(@as(usize, 0), stats.partitioned);
    try testing.expectEqual(@as(usize, 1), stats.components);
    try testing.expect(!stats.is_partitioned);
}

test "analyze: star of direct peers is one reachable component" {
    // local=1, peers 2 and 3 both uplinked to 1.
    const topo = [_]TopoNode{
        .{ .node_id = 2, .uplink = 1 },
        .{ .node_id = 3, .uplink = 1 },
    };
    const stats = analyze(1, &topo);
    try testing.expectEqual(@as(usize, 3), stats.known);
    try testing.expectEqual(@as(usize, 3), stats.reachable);
    try testing.expectEqual(@as(usize, 0), stats.partitioned);
    try testing.expectEqual(@as(usize, 1), stats.components);
    try testing.expect(!stats.is_partitioned);
}

test "analyze: multi-hop chain counts transitively reachable nodes" {
    // local=1 -> 2 -> 3 (node 3 reachable via 2, two hops).
    const topo = [_]TopoNode{
        .{ .node_id = 2, .uplink = 1 },
        .{ .node_id = 3, .uplink = 2 },
    };
    const stats = analyze(1, &topo);
    try testing.expectEqual(@as(usize, 3), stats.known);
    try testing.expectEqual(@as(usize, 3), stats.reachable);
    try testing.expectEqual(@as(usize, 0), stats.partitioned);
    try testing.expect(!stats.is_partitioned);
}

test "analyze: an island the local node cannot reach is partitioned" {
    // {1,2} connected; {3,4} a separate island (3 uplinked to 4, 4 rootless).
    const topo = [_]TopoNode{
        .{ .node_id = 2, .uplink = 1 },
        .{ .node_id = 3, .uplink = 4 },
        .{ .node_id = 4, .uplink = null },
    };
    const stats = analyze(1, &topo);
    try testing.expectEqual(@as(usize, 4), stats.known);
    try testing.expectEqual(@as(usize, 2), stats.reachable);
    try testing.expectEqual(@as(usize, 2), stats.partitioned);
    try testing.expectEqual(@as(usize, 2), stats.components);
    try testing.expect(stats.is_partitioned);
}

test "analyze: duplicate topology entries from multiple peers dedupe" {
    // The same nodes/edges reported twice (as two peers' registries would).
    const topo = [_]TopoNode{
        .{ .node_id = 2, .uplink = 1 },
        .{ .node_id = 3, .uplink = 1 },
        .{ .node_id = 2, .uplink = 1 },
        .{ .node_id = 3, .uplink = 1 },
    };
    const stats = analyze(1, &topo);
    try testing.expectEqual(@as(usize, 3), stats.known);
    try testing.expectEqual(@as(usize, 3), stats.reachable);
    try testing.expectEqual(@as(usize, 0), stats.partitioned);
}

test "fully-connected mesh: not partitioned, single component, quorum" {
    // Arrange: a triangle a-b-c, all alive.
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2, 3 };
    const live = [_]Liveness{ .alive, .alive, .alive };
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
        .{ .a = 1, .b = 3 },
    };
    try d.update(&ids, &live, &edges);

    // Act + Assert.
    try testing.expect(!d.isPartitioned(1));
    try testing.expectEqual(@as(usize, 1), d.componentCount());
    try testing.expect(d.hasQuorum(1));
    try testing.expectEqual(@as(usize, 3), d.liveCount());
}

test "reachableFrom returns sorted full set on a chain a-b-c-d" {
    // Arrange: linear chain 10-20-30-40.
    var d = Detector.init();
    const ids = [_]NodeId{ 10, 20, 30, 40 };
    const live = [_]Liveness{ .alive, .alive, .alive, .alive };
    const edges = [_]Edge{
        .{ .a = 10, .b = 20 },
        .{ .a = 20, .b = 30 },
        .{ .a = 30, .b = 40 },
    };
    try d.update(&ids, &live, &edges);

    // Act.
    var out: [max_nodes]NodeId = undefined;
    const n = d.reachableFrom(10, &out);

    // Assert: all four reachable, ascending.
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualSlices(NodeId, &[_]NodeId{ 10, 20, 30, 40 }, out[0..n]);

    // From the middle node we still reach everyone.
    const n2 = d.reachableFrom(30, &out);
    try testing.expectEqual(@as(usize, 4), n2);
}

test "cut isolating a node: partitioned, two components, minority loses quorum" {
    // Arrange: cluster {1,2,3} fully connected; node 4 isolated (no edges).
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2, 3, 4 };
    const live = [_]Liveness{ .alive, .alive, .alive, .alive };
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
        .{ .a = 1, .b = 3 },
    };
    try d.update(&ids, &live, &edges);

    // Assert: partition exists, two components.
    try testing.expect(d.isPartitioned(1));
    try testing.expect(d.isPartitioned(4));
    try testing.expectEqual(@as(usize, 2), d.componentCount());

    // Majority side (3 of 4) keeps quorum; isolated node (1 of 4) loses it.
    try testing.expect(d.hasQuorum(1));
    try testing.expect(!d.hasQuorum(4));
}

test "even split denies quorum to both halves" {
    // Arrange: {1,2} and {3,4}, no link between halves.
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2, 3, 4 };
    const live = [_]Liveness{ .alive, .alive, .alive, .alive };
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 3, .b = 4 },
    };
    try d.update(&ids, &live, &edges);

    // Assert: 2 of 4 is not a strict majority.
    try testing.expect(d.isPartitioned(1));
    try testing.expectEqual(@as(usize, 2), d.componentCount());
    try testing.expect(!d.hasQuorum(1));
    try testing.expect(!d.hasQuorum(3));
}

test "dead node is excluded from counts, components, and quorum" {
    // Arrange: chain 1-2-3 with edge 3-4, but node 4 is dead.
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2, 3, 4 };
    const live = [_]Liveness{ .alive, .alive, .alive, .dead };
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
        .{ .a = 3, .b = 4 }, // ignored: endpoint 4 is dead.
    };
    try d.update(&ids, &live, &edges);

    // Assert: only 3 live nodes, all reachable, one component, quorum holds.
    try testing.expectEqual(@as(usize, 3), d.liveCount());
    try testing.expect(!d.isPartitioned(1));
    try testing.expectEqual(@as(usize, 1), d.componentCount());
    try testing.expect(d.hasQuorum(1));

    // A dead local cannot see the mesh.
    var out: [max_nodes]NodeId = undefined;
    try testing.expectEqual(@as(usize, 0), d.reachableFrom(4, &out));
}

test "suspect nodes still participate in the graph" {
    // Arrange: 1-2-3 where 2 is suspect (unhealthy but not dead).
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2, 3 };
    const live = [_]Liveness{ .alive, .suspect, .alive };
    const edges = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
    };
    try d.update(&ids, &live, &edges);

    // Assert: suspect relays, so the mesh stays whole.
    try testing.expectEqual(@as(usize, 3), d.liveCount());
    try testing.expect(!d.isPartitioned(1));
    try testing.expectEqual(@as(usize, 1), d.componentCount());
}

test "step reports split then heal across successive views" {
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2, 3 };
    const live = [_]Liveness{ .alive, .alive, .alive };

    // View 0: fully connected -> baseline, no event.
    const whole = [_]Edge{
        .{ .a = 1, .b = 2 },
        .{ .a = 2, .b = 3 },
        .{ .a = 1, .b = 3 },
    };
    try d.update(&ids, &live, &whole);
    try testing.expect(d.step(1) == .none);

    // View 1: node 3 cut off -> split, payload {3}.
    const cut = [_]Edge{.{ .a = 1, .b = 2 }};
    try d.update(&ids, &live, &cut);
    const split_ev = d.step(1);
    switch (split_ev) {
        .split => |unreachable_set| {
            try testing.expectEqualSlices(NodeId, &[_]NodeId{3}, unreachable_set);
        },
        else => return error.TestUnexpectedResult,
    }

    // View 2: same cut -> no new transition.
    try d.update(&ids, &live, &cut);
    try testing.expect(d.step(1) == .none);

    // View 3: link restored -> heal.
    try d.update(&ids, &live, &whole);
    try testing.expect(d.step(1) == .heal);
}

test "diff is stateless and matches step semantics" {
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2, 3 };
    const live = [_]Liveness{ .alive, .alive, .alive };

    // Current view: 3 is isolated.
    const cut = [_]Edge{.{ .a = 1, .b = 2 }};
    try d.update(&ids, &live, &cut);

    // Previously local reached everyone -> a split is implied.
    var scratch: [max_nodes]NodeId = undefined;
    const prev_whole = [_]NodeId{ 1, 2, 3 };
    const ev = d.diff(1, &prev_whole, &scratch);
    switch (ev) {
        .split => |s| try testing.expectEqualSlices(NodeId, &[_]NodeId{3}, s),
        else => return error.TestUnexpectedResult,
    }

    // Previously local already only reached {1,2} and still does -> none.
    const prev_cut = [_]NodeId{ 1, 2 };
    try testing.expect(d.diff(1, &prev_cut, &scratch) == .none);
}

test "empty / unknown local edge cases" {
    var d = Detector.init();

    // No nodes at all: not partitioned, no quorum, zero components.
    try testing.expect(!d.isPartitioned(99));
    try testing.expect(!d.hasQuorum(99));
    try testing.expectEqual(@as(usize, 0), d.componentCount());

    // Known nodes but unknown local id -> partitioned, no quorum.
    const ids = [_]NodeId{ 1, 2 };
    const live = [_]Liveness{ .alive, .alive };
    const edges = [_]Edge{.{ .a = 1, .b = 2 }};
    try d.update(&ids, &live, &edges);
    try testing.expect(d.isPartitioned(7));
    try testing.expect(!d.hasQuorum(7));
}

test "input validation rejects bad views" {
    var d = Detector.init();
    const ids = [_]NodeId{ 1, 2 };
    const live_short = [_]Liveness{.alive};
    try testing.expectError(Error.LengthMismatch, d.setNodes(&ids, &live_short));

    const dup = [_]NodeId{ 5, 5 };
    const live2 = [_]Liveness{ .alive, .alive };
    try testing.expectError(Error.DuplicateNode, d.setNodes(&dup, &live2));
}
