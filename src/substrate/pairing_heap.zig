//! Addressable pairing heap — min-priority queue generic over a payload type.
//!
//! Supports O(log n) amortized extractMin, O(1) insert, O(log n) amortized
//! decreaseKey and delete via node handles.  Pointer stability: nodes are
//! heap-allocated and addresses remain valid across all operations, making
//! them safe to hold as handles in external data structures (e.g. Dijkstra
//! distance tables, timer wheels, scheduler runqueues).
//!
//! Usage:
//!   const H = PairingHeap(u32, u32, compareU32);
//!   var h = H.init(allocator);
//!   defer h.deinit();
//!   const n = try h.insert(5, 42);
//!   try h.decreaseKey(n, 1);
//!   const min = h.extractMin().?; // -> payload=42, prio=1

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Comparator signature expected by PairingHeap.
/// Return true iff `a` should be considered *less than* `b` (i.e. higher
/// priority / should appear earlier in extractMin order).
pub fn PairingHeap(
    comptime Priority: type,
    comptime Payload: type,
    comptime lessThan: fn (a: Priority, b: Priority) bool,
) type {
    return struct {
        const Self = @This();

        /// A single heap node.  Callers receive a *Node from insert() and
        /// pass the same pointer to decreaseKey() / delete().  The node
        /// remains allocated until it is extracted or explicitly deleted.
        pub const Node = struct {
            priority: Priority,
            payload: Payload,
            // Pairing-heap tree links
            parent: ?*Node = null,
            child: ?*Node = null, // leftmost child
            prev: ?*Node = null, // left sibling  (or parent's child-ptr sentinel)
            next: ?*Node = null, // right sibling
        };

        root: ?*Node,
        len: usize,
        alloc: Allocator,

        // ------------------------------------------------------------------ //
        //  Lifecycle
        // ------------------------------------------------------------------ //

        pub fn init(alloc: Allocator) Self {
            return .{ .root = null, .len = 0, .alloc = alloc };
        }

        /// Free every remaining node.  The heap is unusable after this call.
        pub fn deinit(self: *Self) void {
            if (self.root) |r| freeSubtree(self.alloc, r);
            self.root = null;
            self.len = 0;
        }

        // ------------------------------------------------------------------ //
        //  Public API
        // ------------------------------------------------------------------ //

        /// Insert a new element.  Returns a stable pointer usable as a handle
        /// for decreaseKey / delete.  O(1).
        pub fn insert(self: *Self, priority: Priority, payload: Payload) Allocator.Error!*Node {
            const node = try self.alloc.create(Node);
            node.* = .{ .priority = priority, .payload = payload };
            self.root = meld(self.root, node);
            self.len += 1;
            return node;
        }

        /// Return the minimum-priority node without removing it, or null if
        /// the heap is empty.  O(1).
        pub fn peekMin(self: *const Self) ?*Node {
            return self.root;
        }

        /// Remove and return the minimum-priority node, or null if empty.
        /// The caller is responsible for freeing the node (or the heap loses
        /// track of it — see extractMinFree for convenience).
        /// Amortized O(log n).
        pub fn extractMin(self: *Self) ?*Node {
            const r = self.root orelse return null;
            self.root = mergePairs(r.child);
            if (self.root) |nr| {
                nr.parent = null;
                nr.prev = null;
            }
            // clean up extracted node's links
            r.parent = null;
            r.child = null;
            r.prev = null;
            r.next = null;
            self.len -= 1;
            return r;
        }

        /// Extract the min node, copy out its fields, free the allocation,
        /// and return the copied struct (or null if empty).
        pub fn extractMinFree(self: *Self) ?Node {
            const n = self.extractMin() orelse return null;
            const copy = n.*;
            self.alloc.destroy(n);
            return copy;
        }

        /// Decrease the priority of `node` to `new_priority`.  Behaviour is
        /// undefined if `new_priority` is greater than the current priority.
        /// Amortized O(log n).
        pub fn decreaseKey(self: *Self, node: *Node, new_priority: Priority) void {
            node.priority = new_priority;
            if (node == self.root) return; // already the root, nothing to do

            // Cut the node from its current position
            cutNode(node);

            // Meld it back as a new tree with the existing root
            self.root = meld(self.root, node);
        }

        /// Remove an arbitrary node from the heap and free it.
        /// Amortized O(log n).
        pub fn delete(self: *Self, node: *Node) void {
            if (node == self.root) {
                // Fast path: just extract the root
                _ = self.extractMin();
                self.alloc.destroy(node);
                return;
            }
            // Cut the node out, merge its children into a new tree, then meld
            // that tree back into the heap.
            cutNode(node);
            const child_tree = mergePairs(node.child);
            self.root = meld(self.root, child_tree);
            if (self.root) |r| {
                r.parent = null;
                r.prev = null;
            }
            self.len -= 1;
            self.alloc.destroy(node);
        }

        // ------------------------------------------------------------------ //
        //  Internal helpers
        // ------------------------------------------------------------------ //

        /// Link two heap trees so that the one with the smaller root wins.
        /// Either argument (or both) may be null.
        fn meld(a: ?*Node, b: ?*Node) ?*Node {
            if (a == null) return b;
            if (b == null) return a;
            const na = a.?;
            const nb = b.?;
            if (lessThan(na.priority, nb.priority)) {
                // na wins — attach nb as na's leftmost child
                nb.prev = null; // will be set by addChild
                nb.next = na.child;
                if (na.child) |c| c.prev = nb;
                na.child = nb;
                nb.parent = na;
                na.parent = null;
                na.prev = null;
                return na;
            } else {
                // nb wins
                na.prev = null;
                na.next = nb.child;
                if (nb.child) |c| c.prev = na;
                nb.child = na;
                na.parent = nb;
                nb.parent = null;
                nb.prev = null;
                return nb;
            }
        }

        /// Two-pass pairing of a sibling list (the children of an extracted
        /// root).  Returns the new root of the merged forest, or null.
        fn mergePairs(first: ?*Node) ?*Node {
            var node = first orelse return null;

            // Detach everything from its former parent
            node.parent = null;

            // First pass: pair consecutive siblings left-to-right
            var pairs: ?*Node = null; // stack of pair-roots (linked via .next)

            while (true) {
                // isolate node from the sibling chain
                const second = node.next;
                node.next = null;
                node.prev = null;

                if (second) |s| {
                    const rest = s.next;
                    s.next = null;
                    s.prev = null;
                    s.parent = null;

                    const pair = meld(node, s).?;
                    pair.next = pairs; // push onto stack
                    pairs = pair;

                    if (rest) |r| {
                        r.parent = null;
                        node = r;
                    } else break;
                } else {
                    // odd node out — push unpaired
                    node.next = pairs;
                    pairs = node;
                    break;
                }
            }

            // Second pass: merge the stack right-to-left
            var result: ?*Node = null;
            var cur = pairs;
            while (cur) |c| {
                const nx = c.next;
                c.next = null;
                c.prev = null;
                result = meld(result, c);
                cur = nx;
            }
            return result;
        }

        /// Unlink `node` from its position in the tree without altering its
        /// children.  After this call, node.parent == null and it is no longer
        /// reachable from the rest of the heap.
        fn cutNode(node: *Node) void {
            const p = node.parent orelse return; // already a root
            // Remove node from the sibling doubly-linked list.
            if (p.child == node) {
                // node is the leftmost child of its parent
                p.child = node.next;
            } else {
                // node has a left sibling whose .next points at it
                if (node.prev) |pr| pr.next = node.next;
            }
            if (node.next) |nx| nx.prev = node.prev;
            node.parent = null;
            node.prev = null;
            node.next = null;
        }

        /// Recursively free an entire subtree.
        fn freeSubtree(alloc: Allocator, node: *Node) void {
            var child = node.child;
            while (child) |c| {
                const nx = c.next;
                freeSubtree(alloc, c);
                child = nx;
            }
            alloc.destroy(node);
        }
    };
}

// ============================================================
//  Tests
// ============================================================

const testing = std.testing;

fn cmpU32(a: u32, b: u32) bool {
    return a < b;
}

const U32Heap = PairingHeap(u32, u32, cmpU32);

// ---- empty / single element --------------------------------

test "empty heap returns null for peekMin and extractMin" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    try testing.expect(h.peekMin() == null);
    try testing.expect(h.extractMin() == null);
    try testing.expectEqual(@as(usize, 0), h.len);
}

test "single element insert and extractMinFree" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    _ = try h.insert(7, 42);
    try testing.expectEqual(@as(usize, 1), h.len);
    const v = h.peekMin().?;
    try testing.expectEqual(@as(u32, 7), v.priority);
    try testing.expectEqual(@as(u32, 42), v.payload);

    const out = h.extractMinFree().?;
    try testing.expectEqual(@as(u32, 7), out.priority);
    try testing.expectEqual(@as(u32, 42), out.payload);
    try testing.expectEqual(@as(usize, 0), h.len);
    try testing.expect(h.extractMin() == null);
}

// ---- ascending extraction vs sorted oracle -----------------

test "extractMin yields ascending order on random inserts" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    // Deterministic "random" sequence
    const seed: u64 = 0xDEADBEEF_CAFEBABE;
    var rng = std.Random.DefaultPrng.init(seed);
    const random = rng.random();

    const N = 256;
    var oracle: [N]u32 = undefined;
    for (&oracle) |*v| {
        v.* = random.int(u32);
        _ = try h.insert(v.*, v.*);
    }
    try testing.expectEqual(@as(usize, N), h.len);

    std.mem.sort(u32, &oracle, {}, std.sort.asc(u32));

    for (oracle) |expected| {
        const out = h.extractMinFree().?;
        try testing.expectEqual(expected, out.priority);
    }
    try testing.expectEqual(@as(usize, 0), h.len);
}

// ---- decreaseKey moves element up --------------------------

test "decreaseKey promotes a node and it extracts in the right place" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    _ = try h.insert(10, 10);
    _ = try h.insert(20, 20);
    const target = try h.insert(30, 30);
    _ = try h.insert(40, 40);
    _ = try h.insert(50, 50);

    // Promote the node with prio=30 to prio=5 (new minimum)
    h.decreaseKey(target, 5);

    try testing.expectEqual(@as(u32, 5), h.peekMin().?.priority);

    const first = h.extractMinFree().?;
    try testing.expectEqual(@as(u32, 5), first.priority);
    try testing.expectEqual(@as(u32, 30), first.payload); // payload unchanged

    // Remaining order: 10, 20, 40, 50
    const expected = [_]u32{ 10, 20, 40, 50 };
    for (expected) |exp| {
        const out = h.extractMinFree().?;
        try testing.expectEqual(exp, out.priority);
    }
    try testing.expectEqual(@as(usize, 0), h.len);
}

test "decreaseKey on root node leaves heap consistent" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    const r = try h.insert(5, 5);
    _ = try h.insert(10, 10);
    _ = try h.insert(15, 15);

    h.decreaseKey(r, 1);
    try testing.expectEqual(@as(u32, 1), h.peekMin().?.priority);

    const expected = [_]u32{ 1, 10, 15 };
    for (expected) |exp| {
        try testing.expectEqual(exp, h.extractMinFree().?.priority);
    }
}

test "decreaseKey to equal priority is a no-op" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    _ = try h.insert(3, 3);
    const n = try h.insert(7, 7);
    _ = try h.insert(11, 11);

    h.decreaseKey(n, 7); // same priority

    const expected = [_]u32{ 3, 7, 11 };
    for (expected) |exp| {
        try testing.expectEqual(exp, h.extractMinFree().?.priority);
    }
}

// ---- delete arbitrary handle keeps heap order --------------

test "delete of an arbitrary handle keeps heap order" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    _ = try h.insert(1, 1);
    _ = try h.insert(2, 2);
    const mid = try h.insert(3, 3);
    _ = try h.insert(4, 4);
    _ = try h.insert(5, 5);

    h.delete(mid);
    try testing.expectEqual(@as(usize, 4), h.len);

    const expected = [_]u32{ 1, 2, 4, 5 };
    for (expected) |exp| {
        try testing.expectEqual(exp, h.extractMinFree().?.priority);
    }
}

test "delete of the minimum element" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    const mn = try h.insert(1, 100);
    _ = try h.insert(2, 200);
    _ = try h.insert(3, 300);

    h.delete(mn);
    try testing.expectEqual(@as(usize, 2), h.len);

    try testing.expectEqual(@as(u32, 2), h.extractMinFree().?.priority);
    try testing.expectEqual(@as(u32, 3), h.extractMinFree().?.priority);
    try testing.expect(h.extractMin() == null);
}

test "delete of the only element" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    const sole = try h.insert(42, 0);
    h.delete(sole);
    try testing.expectEqual(@as(usize, 0), h.len);
    try testing.expect(h.peekMin() == null);
}

test "delete of a leaf (rightmost sibling)" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    _ = try h.insert(1, 1);
    _ = try h.insert(2, 2);
    _ = try h.insert(3, 3);
    const leaf = try h.insert(10, 10);

    h.delete(leaf);

    const expected = [_]u32{ 1, 2, 3 };
    for (expected) |exp| {
        try testing.expectEqual(exp, h.extractMinFree().?.priority);
    }
}

// ---- mixed stress test vs std.sort oracle ------------------

test "mixed insert/extract/decreaseKey stress vs sort oracle" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    var rng = std.Random.DefaultPrng.init(0xFEED_F00D_1234_5678);
    const random = rng.random();

    // We track (handle, current-priority) pairs for decrease-key candidates.
    const Tracked = struct { node: *U32Heap.Node, prio: u32 };
    var tracked = std.ArrayListUnmanaged(Tracked).empty;
    defer tracked.deinit(testing.allocator);

    var oracle = std.ArrayListUnmanaged(u32).empty;
    defer oracle.deinit(testing.allocator);

    const ROUNDS = 8;
    const BATCH = 64;

    for (0..ROUNDS) |_| {
        // Insert a batch
        for (0..BATCH) |_| {
            const p = random.int(u32) % 10_000;
            const n = try h.insert(p, p);
            try tracked.append(testing.allocator, .{ .node = n, .prio = p });
            try oracle.append(testing.allocator, p);
        }

        // Randomly decrease some keys
        const ndec = BATCH / 4;
        for (0..ndec) |_| {
            if (tracked.items.len == 0) break;
            const idx = random.uintLessThan(usize, tracked.items.len);
            const t = &tracked.items[idx];
            // Only decrease if there is room
            if (t.prio > 0) {
                const np = random.uintLessThan(u32, t.prio);
                // update oracle entry
                for (oracle.items) |*ov| {
                    if (ov.* == t.prio) { // first match is fine for stress
                        ov.* = np;
                        break;
                    }
                }
                h.decreaseKey(t.node, np);
                t.prio = np;
            }
        }

        // Extract half the current heap and verify ascending order
        var prev: u32 = 0;
        const nextr = h.len / 2;
        var removed_prios = std.ArrayListUnmanaged(u32).empty;
        defer removed_prios.deinit(testing.allocator);

        for (0..nextr) |_| {
            const out = h.extractMinFree().?;
            try testing.expect(out.priority >= prev);
            prev = out.priority;
            try removed_prios.append(testing.allocator, out.priority);
        }

        // Reconcile oracle: sort it, remove the first nextr values
        std.mem.sort(u32, oracle.items, {}, std.sort.asc(u32));
        // The extracted values should exactly match the sorted prefix of oracle
        for (0..nextr) |i| {
            try testing.expectEqual(oracle.items[i], removed_prios.items[i]);
        }
        // Shrink oracle by the removed prefix
        const remaining = oracle.items.len - nextr;
        std.mem.copyForwards(u32, oracle.items[0..remaining], oracle.items[nextr..]);
        oracle.shrinkRetainingCapacity(remaining);

        // Purge stale tracked handles (nodes that were extracted)
        // We mark by priority match — good enough for stress (dupes are fine)
        var new_tracked = std.ArrayListUnmanaged(Tracked).empty;
        outer: for (tracked.items) |t| {
            for (removed_prios.items) |rp| {
                if (t.prio == rp) {
                    // consumed — skip (remove first match)
                    // remove from removed_prios so dupes are handled
                    for (removed_prios.items, 0..) |rp2, ri| {
                        if (rp2 == rp) {
                            _ = removed_prios.swapRemove(ri);
                            break;
                        }
                    }
                    continue :outer;
                }
            }
            try new_tracked.append(testing.allocator, t);
        }
        tracked.deinit(testing.allocator);
        tracked = new_tracked;
    }

    // Drain the rest and verify ascending order
    var prev2: u32 = 0;
    while (h.extractMinFree()) |out| {
        try testing.expect(out.priority >= prev2);
        prev2 = out.priority;
    }
    try testing.expectEqual(@as(usize, 0), h.len);
}

// ---- duplicate priorities ----------------------------------

test "duplicate priorities extract in non-decreasing order" {
    var h = U32Heap.init(testing.allocator);
    defer h.deinit();

    const vals = [_]u32{ 5, 5, 3, 3, 1, 1, 4, 4, 2, 2 };
    for (vals) |v| _ = try h.insert(v, v);

    var prev: u32 = 0;
    while (h.extractMinFree()) |out| {
        try testing.expect(out.priority >= prev);
        prev = out.priority;
    }
}

// ---- Dijkstra-like use: int payload, float priority --------

fn cmpF32(a: f32, b: f32) bool {
    return a < b;
}

const DijkHeap = PairingHeap(f32, u32, cmpF32);

test "Dijkstra-like float priority with integer node ID payload" {
    var h = DijkHeap.init(testing.allocator);
    defer h.deinit();

    // node 0..4 with initial distance infinity
    const inf = std.math.floatMax(f32);
    var handles: [5]*DijkHeap.Node = undefined;
    for (0..5) |i| {
        handles[i] = try h.insert(inf, @intCast(i));
    }

    // "Relax" source node 0 to distance 0
    h.decreaseKey(handles[0], 0.0);
    // Relax some neighbours
    h.decreaseKey(handles[1], 1.5);
    h.decreaseKey(handles[3], 0.8);

    // First three extractions are deterministic (distinct finite priorities)
    const det_order = [_]u32{ 0, 3, 1 };
    const det_prios = [_]f32{ 0.0, 0.8, 1.5 };
    for (det_order, det_prios) |expected_id, expected_p| {
        const out = h.extractMinFree().?;
        try testing.expectEqual(expected_id, out.payload);
        try testing.expectApproxEqAbs(expected_p, out.priority, 1e-6);
    }
    // Remaining two (nodes 2 and 4) both have priority=inf; order is unspecified.
    // Just verify both extract with inf priority.
    const r1 = h.extractMinFree().?;
    const r2 = h.extractMinFree().?;
    try testing.expectApproxEqAbs(inf, r1.priority, 1e-6);
    try testing.expectApproxEqAbs(inf, r2.priority, 1e-6);
    // Their payloads should be the two unreachable nodes {2, 4} in some order
    const s = r1.payload + r2.payload;
    try testing.expectEqual(@as(u32, 6), s); // 2+4 = 6
}
