// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// A state-based grow-only counter CRDT (G-Counter).
///
/// A G-Counter is the simplest convergent replicated data type for counting.
/// Every participating node owns exactly one grow-only entry in a shared map,
/// `counts[node_id]`, which records the total amount that node has ever
/// contributed. A node may only ever increase its own entry; it never touches
/// another node's entry directly. The observable value of the counter is the
/// sum of all per-node entries.
///
/// Because each node's entry only ever grows, replicas reconcile their state by
/// taking the elementwise maximum of their maps. That merge operation is:
///   - commutative:  merge(a, b) == merge(b, a)
///   - idempotent:   merge(a, a) == a
///   - associative:  merge(merge(a, b), c) == merge(a, merge(b, c))
/// which is exactly the join-semilattice property that makes the counter a
/// state-based CRDT: any set of replicas that exchange state in any order,
/// any number of times, converge to the same value.
///
/// Keys are opaque `u64` node identifiers, stored in an owned
/// `std.AutoHashMap(u64, u64)`. The map owns all of its memory; callers must
/// call `deinit` to release it.
pub const GCounter = struct {
    allocator: std.mem.Allocator,
    counts: std.AutoHashMap(u64, u64),

    pub const NodeId = u64;

    /// An entry in the counter, exposed by the iterator.
    pub const Entry = struct {
        node: NodeId,
        count: u64,
    };

    /// Initialize an empty counter backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) GCounter {
        return .{
            .allocator = allocator,
            .counts = std.AutoHashMap(u64, u64).init(allocator),
        };
    }

    /// Release all memory owned by the counter and poison it.
    pub fn deinit(self: *GCounter) void {
        self.counts.deinit();
        self.* = undefined;
    }

    /// Increase this node's grow-only entry by `by`.
    ///
    /// Incrementing by zero is a no-op that still ensures the node has an entry
    /// (so an explicitly-zero node participates in merges identically to one
    /// that has never been seen, which is the correct CRDT semantics).
    ///
    /// Returns `error.Overflow` if the node's entry would exceed `u64`'s range;
    /// the entry is left unchanged in that case so the counter stays valid.
    pub fn increment(self: *GCounter, node: NodeId, by: u64) !void {
        const gop = try self.counts.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = 0;
        }
        const updated = std.math.add(u64, gop.value_ptr.*, by) catch {
            return error.Overflow;
        };
        gop.value_ptr.* = updated;
    }

    /// The observable value: the sum of every node's contribution.
    ///
    /// Uses `u128` accumulation so summing many near-`u64`-max entries cannot
    /// itself overflow the running total.
    pub fn value(self: *const GCounter) u128 {
        var total: u128 = 0;
        var it = self.counts.valueIterator();
        while (it.next()) |amount| {
            total += @as(u128, amount.*);
        }
        return total;
    }

    /// The contribution recorded for a single node, or 0 if the node is unknown.
    pub fn valueForNode(self: *const GCounter, node: NodeId) u64 {
        return self.counts.get(node) orelse 0;
    }

    /// Whether this counter has ever observed `node` (even at count 0).
    pub fn hasNode(self: *const GCounter, node: NodeId) bool {
        return self.counts.contains(node);
    }

    /// The number of distinct nodes that have contributed (or been seen).
    pub fn nodeCount(self: *const GCounter) usize {
        return self.counts.count();
    }

    /// Merge `other` into `self` by taking the elementwise maximum of every
    /// per-node entry. After this call, `self` reflects the most up-to-date
    /// state known to either replica.
    ///
    /// On allocation failure `self` may have absorbed some of `other`'s entries
    /// already; since merge only ever raises entries toward their true maximum,
    /// the partially-merged state is still a valid (if stale) CRDT state, and
    /// re-running the merge is safe and idempotent.
    pub fn merge(self: *GCounter, other: *const GCounter) !void {
        var it = other.counts.iterator();
        while (it.next()) |kv| {
            const node = kv.key_ptr.*;
            const incoming = kv.value_ptr.*;
            const gop = try self.counts.getOrPut(node);
            if (!gop.found_existing) {
                gop.value_ptr.* = incoming;
            } else if (incoming > gop.value_ptr.*) {
                gop.value_ptr.* = incoming;
            }
        }
    }

    /// Produce an independent deep copy backed by `allocator`. The caller owns
    /// the result and must `deinit` it.
    pub fn clone(self: *const GCounter, allocator: std.mem.Allocator) !GCounter {
        var copy = GCounter.init(allocator);
        errdefer copy.deinit();
        try copy.counts.ensureTotalCapacity(self.counts.count());
        var it = self.counts.iterator();
        while (it.next()) |kv| {
            copy.counts.putAssumeCapacity(kv.key_ptr.*, kv.value_ptr.*);
        }
        return copy;
    }

    /// An iterator over `Entry` records. Order is unspecified.
    pub const Iterator = struct {
        inner: std.AutoHashMap(u64, u64).Iterator,

        pub fn next(self: *Iterator) ?Entry {
            const kv = self.inner.next() orelse return null;
            return .{ .node = kv.key_ptr.*, .count = kv.value_ptr.* };
        }
    };

    /// Iterate over every per-node entry.
    pub fn iterator(self: *const GCounter) Iterator {
        return .{ .inner = self.counts.iterator() };
    }

    /// Whether two counters represent exactly the same state (same nodes, same
    /// per-node counts). Useful for asserting convergence in tests.
    pub fn eql(self: *const GCounter, other: *const GCounter) bool {
        if (self.counts.count() != other.counts.count()) return false;
        var it = self.counts.iterator();
        while (it.next()) |kv| {
            const other_val = other.counts.get(kv.key_ptr.*) orelse return false;
            if (other_val != kv.value_ptr.*) return false;
        }
        return true;
    }
};

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

/// Build a counter with the given (node, count) entries.
fn makeCounter(
    allocator: std.mem.Allocator,
    entries: []const GCounter.Entry,
) !GCounter {
    var counter = GCounter.init(allocator);
    errdefer counter.deinit();
    for (entries) |entry| {
        try counter.increment(entry.node, entry.count);
    }
    return counter;
}

test "init produces an empty counter" {
    var counter = GCounter.init(testing.allocator);
    defer counter.deinit();

    try testing.expectEqual(@as(u128, 0), counter.value());
    try testing.expectEqual(@as(usize, 0), counter.nodeCount());
    try testing.expectEqual(@as(u64, 0), counter.valueForNode(42));
    try testing.expect(!counter.hasNode(42));
}

test "increment and value accumulate per node" {
    var counter = GCounter.init(testing.allocator);
    defer counter.deinit();

    try counter.increment(1, 5);
    try counter.increment(2, 3);
    try counter.increment(1, 2);

    try testing.expectEqual(@as(u64, 7), counter.valueForNode(1));
    try testing.expectEqual(@as(u64, 3), counter.valueForNode(2));
    try testing.expectEqual(@as(u128, 10), counter.value());
    try testing.expectEqual(@as(usize, 2), counter.nodeCount());
}

test "increment by zero still registers the node" {
    var counter = GCounter.init(testing.allocator);
    defer counter.deinit();

    try counter.increment(7, 0);

    try testing.expect(counter.hasNode(7));
    try testing.expectEqual(@as(u64, 0), counter.valueForNode(7));
    try testing.expectEqual(@as(u128, 0), counter.value());
    try testing.expectEqual(@as(usize, 1), counter.nodeCount());
}

test "valueForNode returns zero for unknown nodes" {
    var counter = GCounter.init(testing.allocator);
    defer counter.deinit();

    try counter.increment(100, 9);

    try testing.expectEqual(@as(u64, 9), counter.valueForNode(100));
    try testing.expectEqual(@as(u64, 0), counter.valueForNode(101));
}

test "increment overflow is reported and leaves the entry unchanged" {
    var counter = GCounter.init(testing.allocator);
    defer counter.deinit();

    try counter.increment(1, std.math.maxInt(u64));
    try testing.expectError(error.Overflow, counter.increment(1, 1));

    // Entry preserved at its pre-overflow value.
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), counter.valueForNode(1));
}

test "value uses wide accumulation beyond u64 range" {
    var counter = GCounter.init(testing.allocator);
    defer counter.deinit();

    try counter.increment(1, std.math.maxInt(u64));
    try counter.increment(2, std.math.maxInt(u64));

    const expected: u128 = @as(u128, std.math.maxInt(u64)) * 2;
    try testing.expectEqual(expected, counter.value());
}

test "merge takes the elementwise maximum and converges" {
    // a knows: node1=5, node2=1
    var a = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 5 },
        .{ .node = 2, .count = 1 },
    });
    defer a.deinit();

    // b knows: node1=3, node3=7
    var b = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 3 },
        .{ .node = 3, .count = 7 },
    });
    defer b.deinit();

    try a.merge(&b);

    // Elementwise max: node1=max(5,3)=5, node2=1, node3=7
    try testing.expectEqual(@as(u64, 5), a.valueForNode(1));
    try testing.expectEqual(@as(u64, 1), a.valueForNode(2));
    try testing.expectEqual(@as(u64, 7), a.valueForNode(3));
    try testing.expectEqual(@as(u128, 13), a.value());
}

test "merge is commutative: a<-b equals b<-a" {
    var a1 = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 5 },
        .{ .node = 2, .count = 1 },
    });
    defer a1.deinit();
    var b1 = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 3 },
        .{ .node = 3, .count = 7 },
    });
    defer b1.deinit();

    // Mirror image of the same two replicas.
    var a2 = try a1.clone(testing.allocator);
    defer a2.deinit();
    var b2 = try b1.clone(testing.allocator);
    defer b2.deinit();

    try a1.merge(&b1); // a <- b
    try b2.merge(&a2); // b <- a

    try testing.expect(a1.eql(&b2));
}

test "merge is idempotent" {
    var a = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 5 },
        .{ .node = 2, .count = 9 },
    });
    defer a.deinit();

    var snapshot = try a.clone(testing.allocator);
    defer snapshot.deinit();

    // Merging with self, repeatedly, changes nothing.
    try a.merge(&snapshot);
    try a.merge(&snapshot);
    try a.merge(&a);

    try testing.expect(a.eql(&snapshot));
    try testing.expectEqual(@as(u128, 14), a.value());
}

test "merge is associative regardless of grouping" {
    const build = struct {
        fn one(alloc: std.mem.Allocator) !GCounter {
            return makeCounter(alloc, &.{
                .{ .node = 1, .count = 5 },
                .{ .node = 2, .count = 2 },
            });
        }
        fn two(alloc: std.mem.Allocator) !GCounter {
            return makeCounter(alloc, &.{
                .{ .node = 2, .count = 9 },
                .{ .node = 3, .count = 1 },
            });
        }
        fn three(alloc: std.mem.Allocator) !GCounter {
            return makeCounter(alloc, &.{
                .{ .node = 1, .count = 8 },
                .{ .node = 4, .count = 4 },
            });
        }
    };

    // left = (a merge b) merge c
    var left = try build.one(testing.allocator);
    defer left.deinit();
    {
        var b = try build.two(testing.allocator);
        defer b.deinit();
        var c = try build.three(testing.allocator);
        defer c.deinit();
        try left.merge(&b);
        try left.merge(&c);
    }

    // right = a merge (b merge c)
    var right = try build.one(testing.allocator);
    defer right.deinit();
    {
        var bc = try build.two(testing.allocator);
        defer bc.deinit();
        var c = try build.three(testing.allocator);
        defer c.deinit();
        try bc.merge(&c);
        try right.merge(&bc);
    }

    try testing.expect(left.eql(&right));
    // node1=max(5,8)=8, node2=max(2,9)=9, node3=1, node4=4
    try testing.expectEqual(@as(u128, 22), left.value());
}

test "merge is monotonic: value never decreases" {
    var a = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 10 },
        .{ .node = 2, .count = 4 },
    });
    defer a.deinit();
    const before = a.value();

    // b carries strictly-smaller or absent entries; merge must not shrink a.
    var b = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 2 },
    });
    defer b.deinit();

    try a.merge(&b);
    try testing.expect(a.value() >= before);
    try testing.expectEqual(before, a.value());
    try testing.expectEqual(@as(u64, 10), a.valueForNode(1));
}

test "clone is independent of the original" {
    var original = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 3 },
    });
    defer original.deinit();

    var copy = try original.clone(testing.allocator);
    defer copy.deinit();

    // Mutating the copy must not affect the original.
    try copy.increment(1, 100);
    try copy.increment(9, 5);

    try testing.expectEqual(@as(u64, 3), original.valueForNode(1));
    try testing.expect(!original.hasNode(9));
    try testing.expectEqual(@as(u64, 103), copy.valueForNode(1));
}

test "iterator visits every entry exactly once" {
    var counter = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 5 },
        .{ .node = 2, .count = 6 },
        .{ .node = 3, .count = 7 },
    });
    defer counter.deinit();

    var seen: u128 = 0;
    var count: usize = 0;
    var it = counter.iterator();
    while (it.next()) |entry| {
        seen += entry.count;
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqual(@as(u128, 18), seen);
    try testing.expectEqual(counter.value(), seen);
}

test "eql distinguishes differing state" {
    var a = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 5 },
    });
    defer a.deinit();
    var b = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 6 },
    });
    defer b.deinit();
    var c = try makeCounter(testing.allocator, &.{
        .{ .node = 1, .count = 5 },
        .{ .node = 2, .count = 1 },
    });
    defer c.deinit();

    try testing.expect(!a.eql(&b)); // same node, different count
    try testing.expect(!a.eql(&c)); // different node set
    try testing.expect(a.eql(&a)); // reflexive
}

test "three-replica gossip converges to identical state" {
    // Simulate three replicas each incrementing their own node, then gossiping
    // in an arbitrary pairwise order. All must converge.
    var r1 = GCounter.init(testing.allocator);
    defer r1.deinit();
    var r2 = GCounter.init(testing.allocator);
    defer r2.deinit();
    var r3 = GCounter.init(testing.allocator);
    defer r3.deinit();

    try r1.increment(1, 4);
    try r2.increment(2, 7);
    try r3.increment(3, 2);
    try r1.increment(1, 1); // node1 total = 5

    // Arbitrary gossip schedule.
    try r1.merge(&r2);
    try r3.merge(&r1);
    try r2.merge(&r3);
    try r1.merge(&r3);
    try r2.merge(&r1);

    try testing.expect(r1.eql(&r2));
    try testing.expect(r2.eql(&r3));

    const expected: u128 = 5 + 7 + 2;
    try testing.expectEqual(expected, r1.value());
    try testing.expectEqual(expected, r2.value());
    try testing.expectEqual(expected, r3.value());
}
