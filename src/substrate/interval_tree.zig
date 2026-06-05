//! Augmented interval tree over integer [lo, hi] intervals carrying a value.
//!
//! Uses a left-leaning red-black BST (LLRB, Sedgewick 2008) keyed by
//! (lo, hi, serial) where `serial` is a monotonically-increasing counter
//! assigned at insert time.  The serial tiebreaker guarantees every node has a
//! unique key, which lets the standard LLRB delete algorithm work correctly even
//! when many intervals share the same (lo, hi) endpoints.  Every node also
//! stores `max_hi` — the maximum hi value in its subtree — enabling O(log n)
//! subtree pruning so point-stabbing and overlap queries run in O(log n + k).
//!
//! Public API (on `IntervalTree(V)`)
//! ----------------------------------
//!   `init(allocator)`
//!   `deinit()`
//!   `count() usize`
//!   `insert(lo, hi, val) !void`
//!   `remove(lo, hi, val) bool`   — removes the first matching (lo,hi,val) node
//!   `queryPoint(p, alloc, out) !void`
//!   `queryOverlap(lo, hi, alloc, out) !void`
//!
//! Zig 0.16; std-only; no sibling @imports.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Public interval record returned by queries
// ---------------------------------------------------------------------------

pub fn Interval(comptime V: type) type {
    return struct {
        lo: i64,
        hi: i64,
        val: V,
    };
}

// ---------------------------------------------------------------------------
// IntervalTree
// ---------------------------------------------------------------------------

pub fn IntervalTree(comptime V: type) type {
    return struct {
        const Self = @This();
        const Iv = Interval(V);

        // -------------------------------------------------------------------
        // Internal node
        // -------------------------------------------------------------------
        const Color = enum { red, black };

        const Node = struct {
            lo: i64,
            hi: i64,
            serial: u64, // unique insert-order key; breaks (lo,hi) ties
            val: V,
            max_hi: i64, // max hi in this subtree
            color: Color,
            left: ?*Node,
            right: ?*Node,

            fn updateMax(n: *Node) void {
                var m = n.hi;
                if (n.left) |l| if (l.max_hi > m) {
                    m = l.max_hi;
                };
                if (n.right) |r| if (r.max_hi > m) {
                    m = r.max_hi;
                };
                n.max_hi = m;
            }
        };

        // -------------------------------------------------------------------
        // Fields
        // -------------------------------------------------------------------

        root: ?*Node,
        len: usize,
        next_serial: u64,
        allocator: Allocator,

        // -------------------------------------------------------------------
        // Lifecycle
        // -------------------------------------------------------------------

        pub fn init(allocator: Allocator) Self {
            return .{ .root = null, .len = 0, .next_serial = 0, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            freeSubtree(self.allocator, self.root);
            self.root = null;
            self.len = 0;
        }

        fn freeSubtree(alloc: Allocator, node: ?*Node) void {
            const n = node orelse return;
            freeSubtree(alloc, n.left);
            freeSubtree(alloc, n.right);
            alloc.destroy(n);
        }

        /// Number of intervals currently stored.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        // -------------------------------------------------------------------
        // Insert
        // -------------------------------------------------------------------

        pub fn insert(self: *Self, lo: i64, hi: i64, val: V) !void {
            const serial = self.next_serial;
            self.next_serial += 1;
            self.root = try llrbInsert(self.allocator, self.root, lo, hi, serial, val, &self.len);
            self.root.?.color = .black;
        }

        fn llrbInsert(alloc: Allocator, h: ?*Node, lo: i64, hi: i64, serial: u64, val: V, len: *usize) !?*Node {
            if (h == null) {
                const node = try alloc.create(Node);
                node.* = .{
                    .lo = lo,
                    .hi = hi,
                    .serial = serial,
                    .val = val,
                    .max_hi = hi,
                    .color = .red,
                    .left = null,
                    .right = null,
                };
                len.* += 1;
                return node;
            }
            const n = h.?;
            const cmp = cmpKey(lo, hi, serial, n.lo, n.hi, n.serial);
            if (cmp < 0) {
                n.left = try llrbInsert(alloc, n.left, lo, hi, serial, val, len);
            } else {
                // cmp > 0 always (serial is unique), so go right.
                n.right = try llrbInsert(alloc, n.right, lo, hi, serial, val, len);
            }
            return fixUp(n);
        }

        // -------------------------------------------------------------------
        // Remove
        // -------------------------------------------------------------------

        /// Remove the first interval matching (lo, hi, val).  Returns true if
        /// anything was removed.
        pub fn remove(self: *Self, lo: i64, hi: i64, val: V) bool {
            if (self.root == null) return false;
            // Find the serial of the matching node first (read-only scan).
            const serial = findSerial(self.root, lo, hi, val) orelse return false;
            const before = self.len;
            self.root = llrbDelete(self.allocator, self.root, lo, hi, serial, &self.len);
            if (self.root) |r| r.color = .black;
            return self.len < before;
        }

        /// Scan the subtree for a node matching (lo, hi, val) and return its serial.
        fn findSerial(node: ?*Node, lo: i64, hi: i64, val: V) ?u64 {
            const n = node orelse return null;
            // Use max_hi pruning: if max_hi < hi, no descendant has hi this large.
            // But we need exact hi, so just check if subtree max_hi >= hi.
            if (n.max_hi < hi) return null;
            // BST on lo: skip left subtree if all lo values there are too large.
            // (Left has lo <= n.lo, right has lo >= n.lo.)
            // Check left subtree if it could have lo <= query_lo
            if (lo < n.lo) {
                // The node and right subtree have lo >= n.lo > query_lo; skip them
                // unless this is a match.
                return findSerial(n.left, lo, hi, val);
            }
            // lo >= n.lo: check left, this node, right
            if (findSerial(n.left, lo, hi, val)) |s| return s;
            if (n.lo == lo and n.hi == hi and valEq(n.val, val)) return n.serial;
            return findSerial(n.right, lo, hi, val);
        }

        fn llrbDelete(alloc: Allocator, h_opt: ?*Node, lo: i64, hi: i64, serial: u64, len: *usize) ?*Node {
            const h = h_opt orelse return null;
            if (cmpKey(lo, hi, serial, h.lo, h.hi, h.serial) < 0) {
                if (h.left == null) return h; // not found
                var hh = h;
                if (!isRed(hh.left) and !isRed(hh.left.?.left)) {
                    hh = moveRedLeft(hh);
                }
                hh.left = llrbDelete(alloc, hh.left, lo, hi, serial, len);
                return fixUp(hh);
            }
            var hh = h;
            if (isRed(hh.left)) hh = rotateRight(hh);
            // Exact match at a bottom node.
            if (cmpKey(lo, hi, serial, hh.lo, hh.hi, hh.serial) == 0 and hh.right == null) {
                alloc.destroy(hh);
                len.* -= 1;
                return null;
            }
            if (hh.right != null and !isRed(hh.right) and !isRed(hh.right.?.left)) {
                hh = moveRedRight(hh);
            }
            if (cmpKey(lo, hi, serial, hh.lo, hh.hi, hh.serial) == 0) {
                // Replace with in-order successor.
                const succ = minNode(hh.right.?);
                hh.lo = succ.lo;
                hh.hi = succ.hi;
                hh.serial = succ.serial;
                hh.val = succ.val;
                hh.right = deleteMin(alloc, hh.right.?);
                len.* -= 1;
            } else {
                hh.right = llrbDelete(alloc, hh.right, lo, hi, serial, len);
            }
            return fixUp(hh);
        }

        fn minNode(n: *Node) *Node {
            var cur = n;
            while (cur.left) |l| cur = l;
            return cur;
        }

        fn deleteMin(alloc: Allocator, h: *Node) ?*Node {
            if (h.left == null) {
                alloc.destroy(h);
                return null;
            }
            var hh = h;
            if (!isRed(hh.left) and !isRed(hh.left.?.left)) {
                hh = moveRedLeft(hh);
            }
            hh.left = deleteMin(alloc, hh.left.?);
            return fixUp(hh);
        }

        // -------------------------------------------------------------------
        // Queries
        // -------------------------------------------------------------------

        /// Append all intervals [a,b] where a <= p <= b into `out`.
        pub fn queryPoint(self: *const Self, p: i64, alloc: Allocator, out: *std.ArrayListUnmanaged(Iv)) !void {
            try stabQuery(self.root, p, alloc, out);
        }

        fn stabQuery(node: ?*Node, p: i64, alloc: Allocator, out: *std.ArrayListUnmanaged(Iv)) !void {
            const n = node orelse return;
            if (n.max_hi < p) return;
            try stabQuery(n.left, p, alloc, out);
            if (n.lo <= p and p <= n.hi) {
                try out.append(alloc, .{ .lo = n.lo, .hi = n.hi, .val = n.val });
            }
            if (n.lo > p) return;
            try stabQuery(n.right, p, alloc, out);
        }

        /// Append all intervals overlapping [qlo, qhi] (touching endpoints count).
        pub fn queryOverlap(self: *const Self, qlo: i64, qhi: i64, alloc: Allocator, out: *std.ArrayListUnmanaged(Iv)) !void {
            try overlapQuery(self.root, qlo, qhi, alloc, out);
        }

        fn overlapQuery(node: ?*Node, qlo: i64, qhi: i64, alloc: Allocator, out: *std.ArrayListUnmanaged(Iv)) !void {
            const n = node orelse return;
            if (n.max_hi < qlo) return;
            try overlapQuery(n.left, qlo, qhi, alloc, out);
            if (n.lo <= qhi and n.hi >= qlo) {
                try out.append(alloc, .{ .lo = n.lo, .hi = n.hi, .val = n.val });
            }
            if (n.lo > qhi) return;
            try overlapQuery(n.right, qlo, qhi, alloc, out);
        }

        // -------------------------------------------------------------------
        // LLRB rotation / balance helpers
        // -------------------------------------------------------------------

        fn isRed(n: ?*Node) bool {
            const nn = n orelse return false;
            return nn.color == .red;
        }

        fn rotateLeft(h: *Node) *Node {
            const x = h.right.?;
            h.right = x.left;
            x.left = h;
            x.color = h.color;
            h.color = .red;
            h.updateMax();
            x.updateMax();
            return x;
        }

        fn rotateRight(h: *Node) *Node {
            const x = h.left.?;
            h.left = x.right;
            x.right = h;
            x.color = h.color;
            h.color = .red;
            h.updateMax();
            x.updateMax();
            return x;
        }

        fn flipColors(h: *Node) void {
            h.color = toggle(h.color);
            if (h.left) |l| l.color = toggle(l.color);
            if (h.right) |r| r.color = toggle(r.color);
        }

        fn toggle(c: Color) Color {
            return if (c == .red) .black else .red;
        }

        fn fixUp(h: *Node) *Node {
            var n = h;
            if (isRed(n.right) and !isRed(n.left)) n = rotateLeft(n);
            if (isRed(n.left) and isRed(n.left.?.left)) n = rotateRight(n);
            if (isRed(n.left) and isRed(n.right)) flipColors(n);
            n.updateMax();
            return n;
        }

        fn moveRedLeft(h: *Node) *Node {
            flipColors(h);
            if (isRed(h.right.?.left)) {
                h.right = rotateRight(h.right.?);
                var hh = rotateLeft(h);
                flipColors(hh);
                hh.updateMax();
                return hh;
            }
            h.updateMax();
            return h;
        }

        fn moveRedRight(h: *Node) *Node {
            flipColors(h);
            if (isRed(h.left.?.left)) {
                var hh = rotateRight(h);
                flipColors(hh);
                hh.updateMax();
                return hh;
            }
            h.updateMax();
            return h;
        }

        // -------------------------------------------------------------------
        // Key comparison: (lo, hi, serial) — serial is always unique
        // -------------------------------------------------------------------

        fn cmpKey(lo1: i64, hi1: i64, s1: u64, lo2: i64, hi2: i64, s2: u64) i32 {
            if (lo1 < lo2) return -1;
            if (lo1 > lo2) return 1;
            if (hi1 < hi2) return -1;
            if (hi1 > hi2) return 1;
            if (s1 < s2) return -1;
            if (s1 > s2) return 1;
            return 0;
        }

        fn valEq(a: V, b: V) bool {
            return switch (@typeInfo(V)) {
                .int, .float, .bool, .@"enum" => a == b,
                .pointer => a == b,
                else => std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b)),
            };
        }

        // -------------------------------------------------------------------
        // Debug / invariant checking (used in tests)
        // -------------------------------------------------------------------

        pub fn checkInvariants(self: *const Self) !void {
            _ = try verify(self.root);
        }

        fn verify(node: ?*Node) !usize {
            const n = node orelse return 1;
            if (isRed(n.left) and isRed(n.left.?.left))
                return error.ConsecutiveRed;
            if (isRed(n.right) and !isRed(n.left))
                return error.RightLeaningRed;
            if (isRed(n.left) and isRed(n.right))
                return error.FourNode;
            const lh = try verify(n.left);
            const rh = try verify(n.right);
            if (lh != rh) return error.BlackHeightMismatch;
            var expected = n.hi;
            if (n.left) |l| if (l.max_hi > expected) {
                expected = l.max_hi;
            };
            if (n.right) |r| if (r.max_hi > expected) {
                expected = r.max_hi;
            };
            if (n.max_hi != expected) return error.MaxHiWrong;
            return lh + @as(usize, if (n.color == .black) 1 else 0);
        }
    };
}

// ===========================================================================
// Tests
// ===========================================================================

test "empty tree" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    try std.testing.expectEqual(@as(usize, 0), tree.count());

    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    try tree.queryPoint(5, alloc, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);

    try tree.queryOverlap(0, 100, alloc, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "single interval — point stabbing" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(u8).init(alloc);
    defer tree.deinit();
    try tree.insert(10, 20, 42);

    var out: std.ArrayListUnmanaged(Interval(u8)) = .empty;
    defer out.deinit(alloc);

    for ([_]i64{ 10, 15, 20 }) |p| { // inside and at endpoints
        try tree.queryPoint(p, alloc, &out);
        try std.testing.expectEqual(@as(usize, 1), out.items.len);
        out.clearRetainingCapacity();
    }
    for ([_]i64{ 9, 21 }) |p| { // outside
        try tree.queryPoint(p, alloc, &out);
        try std.testing.expectEqual(@as(usize, 0), out.items.len);
        out.clearRetainingCapacity();
    }
}

test "overlap query — touching endpoints" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    try tree.insert(10, 20, 1);
    try tree.insert(20, 30, 2);

    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    // [20,20] should touch both.
    try tree.queryOverlap(20, 20, alloc, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    out.clearRetainingCapacity();

    // [0,9] hits none.
    try tree.queryOverlap(0, 9, alloc, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
    out.clearRetainingCapacity();

    // [31,40] hits none.
    try tree.queryOverlap(31, 40, alloc, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
    out.clearRetainingCapacity();

    // [15,25] hits both.
    try tree.queryOverlap(15, 25, alloc, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
}

test "remove — basic" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    try tree.insert(1, 10, 100);
    try tree.insert(5, 15, 200);

    try std.testing.expectEqual(@as(usize, 2), tree.count());
    const removed = tree.remove(1, 10, 100);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 1), tree.count());

    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    try tree.queryPoint(5, alloc, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqual(@as(i32, 200), out.items[0].val);
}

test "remove — non-existent and absent-key return false" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();
    try tree.insert(1, 5, 7);
    try std.testing.expect(!tree.remove(1, 5, 99)); // wrong value
    try std.testing.expect(!tree.remove(10, 20, 7)); // key absent
    try std.testing.expectEqual(@as(usize, 1), tree.count());
}

test "duplicate intervals" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    try tree.insert(3, 7, 1);
    try tree.insert(3, 7, 2);
    try tree.insert(3, 7, 3);
    try std.testing.expectEqual(@as(usize, 3), tree.count());

    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    try tree.queryPoint(5, alloc, &out);
    try std.testing.expectEqual(@as(usize, 3), out.items.len);
    out.clearRetainingCapacity();

    _ = tree.remove(3, 7, 2);
    try std.testing.expectEqual(@as(usize, 2), tree.count());

    try tree.queryPoint(5, alloc, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
}

test "max_hi augmentation invariant after inserts" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    const intervals = [_][2]i64{
        .{ 1, 5 }, .{ 3, 10 }, .{ 7, 15 }, .{ 0, 20 }, .{ 12, 18 }, .{ 6, 8 },
    };
    for (intervals, 0..) |iv, i| {
        try tree.insert(iv[0], iv[1], @as(i32, @intCast(i)));
        try tree.checkInvariants();
    }
}

test "max_hi augmentation invariant after removes" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    const intervals = [_][2]i64{
        .{ 2, 9 }, .{ 4, 12 }, .{ 1, 7 }, .{ 8, 20 }, .{ 5, 11 },
    };
    for (intervals, 0..) |iv, i| {
        try tree.insert(iv[0], iv[1], @as(i32, @intCast(i)));
    }
    try tree.checkInvariants();

    _ = tree.remove(4, 12, 1);
    try tree.checkInvariants();

    _ = tree.remove(8, 20, 3);
    try tree.checkInvariants();

    _ = tree.remove(2, 9, 0);
    try tree.checkInvariants();
}

test "point stabbing correctness — brute force oracle (stress)" {
    const alloc = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF_CAFEF00D);
    const rng = prng.random();

    const COUNT = 200;
    const RANGE: i64 = 100;

    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    var bf_lo = try alloc.alloc(i64, COUNT);
    defer alloc.free(bf_lo);
    var bf_hi = try alloc.alloc(i64, COUNT);
    defer alloc.free(bf_hi);

    for (0..COUNT) |i| {
        const lo = rng.intRangeLessThan(i64, 0, RANGE);
        const hi = lo + rng.intRangeLessThan(i64, 1, 30);
        try tree.insert(lo, hi, @as(i32, @intCast(i)));
        bf_lo[i] = lo;
        bf_hi[i] = hi;
    }
    try tree.checkInvariants();

    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    for (0..50) |_| {
        const p = rng.intRangeLessThan(i64, 0, RANGE + 30);
        out.clearRetainingCapacity();
        try tree.queryPoint(p, alloc, &out);

        var expected: usize = 0;
        for (0..COUNT) |i| {
            if (bf_lo[i] <= p and p <= bf_hi[i]) expected += 1;
        }
        try std.testing.expectEqual(expected, out.items.len);
    }
}

test "overlap query correctness — brute force oracle (stress)" {
    const alloc = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9ABC_DEF0);
    const rng = prng.random();

    const COUNT = 150;
    const RANGE: i64 = 100;

    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    var bf_lo = try alloc.alloc(i64, COUNT);
    defer alloc.free(bf_lo);
    var bf_hi = try alloc.alloc(i64, COUNT);
    defer alloc.free(bf_hi);

    for (0..COUNT) |i| {
        const lo = rng.intRangeLessThan(i64, 0, RANGE);
        const hi = lo + rng.intRangeLessThan(i64, 0, 25);
        try tree.insert(lo, hi, @as(i32, @intCast(i)));
        bf_lo[i] = lo;
        bf_hi[i] = hi;
    }
    try tree.checkInvariants();

    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    for (0..50) |_| {
        const qlo = rng.intRangeLessThan(i64, 0, RANGE);
        const qhi = qlo + rng.intRangeLessThan(i64, 0, 25);
        out.clearRetainingCapacity();
        try tree.queryOverlap(qlo, qhi, alloc, &out);

        var expected: usize = 0;
        for (0..COUNT) |i| {
            if (bf_lo[i] <= qhi and bf_hi[i] >= qlo) expected += 1;
        }
        try std.testing.expectEqual(expected, out.items.len);
    }
}

test "insert/remove stress with invariant checks" {
    const alloc = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xABCD_EF01_2345_6789);
    const rng = prng.random();

    const RANGE: i64 = 50;
    const OPS = 300;

    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    var live_lo: std.ArrayListUnmanaged(i64) = .empty;
    defer live_lo.deinit(alloc);
    var live_hi: std.ArrayListUnmanaged(i64) = .empty;
    defer live_hi.deinit(alloc);
    var live_val: std.ArrayListUnmanaged(i32) = .empty;
    defer live_val.deinit(alloc);

    var seq: i32 = 0;
    for (0..OPS) |_| {
        const op = rng.uintLessThan(u8, 3);
        if (op < 2 or live_lo.items.len == 0) {
            const lo = rng.intRangeLessThan(i64, 0, RANGE);
            const hi = lo + rng.intRangeLessThan(i64, 0, 20);
            try tree.insert(lo, hi, seq);
            try live_lo.append(alloc, lo);
            try live_hi.append(alloc, hi);
            try live_val.append(alloc, seq);
            seq += 1;
        } else {
            const idx = rng.uintLessThan(usize, live_lo.items.len);
            const lo = live_lo.items[idx];
            const hi = live_hi.items[idx];
            const val = live_val.items[idx];
            const removed = tree.remove(lo, hi, val);
            try std.testing.expect(removed);
            _ = live_lo.swapRemove(idx);
            _ = live_hi.swapRemove(idx);
            _ = live_val.swapRemove(idx);
        }
        try tree.checkInvariants();
        try std.testing.expectEqual(live_lo.items.len, tree.count());
    }
}

test "deterministic sequence — exact result set" {
    const alloc = std.testing.allocator;
    var tree = IntervalTree(i32).init(alloc);
    defer tree.deinit();

    //  [1,4]  [2,6]  [3,8]  [7,9]  [5,5]
    try tree.insert(1, 4, 10);
    try tree.insert(2, 6, 20);
    try tree.insert(3, 8, 30);
    try tree.insert(7, 9, 40);
    try tree.insert(5, 5, 50);

    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    // p=5: [2,6]=yes [3,8]=yes [5,5]=yes → 3
    try tree.queryPoint(5, alloc, &out);
    try std.testing.expectEqual(@as(usize, 3), out.items.len);
    out.clearRetainingCapacity();

    // overlap [4,7]: all 5 intervals overlap
    try tree.queryOverlap(4, 7, alloc, &out);
    try std.testing.expectEqual(@as(usize, 5), out.items.len);
    out.clearRetainingCapacity();

    // overlap [9,9]: only [7,9] → 1
    try tree.queryOverlap(9, 9, alloc, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    out.clearRetainingCapacity();

    // Remove [3,8,30] and re-check p=5 → 2
    _ = tree.remove(3, 8, 30);
    try tree.queryPoint(5, alloc, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
}

test "edge cases: disjoint, empty-after-remove, points, negative" {
    const alloc = std.testing.allocator;
    var out: std.ArrayListUnmanaged(Interval(i32)) = .empty;
    defer out.deinit(alloc);

    // Disjoint intervals — no false positives.
    {
        var tree = IntervalTree(i32).init(alloc);
        defer tree.deinit();
        try tree.insert(1, 3, 1);
        try tree.insert(5, 7, 2);
        try tree.insert(9, 11, 3);
        try tree.queryPoint(4, alloc, &out);
        try std.testing.expectEqual(@as(usize, 0), out.items.len);
        out.clearRetainingCapacity();
        try tree.queryPoint(6, alloc, &out);
        try std.testing.expectEqual(@as(usize, 1), out.items.len);
        out.clearRetainingCapacity();
    }

    // Remove all → empty, invariants hold.
    {
        var tree = IntervalTree(i32).init(alloc);
        defer tree.deinit();
        try tree.insert(1, 2, 10);
        try tree.insert(3, 4, 20);
        _ = tree.remove(1, 2, 10);
        _ = tree.remove(3, 4, 20);
        try std.testing.expectEqual(@as(usize, 0), tree.count());
        try tree.checkInvariants();
        try tree.queryPoint(2, alloc, &out);
        try std.testing.expectEqual(@as(usize, 0), out.items.len);
    }

    // Point intervals (lo==hi) with duplicates.
    {
        var tree = IntervalTree(i32).init(alloc);
        defer tree.deinit();
        try tree.insert(5, 5, 1);
        try tree.insert(5, 5, 2);
        try tree.insert(10, 10, 3);
        try tree.queryPoint(5, alloc, &out);
        try std.testing.expectEqual(@as(usize, 2), out.items.len);
        out.clearRetainingCapacity();
        try tree.queryOverlap(5, 10, alloc, &out);
        try std.testing.expectEqual(@as(usize, 3), out.items.len);
        out.clearRetainingCapacity();
    }

    // Negative coordinates.
    {
        var tree = IntervalTree(i32).init(alloc);
        defer tree.deinit();
        try tree.insert(-100, -50, 1);
        try tree.insert(-60, -10, 2);
        try tree.insert(-20, 20, 3);
        try tree.queryPoint(-55, alloc, &out);
        try std.testing.expectEqual(@as(usize, 2), out.items.len);
        out.clearRetainingCapacity();
        try tree.queryPoint(0, alloc, &out);
        try std.testing.expectEqual(@as(usize, 1), out.items.len);
        out.clearRetainingCapacity();
        try tree.queryOverlap(-55, -30, alloc, &out);
        try std.testing.expectEqual(@as(usize, 2), out.items.len);
        out.clearRetainingCapacity();
    }
}
