// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Convergent text sequence CRDT (RGA) — the eg-walker replay target (#14).
//!
//! Lotus gives a causal order over edit events (`Dag.causalOrder`); this is the
//! convergent sequence those events replay into. It is a Replicated Growable
//! Array: every inserted character carries a globally-unique, totally-ordered
//! `OpId` (Lamport clock + replica), and an insert references the element it goes
//! *after*. Two replicas that observe the same set of ops — in ANY causal order —
//! materialize the identical document.
//!
//! Correctness rests on two invariants the caller must uphold (both hold when
//! ops are replayed in `Dag.causalOrder` with Lamport-stamped events):
//!   1. Causal delivery: an insert's `origin` is applied before the insert.
//!   2. Lamport monotonicity: a child's `OpId` is greater than its origin's, so a
//!      concurrent sibling's whole subtree sorts together under the RGA scan.
//! Under these, the canonical RGA placement (insert after origin, skipping the
//! run of following elements whose id is greater than the new id) is convergent.
const std = @import("std");

/// Globally-unique, totally-ordered element identity.
pub const OpId = struct {
    lamport: u64,
    replica: u32,

    pub fn eql(a: OpId, b: OpId) bool {
        return a.lamport == b.lamport and a.replica == b.replica;
    }

    /// Total order: by Lamport time, replica breaking ties. "Greater" wins
    /// precedence (sorts earlier) among concurrent same-origin inserts.
    pub fn gt(a: OpId, b: OpId) bool {
        if (a.lamport != b.lamport) return a.lamport > b.lamport;
        return a.replica > b.replica;
    }
};

pub const Error = std.mem.Allocator.Error || error{MissingOrigin};

const Element = struct {
    id: OpId,
    ch: u8,
    deleted: bool,
};

pub const SeqCrdt = struct {
    allocator: std.mem.Allocator,
    elements: std.ArrayListUnmanaged(Element) = .empty,

    pub fn init(allocator: std.mem.Allocator) SeqCrdt {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SeqCrdt) void {
        self.elements.deinit(self.allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const SeqCrdt, id: OpId) ?usize {
        for (self.elements.items, 0..) |e, i| {
            if (e.id.eql(id)) return i;
        }
        return null;
    }

    /// Insert character `ch` with identity `id` immediately after `origin` (null =
    /// document start). Idempotent: re-applying a known id is a no-op (so the same
    /// op delivered twice converges). `origin` must already be present.
    pub fn insert(self: *SeqCrdt, id: OpId, origin: ?OpId, ch: u8) Error!void {
        if (self.indexOf(id) != null) return; // duplicate op

        var idx: usize = 0;
        if (origin) |o| {
            idx = (self.indexOf(o) orelse return error.MissingOrigin) + 1;
        }
        // RGA placement: skip the run of following elements whose id outranks the
        // new one (concurrent inserts — and their subtrees — that win precedence).
        while (idx < self.elements.items.len and self.elements.items[idx].id.gt(id)) : (idx += 1) {}

        try self.elements.insert(self.allocator, idx, .{ .id = id, .ch = ch, .deleted = false });
    }

    /// Tombstone the element `target` (idempotent; unknown target is a no-op).
    pub fn remove(self: *SeqCrdt, target: OpId) void {
        if (self.indexOf(target)) |i| self.elements.items[i].deleted = true;
    }

    /// Materialize the visible document (caller owns the returned bytes).
    pub fn text(self: *const SeqCrdt, allocator: std.mem.Allocator) Error![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        for (self.elements.items) |e| {
            if (!e.deleted) try out.append(allocator, e.ch);
        }
        return out.toOwnedSlice(allocator);
    }

    /// Number of visible (non-tombstoned) characters.
    pub fn len(self: *const SeqCrdt) usize {
        var n: usize = 0;
        for (self.elements.items) |e| {
            if (!e.deleted) n += 1;
        }
        return n;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectText(crdt: *const SeqCrdt, expected: []const u8) !void {
    const got = try crdt.text(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

test "sequential typing builds the string in order" {
    var c = SeqCrdt.init(testing.allocator);
    defer c.deinit();
    const a = OpId{ .lamport = 1, .replica = 0 };
    const b = OpId{ .lamport = 2, .replica = 0 };
    const d = OpId{ .lamport = 3, .replica = 0 };
    try c.insert(a, null, 'a');
    try c.insert(b, a, 'b');
    try c.insert(d, b, 'c');
    try expectText(&c, "abc");
}

test "delete tombstones a character" {
    var c = SeqCrdt.init(testing.allocator);
    defer c.deinit();
    const a = OpId{ .lamport = 1, .replica = 0 };
    const b = OpId{ .lamport = 2, .replica = 0 };
    try c.insert(a, null, 'x');
    try c.insert(b, a, 'y');
    c.remove(a);
    try expectText(&c, "y");
    try testing.expectEqual(@as(usize, 1), c.len());
}

test "duplicate op delivery is idempotent" {
    var c = SeqCrdt.init(testing.allocator);
    defer c.deinit();
    const a = OpId{ .lamport = 1, .replica = 0 };
    try c.insert(a, null, 'a');
    try c.insert(a, null, 'a'); // redelivered
    try expectText(&c, "a");
}

test "concurrent inserts at the document start converge regardless of order" {
    // Replica 0 inserts 'A' (lamport 5); replica 1 inserts 'B' (lamport 5),
    // both at the start. Higher replica wins precedence -> "BA" on both sides.
    const a = OpId{ .lamport = 5, .replica = 0 };
    const b = OpId{ .lamport = 5, .replica = 1 };

    var left = SeqCrdt.init(testing.allocator);
    defer left.deinit();
    try left.insert(a, null, 'A');
    try left.insert(b, null, 'B');

    var right = SeqCrdt.init(testing.allocator);
    defer right.deinit();
    try right.insert(b, null, 'B');
    try right.insert(a, null, 'A');

    try expectText(&left, "BA");
    try expectText(&right, "BA");
}

test "concurrent inserts after a shared origin converge across interleavings" {
    // Shared base "x"; then replica 0 inserts 'a' after x (lamport 2) and
    // replica 1 inserts 'b' after x (lamport 3), concurrently. Apply in two
    // different orders and require identical convergence.
    const x = OpId{ .lamport = 1, .replica = 0 };
    const a = OpId{ .lamport = 2, .replica = 0 };
    const b = OpId{ .lamport = 3, .replica = 1 };

    var left = SeqCrdt.init(testing.allocator);
    defer left.deinit();
    try left.insert(x, null, 'x');
    try left.insert(a, x, 'a');
    try left.insert(b, x, 'b');

    var right = SeqCrdt.init(testing.allocator);
    defer right.deinit();
    try right.insert(x, null, 'x');
    try right.insert(b, x, 'b');
    try right.insert(a, x, 'a');

    const lt = try left.text(testing.allocator);
    defer testing.allocator.free(lt);
    const rt = try right.text(testing.allocator);
    defer testing.allocator.free(rt);
    try testing.expectEqualStrings(lt, rt);
    try testing.expectEqualStrings("xba", lt); // higher lamport (b) sorts first after x
}

test "interleaved subtrees converge (concurrent edits with descendants)" {
    // Base "1". Replica A: insert 'a' after 1 (l2,rA), then 'c' after a (l3,rA).
    // Replica B: insert 'b' after 1 (l2,rB).  Replicas have different ids so the
    // l2 tie breaks by replica. Apply in two orders; require identical result.
    const one = OpId{ .lamport = 1, .replica = 0 };
    const a = OpId{ .lamport = 2, .replica = 1 };
    const c = OpId{ .lamport = 3, .replica = 1 };
    const b = OpId{ .lamport = 2, .replica = 2 };

    var left = SeqCrdt.init(testing.allocator);
    defer left.deinit();
    try left.insert(one, null, '1');
    try left.insert(a, one, 'a');
    try left.insert(c, a, 'c');
    try left.insert(b, one, 'b');

    var right = SeqCrdt.init(testing.allocator);
    defer right.deinit();
    try right.insert(one, null, '1');
    try right.insert(b, one, 'b'); // b first this time
    try right.insert(a, one, 'a');
    try right.insert(c, a, 'c');

    const lt = try left.text(testing.allocator);
    defer testing.allocator.free(lt);
    const rt = try right.text(testing.allocator);
    defer testing.allocator.free(rt);
    try testing.expectEqualStrings(lt, rt);
    // b (l2,r2) outranks a (l2,r1) after origin 1, so b's group precedes a's: "1bac".
    try testing.expectEqualStrings("1bac", lt);
}

test "missing origin is rejected" {
    var c = SeqCrdt.init(testing.allocator);
    defer c.deinit();
    const ghost = OpId{ .lamport = 9, .replica = 9 };
    const n = OpId{ .lamport = 10, .replica = 0 };
    try testing.expectError(error.MissingOrigin, c.insert(n, ghost, 'z'));
}
