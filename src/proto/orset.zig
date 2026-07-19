// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Observed-Remove Set (OR-Set) CRDT over UTF-8 string elements.
//!
//! An OR-Set is a state-based (CvRDT) set whose merge is a join over an
//! unbounded join-semilattice, giving a commutative, idempotent, and
//! associative `merge`. Each `add` of an element is tagged with a caller-chosen
//! unique tag (for example a `replica:counter` dot, a UUID, or an HLC stamp).
//! Membership is decided by the presence of at least one add-tag that has NOT
//! been observed-removed.
//!
//! ## Semantics
//!
//! State is two tag relations:
//!   * `add-tags(elem)`    — every tag under which `elem` was ever added.
//!   * `remove-tags(elem)` — every add-tag that has been observed and removed.
//!
//! `contains(elem)` is true iff `add-tags(elem) \ remove-tags(elem)` is
//! non-empty. `remove(elem)` tombstones exactly the add-tags currently observed
//! locally; concurrent adds carry tags this replica has not yet seen, so a
//! concurrent add survives a concurrent remove. This is the standard
//! **add-wins** resolution.
//!
//! `merge(other)` unions both add-tag relations and both remove-tag relations.
//! Because set union is the join of a semilattice, the merge inherits the three
//! CRDT laws directly:
//!   * commutative — `A ∪ B == B ∪ A`
//!   * associative — `(A ∪ B) ∪ C == A ∪ (B ∪ C)`
//!   * idempotent  — `A ∪ A == A`
//!
//! ## Distinction from the substrate CRDTs
//!
//! `src/substrate/crdt_orset.zig` keys on `u64` with generated `(replica,
//! counter)` dots, and `concord.OrSet(T)` is a delta-state generic comparing
//! values with `std.meta.eql` (slice identity, not byte content, for strings).
//! This module is a concrete, state-based OR-Set over **owned string elements**
//! with **caller-supplied string tags** and an `elements(buf)` extractor —
//! convenient for protocol-layer sets (membership-by-name, key sets) that need
//! byte-equal string keys and explicit tags rather than generated dots.
//!
//! All strings (elements and tags) are duplicated into the set's allocator and
//! freed in `deinit`; the set never aliases caller memory.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// A set of owned tag strings, used for both add-tags and remove-tags.
const TagSet = std.StringHashMap(void);

/// Per-element record: the add-tags and the observed remove-tags (tombstones).
const Record = struct {
    add_tags: TagSet,
    remove_tags: TagSet,

    fn init(allocator: Allocator) Record {
        return .{
            .add_tags = TagSet.init(allocator),
            .remove_tags = TagSet.init(allocator),
        };
    }

    /// Free all owned tag strings, then the maps themselves.
    fn deinit(self: *Record, allocator: Allocator) void {
        freeTagSet(allocator, &self.add_tags);
        freeTagSet(allocator, &self.remove_tags);
    }

    /// Live iff at least one add-tag has not been observed-removed.
    fn isLive(self: *const Record) bool {
        var it = self.add_tags.keyIterator();
        while (it.next()) |tag| {
            if (!self.remove_tags.contains(tag.*)) return true;
        }
        return false;
    }
};

/// Free every owned key in a `TagSet`, then the backing storage.
fn freeTagSet(allocator: Allocator, set: *TagSet) void {
    var it = set.keyIterator();
    while (it.next()) |key| {
        allocator.free(key.*);
    }
    set.deinit();
}

/// Insert `tag` into `set` if absent, duplicating it into `allocator`.
///
/// Returns `true` when a new owned copy was stored, `false` when the tag was
/// already present (in which case nothing is allocated). Idempotent.
fn insertOwnedTag(allocator: Allocator, set: *TagSet, tag: []const u8) !bool {
    if (set.contains(tag)) return false;
    const owned = try allocator.dupe(u8, tag);
    errdefer allocator.free(owned);
    try set.put(owned, {});
    return true;
}

/// Observed-Remove Set over owned UTF-8 string elements with string add-tags.
pub const OrSet = struct {
    const Self = @This();

    allocator: Allocator,
    /// Owned-element-string -> Record. Keys are duplicated and freed here.
    records: std.StringHashMap(Record),

    /// Create an empty set backed by `allocator`.
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .records = std.StringHashMap(Record).init(allocator),
        };
    }

    /// Free every owned element key, its tag strings, and the backing maps.
    pub fn deinit(self: *Self) void {
        var it = self.records.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.records.deinit();
        self.* = undefined;
    }

    /// Add `elem` under the unique `tag`.
    ///
    /// Both `elem` and `tag` are copied into the set's allocator; the caller
    /// retains ownership of its arguments. Re-adding the same `(elem, tag)` pair
    /// is a no-op (idempotent). A previously removed tag is NOT resurrected:
    /// to make a removed element live again, add it under a fresh tag.
    pub fn add(self: *Self, elem: []const u8, tag: []const u8) !void {
        const record = try self.ensureRecord(elem);
        _ = try insertOwnedTag(self.allocator, &record.add_tags, tag);
    }

    /// Remove `elem` by tombstoning every add-tag currently observed locally.
    ///
    /// Add-tags this replica has not yet seen (concurrent remote adds) are left
    /// untouched, so they survive the remove — the add-wins property. No-op if
    /// `elem` is unknown.
    pub fn remove(self: *Self, elem: []const u8) !void {
        const record = self.records.getPtr(elem) orelse return;
        var it = record.add_tags.keyIterator();
        while (it.next()) |tag| {
            _ = try insertOwnedTag(self.allocator, &record.remove_tags, tag.*);
        }
    }

    /// True iff some add-tag of `elem` is not observed-removed.
    pub fn contains(self: *const Self, elem: []const u8) bool {
        const record = self.records.getPtr(elem) orelse return false;
        return record.isLive();
    }

    /// Number of currently-live elements.
    pub fn count(self: *const Self) usize {
        var live: usize = 0;
        var it = self.records.valueIterator();
        while (it.next()) |record| {
            if (record.isLive()) live += 1;
        }
        return live;
    }

    /// Write live element slices into `buf` and return the filled prefix.
    ///
    /// Returns `error.BufferTooSmall` if `buf` cannot hold every live element.
    /// The returned slices alias the set's owned keys and remain valid until the
    /// element is removed-and-compacted or the set is deinitialized. Order is
    /// unspecified (hash-map iteration order).
    pub fn elements(self: *const Self, buf: [][]const u8) ![][]const u8 {
        var n: usize = 0;
        var it = self.records.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.isLive()) continue;
            if (n >= buf.len) return error.BufferTooSmall;
            buf[n] = entry.key_ptr.*;
            n += 1;
        }
        return buf[0..n];
    }

    /// Join `other` into `self`: union add-tags and union remove-tags per
    /// element. Commutative, associative, and idempotent. `other` is not
    /// modified and continues to own its own memory.
    pub fn merge(self: *Self, other: *const Self) !void {
        // Self-merge is the identity join; short-circuit to avoid mutating the
        // records map while iterating it (which could rehash mid-iteration).
        if (self == other) return;

        var it = other.records.iterator();
        while (it.next()) |entry| {
            const dst = try self.ensureRecord(entry.key_ptr.*);

            var add_it = entry.value_ptr.add_tags.keyIterator();
            while (add_it.next()) |tag| {
                _ = try insertOwnedTag(self.allocator, &dst.add_tags, tag.*);
            }

            var rem_it = entry.value_ptr.remove_tags.keyIterator();
            while (rem_it.next()) |tag| {
                _ = try insertOwnedTag(self.allocator, &dst.remove_tags, tag.*);
            }
        }
    }

    /// Get the record for `elem`, creating an empty one (with an owned key copy)
    /// if absent. Returned pointer is valid until the next records mutation.
    fn ensureRecord(self: *Self, elem: []const u8) !*Record {
        if (self.records.getPtr(elem)) |existing| return existing;

        const owned_key = try self.allocator.dupe(u8, elem);
        errdefer self.allocator.free(owned_key);
        try self.records.put(owned_key, Record.init(self.allocator));
        return self.records.getPtr(owned_key).?;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "add then contains, unknown element absent" {
    var set = OrSet.init(testing.allocator);
    defer set.deinit();

    try testing.expect(!set.contains("alice"));

    try set.add("alice", "r1:1");
    try testing.expect(set.contains("alice"));
    try testing.expect(!set.contains("bob"));
    try testing.expectEqual(@as(usize, 1), set.count());
}

test "add is idempotent for repeated element/tag pairs" {
    var set = OrSet.init(testing.allocator);
    defer set.deinit();

    try set.add("k", "tag-a");
    try set.add("k", "tag-a");
    try set.add("k", "tag-a");

    try testing.expect(set.contains("k"));
    try testing.expectEqual(@as(usize, 1), set.count());
}

test "remove tombstones observed tags and clears membership" {
    var set = OrSet.init(testing.allocator);
    defer set.deinit();

    try set.add("x", "t1");
    try set.add("x", "t2");
    try testing.expect(set.contains("x"));

    try set.remove("x");
    try testing.expect(!set.contains("x"));
    try testing.expectEqual(@as(usize, 0), set.count());

    // Removing an unknown element is a no-op.
    try set.remove("never-added");
    try testing.expect(!set.contains("never-added"));
}

test "remove does not resurrect under an old tag but a fresh tag re-adds" {
    var set = OrSet.init(testing.allocator);
    defer set.deinit();

    try set.add("e", "old");
    try set.remove("e");
    try testing.expect(!set.contains("e"));

    // Re-adding the same (already-removed) tag stays dead.
    try set.add("e", "old");
    try testing.expect(!set.contains("e"));

    // A brand-new tag makes it live again.
    try set.add("e", "new");
    try testing.expect(set.contains("e"));
}

test "concurrent add wins over concurrent remove (add-wins)" {
    // Replica A adds "m" under a tag B has never seen, while B removes the
    // copy it has. After bidirectional merge, "m" must be present on both.
    var a = OrSet.init(testing.allocator);
    defer a.deinit();
    var b = OrSet.init(testing.allocator);
    defer b.deinit();

    // Shared history: both observe "m" under tag t0.
    try a.add("m", "t0");
    try b.add("m", "t0");

    // B removes the observed copy (tombstones t0).
    try b.remove("m");
    try testing.expect(!b.contains("m"));

    // A concurrently re-adds "m" under a new tag t1 (B has not seen t1).
    try a.add("m", "t1");

    try a.merge(&b);
    try b.merge(&a);

    // t1 is live on both: add wins.
    try testing.expect(a.contains("m"));
    try testing.expect(b.contains("m"));
}

test "merge converges and is commutative by example" {
    var a = OrSet.init(testing.allocator);
    defer a.deinit();
    var b = OrSet.init(testing.allocator);
    defer b.deinit();

    try a.add("p", "a1");
    try a.add("q", "a2");
    try a.remove("p"); // p tombstoned on A
    try b.add("p", "b1"); // concurrent add of p on B (new tag)
    try b.add("r", "b2");

    var ab = OrSet.init(testing.allocator);
    defer ab.deinit();
    try ab.merge(&a);
    try ab.merge(&b);

    var ba = OrSet.init(testing.allocator);
    defer ba.deinit();
    try ba.merge(&b);
    try ba.merge(&a);

    // Order-independent convergence.
    try testing.expectEqual(ab.contains("p"), ba.contains("p"));
    try testing.expectEqual(ab.contains("q"), ba.contains("q"));
    try testing.expectEqual(ab.contains("r"), ba.contains("r"));
    try testing.expectEqual(ab.count(), ba.count());

    // p survives via the concurrent add (b1), q and r are simple adds.
    try testing.expect(ab.contains("p"));
    try testing.expect(ab.contains("q"));
    try testing.expect(ab.contains("r"));
    try testing.expectEqual(@as(usize, 3), ab.count());
}

test "merge is idempotent" {
    var a = OrSet.init(testing.allocator);
    defer a.deinit();
    var b = OrSet.init(testing.allocator);
    defer b.deinit();

    try a.add("one", "1");
    try a.add("two", "2");
    try a.remove("two");
    try b.add("three", "3");

    try a.merge(&b);
    const after_first = a.count();

    // Re-merging the same peer changes nothing.
    try a.merge(&b);
    try a.merge(&b);
    try testing.expectEqual(after_first, a.count());

    // Self-merge via a clone also changes nothing.
    var clone = OrSet.init(testing.allocator);
    defer clone.deinit();
    try clone.merge(&a);
    try a.merge(&clone);
    try testing.expectEqual(after_first, a.count());
}

test "merge is associative by example" {
    var a = OrSet.init(testing.allocator);
    defer a.deinit();
    var b = OrSet.init(testing.allocator);
    defer b.deinit();
    var c = OrSet.init(testing.allocator);
    defer c.deinit();

    try a.add("alpha", "a");
    try b.add("beta", "b");
    try c.add("gamma", "c");
    try b.remove("beta");
    try c.add("alpha", "c2"); // alpha also added on C under a new tag

    // left = (a ∪ b) ∪ c
    var left = OrSet.init(testing.allocator);
    defer left.deinit();
    try left.merge(&a);
    try left.merge(&b);
    try left.merge(&c);

    // right = a ∪ (b ∪ c)
    var bc = OrSet.init(testing.allocator);
    defer bc.deinit();
    try bc.merge(&b);
    try bc.merge(&c);
    var right = OrSet.init(testing.allocator);
    defer right.deinit();
    try right.merge(&a);
    try right.merge(&bc);

    try testing.expectEqual(left.count(), right.count());
    try testing.expectEqual(left.contains("alpha"), right.contains("alpha"));
    try testing.expectEqual(left.contains("beta"), right.contains("beta"));
    try testing.expectEqual(left.contains("gamma"), right.contains("gamma"));

    try testing.expect(left.contains("alpha")); // survives via c2
    try testing.expect(!left.contains("beta")); // removed on B
    try testing.expect(left.contains("gamma"));
}

test "elements returns only live members and detects small buffers" {
    var set = OrSet.init(testing.allocator);
    defer set.deinit();

    try set.add("live1", "t");
    try set.add("live2", "t");
    try set.add("dead", "t");
    try set.remove("dead");

    var buf: [4][]const u8 = undefined;
    const live = try set.elements(&buf);
    try testing.expectEqual(@as(usize, 2), live.len);

    var saw1 = false;
    var saw2 = false;
    var saw_dead = false;
    for (live) |e| {
        if (std.mem.eql(u8, e, "live1")) saw1 = true;
        if (std.mem.eql(u8, e, "live2")) saw2 = true;
        if (std.mem.eql(u8, e, "dead")) saw_dead = true;
    }
    try testing.expect(saw1);
    try testing.expect(saw2);
    try testing.expect(!saw_dead);

    var tiny: [1][]const u8 = undefined;
    try testing.expectError(error.BufferTooSmall, set.elements(&tiny));
}

test "byte-equal string keys, not pointer identity" {
    var set = OrSet.init(testing.allocator);
    defer set.deinit();

    // Build two distinct heap buffers with identical bytes.
    const a = try testing.allocator.dupe(u8, "chan#1");
    defer testing.allocator.free(a);
    const b = try testing.allocator.dupe(u8, "chan#1");
    defer testing.allocator.free(b);
    try testing.expect(a.ptr != b.ptr);

    try set.add(a, "t1");
    // Adding with a byte-equal but distinct pointer must hit the same record.
    try set.add(b, "t2");
    try testing.expectEqual(@as(usize, 1), set.count());

    try set.remove(b);
    try testing.expect(!set.contains(a));
}

test "no leak across heavy add/remove/merge churn" {
    // Exercises every allocation path; std.testing.allocator fails on leak.
    var a = OrSet.init(testing.allocator);
    defer a.deinit();
    var b = OrSet.init(testing.allocator);
    defer b.deinit();

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        var ebuf: [16]u8 = undefined;
        var tbuf: [16]u8 = undefined;
        const elem = try std.fmt.bufPrint(&ebuf, "elem-{d}", .{i % 8});
        const tag = try std.fmt.bufPrint(&tbuf, "tag-{d}", .{i});
        try a.add(elem, tag);
        if (i % 3 == 0) try a.remove(elem);
        if (i % 2 == 0) try b.add(elem, tag);
    }

    try a.merge(&b);
    try b.merge(&a);
    try a.merge(&a); // self-merge path

    var buf: [16][]const u8 = undefined;
    _ = try a.elements(&buf);
}
