//! Persistent (immutable) hash array-mapped trie — PersistentMap(K, V, Context).
//!
//! This is a 32-way HAMT with **structural sharing** and **reference-counted
//! nodes**. It is the data structure backing Mizuchi's lock-free RCU world
//! snapshots: a published root is an immutable point-in-time view that any
//! number of readers may traverse with no locks and no allocation, while a
//! writer concurrently derives the *next* version.
//!
//! ## HAMT shape
//!
//! Each level of the trie consumes 5 bits of the key's hash (`branch_bits`),
//! giving 32 possible child slots per internal node. Rather than store a dense
//! 32-entry array, an internal node keeps:
//!   - a `u32` bitmap whose set bits indicate which of the 32 logical slots are
//!     occupied, and
//!   - a popcount-compacted `children` array holding exactly `popcount(bitmap)`
//!     pointers, dense and in slot order.
//! The physical index of logical slot `i` is `popcount(bitmap & ((1<<i)-1))`.
//! This keeps internal nodes small while preserving O(1)-ish slot lookup.
//!
//! There are three node kinds:
//!   - `internal`: bitmap + compacted child pointers.
//!   - `leaf`:     a single (key, value) pair living at some depth.
//!   - `collision`: a bounded slice of (key, value) entries that all share the
//!     same hash bits consumed so far. Collisions are resolved by a **linear
//!     scan over a finite slice** — never a linked chain, never an unbounded
//!     `while (true)`. Two distinct keys land in a collision leaf when they
//!     agree on all 64 hash bits, or when the trie reaches `max_depth` (we run
//!     out of fresh hash bits). Because the slice is finite and every scan
//!     loop iterates over it by index, all-colliding key sets can never hang.
//!
//! ## Structural sharing + RCU role
//!
//! `put` / `remove` are pure with respect to the receiver: they return a NEW
//! root that shares every untouched subtree with the prior root. Only the nodes
//! on the single root-to-leaf path actually touched are freshly allocated
//! (`rc == 1`); every sibling pointer the new path carries over is `retain()`ed
//! so it is owned by both versions. An already-published old root therefore
//! stays a fully valid immutable snapshot. This is exactly what an RCU
//! publish/scan cycle needs: writer builds v2 from v1 sharing structure,
//! atomically publishes v2, then `release()`s its reference to v1; readers still
//! on v1 keep it alive via their own references until they finish.
//!
//! ## Refcount discipline (no leaks)
//!
//! Every node carries a `usize` refcount. The invariants:
//!   - A newly allocated node has `rc == 1`.
//!   - When a copied path points at a SHARED child, that child is `retain()`ed.
//!   - When a key is **overwritten** or **removed**, the OLD leaf/path on the
//!     copied route is NOT retained into the new version. It remains owned only
//!     by the old root, so when the caller eventually `release()`s the old root
//!     every node unique to that version reaches `rc == 0` and is freed.
//!   - `release` decrements; at zero it recursively `release`s children then
//!     frees the node. `get` / `iterator` are pure reads — they load child
//!     pointers and compare keys but NEVER touch a refcount — so a reader may
//!     safely traverse an old root concurrently with a writer.

const std = @import("std");

/// A persistent hash array-mapped trie.
///
/// `Context` must provide `pub fn hash(self, key: K) u64` and
/// `pub fn eql(self, a: K, b: K) bool`, exactly like `std.HashMap` contexts.
/// `Context` must be a zero-sized type (stateless) so we can instantiate it
/// freely during pure reads; this mirrors how `std.AutoHashMap` contexts work.
pub fn PersistentMap(comptime K: type, comptime V: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Allocator = std.mem.Allocator;

        /// 5 bits of hash consumed per trie level → 32 slots per internal node.
        const branch_bits: u6 = 5;
        const branch_factor: usize = 1 << branch_bits; // 32
        const branch_mask: u64 = branch_factor - 1; // 0b11111
        /// 64 hash bits / 5 bits per level → 13 levels (0..=12), after which no
        /// fresh hash bits remain to branch on and any colliding keys land in a
        /// collision leaf. `max_depth` is that exhaustion depth.
        const max_depth: u6 = 13; // ceil(64/5) = 13 levels of 5 bits

        /// Key/value pair as yielded by the iterator and stored in leaves.
        pub const Entry = struct {
            key: K,
            value: V,
        };

        const NodeKind = enum { internal, leaf, collision };

        const Node = struct {
            rc: usize,
            kind: union(NodeKind) {
                internal: Internal,
                leaf: Entry,
                collision: Collision,
            },
        };

        const Internal = struct {
            /// Bit `i` set ⇒ logical slot `i` (0..31) is occupied.
            bitmap: u32,
            /// Popcount-compacted, dense, slot-ordered child pointers.
            /// Length is always `@popCount(bitmap)`.
            children: []*Node,
        };

        const Collision = struct {
            /// All entries here share the hash bits consumed up to this depth.
            /// Linear-scanned; always finite.
            entries: []Entry,
        };

        /// Root pointer is null for the empty map. `len` is cached so `count`
        /// is O(1).
        root: ?*Node = null,
        len: usize = 0,

        // ---- construction -------------------------------------------------

        /// The empty map. No allocation; safe to `release` (no-op).
        pub fn empty() Self {
            return .{ .root = null, .len = 0 };
        }

        // ---- refcount primitives -----------------------------------------

        fn retainNode(node: *Node) void {
            node.rc += 1;
        }

        fn releaseNode(node: *Node, allocator: Allocator) void {
            std.debug.assert(node.rc > 0);
            node.rc -= 1;
            if (node.rc != 0) return;
            switch (node.kind) {
                .internal => |*i| {
                    for (i.children) |child| releaseNode(child, allocator);
                    allocator.free(i.children);
                },
                .collision => |*c| {
                    allocator.free(c.entries);
                },
                .leaf => {},
            }
            allocator.destroy(node);
        }

        /// Add one owning reference to this snapshot. Each `retain` must be
        /// balanced by a later `release`.
        pub fn retain(self: Self) void {
            if (self.root) |r| retainNode(r);
        }

        /// Drop one owning reference. When the last reference to any node is
        /// dropped the node (and the subtrees it uniquely owns) is freed.
        pub fn release(self: Self, allocator: Allocator) void {
            if (self.root) |r| releaseNode(r, allocator);
        }

        // ---- node allocators ---------------------------------------------

        fn newLeaf(allocator: Allocator, key: K, value: V) !*Node {
            const n = try allocator.create(Node);
            n.* = .{ .rc = 1, .kind = .{ .leaf = .{ .key = key, .value = value } } };
            return n;
        }

        /// Allocate an internal node taking ownership of `children` (already
        /// the correct length for `bitmap`). On allocation failure the caller
        /// still owns `children`.
        fn newInternal(allocator: Allocator, bitmap: u32, children: []*Node) !*Node {
            const n = try allocator.create(Node);
            n.* = .{ .rc = 1, .kind = .{ .internal = .{ .bitmap = bitmap, .children = children } } };
            return n;
        }

        fn newCollision(allocator: Allocator, entries: []Entry) !*Node {
            const n = try allocator.create(Node);
            n.* = .{ .rc = 1, .kind = .{ .collision = .{ .entries = entries } } };
            return n;
        }

        // ---- bit/slot helpers --------------------------------------------

        /// The 5-bit logical slot for `hash` at `depth`.
        fn slotOf(hash: u64, depth: u6) u5 {
            const shift: u6 = depth * branch_bits;
            return @intCast((hash >> shift) & branch_mask);
        }

        /// Physical index of logical `slot` within a compacted child array.
        fn physIndex(bitmap: u32, slot: u5) usize {
            const below: u32 = (@as(u32, 1) << slot) - 1;
            return @popCount(bitmap & below);
        }

        fn slotOccupied(bitmap: u32, slot: u5) bool {
            return (bitmap & (@as(u32, 1) << slot)) != 0;
        }

        // ---- reads (no refcount, no alloc) -------------------------------

        /// Look up `key`. Pure read: never allocates, never touches a
        /// refcount, safe to call on a snapshot concurrently with a writer.
        pub fn get(self: Self, key: K) ?V {
            const ctx: Context = undefined;
            const h = ctx.hash(key);
            var node = self.root orelse return null;
            var depth: u6 = 0;
            // Bounded: descends at most `max_depth` levels, then resolves at a
            // leaf or collision. No unbounded loop.
            while (depth <= max_depth) : (depth += 1) {
                switch (node.kind) {
                    .leaf => |entry| {
                        if (ctx.eql(entry.key, key)) return entry.value;
                        return null;
                    },
                    .collision => |c| {
                        for (c.entries) |entry| {
                            if (ctx.eql(entry.key, key)) return entry.value;
                        }
                        return null;
                    },
                    .internal => |inode| {
                        const slot = slotOf(h, depth);
                        if (!slotOccupied(inode.bitmap, slot)) return null;
                        node = inode.children[physIndex(inode.bitmap, slot)];
                    },
                }
            }
            return null;
        }

        /// Number of live keys. O(1).
        pub fn count(self: Self) usize {
            return self.len;
        }

        // ---- writes (return a new shared root) ---------------------------

        /// Return a new map with `key` bound to `value`, sharing all untouched
        /// structure with `self`. `self` is unchanged and remains valid.
        pub fn put(self: Self, allocator: Allocator, key: K, value: V) !Self {
            const ctx: Context = undefined;
            const h = ctx.hash(key);
            var added: bool = undefined;
            const new_root = try putNode(allocator, self.root, h, 0, key, value, &added);
            return .{
                .root = new_root,
                .len = if (added) self.len + 1 else self.len,
            };
        }

        /// Build the replacement subtree for `node` (which may be null) along
        /// the path for (`key`,`value`). Sets `added.*` to whether a new key
        /// was inserted (false ⇒ overwrite). The returned node has `rc == 1`;
        /// every shared child it carries over is `retain`ed. `node` itself is
        /// NOT mutated and NOT released here — it stays owned by the old root.
        fn putNode(
            allocator: Allocator,
            node: ?*Node,
            h: u64,
            depth: u6,
            key: K,
            value: V,
            added: *bool,
        ) error{OutOfMemory}!*Node {
            const ctx: Context = undefined;

            const cur = node orelse {
                added.* = true;
                return try newLeaf(allocator, key, value);
            };

            switch (cur.kind) {
                .leaf => |entry| {
                    if (ctx.eql(entry.key, key)) {
                        // Overwrite: brand-new leaf, old leaf left to the old
                        // version. Not retained ⇒ no leak, freed when old root
                        // is released.
                        added.* = false;
                        return try newLeaf(allocator, key, value);
                    }
                    // Two distinct keys. Split into a deeper structure.
                    added.* = true;
                    const existing_h = ctx.hash(entry.key);
                    return try mergeTwo(allocator, depth, entry.key, entry.value, existing_h, key, value, h);
                },
                .collision => |c| {
                    return try putIntoCollision(allocator, c, key, value, added);
                },
                .internal => |inode| {
                    return try putIntoInternal(allocator, inode, h, depth, key, value, added);
                },
            }
        }

        /// Insert/overwrite into a copy of a collision leaf via linear scan.
        fn putIntoCollision(
            allocator: Allocator,
            c: Collision,
            key: K,
            value: V,
            added: *bool,
        ) error{OutOfMemory}!*Node {
            const ctx: Context = undefined;
            // Finite scan for an existing matching key.
            var match: ?usize = null;
            for (c.entries, 0..) |entry, idx| {
                if (ctx.eql(entry.key, key)) {
                    match = idx;
                    break;
                }
            }
            if (match) |idx| {
                added.* = false;
                const entries = try allocator.dupe(Entry, c.entries);
                entries[idx] = .{ .key = key, .value = value };
                return newCollision(allocator, entries) catch |err| {
                    allocator.free(entries);
                    return err;
                };
            }
            added.* = true;
            const entries = try allocator.alloc(Entry, c.entries.len + 1);
            errdefer allocator.free(entries);
            @memcpy(entries[0..c.entries.len], c.entries);
            entries[c.entries.len] = .{ .key = key, .value = value };
            return newCollision(allocator, entries) catch |err| {
                allocator.free(entries);
                return err;
            };
        }

        /// Insert/overwrite into a copy of an internal node, recursing into the
        /// affected slot and `retain`ing every sibling carried over.
        fn putIntoInternal(
            allocator: Allocator,
            inode: Internal,
            h: u64,
            depth: u6,
            key: K,
            value: V,
            added: *bool,
        ) error{OutOfMemory}!*Node {
            const slot = slotOf(h, depth);
            const pop: usize = @popCount(inode.bitmap);

            if (slotOccupied(inode.bitmap, slot)) {
                const pidx = physIndex(inode.bitmap, slot);
                const child = inode.children[pidx];
                // Recurse first; child is shared input, not consumed.
                const new_child = try putNode(allocator, child, h, depth + 1, key, value, added);
                // Copy child array; retain every sibling, point at new_child.
                const children = try allocator.alloc(*Node, pop);
                errdefer {
                    releaseNode(new_child, allocator);
                    allocator.free(children);
                }
                for (inode.children, 0..) |sib, i| {
                    if (i == pidx) {
                        children[i] = new_child; // already rc==1, owned by us
                    } else {
                        retainNode(sib);
                        children[i] = sib;
                    }
                }
                return newInternal(allocator, inode.bitmap, children) catch |err| {
                    for (children) |ch| releaseNode(ch, allocator);
                    allocator.free(children);
                    return err;
                };
            }

            // Slot empty: add a fresh leaf and grow the compacted array by one.
            added.* = true;
            const new_leaf = try newLeaf(allocator, key, value);
            errdefer releaseNode(new_leaf, allocator);
            const pidx = physIndex(inode.bitmap, slot);
            const children = try allocator.alloc(*Node, pop + 1);
            errdefer allocator.free(children);
            // Copy [0,pidx), insert, copy [pidx,pop) — all siblings retained.
            for (inode.children[0..pidx], 0..) |sib, i| {
                retainNode(sib);
                children[i] = sib;
            }
            children[pidx] = new_leaf;
            for (inode.children[pidx..], 0..) |sib, j| {
                retainNode(sib);
                children[pidx + 1 + j] = sib;
            }
            const new_bitmap = inode.bitmap | (@as(u32, 1) << slot);
            // On error, release everything we retained (incl. the new leaf).
            return newInternal(allocator, new_bitmap, children) catch |err| {
                for (children) |ch| releaseNode(ch, allocator);
                allocator.free(children);
                return err;
            };
        }

        /// Build a subtree holding two distinct keys whose hashes are
        /// `ha` / `hb`, starting at `depth`. Descends one level per shared
        /// 5-bit slot; if the keys still collide once hash bits are exhausted
        /// (or at `max_depth`), produces a bounded 2-entry collision leaf.
        fn mergeTwo(
            allocator: Allocator,
            depth: u6,
            ka: K,
            va: V,
            ha: u64,
            kb: K,
            vb: V,
            hb: u64,
        ) error{OutOfMemory}!*Node {
            // Out of fresh hash bits → collision leaf (finite, 2 entries).
            if (depth >= max_depth) {
                const entries = try allocator.alloc(Entry, 2);
                errdefer allocator.free(entries);
                entries[0] = .{ .key = ka, .value = va };
                entries[1] = .{ .key = kb, .value = vb };
                return newCollision(allocator, entries) catch |err| {
                    allocator.free(entries);
                    return err;
                };
            }

            const sa = slotOf(ha, depth);
            const sb = slotOf(hb, depth);

            if (sa != sb) {
                // Diverge here: a 2-child internal node.
                const leaf_a = try newLeaf(allocator, ka, va);
                errdefer releaseNode(leaf_a, allocator);
                const leaf_b = try newLeaf(allocator, kb, vb);
                errdefer releaseNode(leaf_b, allocator);
                const children = try allocator.alloc(*Node, 2);
                errdefer allocator.free(children);
                const bitmap = (@as(u32, 1) << sa) | (@as(u32, 1) << sb);
                if (sa < sb) {
                    children[0] = leaf_a;
                    children[1] = leaf_b;
                } else {
                    children[0] = leaf_b;
                    children[1] = leaf_a;
                }
                return newInternal(allocator, bitmap, children) catch |err| {
                    releaseNode(leaf_a, allocator);
                    releaseNode(leaf_b, allocator);
                    allocator.free(children);
                    return err;
                };
            }

            // Same slot at this level → recurse one deeper, wrap in a single-
            // child internal node.
            const sub = try mergeTwo(allocator, depth + 1, ka, va, ha, kb, vb, hb);
            errdefer releaseNode(sub, allocator);
            const children = try allocator.alloc(*Node, 1);
            errdefer allocator.free(children);
            children[0] = sub;
            const bitmap = @as(u32, 1) << sa;
            return newInternal(allocator, bitmap, children) catch |err| {
                releaseNode(sub, allocator);
                allocator.free(children);
                return err;
            };
        }

        // ---- remove ------------------------------------------------------

        /// Return a new map with `key` removed, sharing all untouched
        /// structure. If `key` is absent, returns an independent (`retain`ed)
        /// reference to the same tree so the caller owns its own handle.
        pub fn remove(self: Self, allocator: Allocator, key: K) !Self {
            const ctx: Context = undefined;
            const root = self.root orelse {
                return .{ .root = null, .len = 0 };
            };
            const h = ctx.hash(key);
            var removed: bool = false;
            const new_root = try removeNode(allocator, root, h, 0, key, &removed);
            if (!removed) {
                // Absent: hand back an independent reference to the same tree.
                retainNode(root);
                return .{ .root = root, .len = self.len };
            }
            return .{
                .root = new_root, // may be null if the tree became empty
                .len = self.len - 1,
            };
        }

        /// Produce the replacement for `node` with `key` removed. Returns null
        /// when the subtree becomes empty OR when `key` was absent (the caller
        /// distinguishes via `removed.*`). When `removed.*` is true the
        /// returned node (if any) has `rc == 1` and is owned by the caller.
        /// When `removed.*` is false the return value is meaningless (the
        /// caller carries over the original child unchanged).
        fn removeNode(
            allocator: Allocator,
            node: *Node,
            h: u64,
            depth: u6,
            key: K,
            removed: *bool,
        ) error{OutOfMemory}!?*Node {
            const ctx: Context = undefined;
            switch (node.kind) {
                .leaf => |entry| {
                    if (ctx.eql(entry.key, key)) {
                        removed.* = true;
                        return null; // leaf gone
                    }
                    removed.* = false;
                    return null;
                },
                .collision => |c| {
                    return try removeFromCollision(allocator, c, key, removed);
                },
                .internal => |inode| {
                    return try removeFromInternal(allocator, inode, h, depth, key, removed);
                },
            }
        }

        fn removeFromCollision(
            allocator: Allocator,
            c: Collision,
            key: K,
            removed: *bool,
        ) error{OutOfMemory}!?*Node {
            const ctx: Context = undefined;
            // Finite scan for the victim.
            var match: ?usize = null;
            for (c.entries, 0..) |entry, idx| {
                if (ctx.eql(entry.key, key)) {
                    match = idx;
                    break;
                }
            }
            const idx = match orelse {
                removed.* = false;
                return null;
            };
            removed.* = true;
            if (c.entries.len == 2) {
                // Collapses back to a single leaf.
                const keep = c.entries[1 - idx];
                return try newLeaf(allocator, keep.key, keep.value);
            }
            // Copy out, dropping the victim. Finite.
            const entries = try allocator.alloc(Entry, c.entries.len - 1);
            errdefer allocator.free(entries);
            var w: usize = 0;
            for (c.entries, 0..) |entry, i| {
                if (i == idx) continue;
                entries[w] = entry;
                w += 1;
            }
            return newCollision(allocator, entries) catch |err| {
                allocator.free(entries);
                return err;
            };
        }

        fn removeFromInternal(
            allocator: Allocator,
            inode: Internal,
            h: u64,
            depth: u6,
            key: K,
            removed: *bool,
        ) error{OutOfMemory}!?*Node {
            const slot = slotOf(h, depth);
            if (!slotOccupied(inode.bitmap, slot)) {
                removed.* = false;
                return null; // not present in this subtree
            }
            const pidx = physIndex(inode.bitmap, slot);
            const child = inode.children[pidx];
            const new_child = try removeNode(allocator, child, h, depth + 1, key, removed);
            if (!removed.*) {
                // Nothing changed below; signal no-change to caller via flag.
                return null;
            }

            const pop: usize = @popCount(inode.bitmap);

            if (new_child == null) {
                // Child disappeared. Drop this slot from the bitmap.
                if (pop == 1) {
                    // This internal node becomes empty → remove it entirely.
                    return null;
                }
                const new_bitmap = inode.bitmap & ~(@as(u32, 1) << slot);
                const children = try allocator.alloc(*Node, pop - 1);
                errdefer allocator.free(children);
                var w: usize = 0;
                for (inode.children, 0..) |sib, i| {
                    if (i == pidx) continue;
                    retainNode(sib);
                    children[w] = sib;
                    w += 1;
                }
                return newInternal(allocator, new_bitmap, children) catch |err| {
                    for (children) |ch| releaseNode(ch, allocator);
                    allocator.free(children);
                    return err;
                };
            }

            // Child shrank but still present: copy array, swap in new_child,
            // retain the rest. new_child already rc==1 and owned by us.
            const nc = new_child.?;
            const children = try allocator.alloc(*Node, pop);
            errdefer {
                releaseNode(nc, allocator);
                allocator.free(children);
            }
            for (inode.children, 0..) |sib, i| {
                if (i == pidx) {
                    children[i] = nc;
                } else {
                    retainNode(sib);
                    children[i] = sib;
                }
            }
            return newInternal(allocator, inode.bitmap, children) catch |err| {
                for (children) |ch| releaseNode(ch, allocator);
                allocator.free(children);
                return err;
            };
        }

        // ---- iteration (pure read) ---------------------------------------

        /// Depth-first iterator over live entries. Pure read: uses a small
        /// fixed-size traversal stack on the iterator struct, touches no
        /// refcounts. Yields each `Entry` exactly once.
        pub const Iterator = struct {
            /// One stack frame per trie level plus collision/leaf resolution.
            const Frame = struct {
                node: *Node,
                /// Next physical child index (internal) or entry index
                /// (collision) to visit.
                idx: usize,
            };
            // Depth bound: max_depth internal levels, then a leaf or collision
            // frame. +2 slack.
            stack: [max_depth + 2]Frame,
            sp: usize,

            pub fn next(it: *Iterator) ?Entry {
                while (it.sp > 0) {
                    const top = &it.stack[it.sp - 1];
                    switch (top.node.kind) {
                        .leaf => |entry| {
                            it.sp -= 1; // pop; leaves are visited once
                            return entry;
                        },
                        .collision => |c| {
                            if (top.idx < c.entries.len) {
                                const e = c.entries[top.idx];
                                top.idx += 1;
                                return e;
                            }
                            it.sp -= 1;
                        },
                        .internal => |inode| {
                            if (top.idx < inode.children.len) {
                                const child = inode.children[top.idx];
                                top.idx += 1;
                                it.stack[it.sp] = .{ .node = child, .idx = 0 };
                                it.sp += 1;
                            } else {
                                it.sp -= 1;
                            }
                        },
                    }
                }
                return null;
            }
        };

        /// Create an iterator over this snapshot's live entries.
        pub fn iterator(self: Self) Iterator {
            var it: Iterator = .{ .stack = undefined, .sp = 0 };
            if (self.root) |r| {
                it.stack[0] = .{ .node = r, .idx = 0 };
                it.sp = 1;
            }
            return it;
        }
    };
}

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

/// Normal u64 context: real hashing, behaves like AutoHashMap.
const U64Context = struct {
    pub fn hash(_: U64Context, key: u64) u64 {
        return std.hash.Wyhash.hash(0, std.mem.asBytes(&key));
    }
    pub fn eql(_: U64Context, a: u64, b: u64) bool {
        return a == b;
    }
};

/// Pathological context: almost every key collides (hash is just `key & 1`),
/// so most distinct keys agree on all hash bits and pile into collision leaves.
/// Exercises the bounded-collision-leaf path hard.
const CollidingContext = struct {
    pub fn hash(_: CollidingContext, key: u64) u64 {
        return key & 1;
    }
    pub fn eql(_: CollidingContext, a: u64, b: u64) bool {
        return a == b;
    }
};

const Map = PersistentMap(u64, u64, U64Context);
const CMap = PersistentMap(u64, u64, CollidingContext);

test "empty / put / get / count / overwrite" {
    const a = testing.allocator;
    const m0 = Map.empty();
    defer m0.release(a);
    try testing.expectEqual(@as(usize, 0), m0.count());
    try testing.expectEqual(@as(?u64, null), m0.get(42));

    const m1 = try m0.put(a, 1, 100);
    defer m1.release(a);
    const m2 = try m1.put(a, 2, 200);
    defer m2.release(a);
    const m3 = try m2.put(a, 3, 300);
    defer m3.release(a);

    try testing.expectEqual(@as(usize, 3), m3.count());
    try testing.expectEqual(@as(?u64, 100), m3.get(1));
    try testing.expectEqual(@as(?u64, 200), m3.get(2));
    try testing.expectEqual(@as(?u64, 300), m3.get(3));
    try testing.expectEqual(@as(?u64, null), m3.get(4));

    // Overwrite existing key: count unchanged, value updated, no leak.
    const m4 = try m3.put(a, 2, 222);
    defer m4.release(a);
    try testing.expectEqual(@as(usize, 3), m4.count());
    try testing.expectEqual(@as(?u64, 222), m4.get(2));
    // Old version still sees old value.
    try testing.expectEqual(@as(?u64, 200), m3.get(2));
}

test "remove present and absent" {
    const a = testing.allocator;
    var m = Map.empty();
    defer m.release(a);
    {
        var i: u64 = 0;
        while (i < 20) : (i += 1) {
            const next = try m.put(a, i, i * 10);
            m.release(a);
            m = next;
        }
    }
    try testing.expectEqual(@as(usize, 20), m.count());

    // Remove absent key: count unchanged, independent reference returned.
    const m_absent = try m.remove(a, 999);
    defer m_absent.release(a);
    try testing.expectEqual(@as(usize, 20), m_absent.count());
    try testing.expectEqual(@as(?u64, 50), m_absent.get(5));

    // Remove present key.
    const m_less = try m.remove(a, 5);
    defer m_less.release(a);
    try testing.expectEqual(@as(usize, 19), m_less.count());
    try testing.expectEqual(@as(?u64, null), m_less.get(5));
    // Other keys intact.
    try testing.expectEqual(@as(?u64, 70), m_less.get(7));
    // Original still has it.
    try testing.expectEqual(@as(?u64, 50), m.get(5));

    // Remove down to empty.
    var e = m_less;
    e.retain();
    {
        var i: u64 = 0;
        while (i < 20) : (i += 1) {
            const next = try e.remove(a, i);
            e.release(a);
            e = next;
        }
    }
    defer e.release(a);
    try testing.expectEqual(@as(usize, 0), e.count());
    try testing.expectEqual(@as(?u64, null), e.get(7));
}

test "persistence: deriving v2 leaves v1 intact" {
    const a = testing.allocator;
    const v1 = blk: {
        var m = Map.empty();
        var i: u64 = 0;
        while (i < 50) : (i += 1) {
            const next = try m.put(a, i, i);
            m.release(a);
            m = next;
        }
        break :blk m;
    };
    defer v1.release(a);

    // Derive v2: overwrite some, add some, remove some.
    const v2 = blk: {
        var m = try v1.put(a, 10, 9999);
        const m2 = try m.put(a, 100, 100);
        m.release(a);
        m = m2;
        const m3 = try m.remove(a, 20);
        m.release(a);
        m = m3;
        break :blk m;
    };
    defer v2.release(a);

    // v1 untouched.
    try testing.expectEqual(@as(usize, 50), v1.count());
    try testing.expectEqual(@as(?u64, 10), v1.get(10));
    try testing.expectEqual(@as(?u64, 20), v1.get(20));
    try testing.expectEqual(@as(?u64, null), v1.get(100));

    // v2 reflects changes.
    try testing.expectEqual(@as(usize, 50), v2.count()); // +1 add, -1 remove
    try testing.expectEqual(@as(?u64, 9999), v2.get(10));
    try testing.expectEqual(@as(?u64, null), v2.get(20));
    try testing.expectEqual(@as(?u64, 100), v2.get(100));
}

test "structural sharing: releasing one version never corrupts another" {
    const a = testing.allocator;
    // Build a chain of versions, hold them all, release in scrambled order,
    // verifying survivors stay correct at every step.
    var versions: [16]Map = undefined;
    versions[0] = Map.empty();
    {
        var v: usize = 1;
        while (v < versions.len) : (v += 1) {
            versions[v] = try versions[v - 1].put(a, @intCast(v), @as(u64, @intCast(v)) * 7);
        }
    }
    // Each versions[v] should contain keys 1..=v.
    {
        var v: usize = 0;
        while (v < versions.len) : (v += 1) {
            try testing.expectEqual(@as(usize, v), versions[v].count());
            if (v >= 1) try testing.expectEqual(@as(?u64, @as(u64, @intCast(v)) * 7), versions[v].get(@intCast(v)));
        }
    }
    // Release even indices first, then verify odd ones still correct.
    {
        var v: usize = 0;
        while (v < versions.len) : (v += 2) versions[v].release(a);
    }
    {
        var v: usize = 1;
        while (v < versions.len) : (v += 2) {
            try testing.expectEqual(@as(usize, v), versions[v].count());
            try testing.expectEqual(@as(?u64, @as(u64, @intCast(v)) * 7), versions[v].get(@intCast(v)));
            try testing.expectEqual(@as(?u64, 7), versions[v].get(1));
        }
    }
    // Release the rest; everything frees, allocator verifies no leak.
    {
        var v: usize = 1;
        while (v < versions.len) : (v += 2) versions[v].release(a);
    }
}

test "overwrite then release old root frees old leaf (no leak)" {
    const a = testing.allocator;
    var old = Map.empty();
    {
        var i: u64 = 0;
        while (i < 30) : (i += 1) {
            const next = try old.put(a, i, i);
            old.release(a);
            old = next;
        }
    }
    const new = try old.put(a, 15, 1500);
    // Release old: its unique nodes (incl. the old leaf for key 15) must free.
    old.release(a);
    // new fully intact.
    try testing.expectEqual(@as(usize, 30), new.count());
    try testing.expectEqual(@as(?u64, 1500), new.get(15));
    try testing.expectEqual(@as(?u64, 7), new.get(7));
    new.release(a); // frees everything; allocator asserts no leak
}

test "collisions: hundreds of all-colliding keys, no hang, no leak" {
    const a = testing.allocator;
    const n: u64 = 400;
    var m = CMap.empty();
    defer m.release(a);
    {
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            // keys 0,2,4,... share hash 0; 1,3,5,... share hash 1.
            const next = try m.put(a, i, i * 3 + 1);
            m.release(a);
            m = next;
        }
    }
    try testing.expectEqual(@as(usize, n), m.count());
    {
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            try testing.expectEqual(@as(?u64, i * 3 + 1), m.get(i));
        }
    }
    try testing.expectEqual(@as(?u64, null), m.get(n + 1));

    // Overwrite half (still colliding), then remove a third.
    {
        var i: u64 = 0;
        while (i < n) : (i += 2) {
            const next = try m.put(a, i, i * 100);
            m.release(a);
            m = next;
        }
    }
    {
        var i: u64 = 0;
        while (i < n) : (i += 3) {
            const next = try m.remove(a, i);
            m.release(a);
            m = next;
        }
    }
    // Verify final state against expectation.
    {
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const was_removed = (i % 3 == 0);
            if (was_removed) {
                try testing.expectEqual(@as(?u64, null), m.get(i));
            } else if (i % 2 == 0) {
                try testing.expectEqual(@as(?u64, i * 100), m.get(i));
            } else {
                try testing.expectEqual(@as(?u64, i * 3 + 1), m.get(i));
            }
        }
    }
}

test "randomized differential vs std.AutoHashMap" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_D00D_1234);
    const rng = prng.random();

    var model = std.AutoHashMap(u64, u64).init(a);
    defer model.deinit();

    var m = Map.empty();
    defer m.release(a);

    // A held snapshot taken partway; must stay consistent with its own model.
    var snap: ?Map = null;
    var snap_model = std.AutoHashMap(u64, u64).init(a);
    defer snap_model.deinit();
    defer if (snap) |s| s.release(a);

    const iterations: usize = 4000;
    var step: usize = 0;
    while (step < iterations) : (step += 1) {
        // Bias toward a small key space so collisions/overwrites/removes happen.
        const key = rng.intRangeAtMost(u64, 0, 256);
        const do_remove = rng.boolean() and rng.boolean(); // ~25% removes

        if (do_remove) {
            const next = try m.remove(a, key);
            m.release(a);
            m = next;
            _ = model.remove(key);
        } else {
            const val = rng.int(u64);
            const next = try m.put(a, key, val);
            m.release(a);
            m = next;
            try model.put(key, val);
        }

        // count always agrees.
        try testing.expectEqual(model.count(), m.count());

        // Spot-check a few keys.
        var probe: u64 = 0;
        while (probe < 8) : (probe += 1) {
            const pk = rng.intRangeAtMost(u64, 0, 256);
            try testing.expectEqual(model.get(pk), m.get(pk));
        }

        // Take a snapshot once, midway. Copy its model too.
        if (step == iterations / 2 and snap == null) {
            m.retain();
            snap = m;
            var kit = model.iterator();
            while (kit.next()) |e| try snap_model.put(e.key_ptr.*, e.value_ptr.*);
        }
    }

    // Full verification of the live map against the model.
    {
        var kit = model.iterator();
        while (kit.next()) |e| {
            try testing.expectEqual(@as(?u64, e.value_ptr.*), m.get(e.key_ptr.*));
        }
        // And the reverse: every live entry is in the model.
        var it = m.iterator();
        var live_seen: usize = 0;
        while (it.next()) |entry| {
            try testing.expectEqual(@as(?u64, entry.value), model.get(entry.key));
            live_seen += 1;
        }
        try testing.expectEqual(model.count(), live_seen);
    }

    // The mid-run snapshot must STILL match its frozen model, despite all the
    // later derived mutations on `m`.
    if (snap) |s| {
        try testing.expectEqual(snap_model.count(), s.count());
        var kit = snap_model.iterator();
        while (kit.next()) |e| {
            try testing.expectEqual(@as(?u64, e.value_ptr.*), s.get(e.key_ptr.*));
        }
    }
}

test "iterator yields exactly the live set" {
    const a = testing.allocator;
    var m = Map.empty();
    defer m.release(a);

    var expected = std.AutoHashMap(u64, u64).init(a);
    defer expected.deinit();

    {
        var i: u64 = 0;
        while (i < 100) : (i += 1) {
            const next = try m.put(a, i * 7 + 3, i);
            m.release(a);
            m = next;
            try expected.put(i * 7 + 3, i);
        }
    }
    // Remove a handful.
    {
        const victims = [_]u64{ 3, 7 * 5 + 3, 7 * 50 + 3, 7 * 99 + 3 };
        for (victims) |vk| {
            const next = try m.remove(a, vk);
            m.release(a);
            m = next;
            _ = expected.remove(vk);
        }
    }

    var seen = std.AutoHashMap(u64, void).init(a);
    defer seen.deinit();

    var it = m.iterator();
    var n: usize = 0;
    while (it.next()) |entry| {
        // No duplicates.
        try testing.expect(!seen.contains(entry.key));
        try seen.put(entry.key, {});
        // Value matches.
        try testing.expectEqual(@as(?u64, entry.value), expected.get(entry.key));
        n += 1;
    }
    try testing.expectEqual(expected.count(), n);
    try testing.expectEqual(m.count(), n);
}
