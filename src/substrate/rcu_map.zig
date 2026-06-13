//! Read-Copy-Update (RCU) concurrent map — `RcuMap(K, V, Context)`.
//!
//! `RcuMap` is the lock-free-read concurrent map of Orochi's sharded reactor
//! world. It composes two committed substrates into the classic RCU
//! publish/retire pattern:
//!
//!   * `persistent_map.zig` — an immutable, structurally-shared HAMT. A writer
//!     derives the NEXT version from the current one (`put`/`remove`), sharing
//!     every untouched subtree; the old version stays a fully valid immutable
//!     snapshot for any reader still traversing it.
//!   * `ebr.zig` — epoch-based reclamation. A reader `pin`s into the current
//!     epoch before loading the published root and `unpin`s when done; a writer
//!     `retire`s the OLD root so its unique nodes are freed only after a grace
//!     period during which every reader has crossed an epoch boundary.
//!
//! ## The RCU publish/retire cycle
//!
//! The published map state is a heap-allocated immutable *root cell* holding a
//! `PersistentMap` value (its `?*Node` root + cached `len`). The cell is stored
//! behind a single `std.atomic.Value(?*Cell)`:
//!
//!   * READ (lock-free, never blocks): pin an EBR participant, load the cell
//!     `.acquire`, take the `PersistentMap` snapshot out of it. The EBR pin
//!     guarantees the snapshot's nodes (and the cell) cannot be freed until the
//!     reader unpins and the epoch advances twice. Reads touch NO refcount and
//!     NO lock.
//!   * WRITE (serialized by a writer spinlock; never blocks on readers): load
//!     the current cell, derive `new = current.map.put(allocator, k, v)`,
//!     allocate a fresh cell holding `new`, publish it with a single atomic
//!     store `.release`, then `retireErased` the OLD cell. The retire free-fn
//!     `release`s the old cell's `PersistentMap` root (freeing only the nodes
//!     unique to that version, after the grace period) and destroys the cell.
//!
//! Publication is one atomic store; freeing is fully deferred to EBR. Writers
//! serialize against each other via the spinlock but NEVER wait on readers, and
//! readers NEVER take the spinlock.
//!
//! ## Borrowed domain invariant
//!
//! The `*ebr.Domain` is BORROWED, not owned: it is shared across every reactor
//! shard and owned by the caller. `RcuMap.init` records the pointer; `deinit`
//! never touches the domain's lifecycle. Quiescence (no in-flight readers) is
//! the caller's responsibility at shutdown — they must drive `domain.drainAll()`
//! (after all readers unpin and unregister) so every retired cell is reclaimed
//! before `domain.deinit()` asserts quiescence. `RcuMap.deinit` releases the
//! current (published) root directly, which is correct only once no reader can
//! still be pinned on it — exactly the shutdown quiescence the EBR domain
//! enforces.
//!
//! ## Lock-free-read invariant
//!
//! A `ReadHandle` is valid for its whole lifetime: the snapshot it holds is an
//! immutable `PersistentMap` and the EBR guard it carries prevents that
//! snapshot's nodes from being freed. Concurrent writers may publish any number
//! of newer versions; the handle keeps seeing exactly the version it loaded.
//! `get` / `count` / `iterator` on a handle are pure reads.

const std = @import("std");
const ebr = @import("ebr.zig");
const persistent_map = @import("persistent_map.zig");

/// A lock-free-read, copy-on-write concurrent map.
///
/// `Context` must be a stateless (zero-sized) type providing
/// `pub fn hash(self, key: K) u64` and `pub fn eql(self, a: K, b: K) bool`,
/// exactly like `std.HashMap` contexts — this is forwarded to `PersistentMap`.
pub fn RcuMap(comptime K: type, comptime V: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Map = persistent_map.PersistentMap(K, V, Context);
        const Allocator = std.mem.Allocator;

        /// Immutable root cell: a single published (root, len) snapshot. Stored
        /// behind one atomic pointer so the pair publishes atomically. Owns one
        /// reference to its `PersistentMap` root; retired (via EBR) as a unit.
        const Cell = struct {
            map: Map,
        };

        /// Re-export of `PersistentMap.Entry` for iterator consumers.
        pub const Entry = Map.Entry;

        /// Backing allocator for cells AND for `PersistentMap` node copies. Used
        /// by the writer path and by `deinit`.
        allocator: Allocator,
        /// BORROWED epoch-reclamation domain, shared across reactors and owned
        /// by the caller. Never deinit'd here.
        domain: *ebr.Domain,
        /// The currently published root cell. Loaded `.acquire` by readers,
        /// stored `.release` by writers. Always non-null after `init`.
        published: std.atomic.Value(?*Cell),
        /// Writer spinlock. Writers serialize on this; readers NEVER touch it.
        writer_lock: std.atomic.Value(bool),

        // ---- construction -------------------------------------------------

        /// Start an empty map over the borrowed `domain`. The initial empty cell
        /// is allocated eagerly so `published` is always non-null.
        pub fn init(allocator: Allocator, domain: *ebr.Domain) !Self {
            const cell = try allocator.create(Cell);
            cell.* = .{ .map = Map.empty() };
            return .{
                .allocator = allocator,
                .domain = domain,
                .published = .init(cell),
                .writer_lock = .init(false),
            };
        }

        /// Release the currently published root and free its cell. Valid ONLY
        /// at quiescence: no reader may be pinned on the published snapshot, and
        /// the caller must already have drained the EBR domain (`drainAll`) so
        /// every retired older cell is reclaimed. Does NOT touch the borrowed
        /// domain's lifecycle.
        pub fn deinit(self: *Self) void {
            // No reader may hold a pin here (shutdown quiescence); freeing the
            // live root directly is safe.
            const cell = self.published.swap(null, .acq_rel) orelse return;
            cell.map.release(self.allocator);
            self.allocator.destroy(cell);
        }

        // ---- writer spinlock ---------------------------------------------

        fn lockWriter(self: *Self) void {
            // Test-and-test-and-set with a spin hint. Writers serialize; this is
            // never contended by readers.
            while (true) {
                if (!self.writer_lock.swap(true, .acquire)) return;
                while (self.writer_lock.load(.monotonic)) std.atomic.spinLoopHint();
            }
        }

        fn unlockWriter(self: *Self) void {
            self.writer_lock.store(false, .release);
        }

        // ---- retire plumbing ---------------------------------------------

        /// EBR free-fn for a retired cell: release the version's unique nodes,
        /// then destroy the cell struct itself.
        fn reclaimCell(ptr: *anyopaque, allocator: Allocator) void {
            const cell: *Cell = @ptrCast(@alignCast(ptr));
            cell.map.release(allocator);
            allocator.destroy(cell);
        }

        // ---- reads (lock-free) -------------------------------------------

        /// A live read view over one published snapshot. The EBR guard it
        /// carries keeps the snapshot's nodes alive for the handle's whole
        /// lifetime, regardless of concurrent writes. MUST be `release`d.
        pub const ReadHandle = struct {
            snapshot: Map,
            guard: ebr.Guard,

            /// Look up `key` in this snapshot. Pure read.
            pub fn get(self: ReadHandle, key: K) ?V {
                return self.snapshot.get(key);
            }

            /// Number of keys in this snapshot. O(1) pure read.
            pub fn count(self: ReadHandle) usize {
                return self.snapshot.count();
            }

            /// Iterate this snapshot's live entries. Pure read.
            pub fn iterator(self: ReadHandle) Map.Iterator {
                return self.snapshot.iterator();
            }

            /// Leave the read critical section. After this the snapshot must no
            /// longer be used.
            pub fn release(self: *ReadHandle) void {
                self.guard.unpin();
            }
        };

        /// Open a lock-free read view using the caller's EBR participant `p`.
        /// Pins `p`, loads the published root `.acquire`, and returns a handle
        /// over that immutable snapshot. Never blocks, never allocates, never
        /// touches a refcount or the writer lock.
        pub fn read(self: *Self, p: *ebr.Participant) ReadHandle {
            const guard = p.pin();
            // The pin (with its seq_cst fence) happens-before this acquire load,
            // so the snapshot we observe cannot be reclaimed until we unpin.
            const cell = self.published.load(.acquire).?;
            return .{ .snapshot = cell.map, .guard = guard };
        }

        // ---- writes (serialized; never block on readers) -----------------

        /// Bind `key` to `value`, publishing a new immutable version and
        /// retiring the old one for epoch-deferred free. Serialized via the
        /// writer spinlock; does not wait on readers. `p` is the writer's EBR
        /// participant (used to retire the old cell).
        pub fn put(self: *Self, p: *ebr.Participant, key: K, value: V) !void {
            try self.replace(p, .{ .put = .{ .key = key, .value = value } });
        }

        /// Remove `key`, publishing a new immutable version and retiring the old
        /// one. Serialized via the writer spinlock; does not wait on readers.
        pub fn remove(self: *Self, p: *ebr.Participant, key: K) !void {
            try self.replace(p, .{ .remove = .{ .key = key } });
        }

        /// Drive epoch reclamation for this map's domain under the writer lock.
        ///
        /// Reclamation `release`s retired versions, which mutates the (non-atomic)
        /// refcounts of structurally-shared `PersistentMap` nodes. A concurrent
        /// `put`/`remove` `retain`s those same shared nodes. Both must be mutually
        /// exclusive, so epoch advancement is serialized on the SAME writer lock
        /// as the COW writers. Readers are never involved. Returns whether the
        /// epoch advanced. Prefer this over calling `domain.advance()` directly
        /// when multiple writers share the domain.
        pub fn advance(self: *Self) bool {
            self.lockWriter();
            defer self.unlockWriter();
            return self.domain.advance();
        }

        const Op = union(enum) {
            put: struct { key: K, value: V },
            remove: struct { key: K },
        };

        /// Shared writer body: derive the next version under the writer lock,
        /// publish it atomically, retire the old cell.
        fn replace(self: *Self, p: *ebr.Participant, op: Op) !void {
            self.lockWriter();
            defer self.unlockWriter();

            const old_cell = self.published.load(.acquire).?;

            // Derive the next immutable version. On failure the old cell is
            // untouched and still published — the map is unchanged.
            const next: Map = switch (op) {
                .put => |kv| try old_cell.map.put(self.allocator, kv.key, kv.value),
                .remove => |k| try old_cell.map.remove(self.allocator, k.key),
            };

            const new_cell = self.allocator.create(Cell) catch |err| {
                // Roll back the derived version we will not publish.
                next.release(self.allocator);
                return err;
            };
            new_cell.* = .{ .map = next };

            // Single-store publication: readers either see old_cell or new_cell,
            // never a torn pair. Release so the new nodes' writes are visible to
            // a reader's acquire load.
            self.published.store(new_cell, .release);

            // Defer the old version's free until every reader pinned on it has
            // crossed two epoch boundaries. We never block on readers here.
            p.retireErased(@ptrCast(old_cell), reclaimCell, self.allocator);
        }
    };
}

// =====================================================================
// Tests
// =====================================================================

const testing = std.testing;

const U64Context = struct {
    pub fn hash(_: U64Context, key: u64) u64 {
        return std.hash.Wyhash.hash(0, std.mem.asBytes(&key));
    }
    pub fn eql(_: U64Context, a: u64, b: u64) bool {
        return a == b;
    }
};

const TestMap = RcuMap(u64, u64, U64Context);

test "single-thread put/get/remove/overwrite/count under read handles" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();

    var map = try TestMap.init(a, &domain);
    // Tear down: drain retired cells, then release the live root.
    defer {
        domain.drainAll();
        map.deinit();
    }

    const w = domain.register() catch unreachable;
    defer w.unregister();
    const r = domain.register() catch unreachable;
    defer r.unregister();

    // Empty.
    {
        var h = map.read(r);
        defer h.release();
        try testing.expectEqual(@as(usize, 0), h.count());
        try testing.expectEqual(@as(?u64, null), h.get(1));
    }

    // Insert three.
    try map.put(w, 1, 100);
    try map.put(w, 2, 200);
    try map.put(w, 3, 300);
    {
        var h = map.read(r);
        defer h.release();
        try testing.expectEqual(@as(usize, 3), h.count());
        try testing.expectEqual(@as(?u64, 100), h.get(1));
        try testing.expectEqual(@as(?u64, 200), h.get(2));
        try testing.expectEqual(@as(?u64, 300), h.get(3));
        try testing.expectEqual(@as(?u64, null), h.get(4));
    }

    // Overwrite: count stable, value updated.
    try map.put(w, 2, 222);
    {
        var h = map.read(r);
        defer h.release();
        try testing.expectEqual(@as(usize, 3), h.count());
        try testing.expectEqual(@as(?u64, 222), h.get(2));
    }

    // Remove.
    try map.remove(w, 2);
    {
        var h = map.read(r);
        defer h.release();
        try testing.expectEqual(@as(usize, 2), h.count());
        try testing.expectEqual(@as(?u64, null), h.get(2));
        try testing.expectEqual(@as(?u64, 100), h.get(1));
        try testing.expectEqual(@as(?u64, 300), h.get(3));
    }

    // Remove absent: no change.
    try map.remove(w, 999);
    {
        var h = map.read(r);
        defer h.release();
        try testing.expectEqual(@as(usize, 2), h.count());
    }

    // Iterator over the handle yields the live set.
    {
        var h = map.read(r);
        defer h.release();
        var seen: usize = 0;
        var sum: u64 = 0;
        var it = h.iterator();
        while (it.next()) |e| {
            seen += 1;
            sum += e.value;
        }
        try testing.expectEqual(@as(usize, 2), seen);
        try testing.expectEqual(@as(u64, 100 + 300), sum);
    }

    // Advance enough to reclaim everything retired so far (keeps live count low).
    _ = domain.advance();
    _ = domain.advance();
    _ = domain.advance();
}

test "snapshot stability: held handle keeps the old version across writes" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();

    var map = try TestMap.init(a, &domain);
    defer {
        domain.drainAll();
        map.deinit();
    }

    const w = domain.register() catch unreachable;
    defer w.unregister();
    const r = domain.register() catch unreachable;
    defer r.unregister();

    try map.put(w, 1, 10);
    try map.put(w, 2, 20);

    // Take a read handle, pinning the current version.
    var held = map.read(r);
    try testing.expectEqual(@as(usize, 2), held.count());
    try testing.expectEqual(@as(?u64, 10), held.get(1));

    // Mutate heavily while the handle is open. The old cells get retired but
    // CANNOT be freed: the reader is pinned. advance() must not reclaim them.
    try map.put(w, 1, 999);
    try map.put(w, 3, 30);
    try map.remove(w, 2);
    _ = domain.advance(); // blocked from reclaiming the held version's bag

    // The held handle still sees exactly the version it loaded.
    try testing.expectEqual(@as(usize, 2), held.count());
    try testing.expectEqual(@as(?u64, 10), held.get(1));
    try testing.expectEqual(@as(?u64, 20), held.get(2));
    try testing.expectEqual(@as(?u64, null), held.get(3));

    held.release();

    // A fresh read sees the new version.
    {
        var h = map.read(r);
        defer h.release();
        try testing.expectEqual(@as(usize, 2), h.count()); // {1,3}
        try testing.expectEqual(@as(?u64, 999), h.get(1));
        try testing.expectEqual(@as(?u64, 30), h.get(3));
        try testing.expectEqual(@as(?u64, null), h.get(2));
    }

    _ = domain.advance();
    _ = domain.advance();
    _ = domain.advance();
}

test "threaded: readers never observe garbage while writers churn, no leak" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();

    var map = try TestMap.init(a, &domain);
    defer {
        domain.drainAll();
        map.deinit();
    }

    // Key space and an invariant the value always satisfies: value == key * 7 + 1
    // whenever a key is present. A reader that ever sees a different value for a
    // present key has observed torn/garbage memory.
    const key_space: u64 = 64;

    const Shared = struct {
        map: *TestMap,
        stop: *std.atomic.Value(bool),
        corruption: *std.atomic.Value(bool),

        fn readerLoop(ctx: @This(), p: *ebr.Participant) void {
            var iters: usize = 0;
            while (!ctx.stop.load(.acquire)) : (iters += 1) {
                var h = ctx.map.read(p);
                var probe: u64 = 0;
                while (probe < key_space) : (probe += 1) {
                    if (h.get(probe)) |v| {
                        if (v != probe * 7 + 1) {
                            ctx.corruption.store(true, .release);
                        }
                    }
                }
                // Iterator must also only ever yield valid pairs.
                var it = h.iterator();
                while (it.next()) |e| {
                    if (e.value != e.key * 7 + 1) {
                        ctx.corruption.store(true, .release);
                    }
                }
                h.release();
                if (iters % 32 == 0) std.atomic.spinLoopHint();
            }
        }

        fn writerLoop(ctx: @This(), p: *ebr.Participant, rounds: usize) void {
            var prng = std.Random.DefaultPrng.init(0xABCD_1234_5678);
            const rng = prng.random();
            var r: usize = 0;
            while (r < rounds) : (r += 1) {
                const key = rng.intRangeLessThan(u64, 0, key_space);
                if (rng.boolean()) {
                    ctx.map.put(p, key, key * 7 + 1) catch return;
                } else {
                    ctx.map.remove(p, key) catch return;
                }
                if (r % 4 == 0) _ = ctx.map.advance();
            }
        }
    };

    var stop = std.atomic.Value(bool).init(false);
    var corruption = std.atomic.Value(bool).init(false);

    const reader_count = 4;
    const writer_count = 2;
    const writer_rounds = 15_000;

    var reader_parts: [reader_count]*ebr.Participant = undefined;
    var writer_parts: [writer_count]*ebr.Participant = undefined;
    for (0..reader_count) |i| reader_parts[i] = domain.register() catch unreachable;
    for (0..writer_count) |i| writer_parts[i] = domain.register() catch unreachable;

    const shared = Shared{
        .map = &map,
        .stop = &stop,
        .corruption = &corruption,
    };

    var reader_threads: [reader_count]std.Thread = undefined;
    var writer_threads: [writer_count]std.Thread = undefined;
    var readers_spawned: usize = 0;
    var writers_spawned: usize = 0;

    // On any spawn failure: stop, join whatever started, drain, and skip.
    errdefer {
        stop.store(true, .release);
        for (0..writers_spawned) |i| writer_threads[i].join();
        for (0..readers_spawned) |i| reader_threads[i].join();
        for (0..reader_count) |i| reader_parts[i].unregister();
        for (0..writer_count) |i| writer_parts[i].unregister();
    }

    for (0..reader_count) |i| {
        reader_threads[i] = std.Thread.spawn(.{}, Shared.readerLoop, .{ shared, reader_parts[i] }) catch return error.SkipZigTest;
        readers_spawned += 1;
    }
    for (0..writer_count) |i| {
        writer_threads[i] = std.Thread.spawn(.{}, Shared.writerLoop, .{ shared, writer_parts[i], writer_rounds }) catch return error.SkipZigTest;
        writers_spawned += 1;
    }

    // Writers finish first; then stop readers.
    for (0..writers_spawned) |i| writer_threads[i].join();
    stop.store(true, .release);
    for (0..readers_spawned) |i| reader_threads[i].join();

    try testing.expect(!corruption.load(.acquire));

    // Compute the live set from the final published snapshot and verify the
    // invariant once more single-threaded.
    {
        var h = map.read(reader_parts[0]);
        defer h.release();
        var it = h.iterator();
        var live: usize = 0;
        while (it.next()) |e| {
            try testing.expectEqual(@as(u64, e.key * 7 + 1), e.value);
            live += 1;
        }
        try testing.expectEqual(live, h.count());
    }

    // Unregister readers/writers (none pinned now), then drain all retired cells
    // so the domain reaches quiescence before deinit. The deferred map.deinit +
    // domain.deinit + testing.allocator then assert no leak.
    for (0..reader_count) |i| reader_parts[i].unregister();
    for (0..writer_count) |i| writer_parts[i].unregister();
}
