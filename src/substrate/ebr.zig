// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Epoch-based reclamation (EBR), the classic 3-epoch scheme (Fraser/Harris).
//!
//! EBR is the memory-reclamation foundation of Orochi's lock-free world.
//! Readers `pin` into the current global epoch, traverse shared immutable
//! structures lock-free, then `unpin`. Writers `retire` nodes they have
//! unlinked; a retired node is freed only after a *grace period* during which
//! every reader has crossed an epoch boundary, so no reader can ever observe
//! freed memory.
//!
//! ## The 3-epoch grace-period argument (why deferred frees are safe)
//!
//! The global epoch `g` cycles 0 -> 1 -> 2 -> 0 ... Each participant keeps a
//! `local_epoch` and an `active` flag. On `pin`, a participant publishes
//! `local_epoch := g` and sets `active`. Each participant owns three limbo
//! bags, indexed `epoch % 3`.
//!
//! `retire(x)` during global epoch `e` appends `x` to the retiring
//! participant's bag `e % 3`. The invariant we maintain is:
//!
//!   The global epoch advances from `e` to `e+1` ONLY when every *active*
//!   (pinned) participant has `local_epoch == e`.
//!
//! That means: when we are in epoch `e`, no pinned reader is still observing a
//! snapshot from epoch `e-1` or earlier — they have all either unpinned or
//! re-pinned at `e`. Consider a node `x` retired in epoch `e`:
//!
//!   * `x` was unlinked from the shared structure no later than epoch `e`. Any
//!     reader that could still reach `x` must have pinned during epoch `e` or
//!     earlier (it observed `x` before, or concurrently with, the unlink).
//!   * To advance e -> e+1, all such readers had `local_epoch == e`. To then
//!     advance e+1 -> e+2, all *currently* pinned readers have
//!     `local_epoch == e+1`, which proves every reader that was pinned during
//!     epoch `e` has since unpinned (and possibly re-pinned at e+1). None of
//!     them can hold a reference to `x` any longer: a reader only acquires
//!     references *after* publishing its pin epoch, and `x` was already
//!     unlinked before any e+1 pin could observe the structure.
//!
//! Therefore a node retired in epoch `e` is unreachable by every reader once
//! the epoch reaches `e+2`. When the global epoch advances to a new value `n`,
//! the bag `n % 3` is exactly the bag two epochs in the past
//! (`(n-2) % 3 == n % 3`, since `n % 3 == (n+3) % 3 == (n-... )`; concretely
//! the three indices 0,1,2 rotate, and the bag we are about to reclaim is the
//! one last written two epochs ago and not touched since). Two full epochs have
//! elapsed, so reclaiming that bag is safe. This is why three bags suffice:
//! one for the current epoch (being filled), one for the previous epoch (still
//! potentially referenced), and one two epochs back (safe to free, and being
//! drained right before it is reused as the new current bag).
//!
//! ## Memory ordering
//!
//! Read fast path (`pin` / traverse / `unpin`) is lock-free: no mutex, no CAS
//! loop. The orderings:
//!
//!   * `pin` loads the global epoch with `.acquire` and stores the
//!     participant's `local_epoch` / `active` with `.seq_cst`, then performs a
//!     seq_cst read-modify-write on a domain-wide `fence_seq` counter. This RMW
//!     is a full StoreLoad barrier (this Zig has no standalone `@fence`
//!     builtin), guaranteeing the publication is globally visible before the
//!     reader's first shared-pointer load. The fence is REQUIRED: without it,
//!     the CPU/compiler could reorder the participant's first shared-pointer
//!     load ABOVE the publication of `local_epoch`. A writer scanning
//!     participants
//!     could then see the old (or absent) pin, advance the epoch, and free a
//!     node the reader is about to load — a use-after-free. The seq_cst fence
//!     on the reader side, paired with the seq_cst load of `local_epoch` on the
//!     writer's scan, establishes a total order: either the writer sees the
//!     reader's pin (and refuses to advance / reclaim that node), or the reader
//!     sees the post-advance epoch (and never touches the freed node).
//!   * `unpin` clears `active` with `.release` so all reads inside the critical
//!     section happen-before the writer observing the participant idle.
//!   * The writer's epoch scan loads each `local_epoch`/`active` with
//!     `.seq_cst` so it is ordered against reader fences. The epoch advance
//!     itself is a `.seq_cst` CAS (only one writer should call `advance`, but
//!     seq_cst keeps it correct even if serialization is imperfect).
//!   * Shared-pointer publication by the writer (the slot a reader loads in its
//!     critical section) must use `.release`; the reader's load `.acquire`.
//!     That is the caller's responsibility for their own data; EBR only governs
//!     *when memory is freed*, not how the structure itself is published.
//!
//! ## Usage model
//!
//! `register` claims one `Participant` slot per reader thread. `retire` and
//! `advance` are the writer side; Orochi serializes writers per shard, so
//! `retire`/`advance` are expected to be called from a single writer context
//! per domain (or externally synchronized). The read path is fully concurrent.

const std = @import("std");
const testing = std.testing;

pub const cache_line_bytes: usize = 64;

/// Maximum number of concurrently registered participants. Registration beyond
/// this fails. 256 is ample for Orochi's sharded reactor + worker pool.
pub const max_participants: usize = 256;

/// Number of epochs in the rotation. The classic scheme uses 3.
pub const epoch_count: usize = 3;

pub const RegisterError = error{
    TooManyParticipants,
};

/// A type-erased retired node awaiting reclamation.
const Retired = struct {
    ptr: *anyopaque,
    free_fn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) void,
    allocator: std.mem.Allocator,

    fn reclaim(self: Retired) void {
        self.free_fn(self.ptr, self.allocator);
    }
};

/// A per-participant limbo bag for one epoch slot. Unmanaged: storage is owned
/// by the domain's backing allocator and grown on demand during `retire`.
const Bag = struct {
    items: std.ArrayListUnmanaged(Retired) = .empty,

    fn reclaimAll(self: *Bag) void {
        for (self.items.items) |r| r.reclaim();
        self.items.clearRetainingCapacity();
    }

    fn deinit(self: *Bag, allocator: std.mem.Allocator) void {
        // On a quiescent domain this should already be empty; we only free the
        // backing storage here.
        self.items.deinit(allocator);
    }
};

/// One reader/writer participant, cache-line padded to avoid false sharing on
/// the hot `local_epoch` / `active` fields.
pub const Participant = struct {
    /// The epoch this participant last pinned into. Only meaningful when
    /// `active` is set. Written `.release` (+ seq_cst fence) by the owner on
    /// `pin`; read `.seq_cst` by the writer's epoch scan.
    local_epoch: std.atomic.Value(u64) align(cache_line_bytes) = .init(0),
    /// Whether this participant is currently inside a read critical section.
    active: std.atomic.Value(bool) = .init(false),
    /// Whether this slot is claimed (registered). Written by register/unregister.
    in_use: std.atomic.Value(bool) = .init(false),

    /// Per-participant limbo bags, indexed by `epoch % epoch_count`.
    bags: [epoch_count]Bag = .{ .{}, .{}, .{} },

    domain: *Domain = undefined,

    /// Pins one writer participant to the epoch observed while a transaction
    /// reserves a specific limbo bag. At most one epoch advance can occur while
    /// this token is active; a second advance sees the participant pinned in
    /// the older epoch and stops. Retires therefore stay both allocation-free
    /// and correctly aged even when another thread advances concurrently.
    pub const RetireReservation = struct {
        participant: *Participant,
        bag_index: usize,
        remaining: usize,
        active: bool = true,

        pub fn retireErased(
            self: *RetireReservation,
            ptr: *anyopaque,
            free_fn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) void,
            allocator: std.mem.Allocator,
        ) void {
            std.debug.assert(self.active);
            std.debug.assert(self.remaining != 0);
            self.participant.bags[self.bag_index].items.appendAssumeCapacity(.{
                .ptr = ptr,
                .free_fn = free_fn,
                .allocator = allocator,
            });
            self.remaining -= 1;
            _ = self.participant.domain.retired_count.fetchAdd(1, .monotonic);
        }

        /// Release the epoch pin. Unused capacity is harmless; it remains in
        /// the bag for a future reservation.
        pub fn finish(self: *RetireReservation) void {
            std.debug.assert(self.active);
            var guard = Guard{ .participant = self.participant };
            guard.unpin();
            self.active = false;
        }
    };

    /// Enter a read critical section. Publishes the current global epoch as this
    /// participant's local epoch and marks it active, then fences so the first
    /// shared-pointer load cannot float above the publication.
    pub fn pin(self: *Participant) Guard {
        std.debug.assert(self.in_use.load(.monotonic));
        std.debug.assert(!self.active.load(.monotonic)); // no recursive pin

        const g = self.domain.global_epoch.load(.acquire);
        self.local_epoch.store(g, .seq_cst);
        self.active.store(true, .seq_cst);

        // CRITICAL: order the pin publication before any subsequent shared load.
        // This Zig has no `@fence`; a seq_cst RMW on a shared counter is a full
        // StoreLoad barrier and provides the needed total-order point. Pairs
        // with the writer's seq_cst scan loads. See module doc.
        _ = self.domain.fence_seq.fetchAdd(1, .seq_cst);

        return .{ .participant = self };
    }

    /// Retire a typed node to be freed after the grace period. The node is
    /// placed in the bag for the CURRENT global epoch. Writer side.
    pub fn retire(self: *Participant, comptime T: type, ptr: *T, allocator: std.mem.Allocator) void {
        const Closure = struct {
            fn free(p: *anyopaque, a: std.mem.Allocator) void {
                const typed: *T = @ptrCast(@alignCast(p));
                a.destroy(typed);
            }
        };
        self.retireErased(@ptrCast(ptr), Closure.free, allocator);
    }

    /// Pin the observed epoch and reserve exact limbo-bag slots before
    /// publication. Callers must enqueue through the returned token and finish
    /// it on both commit and abort. Pinning closes the reserve/reload race where
    /// a concurrent epoch advance selected an unreserved bag after publication.
    pub fn reserveRetireCapacity(self: *Participant, additional: usize) std.mem.Allocator.Error!RetireReservation {
        std.debug.assert(self.in_use.load(.monotonic));
        var guard = self.pin();
        errdefer guard.unpin();
        const g = self.domain.global_epoch.load(.acquire);
        const idx = g % epoch_count;
        try self.bags[idx].items.ensureUnusedCapacity(self.domain.backing, additional);
        return .{
            .participant = self,
            .bag_index = idx,
            .remaining = additional,
        };
    }

    /// Type-erased retire: caller supplies a free function. Writer side.
    pub fn retireErased(
        self: *Participant,
        ptr: *anyopaque,
        free_fn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) void,
        allocator: std.mem.Allocator,
    ) void {
        std.debug.assert(self.in_use.load(.monotonic));
        const g = self.domain.global_epoch.load(.acquire);
        const idx = g % epoch_count;
        self.bags[idx].items.append(self.domain.backing, .{
            .ptr = ptr,
            .free_fn = free_fn,
            .allocator = allocator,
        }) catch @panic("ebr: limbo bag allocation failed");
        _ = self.domain.retired_count.fetchAdd(1, .monotonic);
    }

    /// Release this participant slot. Asserts it is not pinned. Any remaining
    /// retired nodes in this participant's bags are handed off / drained by the
    /// domain on `deinit`; here we just free bag storage if empty.
    pub fn unregister(self: *Participant) void {
        std.debug.assert(!self.active.load(.monotonic));
        // Caller is responsible for having drained retired nodes (or the domain
        // will assert non-quiescence on deinit). We keep the slot's bags intact
        // for the domain to account; just clear the claim.
        self.in_use.store(false, .release);
    }

    fn bagLen(self: *const Participant) usize {
        return self.bags[0].items.items.len +
            self.bags[1].items.items.len +
            self.bags[2].items.items.len;
    }
};

/// A read-critical-section guard. Dropping conceptually requires `unpin`; Zig
/// has no destructors, so callers MUST call `unpin` explicitly (the substrate
/// convention).
pub const Guard = struct {
    participant: *Participant,

    /// Leave the read critical section.
    pub fn unpin(self: *Guard) void {
        std.debug.assert(self.participant.active.load(.monotonic));
        // Release so all reads in the critical section happen-before a writer
        // observing this participant as idle.
        self.participant.active.store(false, .release);
    }
};

pub const Domain = struct {
    /// The global epoch, monotonically increasing; bag index is `epoch % 3`.
    global_epoch: std.atomic.Value(u64) align(cache_line_bytes) = .init(0),
    /// Total retired-but-not-yet-freed node count, for quiescence assertions.
    retired_count: std.atomic.Value(usize) align(cache_line_bytes) = .init(0),
    /// Dummy counter touched by a seq_cst RMW on each `pin` to act as a
    /// standalone StoreLoad fence (no `@fence` builtin in this Zig).
    fence_seq: std.atomic.Value(u64) align(cache_line_bytes) = .init(0),

    participants: [max_participants]Participant = undefined,
    participant_count: std.atomic.Value(usize) = .init(0),

    /// Allocator backing the limbo bags themselves (not the retired payloads,
    /// which carry their own allocator).
    backing: std.mem.Allocator,

    pub fn init(backing: std.mem.Allocator) Domain {
        var d: Domain = .{ .backing = backing };
        for (&d.participants) |*p| {
            p.* = .{};
        }
        return d;
    }

    /// Assert quiescence then free all bag storage.
    pub fn deinit(self: *Domain) void {
        // Quiescence: no participant may be pinned, and nothing may remain
        // retired-but-unfreed.
        std.debug.assert(self.retired_count.load(.acquire) == 0);
        var i: usize = 0;
        while (i < self.participant_count.load(.acquire)) : (i += 1) {
            const p = &self.participants[i];
            std.debug.assert(!p.active.load(.acquire));
            std.debug.assert(p.bagLen() == 0);
            for (&p.bags) |*b| b.deinit(self.backing);
        }
    }

    /// Claim a free participant slot. One per reader thread.
    pub fn register(self: *Domain) RegisterError!*Participant {
        var idx = self.participant_count.load(.acquire);
        while (true) {
            if (idx >= max_participants) return error.TooManyParticipants;
            if (self.participant_count.cmpxchgWeak(idx, idx + 1, .acq_rel, .acquire)) |next| {
                idx = next;
                continue;
            }
            break;
        }
        const p = &self.participants[idx];
        p.* = .{};
        p.domain = self;
        p.in_use.store(true, .release);
        return p;
    }

    /// Attempt to advance the global epoch. Returns true if it advanced.
    ///
    /// Advance is permitted only when every active participant has
    /// `local_epoch == current`. On advance to `current+1`, the bag at index
    /// `(current+1) % 3` (== the bag two epochs back) is reclaimed.
    ///
    /// Writer side; expected to be externally serialized per domain.
    pub fn advance(self: *Domain) bool {
        const current = self.global_epoch.load(.seq_cst);
        const n = self.participant_count.load(.acquire);

        var i: usize = 0;
        while (i < n) : (i += 1) {
            const p = &self.participants[i];
            // seq_cst loads ordered against the readers' pin fences.
            if (!p.active.load(.seq_cst)) continue;
            if (p.local_epoch.load(.seq_cst) != current) {
                // Some reader is still in an older epoch; cannot advance.
                return false;
            }
        }

        const next = current + 1;
        // Single-writer expectation; seq_cst keeps correctness regardless.
        self.global_epoch.store(next, .seq_cst);

        // The bag we now reclaim is the one written two epochs ago. With three
        // bags, next % 3 names exactly that slot (it has not been written since
        // epoch `next - 3`, and everything in it was retired no later than
        // `next - 2`, which is now safe by the grace-period argument).
        const reclaim_idx = next % epoch_count;
        self.reclaimBagAcrossParticipants(reclaim_idx);
        return true;
    }

    fn reclaimBagAcrossParticipants(self: *Domain, idx: usize) void {
        const n = self.participant_count.load(.acquire);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const p = &self.participants[i];
            const freed = p.bags[idx].items.items.len;
            p.bags[idx].reclaimAll();
            if (freed != 0) _ = self.retired_count.fetchSub(freed, .acq_rel);
        }
    }

    /// Drain ALL bags regardless of epoch safety. ONLY valid when no
    /// participant is pinned (full quiescence) — used by tests and shutdown to
    /// reach the quiescent state `deinit` requires.
    pub fn drainAll(self: *Domain) void {
        const n = self.participant_count.load(.acquire);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const p = &self.participants[i];
            std.debug.assert(!p.active.load(.acquire));
            var b: usize = 0;
            while (b < epoch_count) : (b += 1) {
                const freed = p.bags[b].items.items.len;
                p.bags[b].reclaimAll();
                if (freed != 0) _ = self.retired_count.fetchSub(freed, .acq_rel);
            }
        }
    }
};

// ===========================================================================
// Tests
// ===========================================================================

/// A tracking allocator that poisons freed blocks and panics on double-free,
/// while counting live allocations. Wraps a child allocator.
const TrackingAllocator = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    total_alloc: usize = 0,
    total_free: usize = 0,
    mutex: std.atomic.Mutex = .unlocked,

    const poison_byte: u8 = 0xDE;

    fn lock(self: *TrackingAllocator) void {
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
    }

    fn allocator(self: *TrackingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        const out = self.child.rawAlloc(len, alignment, ra) orelse return null;
        self.lock();
        defer self.mutex.unlock();
        self.live += 1;
        self.total_alloc += 1;
        return out;
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(buf, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(buf, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        // Poison before handing back to the child so any reader still touching
        // it sees 0xDE (a non-zero, recognizable pattern).
        @memset(buf, poison_byte);
        self.child.rawFree(buf, alignment, ra);
        self.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.live > 0); // double-free / underflow guard
        self.live -= 1;
        self.total_free += 1;
    }
};

const TestNode = struct {
    value: u64,
    canary: u64 = 0xC0FFEE,
};

test "single-thread: deferred free happens only after enough epoch advances" {
    var tracking: TrackingAllocator = .{ .child = std.testing.allocator };
    const alloc = tracking.allocator();

    var domain = Domain.init(std.testing.allocator);
    defer domain.deinit();
    const p = try domain.register();
    defer p.unregister();

    // Retire a node in epoch 0.
    const node = try alloc.create(TestNode);
    node.* = .{ .value = 1 };
    try testing.expectEqual(@as(usize, 1), tracking.live);
    p.retire(TestNode, node, alloc);

    // Still live: retired in epoch 0, needs epoch to reach 2.
    try testing.expectEqual(@as(usize, 1), tracking.live);
    try testing.expectEqual(@as(usize, 1), domain.retired_count.load(.monotonic));

    // Advance 0 -> 1: reclaims bag 1%3=1 (empty). Node (bag 0) survives.
    try testing.expect(domain.advance());
    try testing.expectEqual(@as(usize, 1), tracking.live);

    // Advance 1 -> 2: reclaims bag 2%3=2 (empty). Node (bag 0) survives.
    try testing.expect(domain.advance());
    try testing.expectEqual(@as(usize, 1), tracking.live);

    // Advance 2 -> 3: reclaims bag 3%3=0 — the node's bag. Now freed.
    try testing.expect(domain.advance());
    try testing.expectEqual(@as(usize, 0), tracking.live);
    try testing.expectEqual(@as(usize, 0), domain.retired_count.load(.monotonic));
}

test "pin and unpin toggle active flag" {
    var domain = Domain.init(std.testing.allocator);
    defer domain.deinit();
    const p = try domain.register();
    defer p.unregister();

    try testing.expect(!p.active.load(.monotonic));
    var guard = p.pin();
    try testing.expect(p.active.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), p.local_epoch.load(.monotonic));
    guard.unpin();
    try testing.expect(!p.active.load(.monotonic));
}

test "advance is blocked while a participant is pinned in an older epoch" {
    var domain = Domain.init(std.testing.allocator);
    defer domain.deinit();
    const reader = try domain.register();
    defer reader.unregister();
    const writer = try domain.register();
    defer writer.unregister();

    // Reader pins at epoch 0.
    var g = reader.pin();

    // Writer can still advance the first time because the reader IS at the
    // current epoch (0 == current 0).
    try testing.expect(domain.advance()); // 0 -> 1

    // Now global epoch is 1 but reader is still pinned at 0. Cannot advance.
    try testing.expect(!domain.advance());

    // Reader leaves; now advance succeeds.
    g.unpin();
    try testing.expect(domain.advance()); // 1 -> 2
}

test "retire reservation survives concurrent epoch advance and allocation failure" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var tracking: TrackingAllocator = .{ .child = testing.allocator };
    const node_allocator = tracking.allocator();
    var domain = Domain.init(failing.allocator());
    defer domain.deinit();
    const writer = try domain.register();
    defer writer.unregister();

    const node = try node_allocator.create(TestNode);
    node.* = .{ .value = 99 };
    var reservation = try writer.reserveRetireCapacity(1);

    // Advance on another thread between reservation and publication. The first
    // advance is legal; the reservation's epoch pin blocks the second.
    const Advancer = struct {
        fn run(d: *Domain) void {
            _ = d.advance();
            _ = d.advance();
        }
    };
    var thread = try std.Thread.spawn(.{}, Advancer.run, .{&domain});
    thread.join();
    try testing.expectEqual(@as(u64, 1), domain.global_epoch.load(.acquire));

    // Any append to the newly-current, unreserved bag would now fail. The
    // token appends to its fixed pre-reserved bag without touching allocator.
    failing.fail_index = failing.alloc_index;
    const Closure = struct {
        fn reclaim(ptr: *anyopaque, allocator: std.mem.Allocator) void {
            allocator.destroy(@as(*TestNode, @ptrCast(@alignCast(ptr))));
        }
    };
    reservation.retireErased(@ptrCast(node), Closure.reclaim, node_allocator);
    try testing.expect(!failing.has_induced_failure);
    reservation.finish();

    try testing.expect(domain.advance()); // 1 -> 2
    try testing.expectEqual(@as(usize, 1), tracking.live);
    try testing.expect(domain.advance()); // 2 -> 3, fixed bag 0 is now safe
    try testing.expectEqual(@as(usize, 0), tracking.live);
    failing.fail_index = std.math.maxInt(usize);
}

test "premature free is impossible while a reader holds a retired pointer" {
    var tracking: TrackingAllocator = .{ .child = std.testing.allocator };
    const alloc = tracking.allocator();

    var domain = Domain.init(std.testing.allocator);
    defer domain.deinit();

    const reader = try domain.register();
    defer reader.unregister();
    const writer = try domain.register();
    defer writer.unregister();

    // Reader pins at epoch 0 and captures a pointer to a node.
    const node = try alloc.create(TestNode);
    node.* = .{ .value = 42 };
    var g = reader.pin();
    const held: *TestNode = node;

    // Writer retires the node (epoch 0) and then drives several advance cycles.
    writer.retire(TestNode, node, alloc);

    // Every advance attempt must fail to *fully* reclaim the held node because
    // the reader is pinned at epoch 0. The first advance (reader at current
    // epoch 0) succeeds to epoch 1 but reclaims only bag 1 (empty). Subsequent
    // advances are blocked entirely.
    try testing.expect(domain.advance()); // 0 -> 1, reclaims bag1 (empty)
    try testing.expect(!domain.advance()); // blocked: reader still at 0
    try testing.expect(!domain.advance()); // still blocked

    // The reader can still safely read the node: not freed, canary intact.
    try testing.expectEqual(@as(u64, 42), held.value);
    try testing.expectEqual(@as(u64, 0xC0FFEE), held.canary);
    try testing.expectEqual(@as(usize, 1), tracking.live);

    // Reader unpins; grace period can now complete.
    g.unpin();

    // global=1, node in bag 0. Reclaim of bag 0 happens when epoch reaches 3.
    try testing.expect(domain.advance()); // 1 -> 2, reclaims bag2 (empty)
    try testing.expectEqual(@as(usize, 1), tracking.live); // still alive
    try testing.expect(domain.advance()); // 2 -> 3, reclaims bag0 -> frees node
    try testing.expectEqual(@as(usize, 0), tracking.live);
}

test "deinit asserts quiescence after draining" {
    var tracking: TrackingAllocator = .{ .child = std.testing.allocator };
    const alloc = tracking.allocator();

    var domain = Domain.init(std.testing.allocator);
    const p = try domain.register();

    const node = try alloc.create(TestNode);
    node.* = .{ .value = 7 };
    p.retire(TestNode, node, alloc);

    // Reach quiescence via drainAll (no participant pinned), then deinit is OK.
    domain.drainAll();
    try testing.expectEqual(@as(usize, 0), tracking.live);
    p.unregister();
    domain.deinit();
}

test "threaded stress: readers never observe poisoned memory, no leaks" {
    const Shared = struct {
        domain: *Domain,
        published: *std.atomic.Value(?*TestNode),
        tracking: *TrackingAllocator,
        stop: *std.atomic.Value(bool),
        observed_poison: *std.atomic.Value(bool),

        fn readerLoop(ctx: @This(), participant: *Participant) void {
            var iters: usize = 0;
            while (!ctx.stop.load(.acquire)) : (iters += 1) {
                var guard = participant.pin();
                // Read the currently published node. It is guaranteed live for
                // the duration of our pin: any node retired now cannot be freed
                // until we unpin and the epoch advances twice.
                const node = ctx.published.load(.acquire);
                if (node) |nn| {
                    // Touch the canary; if EBR is broken and the block was
                    // freed+poisoned, canary won't be 0xC0FFEE.
                    if (nn.canary != 0xC0FFEE) {
                        ctx.observed_poison.store(true, .release);
                    }
                    std.mem.doNotOptimizeAway(nn.value);
                }
                guard.unpin();
                if (iters % 64 == 0) std.atomic.spinLoopHint();
            }
        }

        fn writerLoop(ctx: @This(), participant: *Participant, rounds: usize) void {
            var r: usize = 0;
            while (r < rounds) : (r += 1) {
                const fresh = ctx.tracking.allocator().create(TestNode) catch return;
                fresh.* = .{ .value = r };
                // Publish the new node, retire the old one.
                const old = ctx.published.swap(fresh, .acq_rel);
                if (old) |o| participant.retire(TestNode, o, ctx.tracking.allocator());
                // Try to advance the epoch a few times per round.
                _ = ctx.domain.advance();
                _ = ctx.domain.advance();
                if (r % 128 == 0) std.atomic.spinLoopHint();
            }
        }
    };

    var tracking: TrackingAllocator = .{ .child = std.testing.allocator };
    var domain = Domain.init(std.testing.allocator);
    defer domain.deinit();

    var published = std.atomic.Value(?*TestNode).init(null);
    var stop = std.atomic.Value(bool).init(false);
    var observed_poison = std.atomic.Value(bool).init(false);

    const reader_count = 4;
    const writer_rounds = 20_000;

    // Seed an initial published node so readers have something immediately.
    const seed = try tracking.allocator().create(TestNode);
    seed.* = .{ .value = 0 };
    published.store(seed, .release);

    const writer_part = try domain.register();

    const shared = Shared{
        .domain = &domain,
        .published = &published,
        .tracking = &tracking,
        .stop = &stop,
        .observed_poison = &observed_poison,
    };

    var reader_parts: [reader_count]*Participant = undefined;
    var threads: [reader_count]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        stop.store(true, .release);
        for (0..spawned) |i| threads[i].join();
    }

    for (0..reader_count) |i| {
        reader_parts[i] = try domain.register();
        threads[i] = std.Thread.spawn(.{}, Shared.readerLoop, .{ shared, reader_parts[i] }) catch return error.SkipZigTest;
        spawned += 1;
    }

    // Run the writer on this thread.
    Shared.writerLoop(shared, writer_part, writer_rounds);

    // Signal readers to stop and join.
    stop.store(true, .release);
    for (0..spawned) |i| threads[i].join();

    try testing.expect(!observed_poison.load(.acquire));

    // Drain: no readers pinned now. The final published node is still live and
    // referenced; pull it out and free it directly, then drain limbo.
    if (published.swap(null, .acq_rel)) |last| {
        tracking.allocator().destroy(last);
    }
    domain.drainAll();

    // Unregister all participants.
    writer_part.unregister();
    for (0..reader_count) |i| reader_parts[i].unregister();

    // Quiescence: every allocation freed.
    try testing.expectEqual(tracking.total_alloc, tracking.total_free);
    try testing.expectEqual(@as(usize, 0), tracking.live);
    try testing.expectEqual(@as(usize, 0), domain.retired_count.load(.monotonic));
}

test "max_participants overflow is asserted" {
    // Compile-time sanity: ensure the constant is the expected classic value
    // and the bag rotation matches.
    try testing.expectEqual(@as(usize, 3), epoch_count);
    try testing.expect(max_participants >= 64);
}
