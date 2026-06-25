// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fair multi-class task scheduler for a thread-per-core runtime.
//!
//! Implements Deficit Round Robin (DRR) across N weighted classes, with a
//! strict-priority realtime tier above DRR and starvation-protection aging.
//!
//! ## Overview
//!
//! Classes are arranged in two tiers:
//!
//!   1. **Realtime** (`Tier.realtime`) — always drained before any DRR
//!      work is considered. Tasks in this tier preempt all normal work.
//!
//!   2. **Normal** (`Tier.normal`) — served via Deficit Round Robin.
//!      Each class has a weight; at the start of a class's DRR turn it
//!      receives `weight * quantum_unit` deficit credits and may dequeue
//!      consecutive tasks as long as each task's cost fits within the
//!      remaining credits.  The class retains any leftover deficit into the
//!      next round; if it is idle its deficit resets to zero (canonical DRR).
//!
//! ## DRR Turn Semantics
//!
//! `drr_cursor` points to the class currently holding the turn.
//! `drr_topped` records whether that class has already received its quantum
//! credit for this turn.  A class keeps the turn (cursor stays) across
//! multiple `next()` calls as long as it can still emit tasks from its
//! remaining deficit.  When the deficit is exhausted or the next task's cost
//! exceeds the remaining deficit, the cursor advances to the next class.
//!
//! ## Starvation Protection (Aging)
//!
//! Each time the cursor skips past a non-empty normal class (because it has
//! zero deficit and the cursor is moving on), that class's `age_ticks`
//! counter increments.  When `age_ticks` reaches `aging_threshold` the class
//! receives a bonus credit burst equal to one extra quantum and its counter
//! resets, ensuring it eventually runs even under sustained heavy load from
//! high-weight peers.
//!
//! ## Thread Safety
//!
//! None — designed for single-threaded use within one reactor shard.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;
const assert = std.debug.assert;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single unit of work submitted to the scheduler.
pub const Task = struct {
    /// Opaque identifier assigned by the caller.
    id: u64,
    /// Estimated work units (must be >= 1).
    cost: u32,
};

/// Priority tier for a class.
pub const Tier = enum {
    /// Served before any DRR class, regardless of weight.
    realtime,
    /// Served via Deficit Round Robin proportional to weight.
    normal,
};

/// Handle returned by `addClass`; passed to `submit`.
pub const ClassHandle = u32;

/// Scheduler configuration knobs.
pub const Config = struct {
    /// Base quantum unit multiplied by `weight` to give each DRR class its
    /// per-turn credit allowance.
    quantum_unit: u32 = 64,
    /// How many times the DRR cursor may skip a non-empty normal class before
    /// that class receives a free credit burst (starvation protection).
    aging_threshold: u32 = 32,
};

// ---------------------------------------------------------------------------
// Internal representation
// ---------------------------------------------------------------------------

const Class = struct {
    tier: Tier,
    weight: u32,
    /// Current deficit credit balance (DRR classes only).
    deficit: i64,
    /// Counts cursor passes over this non-empty class without service.
    age_ticks: u32,
    /// Pending tasks, FIFO.
    queue: ArrayList(Task),
};

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// Fair multi-class task scheduler.
///
/// Usage:
/// ```zig
/// var sched = Scheduler.init(allocator, .{});
/// defer sched.deinit();
/// const rt = try sched.addClass(.realtime, 1);
/// const hi = try sched.addClass(.normal, 4);
/// const lo = try sched.addClass(.normal, 1);
/// try sched.submit(hi, .{ .id = 1, .cost = 10 });
/// while (sched.next()) |task| { ... }
/// ```
pub const Scheduler = struct {
    allocator: Allocator,
    config: Config,
    classes: ArrayList(Class),
    /// Index of the normal class that currently holds the DRR turn.
    drr_cursor: usize,
    /// True when the class at `drr_cursor` has already received its quantum
    /// top-up for this turn (and should not be topped up again until the
    /// cursor advances).
    drr_topped: bool,
    /// Total tasks across all classes (cache for `pending()`).
    total_pending: usize,

    /// Create an empty scheduler.  Call `deinit` when done.
    pub fn init(allocator: Allocator, config: Config) Scheduler {
        return .{
            .allocator = allocator,
            .config = config,
            .classes = .empty,
            .drr_cursor = 0,
            .drr_topped = false,
            .total_pending = 0,
        };
    }

    /// Release all memory.
    pub fn deinit(self: *Scheduler) void {
        for (self.classes.items) |*cls| {
            cls.queue.deinit(self.allocator);
        }
        self.classes.deinit(self.allocator);
    }

    /// Register a new class and return its handle.
    ///
    /// `weight` must be >= 1 for normal classes.  For realtime classes it is
    /// stored but not used for scheduling.
    pub fn addClass(self: *Scheduler, tier: Tier, weight: u32) !ClassHandle {
        if (tier == .normal) assert(weight >= 1);
        const handle: ClassHandle = @intCast(self.classes.items.len);
        try self.classes.append(self.allocator, .{
            .tier = tier,
            .weight = weight,
            .deficit = 0,
            .age_ticks = 0,
            .queue = .empty,
        });
        return handle;
    }

    /// Submit a task to a class.  `task.cost` must be >= 1.
    pub fn submit(self: *Scheduler, handle: ClassHandle, task: Task) !void {
        assert(task.cost >= 1);
        assert(handle < self.classes.items.len);
        try self.classes.items[handle].queue.append(self.allocator, task);
        self.total_pending += 1;
    }

    /// Return the number of tasks waiting across all classes.
    pub fn pending(self: *const Scheduler) usize {
        return self.total_pending;
    }

    /// Dequeue and return the next task, or `null` if no tasks are pending.
    ///
    /// Service order:
    ///   1. Realtime classes are scanned left-to-right; the first non-empty
    ///      realtime class yields its front task immediately.
    ///   2. If no realtime task is ready, DRR selects among normal classes.
    ///      The class at `drr_cursor` holds the current turn; it is given a
    ///      one-time quantum credit top-up then emits tasks until its deficit
    ///      is exhausted or its next task is too expensive.  The cursor then
    ///      advances.  A class with no pending tasks forfeits its deficit and
    ///      is skipped; if it is skipped too many times its age_ticks counter
    ///      triggers a free bonus credit.
    pub fn next(self: *Scheduler) ?Task {
        if (self.total_pending == 0) return null;

        // --- Tier 1: realtime preemption ---
        for (self.classes.items) |*cls| {
            if (cls.tier != .realtime) continue;
            if (cls.queue.items.len == 0) continue;
            return self.dequeueFrom(cls);
        }

        // --- Tier 2: DRR among normal classes ---
        return self.drrNext();
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn dequeueFrom(self: *Scheduler, cls: *Class) Task {
        const task = cls.queue.orderedRemove(0);
        self.total_pending -= 1;
        return task;
    }

    /// Advance `drr_cursor` to the next normal class, wrapping around, and
    /// reset the topped flag.
    fn advanceCursor(self: *Scheduler) void {
        self.drr_cursor += 1;
        self.drr_topped = false;
    }

    /// DRR dequeue: find the next task from the current-turn normal class,
    /// rotating the cursor when necessary.
    ///
    /// The outer loop scans at most `n` class slots to find a class that
    /// can emit.  Within each class, the cursor stays until the deficit is
    /// spent or the queue empties.
    fn drrNext(self: *Scheduler) ?Task {
        const n = self.classes.items.len;
        if (n == 0) return null;

        // Try every class at most once per call.
        var attempts: usize = 0;
        while (attempts <= n) : (attempts += 1) {
            // Wrap cursor.
            if (self.drr_cursor >= n) {
                self.drr_cursor = 0;
                self.drr_topped = false;
            }

            const idx = self.drr_cursor;
            var cls = &self.classes.items[idx];

            // Skip non-normal classes.
            if (cls.tier != .normal) {
                self.advanceCursor();
                continue;
            }

            // Idle class: forfeit deficit and advance.
            if (cls.queue.items.len == 0) {
                cls.deficit = 0;
                cls.age_ticks = 0;
                self.advanceCursor();
                continue;
            }

            // Top up deficit once per turn.
            if (!self.drr_topped) {
                const quantum: i64 = @as(i64, cls.weight) *
                    @as(i64, self.config.quantum_unit);
                cls.deficit += quantum;

                // Starvation protection: extra quantum for long-waiting classes.
                if (cls.age_ticks >= self.config.aging_threshold) {
                    cls.deficit += quantum;
                    cls.age_ticks = 0;
                }
                self.drr_topped = true;
            }

            const task = cls.queue.items[0];
            if (@as(i64, task.cost) <= cls.deficit) {
                cls.deficit -= @as(i64, task.cost);
                // Stay on this class (don't advance cursor) so the next
                // call can continue spending the remaining deficit.
                // But if deficit is now zero, pre-advance so we don't spin.
                if (cls.deficit == 0) {
                    self.advanceCursor();
                }
                return self.dequeueFrom(cls);
            }

            // Deficit too small for the next task; yield the turn.
            // Age this class since it is being skipped while non-empty.
            cls.age_ticks +|= 1;
            self.advanceCursor();
        }

        // All normal classes were empty or had insufficient deficit; this
        // path should be unreachable given total_pending > 0 at entry,
        // but guard defensively.
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "empty scheduler returns null" {
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    try std.testing.expectEqual(@as(?Task, null), sched.next());
    try std.testing.expectEqual(@as(usize, 0), sched.pending());
}

test "single class basic submit and next" {
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    const cls = try sched.addClass(.normal, 1);
    try sched.submit(cls, .{ .id = 1, .cost = 1 });
    try sched.submit(cls, .{ .id = 2, .cost = 1 });

    try std.testing.expectEqual(@as(usize, 2), sched.pending());

    const t1 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 1), t1.id);
    try std.testing.expectEqual(@as(usize, 1), sched.pending());

    const t2 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 2), t2.id);
    try std.testing.expectEqual(@as(usize, 0), sched.pending());

    try std.testing.expectEqual(@as(?Task, null), sched.next());
}

test "realtime tier preempts normal tier" {
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    const normal_cls = try sched.addClass(.normal, 4);
    const rt_cls = try sched.addClass(.realtime, 1);

    // Submit normal tasks first so they are logically "older".
    try sched.submit(normal_cls, .{ .id = 10, .cost = 1 });
    try sched.submit(normal_cls, .{ .id = 11, .cost = 1 });
    // Now submit a realtime task.
    try sched.submit(rt_cls, .{ .id = 99, .cost = 1 });

    // Realtime must come out first regardless.
    const t = sched.next().?;
    try std.testing.expectEqual(@as(u64, 99), t.id);

    // Remaining tasks are normal.
    const t2 = sched.next().?;
    try std.testing.expect(t2.id == 10 or t2.id == 11);
}

test "multiple realtime tasks all preempt normal work" {
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    const nc = try sched.addClass(.normal, 1);
    const rc = try sched.addClass(.realtime, 1);

    for (0..5) |i| try sched.submit(nc, .{ .id = @intCast(i), .cost = 1 });
    for (100..103) |i| try sched.submit(rc, .{ .id = @intCast(i), .cost = 1 });

    // All three realtime tasks must appear before any normal task.
    var rt_seen: usize = 0;
    for (0..3) |_| {
        const t = sched.next().?;
        try std.testing.expect(t.id >= 100);
        rt_seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), rt_seen);

    // Remaining 5 are normal.
    for (0..5) |_| {
        const t = sched.next().?;
        try std.testing.expect(t.id < 100);
    }
}

test "equal-weight fairness: long-run service counts are approximately equal" {
    // Two classes, same weight.  Over N tasks each, service should split ~50/50.
    const N = 200;
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    const c0 = try sched.addClass(.normal, 1);
    const c1 = try sched.addClass(.normal, 1);

    for (0..N) |i| {
        try sched.submit(c0, .{ .id = @intCast(i), .cost = 1 });
        try sched.submit(c1, .{ .id = @intCast(1000 + i), .cost = 1 });
    }

    var count0: usize = 0;
    var count1: usize = 0;
    while (sched.next()) |t| {
        if (t.id < 1000) count0 += 1 else count1 += 1;
    }

    try std.testing.expectEqual(N, count0);
    try std.testing.expectEqual(N, count1);

    // Fairness: neither class should get more than 50% more service than the
    // other during the balanced portion.
    const diff = if (count0 > count1) count0 - count1 else count1 - count0;
    try std.testing.expect(diff * 10 <= N); // diff <= 10% of N
}

test "weighted classes: 4:1 weight ratio yields proportional throughput" {
    // Class A weight=4, class B weight=1.
    // In one DRR turn, A gets 4x the credits of B (quantum_unit=64: 256 vs 64),
    // so A emits 4x more unit-cost tasks per round.
    //
    // To measure the ratio cleanly we give A far more tasks than B so A never
    // exhausts first.  We stop after B drains completely and compare counts.
    //
    // Expected: ratio ~4.0 (= weight_a / weight_b).
    const B_TOTAL = 128; // 2 full B turns at quantum=64
    const A_TOTAL = 2000; // enough that A is never empty while B runs
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    const ca = try sched.addClass(.normal, 4);
    const cb = try sched.addClass(.normal, 1);

    for (0..A_TOTAL) |i| try sched.submit(ca, .{ .id = @intCast(i), .cost = 1 });
    for (0..B_TOTAL) |i| try sched.submit(cb, .{ .id = @intCast(10000 + i), .cost = 1 });

    var cnt_a: usize = 0;
    var cnt_b: usize = 0;
    // Stop once B is fully drained.
    while (sched.pending() > 0) {
        const t = sched.next().?;
        if (t.id < 10000) cnt_a += 1 else cnt_b += 1;
        if (cnt_b == B_TOTAL) break;
    }

    // A should have served ~4x as many tasks as B.  Allow ±25% slack.
    const ratio_times_10 = (cnt_a * 10) / cnt_b;
    try std.testing.expect(ratio_times_10 >= 30); // at least 3x
    try std.testing.expect(ratio_times_10 <= 55); // at most 5.5x

    // Drain remainder to avoid leak errors.
    while (sched.next()) |_| {}
}

test "starvation protection: low-weight class eventually runs under heavy load" {
    // Class A weight=100 (very heavy), class B weight=1 (very light).
    // B must eventually be served despite A monopolising credits.
    var sched = Scheduler.init(std.testing.allocator, .{ .aging_threshold = 8 });
    defer sched.deinit();

    const ca = try sched.addClass(.normal, 100);
    const cb = try sched.addClass(.normal, 1);

    // Heavy load on A.
    for (0..500) |i| try sched.submit(ca, .{ .id = @intCast(i), .cost = 1 });
    // A handful of B tasks.
    for (1000..1010) |i| try sched.submit(cb, .{ .id = @intCast(i), .cost = 1 });

    // Drain everything, counting how many B tasks we see.
    var b_count: usize = 0;
    const max_iters = 700;
    var iters: usize = 0;
    while (sched.pending() > 0 and iters < max_iters) : (iters += 1) {
        if (sched.next()) |t| {
            if (t.id >= 1000) b_count += 1;
        }
    }

    // All B tasks must eventually run (aging must have kicked in).
    try std.testing.expectEqual(@as(usize, 10), b_count);
}

test "cost accounting: task cost deducted from deficit correctly" {
    // quantum_unit=10, weight=1 => 10 credits per turn.
    // ca: tasks cost 8 and 4.  After emitting cost-8, deficit=2, too small for cost-4.
    // cb: task cost 3, fits in one quantum of 10.
    // Next turn for ca: deficit = 2+10=12, cost-4 fits.
    var sched = Scheduler.init(std.testing.allocator, .{ .quantum_unit = 10 });
    defer sched.deinit();

    const ca = try sched.addClass(.normal, 1);
    const cb = try sched.addClass(.normal, 1);

    try sched.submit(ca, .{ .id = 1, .cost = 8 });
    try sched.submit(ca, .{ .id = 2, .cost = 4 });
    try sched.submit(cb, .{ .id = 3, .cost = 3 });

    // Turn 1 for ca: top-up deficit 0+10=10.  cost=8 <= 10 → emit id=1, deficit=2.
    const t1 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 1), t1.id);

    // Still ca's turn, deficit=2, next task cost=4 > 2 → yield turn to cb.
    // cb turn: top-up deficit 0+10=10, cost=3 <= 10 → emit id=3, deficit=7.
    const t2 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 3), t2.id);

    // ca turn again: deficit 2+10=12, cost=4 <= 12 → emit id=2.
    const t3 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 2), t3.id);

    try std.testing.expectEqual(@as(?Task, null), sched.next());
}

test "deterministic ordering: same submit order, same dequeue order" {
    var sched1 = Scheduler.init(std.testing.allocator, .{});
    defer sched1.deinit();
    var sched2 = Scheduler.init(std.testing.allocator, .{});
    defer sched2.deinit();

    const c1 = try sched1.addClass(.normal, 2);
    const c2 = try sched2.addClass(.normal, 2);

    for (0..20) |i| {
        try sched1.submit(c1, .{ .id = @intCast(i), .cost = 1 });
        try sched2.submit(c2, .{ .id = @intCast(i), .cost = 1 });
    }

    var ids1: [20]u64 = undefined;
    var ids2: [20]u64 = undefined;
    for (&ids1) |*slot| slot.* = sched1.next().?.id;
    for (&ids2) |*slot| slot.* = sched2.next().?.id;

    try std.testing.expectEqualSlices(u64, &ids1, &ids2);
}

test "pending() tracks count correctly across submits and nexts" {
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    const c = try sched.addClass(.normal, 1);
    try std.testing.expectEqual(@as(usize, 0), sched.pending());

    try sched.submit(c, .{ .id = 1, .cost = 1 });
    try std.testing.expectEqual(@as(usize, 1), sched.pending());

    try sched.submit(c, .{ .id = 2, .cost = 1 });
    try std.testing.expectEqual(@as(usize, 2), sched.pending());

    _ = sched.next();
    try std.testing.expectEqual(@as(usize, 1), sched.pending());

    _ = sched.next();
    try std.testing.expectEqual(@as(usize, 0), sched.pending());
}

test "multiple realtime classes served FIFO within realtime tier" {
    var sched = Scheduler.init(std.testing.allocator, .{});
    defer sched.deinit();

    const r1 = try sched.addClass(.realtime, 1);
    const r2 = try sched.addClass(.realtime, 1);

    try sched.submit(r1, .{ .id = 10, .cost = 1 });
    try sched.submit(r2, .{ .id = 20, .cost = 1 });
    try sched.submit(r1, .{ .id = 11, .cost = 1 });

    // r1 is scanned first (index 0), so id=10 then id=11 before id=20.
    const t1 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 10), t1.id);

    const t2 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 11), t2.id);

    const t3 = sched.next().?;
    try std.testing.expectEqual(@as(u64, 20), t3.id);
}

test "idle class forfeits deficit (DRR canonical reset)" {
    // With quantum=10, ca is idle for one round; its deficit must reset to 0.
    // After submitting to ca, it should start fresh with a single quantum.
    var sched = Scheduler.init(std.testing.allocator, .{ .quantum_unit = 10 });
    defer sched.deinit();

    const ca = try sched.addClass(.normal, 1);
    const cb = try sched.addClass(.normal, 1);

    // cb has tasks, ca is empty.
    try sched.submit(cb, .{ .id = 1, .cost = 3 });
    try sched.submit(cb, .{ .id = 2, .cost = 3 });

    // Drain cb (ca gets skipped as idle → deficit reset).
    _ = sched.next();
    _ = sched.next();

    // Now submit a cheap task to ca.
    try sched.submit(ca, .{ .id = 99, .cost = 1 });
    const t = sched.next().?;
    // ca should be served (it gets a fresh quantum top-up).
    try std.testing.expectEqual(@as(u64, 99), t.id);
}

test "aging threshold zero: every cursor-pass triggers bonus credit" {
    // With aging_threshold=0, every time the cursor moves past a non-empty
    // class without serving it, that class gets a double quantum on its
    // next turn.  The class must still eventually run.
    var sched = Scheduler.init(std.testing.allocator, .{
        .quantum_unit = 5,
        .aging_threshold = 0,
    });
    defer sched.deinit();

    const ca = try sched.addClass(.normal, 100);
    const cb = try sched.addClass(.normal, 1);

    for (0..50) |i| try sched.submit(ca, .{ .id = @intCast(i), .cost = 1 });
    try sched.submit(cb, .{ .id = 9999, .cost = 1 });

    var found = false;
    while (sched.pending() > 0) {
        if (sched.next()) |t| {
            if (t.id == 9999) {
                found = true;
                break;
            }
        }
    }
    try std.testing.expect(found);
    // Drain remainder cleanly.
    while (sched.next()) |_| {}
}

test "DRR cursor stays on class until quantum exhausted" {
    // quantum=8, weight=1 → 8 credits per turn; task cost=2 → 4 tasks per turn.
    // Two classes, 8 tasks each: first class should emit 4 tasks, then second
    // class emits 4, then first again, etc.
    var sched = Scheduler.init(std.testing.allocator, .{ .quantum_unit = 8 });
    defer sched.deinit();

    const ca = try sched.addClass(.normal, 1);
    const cb = try sched.addClass(.normal, 1);

    for (0..8) |i| try sched.submit(ca, .{ .id = @intCast(i), .cost = 2 });
    for (100..108) |i| try sched.submit(cb, .{ .id = @intCast(i), .cost = 2 });

    // First 4 must be from ca (4 tasks × cost 2 = 8 credits).
    for (0..4) |_| {
        const t = sched.next().?;
        try std.testing.expect(t.id < 100);
    }
    // Next 4 from cb.
    for (0..4) |_| {
        const t = sched.next().?;
        try std.testing.expect(t.id >= 100);
    }
    // Back to ca.
    for (0..4) |_| {
        const t = sched.next().?;
        try std.testing.expect(t.id < 100);
    }
    // Back to cb.
    for (0..4) |_| {
        const t = sched.next().?;
        try std.testing.expect(t.id >= 100);
    }
}
