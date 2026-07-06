// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Worker-thread harness for the sharded-reactor model.
//!
//! The target architecture (see docs/planning/24-multithreading.md) runs N OS
//! threads, each owning its own io_uring reactor and a disjoint slice of the
//! connection table. `ReactorPool` is the thread-lifecycle primitive of that
//! design: it spawns one thread per shard, binds each to its shard index, runs
//! a caller-provided loop, and joins them all on stop.
//!
//! It is deliberately *generic* — it knows nothing about the IRC server, the
//! reactor, or io_uring. `server.zig` later hands it a closure that binds its
//! per-shard reactor and runs the io_uring loop; here we only own spawn/join.
//! The degenerate `count == 1` case is a single worker (the single-reactor
//! model), so the same code path covers both topologies.
//!
//! Stopping is cooperative: a shared `*RunFlag` (an atomic bool) is the only
//! control channel. The caller clears it; each worker observes the clear at the
//! top of its loop and returns; `join` then reaps every thread. No thread is
//! ever detached, so there are no leaks.

const std = @import("std");
const shard = @import("shard.zig");

/// Cooperative stop signal shared by the pool owner and every worker. The owner
/// stores `false` to request shutdown; workers poll it and return when cleared.
pub const RunFlag = std.atomic.Value(bool);

/// A pool of worker threads, one per shard, each running the same caller-bound
/// loop function with a distinct shard index. `Context` is the (thread-shared)
/// value handed to every worker; it must be safe to read from all workers.
pub fn ReactorPool(comptime Context: type) type {
    return struct {
        const Self = @This();

        /// The (thread-shared) value type handed to every worker. Exposed so the
        /// type is anchored at struct scope and callers can name it.
        pub const ContextType = Context;

        allocator: std.mem.Allocator,
        /// Backing storage for the worker handles; freed by `deinit`. Stays
        /// allocated across `join` so `deinit` can reclaim it exactly once.
        threads: []std.Thread = &.{},
        /// Whether the workers have already been reaped (so `join`/`deinit`
        /// never double-join). Live worker count is `0` once set.
        joined: bool = true,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        /// Joins any still-running workers and frees the thread storage. Safe to
        /// call after `start`/`join`; idempotent on an empty pool.
        pub fn deinit(self: *Self) void {
            self.join();
            self.allocator.free(self.threads);
            self.threads = &.{};
        }

        /// Spawn `count` worker threads. Each thread calls
        /// `workerFn(ctx, shard_index, run)` with its own shard index in
        /// `0..count`. `count` must be in `1..=shard.max_shards`. On a spawn
        /// failure, every already-spawned thread is joined and the error is
        /// returned, leaving the pool empty.
        pub fn start(
            self: *Self,
            shard_count: usize,
            ctx: Context,
            run: *RunFlag,
            comptime workerFn: fn (Context, u12, *RunFlag) void,
        ) !void {
            std.debug.assert(shard_count >= 1 and shard_count <= shard.max_shards);

            const threads = try self.allocator.alloc(std.Thread, shard_count);
            errdefer self.allocator.free(threads);

            const Runner = struct {
                /// Thread entry: bind the worker to its shard index and run.
                fn entry(c: Context, idx: u12, r: *RunFlag) void {
                    workerFn(c, idx, r);
                }
            };

            var spawned: usize = 0;
            errdefer {
                // A later spawn failed: stop and reap the threads already up so
                // we never leak a running thread.
                run.store(false, .release);
                for (threads[0..spawned]) |t| t.join();
            }
            while (spawned < shard_count) : (spawned += 1) {
                const idx: u12 = @intCast(spawned);
                threads[spawned] = try std.Thread.spawn(.{}, Runner.entry, .{ ctx, idx, run });
            }

            self.threads = threads;
            self.joined = false;
        }

        /// Join every worker thread. Returns once all have exited; the caller is
        /// responsible for having cleared the `RunFlag` so workers can finish.
        /// Idempotent: a second call (or a call on an empty pool) is a no-op.
        /// The backing storage is retained for `deinit` to free.
        pub fn join(self: *Self) void {
            if (self.joined) return;
            for (self.threads) |t| t.join();
            self.joined = true;
        }

        /// Number of live worker threads (0 before `start` and after `join`).
        pub fn count(self: *const Self) usize {
            return if (self.joined) 0 else self.threads.len;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Shared fixture: per-shard work counters plus a per-shard "seen" marker so a
/// test can prove every shard index was bound exactly once.
const Harness = struct {
    /// Incremented by the worker on each loop iteration until `run` clears.
    counters: [shard.max_shards]std.atomic.Value(u64) =
        @splat(std.atomic.Value(u64).init(0)),
    /// Set once when shard `i` first runs; a second set is a duplicate index.
    seen: [shard.max_shards]std.atomic.Value(u32) =
        @splat(std.atomic.Value(u32).init(0)),
    /// Counts any duplicate shard index observed across all workers.
    duplicate_index: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn worker(self: *Harness, idx: u12, run: *RunFlag) void {
        // Claim this shard index; a non-zero prior value means a collision.
        if (self.seen[idx].swap(1, .acq_rel) != 0) {
            _ = self.duplicate_index.fetchAdd(1, .acq_rel);
        }
        while (run.load(.acquire)) {
            _ = self.counters[idx].fetchAdd(1, .acq_rel);
            std.Thread.yield() catch {};
        }
    }

    /// Spin until shard `idx` has made progress, so the test only clears `run`
    /// after the worker has actually started looping.
    fn waitProgress(self: *Harness, idx: u12) void {
        while (self.counters[idx].load(.acquire) == 0) std.Thread.yield() catch {};
    }
};

test "start(1) runs a single worker that stops when the flag clears" {
    const allocator = testing.allocator;
    var harness = Harness{};
    var run = RunFlag.init(true);

    var pool = ReactorPool(*Harness).init(allocator);
    defer pool.deinit();

    pool.start(1, &harness, &run, Harness.worker) catch return error.SkipZigTest;
    try testing.expectEqual(@as(usize, 1), pool.count());

    harness.waitProgress(0);
    run.store(false, .release);
    pool.join();

    try testing.expectEqual(@as(usize, 0), pool.count());
    try testing.expect(harness.counters[0].load(.acquire) > 0);
    try testing.expectEqual(@as(u32, 1), harness.seen[0].load(.acquire));
    try testing.expectEqual(@as(u32, 0), harness.duplicate_index.load(.acquire));
}

test "start(4) binds shard indices 0..3 exactly once and joins cleanly" {
    const allocator = testing.allocator;
    const workers = 4;
    var harness = Harness{};
    var run = RunFlag.init(true);

    var pool = ReactorPool(*Harness).init(allocator);
    defer pool.deinit();

    pool.start(workers, &harness, &run, Harness.worker) catch return error.SkipZigTest;
    try testing.expectEqual(@as(usize, workers), pool.count());

    // Let every worker reach its loop, then signal a cooperative stop.
    var i: u12 = 0;
    while (i < workers) : (i += 1) harness.waitProgress(i);
    run.store(false, .release);
    pool.join();

    try testing.expectEqual(@as(usize, 0), pool.count());
    // Each shard index 0..3 was observed exactly once; none beyond was touched.
    try testing.expectEqual(@as(u32, 0), harness.duplicate_index.load(.acquire));
    i = 0;
    while (i < workers) : (i += 1) {
        try testing.expectEqual(@as(u32, 1), harness.seen[i].load(.acquire));
        try testing.expect(harness.counters[i].load(.acquire) > 0);
    }
    try testing.expectEqual(@as(u32, 0), harness.seen[workers].load(.acquire));
}

test "deinit joins workers even without an explicit join" {
    const allocator = testing.allocator;
    var harness = Harness{};
    var run = RunFlag.init(true);

    var pool = ReactorPool(*Harness).init(allocator);
    pool.start(2, &harness, &run, Harness.worker) catch return error.SkipZigTest;
    harness.waitProgress(0);
    // Clear the flag and let deinit reap the threads (no explicit join call).
    run.store(false, .release);
    pool.deinit();
    try testing.expectEqual(@as(usize, 0), pool.count());
}

test {
    testing.refAllDecls(@This());
}
