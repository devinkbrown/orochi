// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Writer-preferring spin reader-writer lock.
//!
//! The daemon's world projection (channels, nicks, memberships) is read on every
//! lookup and written only on join/part/nick/mode changes, so a reader-writer
//! lock lets the future multi-reactor model run lookups concurrently while
//! serialising the rare mutation. Writer-preferring so a steady stream of
//! readers can't starve a pending mutation.
//!
//! Spin-based (cooperative `Thread.yield`) per the project's no-`std.Thread.Mutex`
//! discipline — built only on `std.atomic`. Non-recursive; a thread holding the
//! write lock must not re-enter. With one reactor (num_shards = 1) the lock is
//! always uncontended, so the single-thread fast path is a couple of atomics.

const std = @import("std");

/// Bit 31 of `state` marks the write lock held; bits 0..30 count active readers.
const writer_bit: u32 = 1 << 31;

pub const RwLock = struct {
    /// writer_bit | reader_count.
    state: std.atomic.Value(u32) = .init(0),
    /// Pending writers; readers defer while this is non-zero (writer preference).
    writers_waiting: std.atomic.Value(u32) = .init(0),

    pub fn init() RwLock {
        return .{};
    }

    /// Acquire shared (read) access. Multiple readers may hold it at once.
    pub fn lockShared(self: *RwLock) void {
        while (true) {
            // Defer to any waiting writer so writers cannot be starved.
            if (self.writers_waiting.load(.acquire) != 0) {
                std.Thread.yield() catch {};
                continue;
            }
            const s = self.state.load(.monotonic);
            if (s & writer_bit != 0) {
                std.Thread.yield() catch {};
                continue;
            }
            if (self.state.cmpxchgWeak(s, s + 1, .acquire, .monotonic) == null) return;
        }
    }

    pub fn unlockShared(self: *RwLock) void {
        _ = self.state.fetchSub(1, .release);
    }

    /// Acquire exclusive (write) access. Blocks until no readers or writer hold it.
    pub fn lockExclusive(self: *RwLock) void {
        _ = self.writers_waiting.fetchAdd(1, .acquire);
        while (self.state.cmpxchgWeak(0, writer_bit, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
        _ = self.writers_waiting.fetchSub(1, .release);
    }

    pub fn unlockExclusive(self: *RwLock) void {
        self.state.store(0, .release);
    }

    /// Non-blocking write acquire; true if taken (only when fully unlocked).
    pub fn tryLockExclusive(self: *RwLock) bool {
        return self.state.cmpxchgStrong(0, writer_bit, .acquire, .monotonic) == null;
    }
};

test "single-thread: shared and exclusive acquire/release" {
    var lock = RwLock.init();
    lock.lockShared();
    lock.lockShared();
    lock.unlockShared();
    lock.unlockShared();
    lock.lockExclusive();
    // While write-held, a try-acquire must fail.
    try std.testing.expect(!lock.tryLockExclusive());
    lock.unlockExclusive();
    try std.testing.expect(lock.tryLockExclusive());
    lock.unlockExclusive();
}

const Hammer = struct {
    lock: *RwLock,
    counter: *u64,
    iters: u64,

    fn writer(ctx: *Hammer) void {
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.lock.lockExclusive();
            ctx.counter.* += 1; // protected critical section
            ctx.lock.unlockExclusive();
        }
    }

    fn reader(ctx: *Hammer) void {
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.lock.lockShared();
            // Read under the shared lock; value is monotonic so a torn read can't
            // exceed the final total.
            std.mem.doNotOptimizeAway(ctx.counter.*);
            ctx.lock.unlockShared();
        }
    }
};

test "concurrent writers see no lost updates under contention" {
    var lock = RwLock.init();
    var counter: u64 = 0;
    const writers = 4;
    const readers = 4;
    const iters: u64 = 5000;

    var ctx = Hammer{ .lock = &lock, .counter = &counter, .iters = iters };
    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();

    for (0..writers) |_| {
        threads[spawned] = std.Thread.spawn(.{}, Hammer.writer, .{&ctx}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |_| {
        threads[spawned] = std.Thread.spawn(.{}, Hammer.reader, .{&ctx}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    // No lost updates: every write-locked increment landed.
    try std.testing.expectEqual(writers * iters, counter);
}
