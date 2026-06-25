// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Two-reactor cross-shard delivery smoke test (multithreading capstone step 6).
//!
//! The sharded daemon runs N reactor threads, each owning its own io_uring and a
//! disjoint slice of the connection table. When a reactor must deliver bytes to a
//! client pinned to another shard it cannot touch that reactor's send queue: it
//! copies the bytes into a pooled `DeliverBuf` (`deliver_handle.zig`), hands a POD
//! `DeliverMsg` over the target shard's lock-free `Mailboxes` inbox
//! (`shard.zig`), and pokes the target's `ReactorWake` eventfd (`reactor_wake.zig`)
//! so its loop runs and drains.
//!
//! Those three primitives are individually unit-tested; this file proves they
//! *compose* end-to-end across real threads before the live `server.zig` fan-out
//! is rewired onto them. Each reactor here stands in for an io_uring loop by
//! sleeping in `poll(2)` on its wake fd — the same edge an io_uring POLL/READ SQE
//! on that fd would deliver. We assert: every cross-shard message reaches the
//! addressed reactor exactly once with intact bytes, only the addressed reactor,
//! and every pooled buffer is released back (no handoff leak).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const shard = @import("shard.zig");
const reactor_wake = @import("reactor_wake.zig");
const deliver_handle = @import("deliver_handle.zig");
const client = @import("client.zig");

const ClientId = client.ClientId;
const DeliverMsg = deliver_handle.DeliverMsg;

const num_shards = 2;
const per_shard = 2000;
const total = per_shard * num_shards;

const Mailboxes = shard.Mailboxes(DeliverMsg, num_shards, 256);
const WakeSet = reactor_wake.WakeSet(num_shards);
const Pool = deliver_handle.DeliverPool(128);

/// Shared world of the two reactors plus the producer. Lock-free throughout: the
/// pool and inboxes are the same primitives the live reactors will share.
const Fabric = struct {
    boxes: Mailboxes = Mailboxes.init(),
    wakes: *WakeSet,
    pool: Pool = Pool.init(),
};

/// One reactor: blocks in poll() on its wake fd, then drains its mailbox, copying
/// each delivery's bytes locally and releasing the pooled buffer. Records, per
/// sequence number, that the message arrived so the test can detect drops or
/// duplicates. Stops once it has received its full quota.
const Reactor = struct {
    fabric: *Fabric,
    shard_id: u12,
    expected: usize,
    received: usize = 0,
    /// seen[seq] — guards against duplicate delivery of the same sequence.
    seen: [per_shard]bool = [_]bool{false} ** per_shard,
    /// Set if a message addressed to the wrong shard, a bad seq, or a duplicate
    /// is ever observed; checked by the test after the join.
    corrupt: bool = false,

    fn run(self: *Reactor) void {
        var pfd = [_]std.posix.pollfd{.{
            .fd = self.fabric.wakes.fd(self.shard_id),
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        var out: [64]DeliverMsg = undefined;
        // Bounded so a wiring bug fails the test instead of hanging forever:
        // total work is `expected` deliveries; 100ms per poll gives generous slack.
        var idle_polls: usize = 0;
        while (self.received < self.expected) {
            _ = std.posix.poll(&pfd, 100) catch break;
            // Drain the eventfd *before* the mailbox: a wake that lands after this
            // drain but after a later push re-arms readiness, so no wakeup is lost.
            self.fabric.wakes.drain(self.shard_id);

            const n = self.fabric.boxes.drain(self.shard_id, &out);
            if (n == 0) {
                idle_polls += 1;
                if (idle_polls > 200) break; // ~20s of no progress: give up, test fails.
                continue;
            }
            idle_polls = 0;
            for (out[0..n]) |msg| self.consume(msg);
        }
    }

    fn consume(self: *Reactor, msg: DeliverMsg) void {
        defer self.fabric.pool.release(msg.buf);
        if (msg.to.shard != self.shard_id) {
            self.corrupt = true;
            return;
        }
        const bytes = self.fabric.pool.bytes(msg.buf);
        // Payload is "<shard>:<seq>" — re-derive and check it round-tripped intact.
        var it = std.mem.splitScalar(u8, bytes, ':');
        const sh = std.fmt.parseInt(u12, it.first(), 10) catch {
            self.corrupt = true;
            return;
        };
        const seq = std.fmt.parseInt(usize, it.rest(), 10) catch {
            self.corrupt = true;
            return;
        };
        if (sh != self.shard_id or seq >= per_shard or self.seen[seq]) {
            self.corrupt = true;
            return;
        }
        self.seen[seq] = true;
        self.received += 1;
    }
};

/// The cross-shard sender. Produces `total` deliveries split evenly between the
/// two shards, addressing each as if it were a member living on the other reactor.
/// Retries on transient pool exhaustion / inbox back-pressure (the live path will
/// back-pressure the same way) so the test exercises steady-state churn.
fn produce(fabric: *Fabric) void {
    var line: [32]u8 = undefined;
    var seqs = [_]usize{ 0, 0 };
    var produced: usize = 0;
    while (produced < total) : (produced += 1) {
        const target: u12 = @intCast(produced % num_shards);
        const seq = seqs[target];
        seqs[target] += 1;
        const payload = std.fmt.bufPrint(&line, "{d}:{d}", .{ target, seq }) catch unreachable;

        // Acquire a pooled buffer (copies the bytes), retrying if the pool is
        // momentarily drained by in-flight deliveries.
        const buf = while (true) {
            if (fabric.pool.acquire(payload)) |b| break b;
            std.Thread.yield() catch {};
        };
        const msg = DeliverMsg{ .to = .{ .shard = target, .slot = @intCast(seq), .gen = 1 }, .buf = buf };
        // Hand off + wake, retrying on a full inbox.
        while (!fabric.boxes.sendTo(target, msg)) std.Thread.yield() catch {};
        fabric.wakes.wake(target);
    }
}

test "two reactors deliver cross-shard messages exactly once with no buffer leak" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var wakes = WakeSet.init() catch return error.SkipZigTest;
    defer wakes.deinit();

    var fabric = Fabric{ .wakes = &wakes };

    var reactors: [num_shards]Reactor = undefined;
    for (0..num_shards) |i| {
        reactors[i] = .{ .fabric = &fabric, .shard_id = @intCast(i), .expected = per_shard };
    }

    var threads: [num_shards]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..num_shards) |i| {
        threads[i] = std.Thread.spawn(.{}, Reactor.run, .{&reactors[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }

    // Drive the producer on this thread once both reactors are armed.
    produce(&fabric);

    for (threads[0..spawned]) |t| t.join();

    for (&reactors) |*r| {
        try std.testing.expect(!r.corrupt);
        try std.testing.expectEqual(@as(usize, per_shard), r.received);
    }

    // Every handed-off buffer must have been released back to the pool: drain it
    // to exhaustion and confirm exactly the full slot count is reclaimable.
    var reclaimed: usize = 0;
    while (fabric.pool.acquire("x")) |b| {
        reclaimed += 1;
        // Pin so the next acquire can't hand back the same slot mid-count.
        if (reclaimed > 128) {
            fabric.pool.release(b);
            break;
        }
    }
    try std.testing.expectEqual(@as(usize, 128), reclaimed);
}
