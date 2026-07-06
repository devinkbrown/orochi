// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hashed timer wheel for deterministic reactor timers.
//!
//! Callers provide absolute millisecond deadlines from their reactor clock.
//! The wheel never reads time itself, keeps timer storage inline, and reports
//! fired callback ids into caller-owned buffers so the hot paths do not allocate.
const std = @import("std");

/// Compile-time sizing for a timer wheel.
pub const WheelConfig = struct {
    slots: usize,
    capacity: usize,
    tick_ms: i64 = 1,
};

/// Stable timer handle with generation checks for stale-cancel rejection.
pub const TimerHandle = struct {
    index: u32,
    generation: u32,
};

/// One timer callback that became due during `advance`.
pub const FiredTimer = struct {
    id: u64,
    handle: TimerHandle,
    deadline_ms: i64,
};

/// Result from draining due timers into a caller-owned buffer.
pub const AdvanceResult = struct {
    fired: usize,
    output_full: bool = false,
};

/// Fixed-capacity hashed timer wheel.
pub fn HashedTimerWheel(comptime config: WheelConfig) type {
    comptime {
        if (config.slots == 0) @compileError("timer wheel slots must be non-zero");
        if (!std.math.isPowerOfTwo(config.slots)) @compileError("timer wheel slots must be a power of two");
        if (config.capacity == 0) @compileError("timer wheel capacity must be non-zero");
        if (config.capacity > std.math.maxInt(u32)) @compileError("timer wheel capacity must fit in u32 handles");
        if (config.tick_ms <= 0) @compileError("timer wheel tick_ms must be positive");
    }

    return struct {
        const Self = @This();
        const none = std.math.maxInt(usize);
        const slot_mask = config.slots - 1;

        const Node = struct {
            id: u64 = 0,
            deadline_ms: i64 = 0,
            deadline_tick: usize = 0,
            interval_ms: i64 = 0,
            generation: u32 = 1,
            slot: usize = 0,
            prev: usize = none,
            next: usize = none,
            active: bool = false,
        };

        heads: [config.slots]usize = @splat(none),
        tails: [config.slots]usize = @splat(none),
        nodes: [config.capacity]Node = initNodes(),
        free_head: usize = if (config.capacity == 0) none else 0,
        cursor_tick: usize = 0,
        now_ms: i64 = 0,
        active_count: usize = 0,

        /// Create an empty wheel at deterministic time `start_ms`.
        pub fn init(start_ms: i64) !Self {
            if (start_ms < 0) return error.InvalidNow;

            var self = Self{};
            self.cursor_tick = try msToTick(start_ms);
            self.now_ms = start_ms;
            return self;
        }

        /// Number of active timers.
        pub fn count(self: *const Self) usize {
            return self.active_count;
        }

        /// Schedule a one-shot callback at an absolute millisecond deadline.
        pub fn scheduleOneShot(self: *Self, deadline_ms: i64, id: u64) !TimerHandle {
            return self.schedule(deadline_ms, 0, id);
        }

        /// Schedule a periodic callback, first firing at `deadline_ms`.
        pub fn schedulePeriodic(self: *Self, deadline_ms: i64, interval_ms: i64, id: u64) !TimerHandle {
            if (interval_ms <= 0) return error.InvalidInterval;
            return self.schedule(deadline_ms, interval_ms, id);
        }

        /// Cancel an active timer. Stale or forged handles return `error.StaleHandle`.
        pub fn cancel(self: *Self, handle: TimerHandle) !void {
            const index = self.validateHandle(handle) orelse return error.StaleHandle;
            self.unlink(index);
            self.release(index);
        }

        /// Advance deterministic time and write due callbacks into `out`.
        ///
        /// If `out` fills before all due timers are drained, the due timer that
        /// did not fit remains active and a later `advance` with the same `now_ms`
        /// can continue draining.
        pub fn advance(self: *Self, now_ms: i64, out: []FiredTimer) !AdvanceResult {
            if (now_ms < 0) return error.InvalidNow;
            if (now_ms < self.now_ms) return error.TimeWentBackwards;

            self.now_ms = now_ms;
            const target_tick = try msToTick(now_ms);
            var fired: usize = 0;

            while (self.cursor_tick <= target_tick) {
                const slot = slotForTick(self.cursor_tick);
                var index = self.heads[slot];

                while (index != none) {
                    const next = self.nodes[index].next;
                    if (self.nodes[index].deadline_tick <= self.cursor_tick) {
                        if (fired == out.len) {
                            return .{ .fired = fired, .output_full = true };
                        }

                        const handle = self.handleForIndex(index);
                        out[fired] = .{
                            .id = self.nodes[index].id,
                            .handle = handle,
                            .deadline_ms = self.nodes[index].deadline_ms,
                        };
                        fired += 1;

                        self.unlink(index);
                        if (self.nodes[index].interval_ms > 0) {
                            try self.rearmPeriodic(index, now_ms);
                        } else {
                            self.release(index);
                        }
                    }
                    index = next;
                }

                self.cursor_tick += 1;
            }

            return .{ .fired = fired };
        }

        fn schedule(self: *Self, deadline_ms: i64, interval_ms: i64, id: u64) !TimerHandle {
            if (deadline_ms < 0) return error.InvalidDeadline;
            if (interval_ms < 0) return error.InvalidInterval;

            const deadline_tick = try msToTick(deadline_ms);
            if (deadline_tick < self.cursor_tick) return error.DeadlineInPast;

            const index = self.free_head;
            if (index == none) return error.TimerFull;

            self.free_head = self.nodes[index].next;
            self.nodes[index] = .{
                .id = id,
                .deadline_ms = deadline_ms,
                .deadline_tick = deadline_tick,
                .interval_ms = interval_ms,
                .generation = self.nodes[index].generation,
                .active = true,
            };
            self.link(index);
            self.active_count += 1;

            return self.handleForIndex(index);
        }

        fn validateHandle(self: *const Self, handle: TimerHandle) ?usize {
            const index: usize = handle.index;
            if (index >= config.capacity) return null;

            const node = self.nodes[index];
            if (!node.active) return null;
            if (node.generation != handle.generation) return null;
            return index;
        }

        fn handleForIndex(self: *const Self, index: usize) TimerHandle {
            return .{
                .index = @intCast(index),
                .generation = self.nodes[index].generation,
            };
        }

        fn link(self: *Self, index: usize) void {
            const slot = slotForTick(self.nodes[index].deadline_tick);
            self.nodes[index].slot = slot;
            self.nodes[index].prev = self.tails[slot];
            self.nodes[index].next = none;

            if (self.tails[slot] == none) {
                self.heads[slot] = index;
            } else {
                self.nodes[self.tails[slot]].next = index;
            }
            self.tails[slot] = index;
        }

        fn unlink(self: *Self, index: usize) void {
            const slot = self.nodes[index].slot;
            const prev = self.nodes[index].prev;
            const next = self.nodes[index].next;

            if (prev == none) {
                self.heads[slot] = next;
            } else {
                self.nodes[prev].next = next;
            }

            if (next == none) {
                self.tails[slot] = prev;
            } else {
                self.nodes[next].prev = prev;
            }

            self.nodes[index].prev = none;
            self.nodes[index].next = none;
        }

        fn release(self: *Self, index: usize) void {
            self.nodes[index].active = false;
            self.nodes[index].generation = bumpGeneration(self.nodes[index].generation);
            self.nodes[index].next = self.free_head;
            self.nodes[index].prev = none;
            self.free_head = index;
            self.active_count -= 1;
        }

        fn rearmPeriodic(self: *Self, index: usize, now_ms: i64) !void {
            const next_deadline = try nextPeriodicDeadline(
                self.nodes[index].deadline_ms,
                self.nodes[index].interval_ms,
                now_ms,
                self.cursor_tick,
            );

            self.nodes[index].deadline_ms = next_deadline.ms;
            self.nodes[index].deadline_tick = next_deadline.tick;
            self.link(index);
        }

        fn nextPeriodicDeadline(last_ms: i64, interval_ms: i64, now_ms: i64, cursor_tick: usize) !struct { ms: i64, tick: usize } {
            var next_ms = try std.math.add(i64, last_ms, interval_ms);

            if (next_ms <= now_ms) {
                const behind = now_ms - next_ms;
                const skips = @divFloor(behind, interval_ms) + 1;
                const jump = try std.math.mul(i64, interval_ms, skips);
                next_ms = try std.math.add(i64, next_ms, jump);
            }

            var next_tick = try msToTick(next_ms);
            while (next_tick <= cursor_tick) {
                next_ms = try std.math.add(i64, next_ms, interval_ms);
                next_tick = try msToTick(next_ms);
            }

            return .{ .ms = next_ms, .tick = next_tick };
        }

        fn msToTick(ms: i64) !usize {
            if (ms < 0) return error.InvalidNow;
            const tick_ms_i128: i128 = config.tick_ms;
            const tick_i128 = @divFloor(@as(i128, ms), tick_ms_i128);
            if (tick_i128 >= std.math.maxInt(usize)) return error.Overflow;
            return @intCast(tick_i128);
        }

        fn slotForTick(tick: usize) usize {
            return tick & slot_mask;
        }

        fn bumpGeneration(generation: u32) u32 {
            const next = generation +% 1;
            return if (next == 0) 1 else next;
        }

        fn initNodes() [config.capacity]Node {
            var nodes: [config.capacity]Node = undefined;
            for (&nodes, 0..) |*node, i| {
                node.* = .{
                    .generation = 1,
                    .next = if (i + 1 == config.capacity) none else i + 1,
                };
            }
            return nodes;
        }
    };
}

test "one-shot timer fires at deadline" {
    const Wheel = HashedTimerWheel(.{ .slots = 8, .capacity = 4 });
    var wheel = try Wheel.init(0);
    _ = try wheel.scheduleOneShot(10, 100);

    var fired: [2]FiredTimer = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try wheel.advance(9, &fired)).fired);
    const result = try wheel.advance(10, &fired);

    try std.testing.expectEqual(@as(usize, 1), result.fired);
    try std.testing.expect(!result.output_full);
    try std.testing.expectEqual(@as(u64, 100), fired[0].id);
    try std.testing.expectEqual(@as(i64, 10), fired[0].deadline_ms);
    try std.testing.expectEqual(@as(usize, 0), wheel.count());
}

test "timers fire in deadline order across wheel rotations" {
    const Wheel = HashedTimerWheel(.{ .slots = 4, .capacity = 4 });
    var wheel = try Wheel.init(0);

    _ = try wheel.scheduleOneShot(8, 800);
    _ = try wheel.scheduleOneShot(4, 400);
    _ = try wheel.scheduleOneShot(4, 401);

    const fired = try std.testing.allocator.alloc(FiredTimer, 4);
    defer std.testing.allocator.free(fired);

    const result = try wheel.advance(8, fired);
    try std.testing.expectEqual(@as(usize, 3), result.fired);
    try std.testing.expectEqual(@as(u64, 400), fired[0].id);
    try std.testing.expectEqual(@as(u64, 401), fired[1].id);
    try std.testing.expectEqual(@as(u64, 800), fired[2].id);
}

test "periodic timers re-arm on their interval" {
    const Wheel = HashedTimerWheel(.{ .slots = 8, .capacity = 4 });
    var wheel = try Wheel.init(0);
    const handle = try wheel.schedulePeriodic(5, 5, 77);

    var fired: [2]FiredTimer = undefined;
    try std.testing.expectEqual(@as(usize, 1), (try wheel.advance(5, &fired)).fired);
    try std.testing.expectEqual(@as(u64, 77), fired[0].id);
    try std.testing.expectEqual(@as(i64, 5), fired[0].deadline_ms);
    try std.testing.expectEqual(handle, fired[0].handle);
    try std.testing.expectEqual(@as(usize, 1), wheel.count());

    try std.testing.expectEqual(@as(usize, 0), (try wheel.advance(9, &fired)).fired);
    try std.testing.expectEqual(@as(usize, 1), (try wheel.advance(10, &fired)).fired);
    try std.testing.expectEqual(@as(i64, 10), fired[0].deadline_ms);
}

test "cancel prevents a timer from firing" {
    const Wheel = HashedTimerWheel(.{ .slots = 8, .capacity = 4 });
    var wheel = try Wheel.init(0);
    const handle = try wheel.scheduleOneShot(3, 33);
    try wheel.cancel(handle);

    var fired: [1]FiredTimer = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try wheel.advance(3, &fired)).fired);
    try std.testing.expectEqual(@as(usize, 0), wheel.count());
}

test "stale handles are rejected" {
    const Wheel = HashedTimerWheel(.{ .slots = 8, .capacity = 1 });
    var wheel = try Wheel.init(0);

    const stale = try wheel.scheduleOneShot(2, 22);
    try wheel.cancel(stale);
    try std.testing.expectError(error.StaleHandle, wheel.cancel(stale));

    const fresh = try wheel.scheduleOneShot(4, 44);
    try std.testing.expect(stale.generation != fresh.generation);
    try std.testing.expectError(error.StaleHandle, wheel.cancel(stale));
    try wheel.cancel(fresh);
}

test "timer wheel behavior is deterministic" {
    const Wheel = HashedTimerWheel(.{ .slots = 8, .capacity = 8 });
    var a = try Wheel.init(0);
    var b = try Wheel.init(0);

    _ = try a.scheduleOneShot(7, 1);
    _ = try a.schedulePeriodic(3, 4, 2);
    _ = try a.scheduleOneShot(3, 3);

    _ = try b.scheduleOneShot(7, 1);
    _ = try b.schedulePeriodic(3, 4, 2);
    _ = try b.scheduleOneShot(3, 3);

    var fired_a: [8]FiredTimer = undefined;
    var fired_b: [8]FiredTimer = undefined;

    const result_a = try a.advance(11, &fired_a);
    const result_b = try b.advance(11, &fired_b);

    try std.testing.expectEqual(result_a, result_b);
    for (fired_a[0..result_a.fired], fired_b[0..result_b.fired]) |left, right| {
        try std.testing.expectEqual(left, right);
    }
}
