//! Allocator-owned hierarchical timing wheel for deterministic daemon timeouts.
//!
//! Callers provide absolute millisecond times.  The wheel never reads a clock,
//! stores only opaque timeout tokens, and drains due tokens into caller-owned
//! output slices.
const std = @import("std");

pub const Params = struct {
    pub const level_count: usize = 8;
    pub const slots_per_level: usize = 64;
    pub const slot_bits: usize = 6;
    pub const max_timers: usize = std.math.maxInt(u32);
    pub const max_ticks: u64 = @as(u64, 1) << @intCast(level_count * slot_bits);
};

pub const TimerHandle = struct {
    index: u32,
    generation: u32,
};

pub const AdvanceResult = struct {
    expired: usize,
    output_full: bool = false,
};

pub const TimerWheel = struct {
    const Self = @This();
    const none = std.math.maxInt(usize);
    const ready_level = std.math.maxInt(u8);
    const slot_mask: u64 = Params.slots_per_level - 1;

    const Bucket = struct {
        head: usize = none,
        tail: usize = none,
    };

    const Node = struct {
        token: u64 = 0,
        deadline_ms: u64 = 0,
        deadline_tick: u64 = 0,
        seq: u64 = 0,
        generation: u32 = 1,
        level: u8 = 0,
        slot: u8 = 0,
        prev: usize = none,
        next: usize = none,
        active: bool = false,
    };

    allocator: std.mem.Allocator,
    tick_ms: u64,
    now_ms: u64 = 0,
    cursor_tick: u64 = 0,
    next_seq: u64 = 0,
    active_count: usize = 0,
    free_head: usize = none,
    ready_head: usize = none,
    ready_tail: usize = none,
    buckets: [Params.level_count][Params.slots_per_level]Bucket = emptyBuckets(),
    nodes: std.ArrayList(Node) = .empty,

    pub fn init(allocator: std.mem.Allocator, tick_ms: u64) !Self {
        if (tick_ms == 0) return error.InvalidTick;
        return .{
            .allocator = allocator,
            .tick_ms = tick_ms,
        };
    }

    pub fn deinit(self: *Self) void {
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const Self) usize {
        return self.active_count;
    }

    pub fn add(self: *Self, deadline_ms: u64, opaque_token: u64) !TimerHandle {
        if (deadline_ms < self.now_ms) return error.DeadlineInPast;

        const deadline_tick = deadlineTick(deadline_ms, self.tick_ms);
        if (deadline_tick >= self.cursor_tick and deadline_tick - self.cursor_tick >= Params.max_ticks) {
            return error.DeadlineTooFar;
        }

        const index = try self.acquireNode();
        const generation = self.nodes.items[index].generation;
        self.nodes.items[index] = .{
            .token = opaque_token,
            .deadline_ms = deadline_ms,
            .deadline_tick = deadline_tick,
            .seq = self.next_seq,
            .generation = generation,
            .active = true,
        };
        self.next_seq +%= 1;
        self.active_count += 1;

        if (deadline_ms <= self.now_ms) {
            self.insertReady(index);
        } else {
            self.scheduleNode(index);
        }

        return self.handleForIndex(index);
    }

    pub fn cancel(self: *Self, handle: TimerHandle) !void {
        const index = self.validateHandle(handle) orelse return error.StaleHandle;
        self.unlink(index);
        self.release(index);
    }

    pub fn advance(self: *Self, now_ms: u64, out_expired: []u64) !AdvanceResult {
        if (now_ms < self.now_ms) return error.TimeWentBackwards;
        self.now_ms = now_ms;

        var expired: usize = 0;
        var drained = self.drainReady(out_expired);
        expired += drained.expired;
        if (drained.output_full) return .{ .expired = expired, .output_full = true };

        const target_tick = nowTick(now_ms, self.tick_ms);
        if (self.active_count == 0 and self.ready_head == none) {
            self.cursor_tick = saturatingNextTick(target_tick);
            return .{ .expired = expired };
        }

        while (self.cursor_tick <= target_tick) {
            try self.cascade(self.cursor_tick);
            self.collectCurrentSlot();
            self.cursor_tick += 1;

            drained = self.drainReady(out_expired[expired..]);
            expired += drained.expired;
            if (drained.output_full) return .{ .expired = expired, .output_full = true };
        }

        return .{ .expired = expired };
    }

    fn acquireNode(self: *Self) !usize {
        if (self.free_head != none) {
            const index = self.free_head;
            self.free_head = self.nodes.items[index].next;
            self.nodes.items[index].next = none;
            return index;
        }

        if (self.nodes.items.len >= Params.max_timers) return error.TimerFull;
        const index = self.nodes.items.len;
        try self.nodes.append(self.allocator, .{});
        return index;
    }

    fn validateHandle(self: *const Self, handle: TimerHandle) ?usize {
        const index: usize = handle.index;
        if (index >= self.nodes.items.len) return null;

        const node = self.nodes.items[index];
        if (!node.active) return null;
        if (node.generation != handle.generation) return null;
        return index;
    }

    fn handleForIndex(self: *const Self, index: usize) TimerHandle {
        return .{
            .index = @intCast(index),
            .generation = self.nodes.items[index].generation,
        };
    }

    fn scheduleNode(self: *Self, index: usize) void {
        const deadline = self.nodes.items[index].deadline_tick;
        const diff = if (deadline > self.cursor_tick) deadline - self.cursor_tick else 0;
        const level = levelForDiff(diff);
        const slot = slotFor(level, deadline);

        self.nodes.items[index].level = @intCast(level);
        self.nodes.items[index].slot = @intCast(slot);
        self.nodes.items[index].prev = self.buckets[level][slot].tail;
        self.nodes.items[index].next = none;

        if (self.buckets[level][slot].tail == none) {
            self.buckets[level][slot].head = index;
        } else {
            self.nodes.items[self.buckets[level][slot].tail].next = index;
        }
        self.buckets[level][slot].tail = index;
    }

    fn insertReady(self: *Self, index: usize) void {
        self.nodes.items[index].level = ready_level;
        self.nodes.items[index].slot = 0;
        self.nodes.items[index].prev = none;
        self.nodes.items[index].next = none;

        var at = self.ready_head;
        while (at != none) : (at = self.nodes.items[at].next) {
            if (dueBefore(self.nodes.items[index], self.nodes.items[at])) break;
        }

        if (at == none) {
            self.nodes.items[index].prev = self.ready_tail;
            if (self.ready_tail == none) {
                self.ready_head = index;
            } else {
                self.nodes.items[self.ready_tail].next = index;
            }
            self.ready_tail = index;
            return;
        }

        const prev = self.nodes.items[at].prev;
        self.nodes.items[index].prev = prev;
        self.nodes.items[index].next = at;
        self.nodes.items[at].prev = index;
        if (prev == none) {
            self.ready_head = index;
        } else {
            self.nodes.items[prev].next = index;
        }
    }

    fn unlink(self: *Self, index: usize) void {
        if (self.nodes.items[index].level == ready_level) {
            self.unlinkReady(index);
        } else {
            self.unlinkBucket(index);
        }
        self.nodes.items[index].prev = none;
        self.nodes.items[index].next = none;
    }

    fn unlinkReady(self: *Self, index: usize) void {
        const prev = self.nodes.items[index].prev;
        const next = self.nodes.items[index].next;

        if (prev == none) {
            self.ready_head = next;
        } else {
            self.nodes.items[prev].next = next;
        }

        if (next == none) {
            self.ready_tail = prev;
        } else {
            self.nodes.items[next].prev = prev;
        }
    }

    fn unlinkBucket(self: *Self, index: usize) void {
        const level: usize = self.nodes.items[index].level;
        const slot: usize = self.nodes.items[index].slot;
        const prev = self.nodes.items[index].prev;
        const next = self.nodes.items[index].next;

        if (prev == none) {
            self.buckets[level][slot].head = next;
        } else {
            self.nodes.items[prev].next = next;
        }

        if (next == none) {
            self.buckets[level][slot].tail = prev;
        } else {
            self.nodes.items[next].prev = prev;
        }
    }

    fn release(self: *Self, index: usize) void {
        self.nodes.items[index].active = false;
        self.nodes.items[index].generation = bumpGeneration(self.nodes.items[index].generation);
        self.nodes.items[index].level = 0;
        self.nodes.items[index].slot = 0;
        self.nodes.items[index].next = self.free_head;
        self.nodes.items[index].prev = none;
        self.free_head = index;
        self.active_count -= 1;
    }

    fn drainReady(self: *Self, out: []u64) AdvanceResult {
        var expired: usize = 0;
        while (self.ready_head != none) {
            if (expired == out.len) return .{ .expired = expired, .output_full = true };

            const index = self.ready_head;
            out[expired] = self.nodes.items[index].token;
            expired += 1;

            self.unlinkReady(index);
            self.nodes.items[index].prev = none;
            self.nodes.items[index].next = none;
            self.release(index);
        }
        return .{ .expired = expired };
    }

    fn cascade(self: *Self, tick: u64) !void {
        if (tick == 0) return;

        var level = Params.level_count;
        while (level > 1) {
            level -= 1;
            const span = levelSpan(level);
            if ((tick & (span - 1)) == 0) {
                try self.rescheduleBucket(level, slotFor(level, tick));
            }
        }

        if ((tick & (levelSpan(1) - 1)) == 0) {
            try self.rescheduleBucket(1, slotFor(1, tick));
        }
    }

    fn rescheduleBucket(self: *Self, level: usize, slot: usize) !void {
        var index = self.buckets[level][slot].head;
        self.buckets[level][slot] = .{};

        while (index != none) {
            const next = self.nodes.items[index].next;
            self.nodes.items[index].prev = none;
            self.nodes.items[index].next = none;

            if (self.nodes.items[index].deadline_tick < self.cursor_tick) {
                return error.InternalTimerOrder;
            }
            self.scheduleNode(index);
            index = next;
        }
    }

    fn collectCurrentSlot(self: *Self) void {
        const slot = slotFor(0, self.cursor_tick);
        var index = self.buckets[0][slot].head;

        while (index != none) {
            const next = self.nodes.items[index].next;
            if (self.nodes.items[index].deadline_tick <= self.cursor_tick and
                self.nodes.items[index].deadline_ms <= self.now_ms)
            {
                self.unlinkBucket(index);
                self.nodes.items[index].prev = none;
                self.nodes.items[index].next = none;
                self.insertReady(index);
            }
            index = next;
        }
    }

    fn emptyBuckets() [Params.level_count][Params.slots_per_level]Bucket {
        return [_][Params.slots_per_level]Bucket{
            [_]Bucket{.{}} ** Params.slots_per_level,
        } ** Params.level_count;
    }

    fn dueBefore(a: Node, b: Node) bool {
        const deadline_order = std.math.order(a.deadline_ms, b.deadline_ms);
        if (deadline_order != .eq) return deadline_order == .lt;
        return a.seq < b.seq;
    }

    fn deadlineTick(deadline_ms: u64, tick_ms: u64) u64 {
        const q = deadline_ms / tick_ms;
        return q + @as(u64, @intFromBool(deadline_ms % tick_ms != 0));
    }

    fn nowTick(now_ms: u64, tick_ms: u64) u64 {
        return now_ms / tick_ms;
    }

    fn levelForDiff(diff: u64) usize {
        var level: usize = 0;
        while (level + 1 < Params.level_count and diff >= levelSpan(level + 1)) {
            level += 1;
        }
        return level;
    }

    fn levelSpan(level: usize) u64 {
        return @as(u64, 1) << shiftForLevel(level);
    }

    fn slotFor(level: usize, tick: u64) usize {
        return @intCast((tick >> shiftForLevel(level)) & slot_mask);
    }

    fn shiftForLevel(level: usize) std.math.Log2Int(u64) {
        return @intCast(level * Params.slot_bits);
    }

    fn bumpGeneration(generation: u32) u32 {
        const next = generation +% 1;
        return if (next == 0) 1 else next;
    }

    fn saturatingNextTick(tick: u64) u64 {
        return if (tick == std.math.maxInt(u64)) tick else tick + 1;
    }
};

pub fn init(allocator: std.mem.Allocator, tick_ms: u64) !TimerWheel {
    return TimerWheel.init(allocator, tick_ms);
}

test "add several and advance partially in deadline order" {
    var wheel = try init(std.testing.allocator, 10);
    defer wheel.deinit();

    _ = try wheel.add(30, 300);
    _ = try wheel.add(10, 100);
    _ = try wheel.add(20, 200);
    _ = try wheel.add(20, 201);

    var out: [4]u64 = undefined;
    var result = try wheel.advance(15, &out);
    try std.testing.expectEqual(@as(usize, 1), result.expired);
    try std.testing.expect(!result.output_full);
    try std.testing.expectEqual(@as(u64, 100), out[0]);
    try std.testing.expectEqual(@as(usize, 3), wheel.count());

    result = try wheel.advance(20, &out);
    try std.testing.expectEqual(@as(usize, 2), result.expired);
    try std.testing.expectEqual(@as(u64, 200), out[0]);
    try std.testing.expectEqual(@as(u64, 201), out[1]);
    try std.testing.expectEqual(@as(usize, 1), wheel.count());

    result = try wheel.advance(29, &out);
    try std.testing.expectEqual(@as(usize, 0), result.expired);
    result = try wheel.advance(30, &out);
    try std.testing.expectEqual(@as(usize, 1), result.expired);
    try std.testing.expectEqual(@as(u64, 300), out[0]);
    try std.testing.expectEqual(@as(usize, 0), wheel.count());
}

test "output slice can drain due timers over repeated advance calls" {
    var wheel = try init(std.testing.allocator, 1);
    defer wheel.deinit();

    _ = try wheel.add(3, 1);
    _ = try wheel.add(3, 2);
    _ = try wheel.add(4, 3);

    var out: [2]u64 = undefined;
    var result = try wheel.advance(4, &out);
    try std.testing.expectEqual(@as(usize, 2), result.expired);
    try std.testing.expect(result.output_full);
    try std.testing.expectEqual(@as(u64, 1), out[0]);
    try std.testing.expectEqual(@as(u64, 2), out[1]);

    result = try wheel.advance(4, &out);
    try std.testing.expectEqual(@as(usize, 1), result.expired);
    try std.testing.expect(!result.output_full);
    try std.testing.expectEqual(@as(u64, 3), out[0]);
}

test "cancel before fire and re-add rejects stale handle" {
    var wheel = try init(std.testing.allocator, 5);
    defer wheel.deinit();

    const stale = try wheel.add(25, 25);
    try wheel.cancel(stale);
    try std.testing.expectError(error.StaleHandle, wheel.cancel(stale));

    var out: [2]u64 = undefined;
    var result = try wheel.advance(30, &out);
    try std.testing.expectEqual(@as(usize, 0), result.expired);

    const fresh = try wheel.add(35, 35);
    try std.testing.expect(stale.generation != fresh.generation);
    result = try wheel.advance(35, &out);
    try std.testing.expectEqual(@as(usize, 1), result.expired);
    try std.testing.expectEqual(@as(u64, 35), out[0]);
}

test "no leak across add cancel and fire churn" {
    var wheel = try init(std.testing.allocator, 1);
    defer wheel.deinit();

    var out: [8]u64 = undefined;
    var i: u64 = 0;
    while (i < 512) : (i += 1) {
        const a = try wheel.add(i + 10, i);
        const b = try wheel.add(i + 11, i + 10_000);
        if ((i & 1) == 0) {
            try wheel.cancel(a);
        } else {
            try wheel.cancel(b);
        }

        const result = try wheel.advance(i + 11, &out);
        try std.testing.expectEqual(@as(usize, 1), result.expired);
        try std.testing.expectEqual(@as(usize, 0), wheel.count());
    }
}

test "deterministic with a seeded sequence" {
    var left = try init(std.testing.allocator, 3);
    defer left.deinit();
    var right = try init(std.testing.allocator, 3);
    defer right.deinit();

    var left_handles = [_]?TimerHandle{null} ** 32;
    var right_handles = [_]?TimerHandle{null} ** 32;
    var prng = std.Random.Pcg.init(0x4d495a55434849);

    var now: u64 = 0;
    var step: usize = 0;
    while (step < 200) : (step += 1) {
        const random = prng.random();
        now += random.uintLessThan(u64, 7);

        const slot = random.uintLessThan(usize, left_handles.len);
        if (left_handles[slot]) |handle| {
            try left.cancel(handle);
            try right.cancel(right_handles[slot].?);
            left_handles[slot] = null;
            right_handles[slot] = null;
        } else {
            const delta = 1 + random.uintLessThan(u64, 80);
            left_handles[slot] = try left.add(now + delta, @intCast(slot));
            right_handles[slot] = try right.add(now + delta, @intCast(slot));
        }

        var left_out: [64]u64 = undefined;
        var right_out: [64]u64 = undefined;
        const left_result = try left.advance(now, &left_out);
        const right_result = try right.advance(now, &right_out);

        try std.testing.expectEqual(left_result, right_result);
        try std.testing.expectEqualSlices(u64, left_out[0..left_result.expired], right_out[0..right_result.expired]);
        for (left_out[0..left_result.expired]) |token| {
            const fired_slot: usize = @intCast(token);
            left_handles[fired_slot] = null;
            right_handles[fired_slot] = null;
        }
    }

    var left_out: [64]u64 = undefined;
    var right_out: [64]u64 = undefined;
    const left_result = try left.advance(now + 512, &left_out);
    const right_result = try right.advance(now + 512, &right_out);
    try std.testing.expectEqual(left_result, right_result);
    try std.testing.expectEqualSlices(u64, left_out[0..left_result.expired], right_out[0..right_result.expired]);
}
