// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Self-contained hierarchical timing wheel for deterministic millisecond timers.
//!
//! The wheel is caller-clocked: it never reads real time. `schedule` takes an
//! absolute millisecond deadline, `cancel` removes an active handle, and
//! `advance` moves the deterministic clock forward and returns an allocator-owned
//! slice of expired ids sorted by deadline and insertion order.
const std = @import("std");

pub const TimerHandle = struct {
    index: u32,
    generation: u32,
};

pub const TimingWheel = struct {
    const Self = @This();

    const level_count: usize = 8;
    const slots_per_level: usize = 256;
    const slot_bits: u6 = 8;
    const slot_mask: u64 = slots_per_level - 1;
    const none = std.math.maxInt(usize);
    const ready_level = std.math.maxInt(u8);

    const Bucket = struct {
        head: usize = none,
        tail: usize = none,
    };

    const Node = struct {
        id: u64 = 0,
        deadline_ms: u64 = 0,
        seq: u64 = 0,
        generation: u32 = 1,
        level: u8 = 0,
        slot: u8 = 0,
        prev: usize = none,
        next: usize = none,
        active: bool = false,
    };

    allocator: std.mem.Allocator,
    now_ms: u64 = 0,
    cursor_ms: u64 = 0,
    next_seq: u64 = 0,
    active_count: usize = 0,
    free_head: usize = none,
    ready_head: usize = none,
    ready_tail: usize = none,
    buckets: [level_count][slots_per_level]Bucket = emptyBuckets(),
    nodes: std.ArrayList(Node) = .empty,

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn initAt(allocator: std.mem.Allocator, now_ms: u64) Self {
        return .{
            .allocator = allocator,
            .now_ms = now_ms,
            .cursor_ms = nextTick(now_ms),
        };
    }

    pub fn deinit(self: *Self) void {
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const Self) usize {
        return self.active_count;
    }

    pub fn schedule(self: *Self, deadline_ms: u64, id: u64) !TimerHandle {
        if (deadline_ms < self.now_ms) return error.DeadlineInPast;

        const index = try self.acquireNode();
        const generation = self.nodes.items[index].generation;
        self.nodes.items[index] = .{
            .id = id,
            .deadline_ms = deadline_ms,
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

    pub fn advance(self: *Self, now_ms: u64) ![]u64 {
        if (now_ms < self.now_ms) return error.TimeWentBackwards;
        self.now_ms = now_ms;

        var expired: std.ArrayList(u64) = .empty;
        errdefer expired.deinit(self.allocator);

        try self.drainReady(&expired);
        if (self.active_count == 0 and self.ready_head == none) {
            self.cursor_ms = nextTick(now_ms);
            return expired.toOwnedSlice(self.allocator);
        }

        while (self.cursor_ms <= now_ms) {
            self.cascade(self.cursor_ms);
            self.collectCurrentSlot();
            if (self.cursor_ms == std.math.maxInt(u64)) break;
            self.cursor_ms += 1;

            try self.drainReady(&expired);
            if (self.active_count == 0 and self.ready_head == none) {
                self.cursor_ms = nextTick(now_ms);
                break;
            }
        }

        return expired.toOwnedSlice(self.allocator);
    }

    fn acquireNode(self: *Self) !usize {
        if (self.free_head != none) {
            const index = self.free_head;
            self.free_head = self.nodes.items[index].next;
            self.nodes.items[index].prev = none;
            self.nodes.items[index].next = none;
            return index;
        }

        if (self.nodes.items.len > std.math.maxInt(u32)) return error.TimerFull;
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
        const deadline = self.nodes.items[index].deadline_ms;
        const diff = if (deadline > self.cursor_ms) deadline - self.cursor_ms else 0;
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

    fn drainReady(self: *Self, expired: *std.ArrayList(u64)) !void {
        while (self.ready_head != none) {
            const index = self.ready_head;
            try expired.append(self.allocator, self.nodes.items[index].id);
            self.unlink(index);
            self.release(index);
        }
    }

    fn cascade(self: *Self, tick: u64) void {
        var level: usize = 1;
        while (level < level_count) : (level += 1) {
            if ((tick & lowerLevelMask(level)) != 0) break;
            self.moveBucket(level, slotFor(level, tick));
        }
    }

    fn moveBucket(self: *Self, level: usize, slot: usize) void {
        var index = self.buckets[level][slot].head;
        self.buckets[level][slot] = .{};

        while (index != none) {
            const next = self.nodes.items[index].next;
            self.nodes.items[index].prev = none;
            self.nodes.items[index].next = none;
            self.scheduleNode(index);
            index = next;
        }
    }

    fn collectCurrentSlot(self: *Self) void {
        const slot = slotFor(0, self.cursor_ms);
        var index = self.buckets[0][slot].head;
        self.buckets[0][slot] = .{};

        while (index != none) {
            const next = self.nodes.items[index].next;
            self.nodes.items[index].prev = none;
            self.nodes.items[index].next = none;
            if (self.nodes.items[index].deadline_ms <= self.cursor_ms) {
                self.insertReady(index);
            } else {
                self.scheduleNode(index);
            }
            index = next;
        }
    }

    fn unlink(self: *Self, index: usize) void {
        const node = self.nodes.items[index];
        if (node.level == ready_level) {
            if (node.prev == none) {
                self.ready_head = node.next;
            } else {
                self.nodes.items[node.prev].next = node.next;
            }
            if (node.next == none) {
                self.ready_tail = node.prev;
            } else {
                self.nodes.items[node.next].prev = node.prev;
            }
        } else {
            const level: usize = node.level;
            const slot: usize = node.slot;
            if (node.prev == none) {
                self.buckets[level][slot].head = node.next;
            } else {
                self.nodes.items[node.prev].next = node.next;
            }
            if (node.next == none) {
                self.buckets[level][slot].tail = node.prev;
            } else {
                self.nodes.items[node.next].prev = node.prev;
            }
        }

        self.nodes.items[index].prev = none;
        self.nodes.items[index].next = none;
    }

    fn release(self: *Self, index: usize) void {
        var next_generation = self.nodes.items[index].generation +% 1;
        if (next_generation == 0) next_generation = 1;

        self.nodes.items[index] = .{
            .generation = next_generation,
            .next = self.free_head,
        };
        self.free_head = index;
        self.active_count -= 1;
    }
};

fn emptyBuckets() [TimingWheel.level_count][TimingWheel.slots_per_level]TimingWheel.Bucket {
    return [_][TimingWheel.slots_per_level]TimingWheel.Bucket{
        [_]TimingWheel.Bucket{.{}} ** TimingWheel.slots_per_level,
    } ** TimingWheel.level_count;
}

fn levelForDiff(diff: u64) usize {
    var level: usize = 0;
    var threshold: u64 = TimingWheel.slots_per_level;
    while (level + 1 < TimingWheel.level_count and diff >= threshold) {
        level += 1;
        if (threshold > (std.math.maxInt(u64) >> TimingWheel.slot_bits)) {
            threshold = std.math.maxInt(u64);
        } else {
            threshold <<= TimingWheel.slot_bits;
        }
    }
    return level;
}

fn slotFor(level: usize, tick: u64) usize {
    const shift: u6 = @intCast(level * TimingWheel.slot_bits);
    return @intCast((tick >> shift) & TimingWheel.slot_mask);
}

fn lowerLevelMask(level: usize) u64 {
    const bits: u6 = @intCast(level * TimingWheel.slot_bits);
    return (@as(u64, 1) << bits) - 1;
}

fn dueBefore(a: TimingWheel.Node, b: TimingWheel.Node) bool {
    if (a.deadline_ms != b.deadline_ms) return a.deadline_ms < b.deadline_ms;
    return a.seq < b.seq;
}

fn nextTick(tick: u64) u64 {
    if (tick == std.math.maxInt(u64)) return tick;
    return tick + 1;
}

fn expectExpired(expected: []const u64, actual: []const u64) !void {
    try std.testing.expectEqualSlices(u64, expected, actual);
}

test "timers fire at or after deadline in deadline order" {
    var wheel = TimingWheel.init(std.testing.allocator);
    defer wheel.deinit();

    _ = try wheel.schedule(30, 300);
    _ = try wheel.schedule(10, 100);
    _ = try wheel.schedule(20, 200);
    _ = try wheel.schedule(10, 101);

    const before = try wheel.advance(9);
    defer std.testing.allocator.free(before);
    try expectExpired(&.{}, before);
    try std.testing.expectEqual(@as(usize, 4), wheel.count());

    const first = try wheel.advance(10);
    defer std.testing.allocator.free(first);
    try expectExpired(&.{ 100, 101 }, first);
    try std.testing.expectEqual(@as(usize, 2), wheel.count());

    const rest = try wheel.advance(30);
    defer std.testing.allocator.free(rest);
    try expectExpired(&.{ 200, 300 }, rest);
    try std.testing.expectEqual(@as(usize, 0), wheel.count());
}

test "cancel prevents firing and stale handles are rejected" {
    var wheel = TimingWheel.init(std.testing.allocator);
    defer wheel.deinit();

    const keep = try wheel.schedule(15, 1);
    const drop = try wheel.schedule(10, 2);
    try wheel.cancel(drop);
    try std.testing.expectError(error.StaleHandle, wheel.cancel(drop));

    const expired = try wheel.advance(20);
    defer std.testing.allocator.free(expired);
    try expectExpired(&.{1}, expired);
    try std.testing.expectError(error.StaleHandle, wheel.cancel(keep));
    try std.testing.expectEqual(@as(usize, 0), wheel.count());
}

test "multi-level cascade fires far future timers" {
    var wheel = TimingWheel.init(std.testing.allocator);
    defer wheel.deinit();

    _ = try wheel.schedule(65_536, 1);
    _ = try wheel.schedule(70_000, 2);
    _ = try wheel.schedule(1_000_003, 3);

    const none_yet = try wheel.advance(65_535);
    defer std.testing.allocator.free(none_yet);
    try expectExpired(&.{}, none_yet);

    const first = try wheel.advance(65_536);
    defer std.testing.allocator.free(first);
    try expectExpired(&.{1}, first);

    const second = try wheel.advance(70_000);
    defer std.testing.allocator.free(second);
    try expectExpired(&.{2}, second);

    const third = try wheel.advance(1_000_003);
    defer std.testing.allocator.free(third);
    try expectExpired(&.{3}, third);
}

test "advancing past many ticks expires every due timer correctly" {
    var wheel = TimingWheel.init(std.testing.allocator);
    defer wheel.deinit();

    var expected: std.ArrayList(u64) = .empty;
    defer expected.deinit(std.testing.allocator);

    var i: u64 = 0;
    while (i < 80) : (i += 1) {
        const deadline = 5 + i * 257;
        const id = 10_000 + i;
        _ = try wheel.schedule(deadline, id);
        try expected.append(std.testing.allocator, id);
    }

    const expired = try wheel.advance(25_000);
    defer std.testing.allocator.free(expired);
    try expectExpired(expected.items, expired);
    try std.testing.expectEqual(@as(usize, 0), wheel.count());
}

test "deterministic ordering across identical operation streams" {
    var a = TimingWheel.init(std.testing.allocator);
    defer a.deinit();
    var b = TimingWheel.init(std.testing.allocator);
    defer b.deinit();

    const ha0 = try a.schedule(300, 30);
    const hb0 = try b.schedule(300, 30);
    _ = try a.schedule(1, 1);
    _ = try b.schedule(1, 1);
    _ = try a.schedule(300, 31);
    _ = try b.schedule(300, 31);
    _ = try a.schedule(65_537, 65);
    _ = try b.schedule(65_537, 65);
    try a.cancel(ha0);
    try b.cancel(hb0);
    _ = try a.schedule(2, 2);
    _ = try b.schedule(2, 2);

    const ea = try a.advance(100_000);
    defer std.testing.allocator.free(ea);
    const eb = try b.advance(100_000);
    defer std.testing.allocator.free(eb);

    try expectExpired(&.{ 1, 2, 31, 65 }, ea);
    try expectExpired(ea, eb);
}

test "cannot schedule in the past or move time backwards" {
    var wheel = TimingWheel.initAt(std.testing.allocator, 50);
    defer wheel.deinit();

    try std.testing.expectError(error.DeadlineInPast, wheel.schedule(49, 1));
    _ = try wheel.schedule(50, 2);
    _ = try wheel.schedule(51, 3);

    const due = try wheel.advance(50);
    defer std.testing.allocator.free(due);
    try expectExpired(&.{2}, due);

    const still_pending = try wheel.advance(50);
    defer std.testing.allocator.free(still_pending);
    try expectExpired(&.{}, still_pending);

    const next = try wheel.advance(51);
    defer std.testing.allocator.free(next);
    try expectExpired(&.{3}, next);

    try std.testing.expectError(error.TimeWentBackwards, wheel.advance(49));
}
