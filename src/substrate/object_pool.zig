// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub fn ObjectPool(comptime T: type) type {
    return struct {
        const Self = @This();

        const Slot = union {
            value: T,
            next_free: ?usize,
        };

        pub const ReleaseError = error{
            DoubleFree,
            ForeignPointer,
            MisalignedPointer,
        };

        pub const AcquireError = error{
            PoolExhausted,
        };

        allocator: std.mem.Allocator,
        slots: []Slot,
        free_head: ?usize,
        free_count: usize,

        pub fn init(allocator: std.mem.Allocator, slot_count: usize) !Self {
            const slots = try allocator.alloc(Slot, slot_count);
            var self = Self{
                .allocator = allocator,
                .slots = slots,
                .free_head = null,
                .free_count = 0,
            };
            self.reset();
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.slots);
            self.* = undefined;
        }

        pub fn capacity(self: *const Self) usize {
            return self.slots.len;
        }

        pub fn available(self: *const Self) usize {
            return self.free_count;
        }

        pub fn inUse(self: *const Self) usize {
            return self.slots.len - self.free_count;
        }

        pub fn acquire(self: *Self) ?*T {
            const index = self.free_head orelse return null;
            self.free_head = self.slots[index].next_free;
            self.free_count -= 1;
            self.slots[index] = .{ .value = undefined };
            return &self.slots[index].value;
        }

        pub fn acquireOrAlloc(self: *Self) AcquireError!*T {
            return self.acquire() orelse error.PoolExhausted;
        }

        pub fn release(self: *Self, ptr: *T) void {
            self.releaseChecked(ptr) catch |err| {
                std.debug.panic("object pool release failed: {s}", .{@errorName(err)});
            };
        }

        pub fn releaseChecked(self: *Self, ptr: *T) ReleaseError!void {
            const index = try self.indexOf(ptr);
            if (self.freeListContains(index)) return error.DoubleFree;

            self.slots[index] = .{ .next_free = self.free_head };
            self.free_head = index;
            self.free_count += 1;
        }

        pub fn reset(self: *Self) void {
            for (self.slots, 0..) |*slot, index| {
                slot.* = .{
                    .next_free = if (index + 1 < self.slots.len) index + 1 else null,
                };
            }
            self.free_head = if (self.slots.len == 0) null else 0;
            self.free_count = self.slots.len;
        }

        fn indexOf(self: *const Self, ptr: *const T) ReleaseError!usize {
            if (self.slots.len == 0) return error.ForeignPointer;

            const stride = @sizeOf(Slot);
            const base = @intFromPtr(self.slots.ptr);
            const addr = @intFromPtr(ptr);
            if (addr < base) return error.ForeignPointer;
            if (addr >= base + stride * self.slots.len) return error.ForeignPointer;

            const offset = addr - base;
            if (offset % stride != 0) return error.MisalignedPointer;

            const index = offset / stride;
            if (index >= self.slots.len) return error.ForeignPointer;
            return index;
        }

        fn freeListContains(self: *const Self, needle: usize) bool {
            var cursor = self.free_head;
            var visited: usize = 0;
            while (cursor) |index| {
                std.debug.assert(index < self.slots.len);
                if (index == needle) return true;
                visited += 1;
                std.debug.assert(visited <= self.slots.len);
                cursor = self.slots[index].next_free;
            }
            return false;
        }
    };
}

test "acquire up to capacity then exhaustion" {
    const testing = std.testing;
    var pool = try ObjectPool(u64).init(testing.allocator, 4);
    defer pool.deinit();

    try testing.expectEqual(@as(usize, 4), pool.capacity());
    try testing.expectEqual(@as(usize, 4), pool.available());
    try testing.expectEqual(@as(usize, 0), pool.inUse());

    const a = pool.acquire() orelse return error.UnexpectedNull;
    const b = pool.acquire() orelse return error.UnexpectedNull;
    const c = pool.acquire() orelse return error.UnexpectedNull;
    const d = pool.acquire() orelse return error.UnexpectedNull;

    a.* = 10;
    b.* = 20;
    c.* = 30;
    d.* = 40;

    try testing.expect(pool.acquire() == null);
    try testing.expectError(error.PoolExhausted, pool.acquireOrAlloc());
    try testing.expectEqual(@as(usize, 0), pool.available());
    try testing.expectEqual(@as(usize, 4), pool.inUse());
    try testing.expectEqual(@as(u64, 10), a.*);
    try testing.expectEqual(@as(u64, 20), b.*);
    try testing.expectEqual(@as(u64, 30), c.*);
    try testing.expectEqual(@as(u64, 40), d.*);
}

test "release returns slot for reuse" {
    const testing = std.testing;
    var pool = try ObjectPool(u32).init(testing.allocator, 2);
    defer pool.deinit();

    const first = pool.acquire() orelse return error.UnexpectedNull;
    const second = pool.acquire() orelse return error.UnexpectedNull;
    first.* = 111;
    second.* = 222;

    pool.release(first);
    try testing.expectEqual(@as(usize, 1), pool.available());

    const reused = pool.acquire() orelse return error.UnexpectedNull;
    try testing.expect(reused == first);
    try testing.expectEqual(@as(usize, 0), pool.available());
    try testing.expectEqual(@as(u32, 222), second.*);
}

test "pointers stay stable across acquire release cycles" {
    const testing = std.testing;
    var pool = try ObjectPool(u8).init(testing.allocator, 1);
    defer pool.deinit();

    const original = pool.acquire() orelse return error.UnexpectedNull;
    original.* = 7;
    pool.release(original);

    var cycle: usize = 0;
    while (cycle < 32) : (cycle += 1) {
        const ptr = pool.acquire() orelse return error.UnexpectedNull;
        try testing.expect(ptr == original);
        ptr.* = @intCast(cycle);
        pool.release(ptr);
    }
}

test "double free and foreign pointer are detected by checked release" {
    const testing = std.testing;
    var pool = try ObjectPool(usize).init(testing.allocator, 1);
    defer pool.deinit();

    const ptr = pool.acquire() orelse return error.UnexpectedNull;
    try pool.releaseChecked(ptr);
    try testing.expectError(error.DoubleFree, pool.releaseChecked(ptr));

    var outside: usize = 0;
    try testing.expectError(error.ForeignPointer, pool.releaseChecked(&outside));
}

test "reset reclaims every slot" {
    const testing = std.testing;
    var pool = try ObjectPool(i32).init(testing.allocator, 3);
    defer pool.deinit();

    const a = pool.acquire() orelse return error.UnexpectedNull;
    const b = pool.acquire() orelse return error.UnexpectedNull;
    const c = pool.acquire() orelse return error.UnexpectedNull;
    a.* = 1;
    b.* = 2;
    c.* = 3;
    try testing.expect(pool.acquire() == null);

    pool.release(b);
    try testing.expectEqual(@as(usize, 1), pool.available());
    pool.reset();

    try testing.expectEqual(@as(usize, 3), pool.available());
    try testing.expectEqual(@as(usize, 0), pool.inUse());

    const first = pool.acquire() orelse return error.UnexpectedNull;
    const second = pool.acquire() orelse return error.UnexpectedNull;
    const third = pool.acquire() orelse return error.UnexpectedNull;

    try testing.expect(first == a);
    try testing.expect(second == b);
    try testing.expect(third == c);
    try testing.expect(pool.acquire() == null);
}

test "freelist order is deterministic and lifo after release" {
    const testing = std.testing;
    var pool = try ObjectPool(u16).init(testing.allocator, 3);
    defer pool.deinit();

    const a = pool.acquire() orelse return error.UnexpectedNull;
    const b = pool.acquire() orelse return error.UnexpectedNull;
    const c = pool.acquire() orelse return error.UnexpectedNull;
    try testing.expect(pool.acquire() == null);

    pool.release(b);
    pool.release(a);

    try testing.expect((pool.acquire() orelse return error.UnexpectedNull) == a);
    try testing.expect((pool.acquire() orelse return error.UnexpectedNull) == b);
    try testing.expect(pool.acquire() == null);

    pool.release(c);
    pool.reset();

    try testing.expect((pool.acquire() orelse return error.UnexpectedNull) == a);
    try testing.expect((pool.acquire() orelse return error.UnexpectedNull) == b);
    try testing.expect((pool.acquire() orelse return error.UnexpectedNull) == c);
}

test "zero capacity pool is deterministic and always exhausted" {
    const testing = std.testing;
    var pool = try ObjectPool(u8).init(testing.allocator, 0);
    defer pool.deinit();

    try testing.expectEqual(@as(usize, 0), pool.capacity());
    try testing.expectEqual(@as(usize, 0), pool.available());
    try testing.expect(pool.acquire() == null);

    pool.reset();
    try testing.expect(pool.acquire() == null);
    try testing.expectError(error.PoolExhausted, pool.acquireOrAlloc());
}
