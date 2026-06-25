// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded single-producer/single-consumer ring buffer.
//!
//! The buffer stores items inline, requires a non-zero power-of-two capacity,
//! and uses monotonically advancing head/tail indices. It deliberately avoids
//! atomics; callers that share it across threads must provide the appropriate
//! SPSC ownership and memory-ordering discipline around producer/consumer
//! access.
const std = @import("std");

pub fn isValidCapacity(comptime capacity: usize) bool {
    return capacity > 0 and std.math.isPowerOfTwo(capacity);
}

fn validateCapacity(comptime capacity: usize) void {
    comptime {
        if (!isValidCapacity(capacity)) {
            @compileError("RingBuffer capacity must be a non-zero power of two");
        }
    }
}

/// Inline bounded SPSC ring buffer.
///
/// `push` returns `false` when the buffer is full. `pop` and `peek` return
/// `null` when it is empty. The producer advances `tail`; the consumer advances
/// `head`.
pub fn RingBuffer(comptime T: type, comptime capacity: usize) type {
    validateCapacity(capacity);

    return struct {
        const Self = @This();
        const mask = capacity - 1;

        head: usize = 0,
        tail: usize = 0,
        items: [capacity]T = undefined,

        pub fn init() Self {
            return .{};
        }

        pub fn push(self: *Self, value: T) bool {
            if (self.isFull()) return false;

            self.items[self.tail & mask] = value;
            self.tail +%= 1;
            return true;
        }

        pub fn pop(self: *Self) ?T {
            if (self.isEmpty()) return null;

            const value = self.items[self.head & mask];
            self.head +%= 1;
            return value;
        }

        pub fn peek(self: *const Self) ?T {
            if (self.isEmpty()) return null;
            return self.items[self.head & mask];
        }

        pub fn len(self: *const Self) usize {
            return self.tail -% self.head;
        }

        pub fn isFull(self: *const Self) bool {
            return self.len() == capacity;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head == self.tail;
        }

        pub fn capacityValue(_: *const Self) usize {
            return capacity;
        }
    };
}

test "capacity validation accepts only non-zero powers of two" {
    try std.testing.expect(!isValidCapacity(0));
    try std.testing.expect(isValidCapacity(1));
    try std.testing.expect(isValidCapacity(2));
    try std.testing.expect(!isValidCapacity(3));
    try std.testing.expect(isValidCapacity(4));
    try std.testing.expect(!isValidCapacity(6));
    try std.testing.expect(isValidCapacity(1024));
}

test "fifo order is preserved" {
    var rb = RingBuffer(u32, 8).init();

    try std.testing.expect(rb.push(10));
    try std.testing.expect(rb.push(20));
    try std.testing.expect(rb.push(30));
    try std.testing.expectEqual(@as(usize, 3), rb.len());

    try std.testing.expectEqual(@as(?u32, 10), rb.pop());
    try std.testing.expectEqual(@as(?u32, 20), rb.pop());
    try std.testing.expectEqual(@as(?u32, 30), rb.pop());
    try std.testing.expectEqual(@as(?u32, null), rb.pop());
}

test "full and empty edges are reported correctly" {
    var rb = RingBuffer(usize, 4).init();

    try std.testing.expect(rb.isEmpty());
    try std.testing.expect(!rb.isFull());
    try std.testing.expectEqual(@as(usize, 0), rb.len());
    try std.testing.expectEqual(@as(?usize, null), rb.peek());
    try std.testing.expectEqual(@as(?usize, null), rb.pop());

    try std.testing.expect(rb.push(0));
    try std.testing.expect(rb.push(1));
    try std.testing.expect(rb.push(2));
    try std.testing.expect(rb.push(3));
    try std.testing.expect(rb.isFull());
    try std.testing.expect(!rb.isEmpty());
    try std.testing.expectEqual(@as(usize, 4), rb.len());
    try std.testing.expect(!rb.push(4));
    try std.testing.expectEqual(@as(?usize, 0), rb.peek());

    try std.testing.expectEqual(@as(?usize, 0), rb.pop());
    try std.testing.expect(!rb.isFull());
    try std.testing.expect(rb.push(4));
    try std.testing.expect(rb.isFull());

    for (1..5) |expected| {
        try std.testing.expectEqual(@as(?usize, expected), rb.pop());
    }
    try std.testing.expect(rb.isEmpty());
    try std.testing.expect(!rb.isFull());
    try std.testing.expectEqual(@as(usize, 0), rb.len());
}

test "peek observes front item without consuming it" {
    var rb = RingBuffer(u8, 2).init();

    try std.testing.expectEqual(@as(?u8, null), rb.peek());
    try std.testing.expect(rb.push(7));
    try std.testing.expect(rb.push(8));

    try std.testing.expectEqual(@as(?u8, 7), rb.peek());
    try std.testing.expectEqual(@as(?u8, 7), rb.peek());
    try std.testing.expectEqual(@as(usize, 2), rb.len());
    try std.testing.expectEqual(@as(?u8, 7), rb.pop());
    try std.testing.expectEqual(@as(?u8, 8), rb.peek());
    try std.testing.expectEqual(@as(?u8, 8), rb.pop());
    try std.testing.expectEqual(@as(?u8, null), rb.peek());
}

test "wraparound correctness after interleaved pushes and pops" {
    var rb = RingBuffer(usize, 4).init();

    for (0..4) |i| {
        try std.testing.expect(rb.push(i));
    }
    try std.testing.expect(rb.isFull());

    try std.testing.expectEqual(@as(?usize, 0), rb.pop());
    try std.testing.expectEqual(@as(?usize, 1), rb.pop());
    try std.testing.expectEqual(@as(usize, 2), rb.len());

    try std.testing.expect(rb.push(4));
    try std.testing.expect(rb.push(5));
    try std.testing.expect(rb.isFull());
    try std.testing.expect(!rb.push(6));

    for (2..6) |expected| {
        try std.testing.expectEqual(@as(?usize, expected), rb.pop());
    }
    try std.testing.expect(rb.isEmpty());
}

test "single-slot capacity alternates between full and empty" {
    var rb = RingBuffer(i32, 1).init();

    try std.testing.expect(rb.isEmpty());
    try std.testing.expect(rb.push(-4));
    try std.testing.expect(rb.isFull());
    try std.testing.expect(!rb.push(9));
    try std.testing.expectEqual(@as(?i32, -4), rb.peek());
    try std.testing.expectEqual(@as(?i32, -4), rb.pop());
    try std.testing.expect(rb.isEmpty());
    try std.testing.expectEqual(@as(?i32, null), rb.pop());
}

test "fill and drain cycles retain order and reset occupancy" {
    var rb = RingBuffer(u16, 8).init();

    for (0..32) |cycle| {
        for (0..8) |i| {
            const value: u16 = @intCast(cycle * 100 + i);
            try std.testing.expect(rb.push(value));
            try std.testing.expectEqual(i + 1, rb.len());
        }
        try std.testing.expect(rb.isFull());
        try std.testing.expect(!rb.push(9999));

        for (0..8) |i| {
            const expected: u16 = @intCast(cycle * 100 + i);
            try std.testing.expectEqual(@as(?u16, expected), rb.pop());
            try std.testing.expectEqual(7 - i, rb.len());
        }
        try std.testing.expect(rb.isEmpty());
        try std.testing.expectEqual(@as(?u16, null), rb.pop());
    }
}

test "large number of operations keeps bounded distance invariant" {
    var rb = RingBuffer(usize, 16).init();
    var next_push: usize = 0;
    var next_pop: usize = 0;

    while (next_pop < 512) {
        while (!rb.isFull() and next_push < 512) : (next_push += 1) {
            try std.testing.expect(rb.push(next_push));
            try std.testing.expect(rb.len() <= 16);
        }

        const value = rb.pop() orelse return error.UnexpectedEmpty;
        try std.testing.expectEqual(next_pop, value);
        next_pop += 1;
        try std.testing.expect(rb.len() <= 16);
    }

    try std.testing.expect(rb.isEmpty());
    try std.testing.expectEqual(next_push, next_pop);
}
