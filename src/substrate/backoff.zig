// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const testing = std.testing;

pub const Delay = u64;
pub const Attempt = u32;

pub const Jitter = enum {
    none,
    full,
    equal,
    decorrelated,
};

pub const Policy = struct {
    base: Delay,
    factor: Delay = 2,
    max: Delay,
    jitter: Jitter = .none,
};

pub const Limits = struct {
    max_attempts: ?Attempt = null,
    deadline: ?Delay = null,
};

pub const Retrier = struct {
    policy: Policy,
    limits: Limits = .{},
    attempt_count: Attempt = 0,
    elapsed: Delay = 0,
    previous_delay: Delay = 0,

    pub fn init(policy: Policy, limits: Limits) Retrier {
        return .{
            .policy = policy,
            .limits = limits,
        };
    }

    pub fn reset(self: *Retrier) void {
        self.attempt_count = 0;
        self.elapsed = 0;
        self.previous_delay = 0;
    }

    pub fn next(self: *Retrier, random: std.Random) ?Delay {
        if (self.limits.max_attempts) |max_attempts| {
            if (self.attempt_count >= max_attempts) return null;
        }

        const remaining = if (self.limits.deadline) |deadline| blk: {
            if (self.elapsed >= deadline) return null;
            break :blk deadline - self.elapsed;
        } else null;

        var delay = switch (self.policy.jitter) {
            .none => exponential(
                self.policy.base,
                self.policy.factor,
                self.policy.max,
                self.attempt_count,
            ),
            .full => fullJitter(
                random,
                self.policy.base,
                self.policy.factor,
                self.policy.max,
                self.attempt_count,
            ),
            .equal => equalJitter(
                random,
                self.policy.base,
                self.policy.factor,
                self.policy.max,
                self.attempt_count,
            ),
            .decorrelated => decorrelatedJitter(
                random,
                self.policy.base,
                self.policy.max,
                if (self.previous_delay == 0) self.policy.base else self.previous_delay,
            ),
        };

        if (remaining) |available| {
            delay = @min(delay, available);
        }

        self.attempt_count += 1;
        self.elapsed = saturatingAdd(self.elapsed, delay);
        self.previous_delay = delay;
        return delay;
    }
};

pub fn exponential(base: Delay, factor: Delay, max: Delay, attempt: Attempt) Delay {
    if (attempt == 0) return base;

    var delay = base;
    var i: Attempt = 0;
    while (i < attempt) : (i += 1) {
        delay = saturatingMul(delay, factor);
        if (delay >= max) return max;
    }
    return @min(delay, max);
}

pub fn fullJitter(
    random: std.Random,
    base: Delay,
    factor: Delay,
    max: Delay,
    attempt: Attempt,
) Delay {
    const cap = exponential(base, factor, max, attempt);
    return randomAtMost(random, cap);
}

pub fn equalJitter(
    random: std.Random,
    base: Delay,
    factor: Delay,
    max: Delay,
    attempt: Attempt,
) Delay {
    const cap = exponential(base, factor, max, attempt);
    const half = cap / 2;
    return half + randomAtMost(random, cap - half);
}

pub fn decorrelatedJitter(
    random: std.Random,
    base: Delay,
    max: Delay,
    previous_delay: Delay,
) Delay {
    const previous = @max(previous_delay, base);
    const upper = @min(max, saturatingMul(previous, 3));
    if (upper <= base) return upper;
    return random.intRangeAtMost(Delay, base, upper);
}

fn randomAtMost(random: std.Random, cap: Delay) Delay {
    if (cap == 0) return 0;
    return random.intRangeAtMost(Delay, 0, cap);
}

fn saturatingAdd(a: Delay, b: Delay) Delay {
    if (std.math.maxInt(Delay) - a < b) return std.math.maxInt(Delay);
    return a + b;
}

fn saturatingMul(a: Delay, b: Delay) Delay {
    if (a == 0 or b == 0) return 0;
    if (a > std.math.maxInt(Delay) / b) return std.math.maxInt(Delay);
    return a * b;
}

test "exponential growth is capped at max and attempt zero is base" {
    try testing.expectEqual(@as(Delay, 10), exponential(10, 2, 70, 0));
    try testing.expectEqual(@as(Delay, 20), exponential(10, 2, 70, 1));
    try testing.expectEqual(@as(Delay, 40), exponential(10, 2, 70, 2));
    try testing.expectEqual(@as(Delay, 70), exponential(10, 2, 70, 3));
    try testing.expectEqual(@as(Delay, 70), exponential(10, 2, 70, 10));
}

test "exponential handles zero and saturating factors" {
    try testing.expectEqual(@as(Delay, 0), exponential(0, 2, 100, 0));
    try testing.expectEqual(@as(Delay, 0), exponential(0, 2, 100, 3));
    try testing.expectEqual(@as(Delay, 5), exponential(5, 1, 100, 8));
    try testing.expectEqual(@as(Delay, 100), exponential(5, std.math.maxInt(Delay), 100, 2));
}

test "full jitter stays in inclusive zero to exponential cap range" {
    var prng = std.Random.DefaultPrng.init(0x1111);
    const random = prng.random();

    var attempt: Attempt = 0;
    while (attempt < 8) : (attempt += 1) {
        const cap = exponential(10, 2, 100, attempt);
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const delay = fullJitter(random, 10, 2, 100, attempt);
            try testing.expect(delay <= cap);
        }
    }
}

test "equal jitter stays in upper half of exponential cap range" {
    var prng = std.Random.DefaultPrng.init(0x2222);
    const random = prng.random();

    var attempt: Attempt = 0;
    while (attempt < 8) : (attempt += 1) {
        const cap = exponential(10, 2, 100, attempt);
        const floor = cap / 2;
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const delay = equalJitter(random, 10, 2, 100, attempt);
            try testing.expect(delay >= floor);
            try testing.expect(delay <= cap);
        }
    }
}

test "decorrelated jitter stays between base and three times previous capped at max" {
    var prng = std.Random.DefaultPrng.init(0x3333);
    const random = prng.random();

    var previous: Delay = 10;
    var i: usize = 0;
    while (i < 128) : (i += 1) {
        const upper = @min(@as(Delay, 100), saturatingMul(previous, 3));
        const delay = decorrelatedJitter(random, 10, 100, previous);
        try testing.expect(delay >= 10);
        try testing.expect(delay <= upper);
        previous = delay;
    }
}

test "jitter output is deterministic given the same seed" {
    const alloc = testing.allocator;
    const first = try alloc.alloc(Delay, 16);
    defer alloc.free(first);
    const second = try alloc.alloc(Delay, 16);
    defer alloc.free(second);

    var prng_a = std.Random.DefaultPrng.init(0x4444);
    var prng_b = std.Random.DefaultPrng.init(0x4444);
    const random_a = prng_a.random();
    const random_b = prng_b.random();

    for (first, 0..) |*slot, i| {
        slot.* = fullJitter(random_a, 10, 2, 1000, @intCast(i % 8));
    }
    for (second, 0..) |*slot, i| {
        slot.* = fullJitter(random_b, 10, 2, 1000, @intCast(i % 8));
    }

    try testing.expectEqualSlices(Delay, first, second);
}

test "retrier terminates at max attempts" {
    var prng = std.Random.DefaultPrng.init(0x5555);
    var retrier = Retrier.init(
        .{
            .base = 10,
            .factor = 2,
            .max = 100,
            .jitter = .none,
        },
        .{ .max_attempts = 3 },
    );

    try testing.expectEqual(@as(?Delay, 10), retrier.next(prng.random()));
    try testing.expectEqual(@as(?Delay, 20), retrier.next(prng.random()));
    try testing.expectEqual(@as(?Delay, 40), retrier.next(prng.random()));
    try testing.expectEqual(@as(?Delay, null), retrier.next(prng.random()));
    try testing.expectEqual(@as(Attempt, 3), retrier.attempt_count);
}

test "retrier caps returned delay by deadline budget" {
    var prng = std.Random.DefaultPrng.init(0x6666);
    var retrier = Retrier.init(
        .{
            .base = 10,
            .factor = 2,
            .max = 100,
            .jitter = .none,
        },
        .{ .deadline = 25 },
    );

    try testing.expectEqual(@as(?Delay, 10), retrier.next(prng.random()));
    try testing.expectEqual(@as(?Delay, 15), retrier.next(prng.random()));
    try testing.expectEqual(@as(?Delay, null), retrier.next(prng.random()));
    try testing.expectEqual(@as(Delay, 25), retrier.elapsed);
}

test "retrier decorrelated jitter is deterministic and tracks previous delay" {
    var prng_a = std.Random.DefaultPrng.init(0x7777);
    var prng_b = std.Random.DefaultPrng.init(0x7777);
    var retrier_a = Retrier.init(
        .{
            .base = 10,
            .factor = 2,
            .max = 100,
            .jitter = .decorrelated,
        },
        .{ .max_attempts = 5 },
    );
    var retrier_b = Retrier.init(
        .{
            .base = 10,
            .factor = 2,
            .max = 100,
            .jitter = .decorrelated,
        },
        .{ .max_attempts = 5 },
    );

    var previous: Delay = 10;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const delay_a = retrier_a.next(prng_a.random()).?;
        const delay_b = retrier_b.next(prng_b.random()).?;
        try testing.expectEqual(delay_a, delay_b);
        try testing.expect(delay_a >= 10);
        try testing.expect(delay_a <= @min(@as(Delay, 100), previous * 3));
        previous = delay_a;
    }
}
