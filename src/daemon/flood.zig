//! Per-client flood and rate control.
//!
//! The hot path is pure state transition logic: callers pass monotonic time in
//! milliseconds, and this module never reads a clock or allocates. Token bucket
//! capacities and refill rates are comptime parameters so deployments can tune
//! limits without paying for dynamic policy lookups on every command.
const std = @import("std");

/// Token bucket policy: `refill_tokens` are restored every
/// `refill_period_ms`. Partial refill credit is carried deterministically.
pub const BucketParams = struct {
    capacity: u64,
    refill_tokens: u64,
    refill_period_ms: u64,
};

/// Excess-flood penalty policy. Accumulated points decay at the configured
/// rate, and reaching `threshold` signals that the client should disconnect.
pub const ExcessParams = struct {
    threshold: u64,
    decay_points: u64,
    decay_period_ms: u64,
};

/// Combined per-client policy for normal messages, bytes, JOINs, and excess
/// flood penalties.
pub const ClientFloodParams = struct {
    messages: BucketParams,
    bytes: BucketParams,
    joins: BucketParams,
    excess: ExcessParams,
    throttle_penalty: u64 = 1,
};

/// Result of a rate-control observation.
pub const FloodDecision = enum {
    allow,
    throttle,
    disconnect,
};

/// Generic deterministic token bucket.
pub fn TokenBucket(comptime params: BucketParams) type {
    comptime validateBucketParams(params);

    return struct {
        const Self = @This();

        tokens: u64 = params.capacity,
        last_ms: i64 = 0,
        carry: u64 = 0,

        /// Start full at the caller-provided timestamp.
        pub fn init(now_ms: i64) Self {
            return .{
                .tokens = params.capacity,
                .last_ms = now_ms,
                .carry = 0,
            };
        }

        /// Current whole-token balance. Call `refill` first for a fresh view.
        pub fn available(self: *const Self) u64 {
            return self.tokens;
        }

        /// Refill from elapsed caller-provided time. Backward time does not
        /// move the bucket backward or grant credit.
        pub fn refill(self: *Self, now_ms: i64) void {
            const elapsed_ms = elapsedMillis(self.last_ms, now_ms);
            if (elapsed_ms == 0) return;
            self.last_ms = now_ms;

            if (params.refill_tokens == 0) return;
            if (self.tokens >= params.capacity) {
                self.carry = 0;
                return;
            }

            const units = @as(u128, elapsed_ms) * @as(u128, params.refill_tokens) +
                @as(u128, self.carry);
            const add = units / @as(u128, params.refill_period_ms);

            if (add == 0) {
                self.carry = @intCast(units);
                return;
            }

            const room = params.capacity - self.tokens;
            if (add >= room) {
                self.tokens = params.capacity;
                self.carry = 0;
                return;
            }

            self.tokens += @intCast(add);
            self.carry = @intCast(units % @as(u128, params.refill_period_ms));
        }

        /// Attempt to spend tokens after first applying deterministic refill.
        pub fn tryConsume(self: *Self, now_ms: i64, cost: u64) bool {
            self.refill(now_ms);
            if (cost == 0) return true;
            if (cost > self.tokens) return false;
            self.tokens -= cost;
            return true;
        }
    };
}

/// Leaky excess-flood accumulator.
pub fn ExcessAccumulator(comptime params: ExcessParams) type {
    comptime validateExcessParams(params);

    return struct {
        const Self = @This();

        points: u64 = 0,
        last_ms: i64 = 0,
        carry: u64 = 0,

        /// Start empty at the caller-provided timestamp.
        pub fn init(now_ms: i64) Self {
            return .{ .points = 0, .last_ms = now_ms, .carry = 0 };
        }

        /// Current penalty points. Call `decay` first for a fresh view.
        pub fn current(self: *const Self) u64 {
            return self.points;
        }

        /// Apply deterministic penalty decay.
        pub fn decay(self: *Self, now_ms: i64) void {
            const elapsed_ms = elapsedMillis(self.last_ms, now_ms);
            if (elapsed_ms == 0) return;
            self.last_ms = now_ms;

            if (params.decay_points == 0 or self.points == 0) {
                self.carry = 0;
                return;
            }

            const units = @as(u128, elapsed_ms) * @as(u128, params.decay_points) +
                @as(u128, self.carry);
            const remove = units / @as(u128, params.decay_period_ms);

            if (remove == 0) {
                self.carry = @intCast(units);
                return;
            }

            if (remove >= self.points) {
                self.points = 0;
                self.carry = 0;
                return;
            }

            self.points -= @intCast(remove);
            self.carry = @intCast(units % @as(u128, params.decay_period_ms));
        }

        /// Add excess-flood points and report whether the disconnect threshold
        /// has been reached.
        pub fn add(self: *Self, now_ms: i64, points: u64) FloodDecision {
            self.decay(now_ms);
            self.points = saturatingAdd(self.points, points);
            if (self.points >= params.threshold) return .disconnect;
            return .throttle;
        }

        /// Report whether the current accumulated penalty requires disconnect.
        pub fn tripped(self: *const Self) bool {
            return self.points >= params.threshold;
        }
    };
}

/// Per-client flood controller composed from message, byte, and JOIN buckets.
pub fn ClientFlood(comptime params: ClientFloodParams) type {
    comptime validateClientParams(params);

    return struct {
        const Self = @This();
        const MessageBucket = TokenBucket(params.messages);
        const ByteBucket = TokenBucket(params.bytes);
        const JoinBucket = TokenBucket(params.joins);
        const Excess = ExcessAccumulator(params.excess);

        message_rate: MessageBucket,
        byte_rate: ByteBucket,
        join_rate: JoinBucket,
        excess_flood: Excess,

        /// Start all limiters at the same caller-provided timestamp.
        pub fn init(now_ms: i64) Self {
            return .{
                .message_rate = MessageBucket.init(now_ms),
                .byte_rate = ByteBucket.init(now_ms),
                .join_rate = JoinBucket.init(now_ms),
                .excess_flood = Excess.init(now_ms),
            };
        }

        /// Observe a normal client message with its byte cost.
        pub fn recordMessage(self: *Self, now_ms: i64, byte_count: u64) FloodDecision {
            const message_ok = self.message_rate.tryConsume(now_ms, 1);
            const bytes_ok = self.byte_rate.tryConsume(now_ms, byte_count);
            return self.finishObservation(now_ms, message_ok and bytes_ok);
        }

        /// Observe a JOIN. JOINs count against message, byte, and JOIN limits.
        pub fn recordJoin(self: *Self, now_ms: i64, byte_count: u64) FloodDecision {
            const message_ok = self.message_rate.tryConsume(now_ms, 1);
            const bytes_ok = self.byte_rate.tryConsume(now_ms, byte_count);
            const join_ok = self.join_rate.tryConsume(now_ms, 1);
            return self.finishObservation(now_ms, message_ok and bytes_ok and join_ok);
        }

        /// Apply passive decay without observing a command.
        pub fn decayExcess(self: *Self, now_ms: i64) void {
            self.excess_flood.decay(now_ms);
        }

        fn finishObservation(self: *Self, now_ms: i64, allowed: bool) FloodDecision {
            if (allowed) {
                self.excess_flood.decay(now_ms);
                if (self.excess_flood.tripped()) return .disconnect;
                return .allow;
            }
            return self.excess_flood.add(now_ms, params.throttle_penalty);
        }
    };
}

fn validateBucketParams(comptime params: BucketParams) void {
    if (params.capacity == 0) @compileError("bucket capacity must be non-zero");
    if (params.refill_tokens != 0 and params.refill_period_ms == 0) {
        @compileError("bucket refill period must be non-zero when refill is enabled");
    }
}

fn validateExcessParams(comptime params: ExcessParams) void {
    if (params.threshold == 0) @compileError("excess threshold must be non-zero");
    if (params.decay_points != 0 and params.decay_period_ms == 0) {
        @compileError("excess decay period must be non-zero when decay is enabled");
    }
}

fn validateClientParams(comptime params: ClientFloodParams) void {
    validateBucketParams(params.messages);
    validateBucketParams(params.bytes);
    validateBucketParams(params.joins);
    validateExcessParams(params.excess);
    if (params.throttle_penalty == 0) @compileError("throttle penalty must be non-zero");
}

fn elapsedMillis(last_ms: i64, now_ms: i64) u64 {
    const delta = @as(i128, now_ms) - @as(i128, last_ms);
    if (delta <= 0) return 0;
    if (delta > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(delta);
}

fn saturatingAdd(a: u64, b: u64) u64 {
    const max = std.math.maxInt(u64);
    if (max - a < b) return max;
    return a + b;
}

test "bucket allows up to capacity then throttles" {
    const Bucket = TokenBucket(.{ .capacity = 3, .refill_tokens = 1, .refill_period_ms = 1000 });
    var bucket = Bucket.init(0);

    try std.testing.expect(bucket.tryConsume(0, 1));
    try std.testing.expect(bucket.tryConsume(0, 1));
    try std.testing.expect(bucket.tryConsume(0, 1));
    try std.testing.expect(!bucket.tryConsume(0, 1));
    try std.testing.expectEqual(@as(u64, 0), bucket.available());
}

test "bucket refills over time with deterministic carry" {
    const Bucket = TokenBucket(.{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 });
    var bucket = Bucket.init(0);

    try std.testing.expect(bucket.tryConsume(0, 2));
    try std.testing.expect(!bucket.tryConsume(999, 1));
    try std.testing.expect(bucket.tryConsume(1000, 1));
    try std.testing.expect(!bucket.tryConsume(1000, 1));
    try std.testing.expect(bucket.tryConsume(2000, 1));
}

test "excess-flood threshold trips and decay can recover below threshold" {
    const Excess = ExcessAccumulator(.{
        .threshold = 3,
        .decay_points = 1,
        .decay_period_ms = 1000,
    });
    var excess = Excess.init(0);

    try std.testing.expectEqual(FloodDecision.throttle, excess.add(0, 1));
    try std.testing.expectEqual(FloodDecision.throttle, excess.add(0, 1));
    try std.testing.expectEqual(FloodDecision.disconnect, excess.add(0, 1));
    try std.testing.expect(excess.tripped());

    excess.decay(1000);
    try std.testing.expect(!excess.tripped());
    try std.testing.expectEqual(@as(u64, 2), excess.current());
}

test "large elapsed time and penalties saturate without overflow" {
    const Bucket = TokenBucket(.{
        .capacity = 5,
        .refill_tokens = std.math.maxInt(u64),
        .refill_period_ms = 1,
    });
    var bucket = Bucket.init(std.math.minInt(i64));
    try std.testing.expect(bucket.tryConsume(std.math.minInt(i64), 5));

    bucket.refill(std.math.maxInt(i64));
    try std.testing.expectEqual(@as(u64, 5), bucket.available());

    const Excess = ExcessAccumulator(.{
        .threshold = 10,
        .decay_points = 0,
        .decay_period_ms = 0,
    });
    var excess = Excess.init(0);
    try std.testing.expectEqual(FloodDecision.disconnect, excess.add(0, std.math.maxInt(u64)));
    try std.testing.expectEqual(std.math.maxInt(u64), excess.current());
}

test "client flood control is deterministic for fixed time inputs" {
    const Flood = ClientFlood(.{
        .messages = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 },
        .bytes = .{ .capacity = 10, .refill_tokens = 5, .refill_period_ms = 1000 },
        .joins = .{ .capacity = 1, .refill_tokens = 1, .refill_period_ms = 5000 },
        .excess = .{ .threshold = 4, .decay_points = 1, .decay_period_ms = 2000 },
        .throttle_penalty = 2,
    });

    var a = Flood.init(100);
    var b = Flood.init(100);

    const decisions_a = [_]FloodDecision{
        a.recordMessage(100, 4),
        a.recordJoin(100, 4),
        a.recordMessage(100, 4),
        a.recordJoin(1100, 2),
        a.recordMessage(3100, 2),
    };
    const decisions_b = [_]FloodDecision{
        b.recordMessage(100, 4),
        b.recordJoin(100, 4),
        b.recordMessage(100, 4),
        b.recordJoin(1100, 2),
        b.recordMessage(3100, 2),
    };

    try std.testing.expectEqualSlices(FloodDecision, decisions_a[0..], decisions_b[0..]);
    try std.testing.expectEqual(a.message_rate.available(), b.message_rate.available());
    try std.testing.expectEqual(a.byte_rate.available(), b.byte_rate.available());
    try std.testing.expectEqual(a.join_rate.available(), b.join_rate.available());
    try std.testing.expectEqual(a.excess_flood.current(), b.excess_flood.current());
}
