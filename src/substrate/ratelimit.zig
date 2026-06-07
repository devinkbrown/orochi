//! Token-bucket rate limiting.
//!
//! `Bucket` is a single allocation-free token bucket: callers supply the
//! current time in milliseconds, and the bucket refills lazily on each access
//! (no background timer, no clock reads).  Tokens accrue at `refill_per_ms` and
//! are capped at `capacity`.
//!
//! `KeyedLimiter(K)` maps keys to buckets via an unmanaged hash map, creating a
//! bucket on first use of a key.  `sweepIdle` reclaims buckets that have been
//! untouched (and fully refilled) for a configurable idle window, keeping the
//! map bounded for churny key spaces such as per-IP or per-nick limiting.

const std = @import("std");

/// A single token bucket.
///
/// Time is supplied by the caller in milliseconds; the bucket never reads a
/// clock.  Refilling is lazy and exact (elapsed * rate), capped at `capacity`.
pub const Bucket = struct {
    /// Maximum number of tokens the bucket can hold.
    capacity: f64,
    /// Tokens regenerated per elapsed millisecond.
    refill_per_ms: f64,
    /// Current token balance.
    tokens: f64,
    /// Timestamp (ms) of the last refill.
    last_ms: i64,

    /// Create a full bucket as of `now_ms`.
    pub fn init(capacity: f64, refill_per_ms: f64, now_ms: i64) Bucket {
        std.debug.assert(capacity >= 0);
        std.debug.assert(refill_per_ms >= 0);
        return .{
            .capacity = capacity,
            .refill_per_ms = refill_per_ms,
            .tokens = capacity,
            .last_ms = now_ms,
        };
    }

    /// Refill the bucket up to `now_ms`. Time never moves backwards: a
    /// `now_ms` earlier than `last_ms` only advances the timestamp.
    fn refill(self: *Bucket, now_ms: i64) void {
        if (now_ms <= self.last_ms) {
            self.last_ms = now_ms;
            return;
        }
        const elapsed: f64 = @floatFromInt(now_ms - self.last_ms);
        const added = elapsed * self.refill_per_ms;
        self.tokens = @min(self.capacity, self.tokens + added);
        self.last_ms = now_ms;
    }

    /// Attempt to spend `cost` tokens at `now_ms`.
    ///
    /// Refills first, then deducts `cost` if available and returns `true`;
    /// otherwise leaves the balance untouched and returns `false`. A zero or
    /// negative cost is always accepted and never reduces the balance.
    pub fn allow(self: *Bucket, now_ms: i64, cost: f64) bool {
        self.refill(now_ms);
        if (cost <= 0) return true;
        if (self.tokens >= cost) {
            self.tokens -= cost;
            return true;
        }
        return false;
    }

    /// Current available tokens at `now_ms` after a lazy refill.
    pub fn peek(self: *Bucket, now_ms: i64) f64 {
        self.refill(now_ms);
        return self.tokens;
    }

    /// Whether the bucket is full (idle) as of `now_ms`.
    fn isFull(self: *Bucket, now_ms: i64) bool {
        self.refill(now_ms);
        return self.tokens >= self.capacity;
    }
};

/// A keyed collection of token buckets, one per distinct `K`.
///
/// Buckets share the same `capacity`/`refill_per_ms` and are created on first
/// use. Storage is an unmanaged hash map; the caller passes the allocator on
/// each mutating call.
pub fn KeyedLimiter(comptime K: type) type {
    return struct {
        const Self = @This();
        const Map = std.AutoHashMapUnmanaged(K, Bucket);

        map: Map,
        capacity: f64,
        refill_per_ms: f64,

        /// Create an empty limiter with the per-bucket configuration.
        pub fn init(capacity: f64, refill_per_ms: f64) Self {
            std.debug.assert(capacity >= 0);
            std.debug.assert(refill_per_ms >= 0);
            return .{
                .map = .{},
                .capacity = capacity,
                .refill_per_ms = refill_per_ms,
            };
        }

        /// Release all bucket storage.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.map.deinit(allocator);
            self.* = undefined;
        }

        /// Attempt to spend `cost` tokens for `key` at `now_ms`.
        ///
        /// Creates a full bucket on first use of `key`. Returns the bucket's
        /// `allow` result. May allocate when inserting a new key.
        pub fn allow(
            self: *Self,
            allocator: std.mem.Allocator,
            key: K,
            now_ms: i64,
            cost: f64,
        ) !bool {
            const gop = try self.map.getOrPut(allocator, key);
            if (!gop.found_existing) {
                gop.value_ptr.* = Bucket.init(self.capacity, self.refill_per_ms, now_ms);
            }
            return gop.value_ptr.allow(now_ms, cost);
        }

        /// Current available tokens for `key` at `now_ms`.
        ///
        /// Returns `capacity` for an unknown key without allocating.
        pub fn peek(self: *Self, key: K, now_ms: i64) f64 {
            if (self.map.getPtr(key)) |bucket| {
                return bucket.peek(now_ms);
            }
            return self.capacity;
        }

        /// Number of live buckets.
        pub fn count(self: *const Self) usize {
            return self.map.count();
        }

        /// Drop buckets that have been full and untouched for at least
        /// `idle_ms` as of `now_ms`. A full bucket is indistinguishable from a
        /// freshly created one, so dropping it loses no rate-limiting state.
        pub fn sweepIdle(self: *Self, now_ms: i64, idle_ms: i64) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
                const bucket = entry.value_ptr;
                const idle = now_ms - bucket.last_ms;
                if (idle >= idle_ms and bucket.isFull(now_ms)) {
                    // Removing during iteration over an AutoHashMapUnmanaged is
                    // safe via removeByPtr; restart the iterator to avoid
                    // relying on iterator stability across mutation.
                    self.map.removeByPtr(entry.key_ptr);
                    it = self.map.iterator();
                }
            }
        }
    };
}

test "bucket: refills over time up to capacity" {
    var b = Bucket.init(10, 1, 0); // 1 token/ms
    try std.testing.expect(b.allow(0, 10)); // drain
    try std.testing.expectEqual(@as(f64, 0), b.peek(0));

    // 5 ms later: 5 tokens.
    try std.testing.expectEqual(@as(f64, 5), b.peek(5));
    // Far future: capped at capacity, not unbounded.
    try std.testing.expectEqual(@as(f64, 10), b.peek(1_000));
}

test "bucket: burst then deny then recover" {
    var b = Bucket.init(3, 0.5, 0); // 0.5 token/ms
    // Burst of 3 succeeds.
    try std.testing.expect(b.allow(0, 1));
    try std.testing.expect(b.allow(0, 1));
    try std.testing.expect(b.allow(0, 1));
    // Empty now: deny.
    try std.testing.expect(!b.allow(0, 1));
    // Need 2 ms to regenerate one token.
    try std.testing.expect(!b.allow(1, 1));
    try std.testing.expect(b.allow(2, 1));
}

test "bucket: zero cost always allowed and clock never goes backwards" {
    var b = Bucket.init(2, 1, 100);
    try std.testing.expect(b.allow(100, 0));
    try std.testing.expect(b.allow(100, 2));
    try std.testing.expect(b.allow(100, 0)); // zero cost ok even when empty
    // A stale timestamp does not grant tokens.
    try std.testing.expectEqual(@as(f64, 0), b.peek(50));
    try std.testing.expect(!b.allow(50, 1));
}

test "keyed: independent buckets per key" {
    const a = std.testing.allocator;
    var lim = KeyedLimiter(u32).init(2, 1);
    defer lim.deinit(a);

    try std.testing.expect(try lim.allow(a, 1, 0, 2)); // key 1 drained
    try std.testing.expect(!try lim.allow(a, 1, 0, 1));
    // key 2 is independent and full.
    try std.testing.expect(try lim.allow(a, 2, 0, 2));
    try std.testing.expectEqual(@as(usize, 2), lim.count());
    // unknown key peek returns capacity without allocating.
    try std.testing.expectEqual(@as(f64, 2), lim.peek(99, 0));
}

test "keyed: sweepIdle reclaims full idle buckets only" {
    const a = std.testing.allocator;
    var lim = KeyedLimiter(u32).init(4, 1);
    defer lim.deinit(a);

    // key 1: drained, will refill.
    try std.testing.expect(try lim.allow(a, 1, 0, 4));
    // key 2: drained at a later time, stays partial after sweep window.
    try std.testing.expect(try lim.allow(a, 2, 1_000, 4));
    try std.testing.expectEqual(@as(usize, 2), lim.count());

    // At t=1000: key 1 has fully refilled (idle 1000ms), key 2 just drained.
    lim.sweepIdle(1_000, 500);
    // key 1 reclaimed, key 2 kept (not full / not idle).
    try std.testing.expectEqual(@as(usize, 1), lim.count());
    try std.testing.expect(lim.peek(2, 1_000) < 4);

    // Much later both would be full and idle.
    lim.sweepIdle(10_000, 500);
    try std.testing.expectEqual(@as(usize, 0), lim.count());
}
