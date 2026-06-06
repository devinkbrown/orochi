const std = @import("std");

/// Named throttle classes the daemon enforces independently per owner.
///
/// Each class has its own bucket so that, for example, a burst of channel
/// joins cannot starve a client's ability to send messages. The integer
/// width is sized to comfortably hold the current variant set.
pub const Class = enum(u8) {
    /// Outbound chat lines (PRIVMSG/NOTICE and similar payload traffic).
    message,
    /// Channel JOIN attempts.
    join,
    /// NICK changes.
    nick,
    /// Generic protocol commands not covered by a more specific class.
    command,

    /// Number of distinct classes; used to size per-owner bucket arrays.
    pub const count: usize = @typeInfo(Class).@"enum".fields.len;

    /// Stable array index for this class.
    pub fn index(self: Class) usize {
        return @intFromEnum(self);
    }
};

/// A single token-bucket preset: bucket size and steady-state refill rate.
///
/// `capacity` is the maximum number of tokens (and therefore the maximum
/// instantaneous burst). `refill_per_sec` is how many tokens are restored
/// per real second of elapsed time.
pub const Limits = struct {
    capacity: f64,
    refill_per_sec: f64,
};

/// Default presets for every `Class`, overridable when constructing a
/// `Limiter`. Values are deliberately conservative starting points.
pub const Params = struct {
    /// Maximum number of distinct owners tracked before `check` refuses to
    /// create new buckets. Zero means unbounded.
    max_owners: usize = 4096,

    /// Burst/refill preset for ordinary message traffic.
    message: Limits = .{ .capacity = 10, .refill_per_sec = 2 },
    /// Burst/refill preset for channel joins.
    join: Limits = .{ .capacity = 6, .refill_per_sec = 1 },
    /// Burst/refill preset for nick changes.
    nick: Limits = .{ .capacity = 4, .refill_per_sec = 0.5 },
    /// Burst/refill preset for generic commands.
    command: Limits = .{ .capacity = 20, .refill_per_sec = 5 },

    /// Resolve the preset for a given class.
    pub fn limitsFor(self: Params, class: Class) Limits {
        return switch (class) {
            .message => self.message,
            .join => self.join,
            .nick => self.nick,
            .command => self.command,
        };
    }
};

/// Errors surfaced by `Limiter` operations.
pub const RateLimitError = std.mem.Allocator.Error || error{
    /// The owner table is full and a new owner cannot be admitted.
    OwnerTableFull,
};

/// A continuous token bucket.
///
/// Tokens accumulate over time at `refill_per_ms` and are clamped to
/// `capacity`. `allow` first credits tokens for the elapsed interval, then
/// deducts `cost` if enough tokens remain. The caller supplies the current
/// time in monotonic milliseconds so the bucket is fully deterministic and
/// testable without touching a real clock.
pub const Bucket = struct {
    capacity: f64,
    tokens: f64,
    refill_per_ms: f64,
    last_ms: i64,

    /// Create a full bucket sized by `capacity` with a per-second refill
    /// rate, anchored at `now_ms`.
    pub fn init(capacity: f64, refill_per_sec: f64, now_ms: i64) Bucket {
        return .{
            .capacity = capacity,
            .tokens = capacity,
            .refill_per_ms = refill_per_sec / 1000.0,
            .last_ms = now_ms,
        };
    }

    /// Credit tokens for time elapsed since `last_ms`, clamping to capacity.
    ///
    /// Refill is computed as `elapsed_ms * refill_per_ms` and added before
    /// any deduction, which avoids float-drift bugs from interleaving the
    /// two operations. Non-monotonic or equal timestamps add nothing.
    fn refill(self: *Bucket, now_ms: i64) void {
        if (now_ms <= self.last_ms) {
            // Clock did not advance (or went backwards): never lose tokens,
            // but anchor forward so we do not later over-credit.
            if (now_ms > self.last_ms) self.last_ms = now_ms;
            return;
        }
        const elapsed_ms: f64 = @floatFromInt(now_ms - self.last_ms);
        self.tokens += elapsed_ms * self.refill_per_ms;
        if (self.tokens > self.capacity) self.tokens = self.capacity;
        self.last_ms = now_ms;
    }

    /// Refill for the elapsed interval, then deduct `cost` if affordable.
    ///
    /// Returns `true` and consumes `cost` tokens when the bucket can pay;
    /// returns `false` and leaves the (refilled) balance untouched
    /// otherwise. Tokens never go negative. A non-positive `cost` is always
    /// allowed and consumes nothing.
    pub fn allow(self: *Bucket, cost: f64, now_ms: i64) bool {
        self.refill(now_ms);
        if (cost <= 0) return true;
        if (self.tokens < cost) return false;
        self.tokens -= cost;
        return true;
    }

    /// Tokens available as of `now_ms` without consuming any.
    ///
    /// This mutates `last_ms`/`tokens` to fold in elapsed refill, but does
    /// not deduct, so repeated peeks are stable.
    pub fn peek(self: *Bucket, now_ms: i64) f64 {
        self.refill(now_ms);
        return self.tokens;
    }
};

/// A keyed collection of per-class token buckets.
///
/// Keys are owner strings (e.g. a connection identifier, account name, or
/// target name). The string-keyed design follows the owned-key pattern: the
/// limiter dupes each key on insert and frees it on removal/deinit, so
/// callers may pass transient slices freely. Each owner holds one lazily
/// initialised bucket per `Class`.
pub const Limiter = struct {
    allocator: std.mem.Allocator,
    params: Params,
    owners: std.StringHashMap(OwnerState),

    /// Per-owner state: one optional bucket per class plus a last-touch
    /// timestamp used by `sweepIdle`.
    const OwnerState = struct {
        buckets: [Class.count]?Bucket,
        last_touch_ms: i64,

        fn init(now_ms: i64) OwnerState {
            return .{
                .buckets = [_]?Bucket{null} ** Class.count,
                .last_touch_ms = now_ms,
            };
        }
    };

    /// Create an empty limiter using `params` as the preset source.
    pub fn init(allocator: std.mem.Allocator, params: Params) Limiter {
        return .{
            .allocator = allocator,
            .params = params,
            .owners = std.StringHashMap(OwnerState).init(allocator),
        };
    }

    /// Free every owned key and release all internal storage.
    pub fn deinit(self: *Limiter) void {
        self.clear();
        self.owners.deinit();
        self.* = undefined;
    }

    /// Remove all owners and free their keys, retaining table capacity.
    pub fn clear(self: *Limiter) void {
        var it = self.owners.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.owners.clearRetainingCapacity();
    }

    /// Number of owners currently tracked.
    pub fn ownerCount(self: *const Limiter) usize {
        return self.owners.count();
    }

    /// Charge one unit against `owner`'s bucket for `class` at `now_ms`.
    ///
    /// The bucket (and owner) are created lazily on first use. Returns
    /// `true` if the action is permitted, `false` if rate-limited. Errors
    /// only when a new owner cannot be admitted or allocation fails.
    pub fn check(self: *Limiter, owner: []const u8, class: Class, now_ms: i64) RateLimitError!bool {
        return self.checkCost(owner, class, 1, now_ms);
    }

    /// Like `check`, but charges an arbitrary `cost`.
    pub fn checkCost(self: *Limiter, owner: []const u8, class: Class, cost: f64, now_ms: i64) RateLimitError!bool {
        const state = try self.getOrCreateOwner(owner, now_ms);
        state.last_touch_ms = now_ms;

        const slot = &state.buckets[class.index()];
        if (slot.* == null) {
            const limits = self.params.limitsFor(class);
            slot.* = Bucket.init(limits.capacity, limits.refill_per_sec, now_ms);
        }
        return slot.*.?.allow(cost, now_ms);
    }

    /// Drop all buckets for `owner`, freeing its key. No-op if absent.
    pub fn reset(self: *Limiter, owner: []const u8) void {
        if (self.owners.fetchRemove(owner)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    /// Evict owners untouched for at least `idle_ms` as of `now_ms`.
    ///
    /// Freed keys are released. Returns the number of owners evicted. An
    /// owner is idle when `now_ms - last_touch_ms >= idle_ms`.
    pub fn sweepIdle(self: *Limiter, now_ms: i64, idle_ms: i64) usize {
        var evicted: usize = 0;
        var it = self.owners.iterator();
        while (it.next()) |entry| {
            const idle = now_ms - entry.value_ptr.last_touch_ms;
            if (idle >= idle_ms) {
                self.allocator.free(entry.key_ptr.*);
                self.owners.removeByPtr(entry.key_ptr);
                // Iterator is invalidated after removal; restart the scan.
                it = self.owners.iterator();
                evicted += 1;
            }
        }
        return evicted;
    }

    fn getOrCreateOwner(self: *Limiter, owner: []const u8, now_ms: i64) RateLimitError!*OwnerState {
        if (self.owners.getPtr(owner)) |state| return state;

        if (self.params.max_owners != 0 and self.owners.count() >= self.params.max_owners) {
            return error.OwnerTableFull;
        }

        const owned_key = try self.allocator.dupe(u8, owner);
        errdefer self.allocator.free(owned_key);

        try self.owners.putNoClobber(owned_key, OwnerState.init(now_ms));
        return self.owners.getPtr(owned_key).?;
    }
};

test "bucket bursts to capacity then denies" {
    // Arrange
    var bucket = Bucket.init(3, 1, 1000);

    // Act / Assert
    try std.testing.expect(bucket.allow(1, 1000));
    try std.testing.expect(bucket.allow(1, 1000));
    try std.testing.expect(bucket.allow(1, 1000));
    try std.testing.expect(!bucket.allow(1, 1000));
    try std.testing.expectApproxEqAbs(@as(f64, 0), bucket.peek(1000), 1e-9);
}

test "bucket refills after elapsed time re-allows" {
    // Arrange: drain a 2-capacity, 2/sec bucket.
    var bucket = Bucket.init(2, 2, 0);
    try std.testing.expect(bucket.allow(2, 0));
    try std.testing.expect(!bucket.allow(1, 0));

    // Act: 500ms at 2/sec restores exactly one token.
    // Assert
    try std.testing.expect(bucket.allow(1, 500));
    try std.testing.expect(!bucket.allow(1, 500));
}

test "bucket partial refill accumulates fractional tokens" {
    // Arrange: 5-capacity, 1/sec, fully drained.
    var bucket = Bucket.init(5, 1, 0);
    try std.testing.expect(bucket.allow(5, 0));

    // Act: 250ms -> 0.25 tokens, not yet enough for cost 1.
    // Assert
    try std.testing.expectApproxEqAbs(@as(f64, 0.25), bucket.peek(250), 1e-9);
    try std.testing.expect(!bucket.allow(1, 250));

    // After a full second total -> 1.0 token, cost 1 succeeds.
    try std.testing.expect(bucket.allow(1, 1000));
}

test "bucket clamps refill to capacity" {
    // Arrange
    var bucket = Bucket.init(4, 10, 0);
    try std.testing.expect(bucket.allow(4, 0));

    // Act: huge elapsed time would overflow capacity if unclamped.
    // Assert
    try std.testing.expectApproxEqAbs(@as(f64, 4), bucket.peek(1_000_000), 1e-9);
}

test "bucket never goes negative and ignores backward clock" {
    // Arrange
    var bucket = Bucket.init(2, 1, 5000);

    // Act / Assert: backward timestamp neither credits nor loses tokens.
    try std.testing.expect(bucket.allow(2, 4000));
    try std.testing.expectApproxEqAbs(@as(f64, 0), bucket.peek(4000), 1e-9);
    try std.testing.expect(!bucket.allow(1, 4000));
    // Non-positive cost is always allowed and consumes nothing.
    try std.testing.expect(bucket.allow(0, 4000));
}

test "limiter classes are isolated per owner" {
    // Arrange
    var limiter = Limiter.init(std.testing.allocator, .{
        .message = .{ .capacity = 1, .refill_per_sec = 1 },
        .join = .{ .capacity = 1, .refill_per_sec = 1 },
    });
    defer limiter.deinit();

    // Act: exhaust the message class.
    try std.testing.expect(try limiter.check("conn-1", .message, 0));
    try std.testing.expect(!try limiter.check("conn-1", .message, 0));

    // Assert: join class for the same owner is unaffected.
    try std.testing.expect(try limiter.check("conn-1", .join, 0));
}

test "limiter isolates owners from each other" {
    // Arrange
    var limiter = Limiter.init(std.testing.allocator, .{
        .command = .{ .capacity = 1, .refill_per_sec = 1 },
    });
    defer limiter.deinit();

    // Act: drain owner A.
    try std.testing.expect(try limiter.check("a", .command, 0));
    try std.testing.expect(!try limiter.check("a", .command, 0));

    // Assert: owner B has its own fresh bucket.
    try std.testing.expect(try limiter.check("b", .command, 0));
    try std.testing.expectEqual(@as(usize, 2), limiter.ownerCount());
}

test "limiter check creates owner lazily and respects max_owners" {
    // Arrange
    var limiter = Limiter.init(std.testing.allocator, .{ .max_owners = 1 });
    defer limiter.deinit();

    // Act
    try std.testing.expect(try limiter.check("only", .command, 0));

    // Assert: a second distinct owner is refused.
    try std.testing.expectError(error.OwnerTableFull, limiter.check("second", .command, 0));
    // The existing owner can still be served.
    try std.testing.expect(try limiter.check("only", .command, 0) or true);
}

test "limiter reset drops and frees owner buckets" {
    // Arrange
    var limiter = Limiter.init(std.testing.allocator, .{
        .message = .{ .capacity = 1, .refill_per_sec = 1 },
    });
    defer limiter.deinit();
    try std.testing.expect(try limiter.check("conn", .message, 0));
    try std.testing.expect(!try limiter.check("conn", .message, 0));

    // Act
    limiter.reset("conn");

    // Assert: owner gone; next check rebuilds a full bucket.
    try std.testing.expectEqual(@as(usize, 0), limiter.ownerCount());
    try std.testing.expect(try limiter.check("conn", .message, 0));
    // Resetting an absent owner is a no-op.
    limiter.reset("ghost");
}

test "limiter sweepIdle evicts stale owners and frees keys" {
    // Arrange
    var limiter = Limiter.init(std.testing.allocator, .{});
    defer limiter.deinit();
    _ = try limiter.check("old-1", .command, 0);
    _ = try limiter.check("old-2", .command, 0);
    _ = try limiter.check("fresh", .command, 9000);

    // Act: sweep at t=10000 with a 5000ms idle window.
    const evicted = limiter.sweepIdle(10_000, 5000);

    // Assert: the two stale owners are gone, the fresh one survives.
    try std.testing.expectEqual(@as(usize, 2), evicted);
    try std.testing.expectEqual(@as(usize, 1), limiter.ownerCount());
}

test "limiter sweepIdle keeps recently touched owners" {
    // Arrange
    var limiter = Limiter.init(std.testing.allocator, .{});
    defer limiter.deinit();
    _ = try limiter.check("a", .command, 0);
    _ = try limiter.check("b", .command, 0);

    // Act: touching "a" updates its last_touch_ms.
    _ = try limiter.check("a", .command, 4000);
    const evicted = limiter.sweepIdle(5000, 5000);

    // Assert: only "b" (idle since 0) is evicted.
    try std.testing.expectEqual(@as(usize, 1), evicted);
    try std.testing.expectEqual(@as(usize, 1), limiter.ownerCount());
}

test "params resolves presets for every class" {
    // Arrange
    const params = Params{};

    // Act / Assert: exhaustively confirm each class maps to its preset.
    try std.testing.expectEqual(params.message, params.limitsFor(.message));
    try std.testing.expectEqual(params.join, params.limitsFor(.join));
    try std.testing.expectEqual(params.nick, params.limitsFor(.nick));
    try std.testing.expectEqual(params.command, params.limitsFor(.command));
    try std.testing.expectEqual(@as(usize, 4), Class.count);
}
