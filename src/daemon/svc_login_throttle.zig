//! Failed-login throttle for the IDENTIFY service command.
//!
//! This is the service-layer brute-force guard. It is deliberately distinct
//! from `login_throttle.zig` (which uses a discrete failure counter with
//! exponential lockout backoff and a single keyspace). This module instead
//! models a *continuously decaying* failure score per key, with a flat lockout
//! cooldown once a threshold score is crossed, and it keeps two independent
//! namespaces so that an attacker abusing one account cannot lock out an IP's
//! other accounts and vice versa.
//!
//! The semantics requested by the service layer:
//!   - `recordFailure(scope, key, now_ms)` bumps the decaying score; if the
//!     score crosses the threshold a flat cooldown lockout is armed.
//!   - `recordSuccess(scope, key)` fully clears the key (score + lockout).
//!   - `isLocked(scope, key, now_ms) -> ?retry_after_ms` reports how long the
//!     caller must wait, or null when not locked.
//!
//! All time is injected by the caller as monotonic milliseconds, so behaviour
//! is fully deterministic and testable without a real clock.

const std = @import("std");

/// Which namespace a key belongs to. The two namespaces share no state: the
/// same string in `.account` and `.ip` is two different records.
pub const Scope = enum(u1) {
    account,
    ip,
};

/// Tunable policy for the throttle.
pub const Params = struct {
    /// Each failure adds this much to the key's decaying score.
    failure_weight: f64 = 1.0,
    /// Once a key's score reaches this value (after applying the new failure),
    /// a lockout cooldown is armed. Must be > 0.
    lock_threshold: f64 = 5.0,
    /// Flat cooldown window armed when the threshold is crossed, in ms.
    cooldown_ms: i64 = 60_000,
    /// Half-life of the decaying score in ms: a key's score halves every
    /// `score_half_life_ms` of inactivity. Must be > 0.
    score_half_life_ms: i64 = 300_000,
    /// A record is eligible for sweeping once it is unlocked and its decayed
    /// score has fallen at or below this floor. Must be >= 0.
    sweep_score_floor: f64 = 0.01,
    /// Maximum number of distinct keys held *per scope*. When full, brand-new
    /// keys are refused admission so an attacker cannot evict real records by
    /// flooding fresh keys. 0 disables the cap.
    max_tracked_per_scope: usize = 65_536,
};

/// Per-key decaying-score brute-force throttle across two namespaces.
pub const Throttle = struct {
    allocator: std.mem.Allocator,
    params: Params,
    /// One table per scope, indexed by `@intFromEnum(Scope)`.
    tables: [2]Table,

    const Table = std.StringHashMapUnmanaged(Entry);

    /// Mutable record for a single tracked key within one scope.
    const Entry = struct {
        /// Decaying failure score as of `score_ts_ms`.
        score: f64,
        /// Timestamp the `score` value is anchored to; decay is applied lazily
        /// relative to this on every read/write.
        score_ts_ms: i64,
        /// Absolute time the armed lockout ends. `minInt` means "never locked".
        locked_until_ms: i64,
    };

    /// Create an empty throttle. Validates policy invariants in debug builds.
    pub fn init(allocator: std.mem.Allocator, params: Params) Throttle {
        std.debug.assert(params.lock_threshold > 0);
        std.debug.assert(params.score_half_life_ms > 0);
        std.debug.assert(params.sweep_score_floor >= 0);
        return .{
            .allocator = allocator,
            .params = params,
            .tables = .{ .empty, .empty },
        };
    }

    /// Free every owned key and release all internal storage.
    pub fn deinit(self: *Throttle) void {
        self.clear();
        for (&self.tables) |*t| t.deinit(self.allocator);
        self.* = undefined;
    }

    /// Remove and free all keys in both scopes, retaining table capacity.
    pub fn clear(self: *Throttle) void {
        for (&self.tables) |*t| {
            var it = t.iterator();
            while (it.next()) |e| self.allocator.free(e.key_ptr.*);
            t.clearRetainingCapacity();
        }
    }

    /// Number of keys currently tracked in `scope`.
    pub fn count(self: *const Throttle, scope: Scope) usize {
        return self.tables[@intFromEnum(scope)].count();
    }

    /// Total keys tracked across both scopes.
    pub fn countAll(self: *const Throttle) usize {
        return self.count(.account) + self.count(.ip);
    }

    /// Report how long `key` in `scope` must wait before another attempt, or
    /// null if it is not currently locked. Pure read: never creates entries,
    /// never mutates score state. A key whose lockout has elapsed reports null.
    pub fn isLocked(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?i64 {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse return self.isLockedHeap(scope, key, now_ms);
        return self.lockedFor(scope, norm, now_ms);
    }

    fn isLockedHeap(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?i64 {
        const norm = self.allocator.dupe(u8, key) catch return null;
        defer self.allocator.free(norm);
        toLower(norm);
        return self.lockedFor(scope, norm, now_ms);
    }

    fn lockedFor(self: *Throttle, scope: Scope, norm: []const u8, now_ms: i64) ?i64 {
        const t = &self.tables[@intFromEnum(scope)];
        const entry = t.get(norm) orelse return null;
        if (now_ms < entry.locked_until_ms) {
            // Saturating subtract; both operands are i64 and lhs > rhs here.
            return entry.locked_until_ms - now_ms;
        }
        return null;
    }

    /// Current decayed score for `key` in `scope` as of `now_ms`, or 0 if
    /// untracked. Pure read (does not persist the decayed value).
    pub fn score(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) f64 {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse return self.scoreHeap(scope, key, now_ms);
        const t = &self.tables[@intFromEnum(scope)];
        const entry = t.getPtr(norm) orelse return 0;
        return self.decayedScore(entry, now_ms);
    }

    fn scoreHeap(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) f64 {
        const norm = self.allocator.dupe(u8, key) catch return 0;
        defer self.allocator.free(norm);
        toLower(norm);
        const t = &self.tables[@intFromEnum(scope)];
        const entry = t.getPtr(norm) orelse return 0;
        return self.decayedScore(entry, now_ms);
    }

    /// Record one authentication failure for `key` in `scope` at `now_ms`.
    ///
    /// The decaying score is advanced to `now_ms`, `failure_weight` is added,
    /// and if the result reaches `lock_threshold` a flat `cooldown_ms` lockout
    /// is armed (extending, never shortening, any existing lockout). Returns
    /// the resulting retry-after in ms if now locked, else null.
    ///
    /// Returns null without recording when the scope's table is full and `key`
    /// is not already present.
    pub fn recordFailure(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?i64 {
        const entry = self.getOrCreate(scope, key, now_ms) orelse return null;

        // Advance decay to now, then add this failure's weight.
        entry.score = self.decayedScore(entry, now_ms) + self.params.failure_weight;
        entry.score_ts_ms = now_ms;

        if (entry.score >= self.params.lock_threshold) {
            const candidate = saturatingAdd(now_ms, self.params.cooldown_ms);
            // Extend an existing lockout but never pull it earlier.
            if (candidate > entry.locked_until_ms) entry.locked_until_ms = candidate;
        }

        if (now_ms < entry.locked_until_ms) return entry.locked_until_ms - now_ms;
        return null;
    }

    /// Record a successful authentication: fully clear `key` in `scope`,
    /// freeing its owned storage. No-op when untracked.
    pub fn recordSuccess(self: *Throttle, scope: Scope, key: []const u8) void {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse {
            self.recordSuccessHeap(scope, key);
            return;
        };
        self.removeNorm(scope, norm);
    }

    fn recordSuccessHeap(self: *Throttle, scope: Scope, key: []const u8) void {
        const norm = self.allocator.dupe(u8, key) catch return;
        defer self.allocator.free(norm);
        toLower(norm);
        self.removeNorm(scope, norm);
    }

    fn removeNorm(self: *Throttle, scope: Scope, norm: []const u8) void {
        const t = &self.tables[@intFromEnum(scope)];
        if (t.fetchRemove(norm)) |removed| self.allocator.free(removed.key);
    }

    /// Drop records in both scopes that are unlocked and whose decayed score
    /// has fallen to/below `sweep_score_floor` as of `now_ms`. Returns the
    /// number of records evicted.
    pub fn sweep(self: *Throttle, now_ms: i64) usize {
        var evicted: usize = 0;
        for (&self.tables) |*t| {
            var it = t.iterator();
            while (it.next()) |entry| {
                const e = entry.value_ptr.*;
                const locked = now_ms < e.locked_until_ms;
                const decayed = self.decayedScore(&e, now_ms);
                if (!locked and decayed <= self.params.sweep_score_floor) {
                    self.allocator.free(entry.key_ptr.*);
                    t.removeByPtr(entry.key_ptr);
                    // Removal invalidates the iterator; restart the scan.
                    it = t.iterator();
                    evicted += 1;
                }
            }
        }
        return evicted;
    }

    /// Decay an entry's stored score forward to `now_ms` using the configured
    /// half-life. Time going backwards (now < anchor) is treated as no decay.
    fn decayedScore(self: *Throttle, entry: *const Entry, now_ms: i64) f64 {
        const elapsed = now_ms - entry.score_ts_ms;
        if (elapsed <= 0) return entry.score;
        const half_life: f64 = @floatFromInt(self.params.score_half_life_ms);
        const ratio = @as(f64, @floatFromInt(elapsed)) / half_life;
        // score * 2^(-elapsed/half_life)
        return entry.score * std.math.pow(f64, 0.5, ratio);
    }

    /// Look up `key` in `scope`, creating a fresh record if absent and the
    /// scope still has admission headroom. Returns null when full and new.
    fn getOrCreate(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?*Entry {
        var buf: [256]u8 = undefined;
        if (normalizeInto(&buf, key)) |norm| {
            return self.getOrCreateNorm(scope, norm, now_ms);
        }
        const heap_norm = self.allocator.dupe(u8, key) catch return null;
        defer self.allocator.free(heap_norm);
        toLower(heap_norm);
        return self.getOrCreateNorm(scope, heap_norm, now_ms);
    }

    fn getOrCreateNorm(self: *Throttle, scope: Scope, norm: []const u8, now_ms: i64) ?*Entry {
        const t = &self.tables[@intFromEnum(scope)];
        if (t.getPtr(norm)) |entry| return entry;

        const cap = self.params.max_tracked_per_scope;
        if (cap != 0 and t.count() >= cap) return null;

        const owned_key = self.allocator.dupe(u8, norm) catch return null;
        errdefer self.allocator.free(owned_key);

        t.putNoClobber(self.allocator, owned_key, .{
            .score = 0,
            .score_ts_ms = now_ms,
            .locked_until_ms = std.math.minInt(i64),
        }) catch {
            self.allocator.free(owned_key);
            return null;
        };
        return t.getPtr(owned_key).?;
    }
};

/// Lowercase every ASCII byte of `s` in place.
fn toLower(s: []u8) void {
    for (s) |*c| c.* = std.ascii.toLower(c.*);
}

/// Copy `key` into `buf` lowercased, returning the slice, or null if too long.
fn normalizeInto(buf: []u8, key: []const u8) ?[]const u8 {
    if (key.len > buf.len) return null;
    for (key, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..key.len];
}

/// Add `a + b` with i64 saturation instead of overflow.
fn saturatingAdd(a: i64, b: i64) i64 {
    return std.math.add(i64, a, b) catch if (b > 0) std.math.maxInt(i64) else std.math.minInt(i64);
}

const testing = std.testing;

test "below threshold every failure stays unlocked" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 3, .failure_weight = 1 });
    defer thr.deinit();

    // Act / Assert
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "bob", 0));
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "bob", 0));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "bob", 0));
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, "bob", 0), 1e-9);
}

test "crossing threshold arms a cooldown and isLocked returns retry-after" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 3,
        .failure_weight = 1,
        .cooldown_ms = 1000,
    });
    defer thr.deinit();

    // Act: third failure crosses the threshold.
    _ = thr.recordFailure(.account, "eve", 0);
    _ = thr.recordFailure(.account, "eve", 0);
    const locked = thr.recordFailure(.account, "eve", 0);

    // Assert
    try testing.expectEqual(@as(?i64, 1000), locked);
    try testing.expectEqual(@as(?i64, 1000), thr.isLocked(.account, "eve", 0));
    try testing.expectEqual(@as(?i64, 1), thr.isLocked(.account, "eve", 999));
}

test "cooldown expires then unlocks" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = 250,
    });
    defer thr.deinit();

    // Act
    _ = thr.recordFailure(.account, "kana", 1000);

    // Assert
    try testing.expectEqual(@as(?i64, 150), thr.isLocked(.account, "kana", 1100));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "kana", 1250));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "kana", 5000));
}

test "success fully resets a key and frees it" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 2, .cooldown_ms = 1000 });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "user", 0);
    _ = thr.recordFailure(.account, "user", 0);
    try testing.expect(thr.isLocked(.account, "user", 0) != null);

    // Act
    thr.recordSuccess(.account, "user");

    // Assert
    try testing.expectEqual(@as(usize, 0), thr.count(.account));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "user", 0));
    try testing.expectApproxEqAbs(@as(f64, 0), thr.score(.account, "user", 0), 1e-9);
    // Resetting an unknown key is a harmless no-op.
    thr.recordSuccess(.account, "ghost");
}

test "score decays by half over one half-life" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 100, // high so we never lock
        .failure_weight = 4,
        .score_half_life_ms = 1000,
    });
    defer thr.deinit();

    // Act: score = 4 at t=0.
    _ = thr.recordFailure(.account, "decayer", 0);

    // Assert: halves each half-life.
    try testing.expectApproxEqAbs(@as(f64, 4), thr.score(.account, "decayer", 0), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, "decayer", 1000), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 1), thr.score(.account, "decayer", 2000), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 0.5), thr.score(.account, "decayer", 3000), 1e-6);
}

test "decay lets a key recover below threshold over time" {
    // Arrange: two failures of weight 2 = score 4, threshold 5 (not locked).
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 5,
        .failure_weight = 2,
        .cooldown_ms = 10_000,
        .score_half_life_ms = 1000,
    });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "slow", 0);
    _ = thr.recordFailure(.account, "slow", 0); // score 4, unlocked

    // After a half-life the score is ~2; one more weight-2 failure = ~4 < 5.
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "slow", 1000));

    // But three rapid failures at t=0 would have locked it.
    _ = thr.recordFailure(.account, "fast", 0);
    _ = thr.recordFailure(.account, "fast", 0);
    try testing.expect(thr.recordFailure(.account, "fast", 0) != null);
}

test "account and ip namespaces are independent" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 1, .cooldown_ms = 1000 });
    defer thr.deinit();

    // Act: lock the *account* "1.2.3.4" (same string, different scope).
    _ = thr.recordFailure(.account, "1.2.3.4", 0);

    // Assert: the IP scope with the identical string is untouched.
    try testing.expect(thr.isLocked(.account, "1.2.3.4", 0) != null);
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.ip, "1.2.3.4", 0));
    try testing.expectEqual(@as(usize, 1), thr.count(.account));
    try testing.expectEqual(@as(usize, 0), thr.count(.ip));
}

test "distinct keys within a scope are isolated" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 2, .cooldown_ms = 1000 });
    defer thr.deinit();

    // Act: lock "a" only.
    _ = thr.recordFailure(.ip, "a", 0);
    _ = thr.recordFailure(.ip, "a", 0);

    // Assert
    try testing.expect(thr.isLocked(.ip, "a", 0) != null);
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.ip, "b", 0));
}

test "keys are matched case-insensitively" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 3, .failure_weight = 1 });
    defer thr.deinit();

    // Act
    _ = thr.recordFailure(.account, "Alice", 0);
    _ = thr.recordFailure(.account, "ALICE", 0);
    _ = thr.recordFailure(.account, "alice", 0);

    // Assert: one record, accumulated together.
    try testing.expectEqual(@as(usize, 1), thr.count(.account));
    try testing.expectApproxEqAbs(@as(f64, 3), thr.score(.account, "aLiCe", 0), 1e-9);
}

test "lockout extends but never shortens on repeated failures" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = 1000,
        .score_half_life_ms = 1_000_000, // negligible decay over the test
    });
    defer thr.deinit();

    // Act: lock at t=0 (until 1000), then fail again at t=500 (would-be 1500).
    _ = thr.recordFailure(.account, "x", 0);
    try testing.expectEqual(@as(?i64, 1000), thr.isLocked(.account, "x", 0));
    const extended = thr.recordFailure(.account, "x", 500);

    // Assert: window now ends at 1500, not pulled earlier.
    try testing.expectEqual(@as(?i64, 1000), extended);
    try testing.expectEqual(@as(?i64, 1000), thr.isLocked(.account, "x", 500));
    try testing.expectEqual(@as(?i64, 1), thr.isLocked(.account, "x", 1499));
}

test "sweep drops decayed unlocked records and frees keys" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 100,
        .failure_weight = 1,
        .cooldown_ms = 0,
        .score_half_life_ms = 1000,
        .sweep_score_floor = 0.01,
    });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "stale", 0); // score 1 @ t=0
    _ = thr.recordFailure(.ip, "fresh", 9500); // score 1 @ t=9500

    // Act: at t=10000 "stale" has decayed ~2^-10 < 0.01; "fresh" still ~0.7.
    const evicted = thr.sweep(10_000);

    // Assert
    try testing.expectEqual(@as(usize, 1), evicted);
    try testing.expectEqual(@as(usize, 0), thr.count(.account));
    try testing.expectEqual(@as(usize, 1), thr.count(.ip));
}

test "sweep keeps records still inside their lockout window" {
    // Arrange: locked but old-scored entry must survive the sweep.
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = 100_000,
        .score_half_life_ms = 100,
        .sweep_score_floor = 0.01,
    });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "held", 0);

    // Act: score has fully decayed by t=5000 but lockout runs to t=100000.
    const evicted = thr.sweep(5000);

    // Assert
    try testing.expectEqual(@as(usize, 0), evicted);
    try testing.expect(thr.isLocked(.account, "held", 5000) != null);
}

test "max_tracked_per_scope refuses new keys but serves existing ones" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .max_tracked_per_scope = 1,
        .lock_threshold = 1,
        .cooldown_ms = 1000,
    });
    defer thr.deinit();

    // Act: first account key admitted and locked.
    try testing.expect(thr.recordFailure(.account, "first", 0) != null);

    // Assert: a second distinct account key is refused.
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "second", 0));
    try testing.expectEqual(@as(usize, 1), thr.count(.account));

    // The per-scope cap does not bleed into the other scope.
    try testing.expect(thr.recordFailure(.ip, "first", 0) != null);
    try testing.expectEqual(@as(usize, 1), thr.count(.ip));

    // The existing account key still accrues failures.
    _ = thr.recordFailure(.account, "first", 0);
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, "first", 0), 1e-6);
}

test "retry-after never overflows with a saturated cooldown" {
    // Arrange: an absurd cooldown near i64 max must saturate, not overflow.
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = std.math.maxInt(i64),
    });
    defer thr.deinit();

    // Act
    _ = thr.recordFailure(.ip, "huge", 1_000_000);

    // Assert: still locked far in the future, no panic.
    try testing.expect(thr.isLocked(.ip, "huge", 2_000_000) != null);
}

test "long keys exceeding the inline buffer take the heap path" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 2, .cooldown_ms = 1000 });
    defer thr.deinit();
    const long_key = "X" ** 300;

    // Act
    _ = thr.recordFailure(.account, long_key, 0);
    _ = thr.recordFailure(.account, long_key, 0);

    // Assert: stored lowercased, locked, then cleanly cleared.
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, "x" ** 300, 0), 1e-9);
    try testing.expect(thr.isLocked(.account, long_key, 0) != null);
    thr.recordSuccess(.account, long_key);
    try testing.expectEqual(@as(usize, 0), thr.count(.account));
}

test "deinit frees all keys across both scopes with no leaks" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{});

    // Act
    _ = thr.recordFailure(.account, "one", 0);
    _ = thr.recordFailure(.account, "two", 0);
    _ = thr.recordFailure(.ip, "three", 0);

    // Assert: teardown under the testing allocator catches any leak.
    try testing.expectEqual(@as(usize, 3), thr.countAll());
    thr.deinit();
}
