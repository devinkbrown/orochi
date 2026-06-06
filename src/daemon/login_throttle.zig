const std = @import("std");

/// Tunable thresholds for the authentication-failure throttle.
///
/// The model is a per-key failure counter with exponential lockout, distinct
/// from a token bucket: each consecutive failure increments a counter, and
/// once the counter reaches `max_failures` the key is locked out for a window
/// that doubles with every additional failure. Counters decay back to zero
/// after a quiet period so that a long-idle key is not punished forever.
pub const Params = struct {
    /// Number of consecutive failures tolerated before lockout begins. The
    /// `max_failures`-th failure is the first one that produces a lockout.
    max_failures: u8 = 5,
    /// Base lockout duration applied at the threshold, in milliseconds.
    base_lockout_ms: i64 = 30_000,
    /// Upper bound for any single lockout window, in milliseconds.
    max_lockout_ms: i64 = 3_600_000,
    /// Quiet interval after which an untouched failure record is discarded.
    decay_ms: i64 = 900_000,
    /// Maximum number of distinct keys tracked before new keys are refused
    /// admission (existing keys continue to be served).
    max_tracked: usize = 65536,
};

/// Outcome of consulting the throttle for a key.
pub const Decision = enum(u8) {
    /// The key is permitted to attempt authentication.
    allow,
    /// The key is currently inside an active lockout window.
    locked,
};

/// Per-key brute-force guard tracking authentication failures.
///
/// Keys are arbitrary identity strings chosen by the caller: an account name,
/// a source IP, or any other identifier. Whatever string is passed is stored
/// lowercased and owned (duped on insert, freed on removal/deinit), so lookups
/// are case-insensitive and callers may pass transient slices freely.
///
/// All time is supplied by the caller as monotonic milliseconds (`now_ms`),
/// making every decision deterministic and testable without a real clock.
pub const Tracker = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.StringHashMapUnmanaged(Entry),

    /// Mutable failure record for a single tracked key.
    const Entry = struct {
        /// Consecutive failure count; reset to zero on success.
        failures: u8,
        /// Timestamp of the most recent failure, used for decay.
        last_failure_ms: i64,
        /// Absolute time at which the current lockout (if any) ends. A value
        /// less than or equal to any observed `now_ms` means "not locked".
        locked_until_ms: i64,
    };

    /// Create an empty tracker using `params` as the policy source.
    pub fn init(allocator: std.mem.Allocator, params: Params) Tracker {
        return .{
            .allocator = allocator,
            .params = params,
            .entries = .empty,
        };
    }

    /// Free every owned key and release all internal storage.
    pub fn deinit(self: *Tracker) void {
        self.clear();
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Remove all keys and free them, retaining table capacity.
    pub fn clear(self: *Tracker) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.clearRetainingCapacity();
    }

    /// Number of keys currently tracked.
    pub fn count(self: *const Tracker) usize {
        return self.entries.count();
    }

    /// Current consecutive failure count for `key`, or zero if untracked.
    ///
    /// The key is normalised to lowercase on a small stack buffer for lookup;
    /// keys longer than the buffer fall back to a heap normalisation.
    pub fn failures(self: *Tracker, key: []const u8) u8 {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse {
            return self.failuresHeap(key);
        };
        if (self.entries.get(norm)) |entry| return entry.failures;
        return 0;
    }

    /// Heap-normalised fallback for `failures` when the key exceeds the
    /// inline buffer. Frees the temporary key before returning.
    fn failuresHeap(self: *Tracker, key: []const u8) u8 {
        const norm = self.allocator.dupe(u8, key) catch return 0;
        defer self.allocator.free(norm);
        toLower(norm);
        if (self.entries.get(norm)) |entry| return entry.failures;
        return 0;
    }

    /// Report whether `key` may attempt authentication as of `now_ms`.
    ///
    /// This is a read-mostly probe: it does not create entries and does not
    /// increment counters. It returns `.locked` only while inside an active
    /// lockout window, and `.allow` otherwise (including for unknown keys).
    pub fn check(self: *Tracker, key: []const u8, now_ms: i64) Decision {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse return self.checkHeap(key, now_ms);
        return self.decisionFor(norm, now_ms);
    }

    /// Heap-normalised fallback for `check` for over-long keys.
    fn checkHeap(self: *Tracker, key: []const u8, now_ms: i64) Decision {
        const norm = self.allocator.dupe(u8, key) catch return .allow;
        defer self.allocator.free(norm);
        toLower(norm);
        return self.decisionFor(norm, now_ms);
    }

    /// Shared decision logic over an already-normalised key.
    fn decisionFor(self: *Tracker, norm: []const u8, now_ms: i64) Decision {
        if (self.entries.get(norm)) |entry| {
            if (now_ms < entry.locked_until_ms) return .locked;
        }
        return .allow;
    }

    /// Record one authentication failure for `key` at `now_ms` and return the
    /// resulting decision.
    ///
    /// The failure count is incremented (saturating at the `u8` ceiling). Once
    /// the count reaches `params.max_failures`, a lockout window is opened with
    /// exponential backoff: `base_lockout_ms * 2^(failures - max_failures)`,
    /// clamped to `max_lockout_ms` and computed overflow-safely. Returns
    /// `.locked` if a lockout is now in effect, otherwise `.allow`.
    ///
    /// Returns `.allow` without recording when the table is full and `key` is
    /// not already tracked, so an attacker cannot evict legitimate records by
    /// flooding fresh keys.
    pub fn recordFailure(self: *Tracker, key: []const u8, now_ms: i64) Decision {
        const entry = self.getOrCreate(key, now_ms) orelse return .allow;

        if (entry.failures < std.math.maxInt(u8)) entry.failures += 1;
        entry.last_failure_ms = now_ms;

        if (entry.failures >= self.params.max_failures) {
            const lockout = self.lockoutDuration(entry.failures);
            entry.locked_until_ms = saturatingAdd(now_ms, lockout);
            return .locked;
        }
        entry.locked_until_ms = std.math.minInt(i64);
        return .allow;
    }

    /// Record a successful authentication for `key`, clearing all failure
    /// state and freeing the owned key. No-op if the key is untracked.
    pub fn recordSuccess(self: *Tracker, key: []const u8) void {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse {
            self.recordSuccessHeap(key);
            return;
        };
        if (self.entries.fetchRemove(norm)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    /// Heap-normalised fallback for `recordSuccess` for over-long keys.
    fn recordSuccessHeap(self: *Tracker, key: []const u8) void {
        const norm = self.allocator.dupe(u8, key) catch return;
        defer self.allocator.free(norm);
        toLower(norm);
        if (self.entries.fetchRemove(norm)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    /// Discard records that have both decayed and left any lockout window.
    ///
    /// An entry is dropped when it is not currently locked and its last
    /// failure is at least `params.decay_ms` in the past as of `now_ms`. Freed
    /// keys are released. Returns the number of records evicted.
    pub fn sweep(self: *Tracker, now_ms: i64) usize {
        var evicted: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            const e = entry.value_ptr.*;
            const locked = now_ms < e.locked_until_ms;
            const idle = now_ms - e.last_failure_ms;
            if (!locked and idle >= self.params.decay_ms) {
                self.allocator.free(entry.key_ptr.*);
                self.entries.removeByPtr(entry.key_ptr);
                // Removal invalidates the iterator; restart the scan.
                it = self.entries.iterator();
                evicted += 1;
            }
        }
        return evicted;
    }

    /// Compute the lockout window for a given failure count.
    ///
    /// The exponent is `failures - max_failures`, so the threshold failure
    /// yields exactly `base_lockout_ms`. The doubling is computed with a
    /// saturating left shift and the product is clamped to `max_lockout_ms`,
    /// guaranteeing no `i64` overflow even at the saturated failure ceiling.
    fn lockoutDuration(self: *Tracker, fail_count: u8) i64 {
        if (fail_count < self.params.max_failures) return 0;
        const exponent: u8 = fail_count - self.params.max_failures;

        // 2^exponent capped so the subsequent multiply cannot overflow i64.
        // Anything past ~62 bits already exceeds any sane lockout, so we
        // saturate the multiplier and rely on the final clamp.
        const base = self.params.base_lockout_ms;
        if (base <= 0) return 0;
        if (exponent >= 62) return self.params.max_lockout_ms;

        const multiplier: i64 = @as(i64, 1) << @intCast(exponent);
        const product = std.math.mul(i64, base, multiplier) catch self.params.max_lockout_ms;
        return @min(product, self.params.max_lockout_ms);
    }

    /// Look up `key`, creating a fresh record if absent and admissible.
    ///
    /// Returns a pointer to the (possibly new) entry, or null when the table
    /// is full and `key` is not already present. The key is normalised to
    /// lowercase and duped on insertion following the owned-key pattern.
    fn getOrCreate(self: *Tracker, key: []const u8, now_ms: i64) ?*Entry {
        var buf: [256]u8 = undefined;
        if (normalizeInto(&buf, key)) |norm| {
            return self.getOrCreateNorm(norm, now_ms);
        }
        // Over-long key: normalise on the heap, then reuse the same path.
        const heap_norm = self.allocator.dupe(u8, key) catch return null;
        defer self.allocator.free(heap_norm);
        toLower(heap_norm);
        return self.getOrCreateNorm(heap_norm, now_ms);
    }

    /// Shared insertion path over an already-normalised key slice.
    fn getOrCreateNorm(self: *Tracker, norm: []const u8, now_ms: i64) ?*Entry {
        if (self.entries.getPtr(norm)) |entry| return entry;

        if (self.params.max_tracked != 0 and self.entries.count() >= self.params.max_tracked) {
            return null;
        }

        const owned_key = self.allocator.dupe(u8, norm) catch return null;
        errdefer self.allocator.free(owned_key);

        self.entries.putNoClobber(self.allocator, owned_key, .{
            .failures = 0,
            .last_failure_ms = now_ms,
            .locked_until_ms = std.math.minInt(i64),
        }) catch {
            self.allocator.free(owned_key);
            return null;
        };
        return self.entries.getPtr(owned_key).?;
    }
};

/// Lowercase every ASCII byte of `s` in place.
fn toLower(s: []u8) void {
    for (s) |*c| c.* = std.ascii.toLower(c.*);
}

/// Copy `key` into `buf` lowercased, returning the populated slice, or null if
/// `key` does not fit. Lets the hot path normalise without heap allocation.
fn normalizeInto(buf: []u8, key: []const u8) ?[]const u8 {
    if (key.len > buf.len) return null;
    for (key, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..key.len];
}

/// Add `a + b` with `i64` saturation instead of overflow.
fn saturatingAdd(a: i64, b: i64) i64 {
    return std.math.add(i64, a, b) catch if (b > 0) std.math.maxInt(i64) else std.math.minInt(i64);
}

test "below threshold every failure still allows" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{ .max_failures = 3 });
    defer tracker.deinit();

    // Act / Assert: first two failures stay under the threshold.
    try std.testing.expectEqual(Decision.allow, tracker.recordFailure("bob", 0));
    try std.testing.expectEqual(Decision.allow, tracker.recordFailure("bob", 0));
    try std.testing.expectEqual(@as(u8, 2), tracker.failures("bob"));
    try std.testing.expectEqual(Decision.allow, tracker.check("bob", 0));
}

test "reaching threshold locks out the key" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 3,
        .base_lockout_ms = 1000,
    });
    defer tracker.deinit();

    // Act: third failure trips the lockout.
    _ = tracker.recordFailure("eve", 0);
    _ = tracker.recordFailure("eve", 0);
    const decision = tracker.recordFailure("eve", 0);

    // Assert
    try std.testing.expectEqual(Decision.locked, decision);
    try std.testing.expectEqual(Decision.locked, tracker.check("eve", 0));
    // Still locked just before the window ends...
    try std.testing.expectEqual(Decision.locked, tracker.check("eve", 999));
}

test "lockout window grows exponentially with each extra failure" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 2,
        .base_lockout_ms = 100,
        .max_lockout_ms = 1_000_000,
    });
    defer tracker.deinit();

    // Act / Assert: at exactly the threshold the window is base (100ms).
    _ = tracker.recordFailure("mallory", 0);
    _ = tracker.recordFailure("mallory", 0);
    try std.testing.expectEqual(Decision.locked, tracker.check("mallory", 99));
    try std.testing.expectEqual(Decision.allow, tracker.check("mallory", 100));

    // One more failure doubles the window to 200ms (2^1 * base).
    _ = tracker.recordFailure("mallory", 100);
    try std.testing.expectEqual(Decision.locked, tracker.check("mallory", 299));
    try std.testing.expectEqual(Decision.allow, tracker.check("mallory", 300));

    // Another failure doubles again to 400ms (2^2 * base).
    _ = tracker.recordFailure("mallory", 300);
    try std.testing.expectEqual(Decision.locked, tracker.check("mallory", 699));
    try std.testing.expectEqual(Decision.allow, tracker.check("mallory", 700));
}

test "lockout is clamped to max_lockout_ms" {
    // Arrange: tiny cap so the very first lockout is already clamped.
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 1,
        .base_lockout_ms = 10_000,
        .max_lockout_ms = 500,
    });
    defer tracker.deinit();

    // Act
    _ = tracker.recordFailure("ip-1", 0);

    // Assert: window never exceeds the cap.
    try std.testing.expectEqual(Decision.locked, tracker.check("ip-1", 499));
    try std.testing.expectEqual(Decision.allow, tracker.check("ip-1", 500));
}

test "lockout expires then allows again" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 1,
        .base_lockout_ms = 250,
    });
    defer tracker.deinit();
    _ = tracker.recordFailure("kana", 1000);

    // Act / Assert
    try std.testing.expectEqual(Decision.locked, tracker.check("kana", 1100));
    try std.testing.expectEqual(Decision.allow, tracker.check("kana", 1250));
}

test "recordSuccess clears failure state and frees the key" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{ .max_failures = 2 });
    defer tracker.deinit();
    _ = tracker.recordFailure("user", 0);
    _ = tracker.recordFailure("user", 0);
    try std.testing.expectEqual(Decision.locked, tracker.check("user", 0));

    // Act
    tracker.recordSuccess("user");

    // Assert: record gone, counter reset, no longer locked.
    try std.testing.expectEqual(@as(usize, 0), tracker.count());
    try std.testing.expectEqual(@as(u8, 0), tracker.failures("user"));
    try std.testing.expectEqual(Decision.allow, tracker.check("user", 0));
    // Clearing an unknown key is a harmless no-op.
    tracker.recordSuccess("ghost");
}

test "sweep drops decayed entries and frees keys" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 10,
        .decay_ms = 5000,
    });
    defer tracker.deinit();
    _ = tracker.recordFailure("stale", 0);
    _ = tracker.recordFailure("fresh", 9000);

    // Act: sweep at t=10000 with a 5000ms decay window.
    const evicted = tracker.sweep(10_000);

    // Assert: only the long-idle record is dropped.
    try std.testing.expectEqual(@as(usize, 1), evicted);
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
    try std.testing.expectEqual(@as(u8, 0), tracker.failures("stale"));
}

test "sweep keeps entries still inside their lockout window" {
    // Arrange: a locked entry whose last failure is old enough to decay, but
    // whose lockout window has not yet elapsed, must survive the sweep.
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 1,
        .base_lockout_ms = 100_000,
        .decay_ms = 1000,
    });
    defer tracker.deinit();
    _ = tracker.recordFailure("held", 0);

    // Act: well past decay_ms but still inside the 100s lockout.
    const evicted = tracker.sweep(5000);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), evicted);
    try std.testing.expectEqual(Decision.locked, tracker.check("held", 5000));
}

test "keys are isolated from one another" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 2,
        .base_lockout_ms = 1000,
    });
    defer tracker.deinit();

    // Act: lock out "a" entirely.
    _ = tracker.recordFailure("a", 0);
    _ = tracker.recordFailure("a", 0);

    // Assert: "b" is untouched.
    try std.testing.expectEqual(Decision.locked, tracker.check("a", 0));
    try std.testing.expectEqual(Decision.allow, tracker.check("b", 0));
    try std.testing.expectEqual(@as(u8, 0), tracker.failures("b"));
}

test "keys are matched case-insensitively" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{ .max_failures = 3 });
    defer tracker.deinit();

    // Act: mixed-case variants of the same identity accumulate together.
    _ = tracker.recordFailure("Alice", 0);
    _ = tracker.recordFailure("ALICE", 0);
    _ = tracker.recordFailure("alice", 0);

    // Assert: one record, three failures, locked under any casing.
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
    try std.testing.expectEqual(@as(u8, 3), tracker.failures("aLiCe"));
    try std.testing.expectEqual(Decision.locked, tracker.check("ALicE", 0));
}

test "backoff is overflow-safe at the failure ceiling" {
    // Arrange: saturate the failure counter to its u8 maximum and ensure the
    // exponential shift never overflows, always clamping to the max window.
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 1,
        .base_lockout_ms = 30_000,
        .max_lockout_ms = 3_600_000,
    });
    defer tracker.deinit();

    // Act: hammer the same key far beyond 62 doublings.
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        _ = tracker.recordFailure("flood", 0);
    }

    // Assert: counter saturates at 255 and lockout clamps to the cap.
    try std.testing.expectEqual(@as(u8, 255), tracker.failures("flood"));
    try std.testing.expectEqual(Decision.locked, tracker.check("flood", 3_599_999));
    try std.testing.expectEqual(Decision.allow, tracker.check("flood", 3_600_000));
}

test "max_tracked refuses new keys but serves existing ones" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_tracked = 1,
        .max_failures = 1,
        .base_lockout_ms = 1000,
    });
    defer tracker.deinit();

    // Act: first key is admitted and locked.
    try std.testing.expectEqual(Decision.locked, tracker.recordFailure("first", 0));

    // Assert: a second distinct key is refused (allow, untracked).
    try std.testing.expectEqual(Decision.allow, tracker.recordFailure("second", 0));
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
    // The existing key still accrues failures.
    _ = tracker.recordFailure("first", 0);
    try std.testing.expectEqual(@as(u8, 2), tracker.failures("first"));
}

test "long keys exceeding the inline buffer are handled on the heap" {
    // Arrange: a key longer than the 256-byte stack buffer forces the heap
    // normalisation path through every method.
    var tracker = Tracker.init(std.testing.allocator, .{
        .max_failures = 2,
        .base_lockout_ms = 1000,
    });
    defer tracker.deinit();
    const long_key = "X" ** 300;

    // Act
    _ = tracker.recordFailure(long_key, 0);
    _ = tracker.recordFailure(long_key, 0);

    // Assert: stored lowercased and locked; success clears it cleanly.
    try std.testing.expectEqual(@as(u8, 2), tracker.failures("x" ** 300));
    try std.testing.expectEqual(Decision.locked, tracker.check(long_key, 0));
    tracker.recordSuccess(long_key);
    try std.testing.expectEqual(@as(usize, 0), tracker.count());
}

test "deinit frees all keys with no leaks" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator, .{});

    // Act: populate several distinct keys, then tear down.
    _ = tracker.recordFailure("one", 0);
    _ = tracker.recordFailure("two", 0);
    _ = tracker.recordFailure("three", 0);

    // Assert: deinit must release every owned key (testing allocator fails on
    // any leak), which is verified simply by completing teardown.
    try std.testing.expectEqual(@as(usize, 3), tracker.count());
    tracker.deinit();
}
