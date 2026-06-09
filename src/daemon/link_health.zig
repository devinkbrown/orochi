//! Per-peer S2S mesh link health tracker.
//!
//! Pure data structure + math: maintains live quality metrics for each mesh
//! peer link that the `MESH`/`NETSTAT` oper view consumes. It owns no sockets,
//! no server types, and performs no I/O or allocation — the registry is a
//! fixed-capacity table that copies peer names on insert so callers may pass
//! transient slices.
//!
//! Time is supplied by the caller as a monotonic millisecond clock; this module
//! never reads the system clock.
const std = @import("std");

/// Lifecycle state of a mesh peer link. Names mirror the Suimyaku link state
/// machine (idle -> handshaking -> established -> draining) so values map 1:1
/// onto the mesh report enum, with `connecting` covering pre-handshake dialing
/// and `down` covering a closed/dead link.
pub const PeerState = enum {
    connecting,
    handshaking,
    established,
    draining,
    down,
};

/// Maximum length of a peer name the registry will store. Names longer than
/// this are truncated on copy.
pub const max_name_len: usize = 64;

/// Number of recent RTT samples retained for jitter estimation.
pub const rtt_ring_len: usize = 8;

/// EWMA smoothing factor numerator/denominator. The smoothed RTT is updated as
///   ewma = ewma + alpha * (sample - ewma)
/// with alpha = alpha_num / alpha_den. The default (1/8) weights history
/// heavily while still tracking sustained changes, matching common TCP RTT
/// smoothing practice.
pub const default_alpha_num: u32 = 1;
pub const default_alpha_den: u32 = 8;

/// Live health metrics for a single mesh peer link.
pub const LinkHealth = struct {
    /// Current lifecycle state.
    state: PeerState = .connecting,
    /// Monotonic-ms timestamp of the last state transition.
    state_since_ms: u64 = 0,
    /// Monotonic-ms timestamp of the last observed activity (rtt/bytes).
    last_activity_ms: u64 = 0,

    /// Smoothed RTT in milliseconds (fixed-point f64), or null until the first
    /// sample is observed.
    ewma_rtt_ms: ?f64 = null,
    /// EWMA smoothing factor.
    alpha_num: u32 = default_alpha_num,
    alpha_den: u32 = default_alpha_den,

    /// Cumulative bytes received from / sent to this peer.
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,

    /// Bounded ring of recent raw RTT samples (ms) for jitter estimation.
    rtt_ring: [rtt_ring_len]u32 = [_]u32{0} ** rtt_ring_len,
    /// Number of valid entries currently in the ring (saturates at len).
    rtt_count: u8 = 0,
    /// Next write index into the ring.
    rtt_head: u8 = 0,

    /// Create a health record in the initial `connecting` state at `now_ms`.
    pub fn init(now_ms: u64) LinkHealth {
        return .{
            .state = .connecting,
            .state_since_ms = now_ms,
            .last_activity_ms = now_ms,
        };
    }

    /// Create a health record with a custom EWMA alpha. `alpha_den` is clamped
    /// to at least 1 to avoid division by zero.
    pub fn initWithAlpha(now_ms: u64, alpha_num: u32, alpha_den: u32) LinkHealth {
        var self = init(now_ms);
        self.alpha_num = alpha_num;
        self.alpha_den = @max(alpha_den, 1);
        return self;
    }

    /// Record a state transition. Resets the in-state timer to `now_ms` and
    /// counts as activity. Transitioning to the same state still refreshes the
    /// timestamp (e.g. a re-handshake).
    pub fn transition(self: *LinkHealth, new_state: PeerState, now_ms: u64) void {
        self.state = new_state;
        self.state_since_ms = now_ms;
        self.last_activity_ms = now_ms;
    }

    /// Milliseconds spent in the current state as of `now_ms`. Guards against a
    /// clock that appears to move backwards by returning 0.
    pub fn since(self: *const LinkHealth, now_ms: u64) u64 {
        if (now_ms <= self.state_since_ms) return 0;
        return now_ms - self.state_since_ms;
    }

    /// Feed a fresh RTT sample (ms). Updates the EWMA, pushes onto the jitter
    /// ring, and marks activity.
    pub fn observeRtt(self: *LinkHealth, rtt_ms: u32, now_ms: u64) void {
        const sample: f64 = @floatFromInt(rtt_ms);
        if (self.ewma_rtt_ms) |prev| {
            const alpha = @as(f64, @floatFromInt(self.alpha_num)) /
                @as(f64, @floatFromInt(@max(self.alpha_den, 1)));
            self.ewma_rtt_ms = prev + alpha * (sample - prev);
        } else {
            self.ewma_rtt_ms = sample;
        }

        self.rtt_ring[self.rtt_head] = rtt_ms;
        self.rtt_head = @intCast((@as(usize, self.rtt_head) + 1) % rtt_ring_len);
        if (self.rtt_count < rtt_ring_len) self.rtt_count += 1;

        self.last_activity_ms = now_ms;
    }

    /// Accumulate received-byte count and mark activity.
    pub fn addIn(self: *LinkHealth, n: u64, now_ms: u64) void {
        self.bytes_in +%= n;
        self.last_activity_ms = now_ms;
    }

    /// Accumulate sent-byte count and mark activity.
    pub fn addOut(self: *LinkHealth, n: u64, now_ms: u64) void {
        self.bytes_out +%= n;
        self.last_activity_ms = now_ms;
    }

    /// Smoothed RTT rounded to whole milliseconds. Returns 0 if no sample yet.
    pub fn snapshotRtt(self: *const LinkHealth) u32 {
        const v = self.ewma_rtt_ms orelse return 0;
        if (v <= 0) return 0;
        return @intFromFloat(@round(v));
    }

    /// Mean absolute deviation of the retained RTT samples, in ms. A crude but
    /// stable jitter estimate; returns 0 with fewer than two samples.
    pub fn jitterMs(self: *const LinkHealth) u32 {
        const n: usize = self.rtt_count;
        if (n < 2) return 0;

        var sum: u64 = 0;
        for (0..n) |i| sum += self.rtt_ring[i];
        const mean: f64 = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(n));

        var dev: f64 = 0;
        for (0..n) |i| {
            const s: f64 = @floatFromInt(self.rtt_ring[i]);
            dev += @abs(s - mean);
        }
        const jitter = dev / @as(f64, @floatFromInt(n));
        if (jitter <= 0) return 0;
        return @intFromFloat(@round(jitter));
    }

    /// Milliseconds since the last observed activity as of `now_ms`.
    pub fn idleMs(self: *const LinkHealth, now_ms: u64) u64 {
        if (now_ms <= self.last_activity_ms) return 0;
        return now_ms - self.last_activity_ms;
    }
};

/// One named slot in the registry.
pub const Entry = struct {
    name_buf: [max_name_len]u8 = [_]u8{0} ** max_name_len,
    name_len: usize = 0,
    health: LinkHealth = .{},
    used: bool = false,

    /// Borrowed view of this entry's owned name bytes.
    pub fn name(self: *const Entry) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Fixed-capacity table of peer links keyed by name. No allocation: capacity is
/// chosen at compile time (default 64 peers). Names are copied on insert so
/// callers may pass transient slices.
pub fn Table(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        /// Slot capacity of this table.
        pub const cap: usize = capacity;

        slots: [capacity]Entry = [_]Entry{.{}} ** capacity,

        pub fn init() Self {
            return .{};
        }

        /// Number of occupied slots.
        pub fn len(self: *const Self) usize {
            var n: usize = 0;
            for (self.slots) |slot| {
                if (slot.used) n += 1;
            }
            return n;
        }

        fn truncatedLen(name: []const u8) usize {
            return @min(name.len, max_name_len);
        }

        fn matches(slot: *const Entry, name: []const u8) bool {
            if (!slot.used) return false;
            const want = truncatedLen(name);
            if (slot.name_len != want) return false;
            return std.mem.eql(u8, slot.name_buf[0..slot.name_len], name[0..want]);
        }

        /// Find the health record for `name`, or null if absent.
        pub fn get(self: *Self, name: []const u8) ?*LinkHealth {
            for (&self.slots) |*slot| {
                if (matches(slot, name)) return &slot.health;
            }
            return null;
        }

        /// Find the full entry for `name`, or null if absent.
        pub fn getEntry(self: *Self, name: []const u8) ?*Entry {
            for (&self.slots) |*slot| {
                if (matches(slot, name)) return slot;
            }
            return null;
        }

        /// Return the existing record for `name`, or create a fresh one in the
        /// `connecting` state. Returns error.TableFull if at capacity and the
        /// name is new. Copies the name (truncated to `max_name_len`).
        pub fn upsert(self: *Self, name: []const u8, now_ms: u64) !*LinkHealth {
            if (self.get(name)) |existing| return existing;

            for (&self.slots) |*slot| {
                if (slot.used) continue;
                const n = truncatedLen(name);
                @memcpy(slot.name_buf[0..n], name[0..n]);
                slot.name_len = n;
                slot.health = LinkHealth.init(now_ms);
                slot.used = true;
                return &slot.health;
            }
            return error.TableFull;
        }

        /// Remove the record for `name`. Returns true if a slot was freed.
        pub fn remove(self: *Self, name: []const u8) bool {
            for (&self.slots) |*slot| {
                if (matches(slot, name)) {
                    slot.* = .{};
                    return true;
                }
            }
            return false;
        }

        /// Iterator over occupied entries, for rendering the oper view.
        pub const Iterator = struct {
            table: *Self,
            idx: usize = 0,

            pub fn next(self: *Iterator) ?*Entry {
                while (self.idx < self.table.slots.len) {
                    const slot = &self.table.slots[self.idx];
                    self.idx += 1;
                    if (slot.used) return slot;
                }
                return null;
            }
        };

        /// Iterate over all occupied entries.
        pub fn entries(self: *Self) Iterator {
            return .{ .table = self };
        }
    };
}

/// Default registry: a 64-peer table.
pub const Registry = Table(64);

const testing = std.testing;

test "EWMA converges toward a steady RTT" {
    // Arrange
    var h = LinkHealth.init(0);

    // Act: feed a constant 100ms RTT repeatedly from a cold start.
    var t: u64 = 0;
    for (0..40) |_| {
        t += 10;
        h.observeRtt(100, t);
    }

    // Assert: smoothed RTT should be at (first sample seeds it) the steady value.
    try testing.expectEqual(@as(u32, 100), h.snapshotRtt());

    // Act: now shift the steady value to 200ms and let it converge.
    for (0..200) |_| {
        t += 10;
        h.observeRtt(200, t);
    }

    // Assert: EWMA tracks the new steady state.
    try testing.expectEqual(@as(u32, 200), h.snapshotRtt());
}

test "EWMA seeds on first sample then smooths a step" {
    // Arrange: alpha = 1/2 so a step moves the average halfway each tick.
    var h = LinkHealth.initWithAlpha(0, 1, 2);

    // Act + Assert: first sample seeds directly.
    h.observeRtt(40, 1);
    try testing.expectEqual(@as(u32, 40), h.snapshotRtt());

    // Step to 80: 40 + 0.5*(80-40) = 60.
    h.observeRtt(80, 2);
    try testing.expectEqual(@as(u32, 60), h.snapshotRtt());

    // Again: 60 + 0.5*(80-60) = 70.
    h.observeRtt(80, 3);
    try testing.expectEqual(@as(u32, 70), h.snapshotRtt());
}

test "snapshotRtt is zero before any sample" {
    const h = LinkHealth.init(5);
    try testing.expectEqual(@as(u32, 0), h.snapshotRtt());
    try testing.expectEqual(@as(u32, 0), h.jitterMs());
}

test "state transitions update since and reset the timer" {
    // Arrange
    var h = LinkHealth.init(1000);
    try testing.expectEqual(PeerState.connecting, h.state);
    try testing.expectEqual(@as(u64, 0), h.since(1000));
    try testing.expectEqual(@as(u64, 250), h.since(1250));

    // Act
    h.transition(.handshaking, 1300);

    // Assert: timer resets at the transition moment.
    try testing.expectEqual(PeerState.handshaking, h.state);
    try testing.expectEqual(@as(u64, 0), h.since(1300));
    try testing.expectEqual(@as(u64, 700), h.since(2000));

    // Act + Assert: full lifecycle to down.
    h.transition(.established, 2000);
    try testing.expectEqual(PeerState.established, h.state);
    h.transition(.draining, 3000);
    h.transition(.down, 3500);
    try testing.expectEqual(PeerState.down, h.state);
    try testing.expectEqual(@as(u64, 500), h.since(4000));
}

test "since guards against a backwards clock" {
    var h = LinkHealth.init(1000);
    try testing.expectEqual(@as(u64, 0), h.since(900));
}

test "byte counters accumulate independently" {
    // Arrange
    var h = LinkHealth.init(0);

    // Act
    h.addIn(100, 1);
    h.addIn(50, 2);
    h.addOut(200, 3);

    // Assert
    try testing.expectEqual(@as(u64, 150), h.bytes_in);
    try testing.expectEqual(@as(u64, 200), h.bytes_out);
    try testing.expectEqual(@as(u64, 3), h.last_activity_ms);
    try testing.expectEqual(@as(u64, 7), h.idleMs(10));
}

test "jitter is zero for constant samples and positive for varying ones" {
    // Arrange: constant RTT -> no jitter.
    var steady = LinkHealth.init(0);
    for (0..5) |i| steady.observeRtt(50, @intCast(i));
    try testing.expectEqual(@as(u32, 0), steady.jitterMs());

    // Act: alternating samples produce non-zero jitter.
    var noisy = LinkHealth.init(0);
    noisy.observeRtt(10, 1);
    noisy.observeRtt(90, 2);
    noisy.observeRtt(10, 3);
    noisy.observeRtt(90, 4);

    // Assert: mean is 50, mean abs deviation is 40.
    try testing.expectEqual(@as(u32, 40), noisy.jitterMs());
}

test "jitter ring is bounded and wraps" {
    // Arrange
    var h = LinkHealth.init(0);

    // Act: push more than the ring capacity.
    for (0..rtt_ring_len + 4) |i| h.observeRtt(@intCast(i), @intCast(i));

    // Assert: count saturates at the ring length.
    try testing.expectEqual(@as(u8, @intCast(rtt_ring_len)), h.rtt_count);
}

test "registry upsert returns same record and is idempotent" {
    // Arrange
    var reg = Registry.init();

    // Act
    const a1 = try reg.upsert("alpha", 100);
    a1.transition(.established, 200);
    const a2 = try reg.upsert("alpha", 999);

    // Assert: upsert of an existing name returns the same record untouched.
    try testing.expectEqual(a1, a2);
    try testing.expectEqual(PeerState.established, a2.state);
    try testing.expectEqual(@as(usize, 1), reg.len());
}

test "registry get and remove" {
    // Arrange
    var reg = Registry.init();
    _ = try reg.upsert("beta", 0);
    _ = try reg.upsert("gamma", 0);

    // Act + Assert
    try testing.expect(reg.get("beta") != null);
    try testing.expect(reg.get("missing") == null);
    try testing.expect(reg.remove("beta"));
    try testing.expect(reg.get("beta") == null);
    try testing.expect(!reg.remove("beta"));
    try testing.expectEqual(@as(usize, 1), reg.len());
}

test "registry owns name bytes copied from transient slices" {
    // Arrange
    var reg = Registry.init();
    var buf = [_]u8{ 'p', 'e', 'e', 'r', '1' };

    // Act: insert from a mutable buffer, then mutate the buffer.
    _ = try reg.upsert(&buf, 0);
    @memset(&buf, 'x');

    // Assert: stored name is unaffected by the caller's mutation.
    const entry = reg.getEntry("peer1").?;
    try testing.expectEqualStrings("peer1", entry.name());
}

test "registry enforces capacity limit" {
    // Arrange: tiny table to exercise the full path.
    var tiny = Table(2).init();

    // Act
    _ = try tiny.upsert("one", 0);
    _ = try tiny.upsert("two", 0);

    // Assert: third distinct name overflows.
    try testing.expectError(error.TableFull, tiny.upsert("three", 0));

    // Existing names still upsert fine even when full and return the same record.
    const one_again = try tiny.upsert("one", 0);
    try testing.expectEqual(tiny.get("one").?, one_again);

    // Freeing a slot makes room again.
    try testing.expect(tiny.remove("one"));
    _ = try tiny.upsert("three", 0);
    try testing.expectEqual(@as(usize, 2), tiny.len());
}

test "registry iterator visits every occupied entry once" {
    // Arrange
    var reg = Registry.init();
    _ = try reg.upsert("a", 0);
    _ = try reg.upsert("b", 0);
    _ = try reg.upsert("c", 0);
    _ = reg.remove("b");

    // Act
    var seen: usize = 0;
    var it = reg.entries();
    while (it.next()) |e| {
        try testing.expect(e.used);
        seen += 1;
    }

    // Assert
    try testing.expectEqual(@as(usize, 2), seen);
}

test "long peer names are truncated to max_name_len on copy" {
    // Arrange
    var reg = Registry.init();
    const long = "n" ** (max_name_len + 10);

    // Act
    _ = try reg.upsert(long, 0);

    // Assert: stored name is exactly max_name_len and lookups by the long
    // (truncated-equal) name still resolve.
    const entry = reg.getEntry(long).?;
    try testing.expectEqual(max_name_len, entry.name().len);
    try testing.expect(reg.get(long) != null);
}
