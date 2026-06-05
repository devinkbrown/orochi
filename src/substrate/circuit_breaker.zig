//! Deterministic circuit breaker with a small rolling failure window.
//!
//! Callers provide time explicitly through `allow(now_ms)` and
//! `onFailure(now_ms)`. `onSuccess()` records the success at the most recent
//! allowed timestamp, which keeps the usual allow -> operation -> success flow
//! deterministic without reading a process clock.

const std = @import("std");

/// Externally visible state for a circuit breaker.
pub const BreakerState = enum {
    closed,
    open,
    half_open,
};

/// Maximum number of recent outcomes retained for rate-based tripping.
pub const max_window_events = 256;

/// Circuit breaker behavior knobs.
pub const Config = struct {
    /// Consecutive failures required to trip immediately while closed.
    failure_threshold: u32 = 5,
    /// How long the breaker remains open before allowing half-open probes.
    cooldown_ms: u64 = 30_000,
    /// Time span covered by the rolling error-rate window.
    rolling_window_ms: u64 = 60_000,
    /// Minimum retained outcomes before error-rate tripping is considered.
    min_window_calls: u32 = 20,
    /// Failure percentage, from 1 to 100, that trips the breaker.
    failure_rate_percent: u8 = 50,
    /// Number of concurrent half-open probes to allow after cooldown.
    half_open_max_probes: u32 = 1,

    pub fn normalized(self: Config) Config {
        return .{
            .failure_threshold = @max(self.failure_threshold, 1),
            .cooldown_ms = self.cooldown_ms,
            .rolling_window_ms = self.rolling_window_ms,
            .min_window_calls = @max(self.min_window_calls, 1),
            .failure_rate_percent = std.math.clamp(self.failure_rate_percent, 1, 100),
            .half_open_max_probes = @max(self.half_open_max_probes, 1),
        };
    }
};

const Outcome = enum {
    success,
    failure,
};

const WindowEvent = struct {
    at_ms: u64,
    outcome: Outcome,
};

pub const WindowStats = struct {
    total: u32 = 0,
    failures: u32 = 0,
};

/// Circuit breaker state machine.
pub const CircuitBreaker = struct {
    config: Config,
    current_state: BreakerState = .closed,
    opened_at_ms: ?u64 = null,
    last_allowed_ms: u64 = 0,
    consecutive_failures: u32 = 0,
    half_open_in_flight: u32 = 0,
    events: [max_window_events]WindowEvent = undefined,
    event_start: usize = 0,
    event_len: usize = 0,

    pub fn init(config: Config) CircuitBreaker {
        return .{ .config = config.normalized() };
    }

    /// Return the current state.
    pub fn state(self: CircuitBreaker) BreakerState {
        return self.current_state;
    }

    /// Return whether a call may be attempted at `now_ms`.
    ///
    /// While open this returns false until the cooldown has elapsed. At that
    /// point the breaker enters half-open and grants up to
    /// `half_open_max_probes` probes.
    pub fn allow(self: *CircuitBreaker, now_ms: u64) bool {
        self.refreshOpen(now_ms);

        switch (self.current_state) {
            .closed => {
                self.last_allowed_ms = now_ms;
                return true;
            },
            .open => return false,
            .half_open => {
                if (self.half_open_in_flight >= self.config.half_open_max_probes) {
                    return false;
                }

                self.half_open_in_flight += 1;
                self.last_allowed_ms = now_ms;
                return true;
            },
        }
    }

    /// Record a successful allowed call.
    pub fn onSuccess(self: *CircuitBreaker) void {
        switch (self.current_state) {
            .closed => {
                self.consecutive_failures = 0;
                self.record(.success, self.last_allowed_ms);
            },
            .open => {},
            .half_open => self.close(),
        }
    }

    /// Record a failed call at `now_ms`.
    pub fn onFailure(self: *CircuitBreaker, now_ms: u64) void {
        switch (self.current_state) {
            .closed => {
                self.consecutive_failures = saturatingAdd(self.consecutive_failures, 1);
                self.record(.failure, now_ms);
                if (self.consecutive_failures >= self.config.failure_threshold or self.windowTrips(now_ms)) {
                    self.open(now_ms);
                }
            },
            .open => {
                self.opened_at_ms = now_ms;
            },
            .half_open => self.open(now_ms),
        }
    }

    /// Clear all history and return to closed.
    pub fn reset(self: *CircuitBreaker) void {
        const config = self.config;
        self.* = .{ .config = config };
    }

    /// Return the current rolling-window counts after pruning by `now_ms`.
    pub fn windowStats(self: *CircuitBreaker, now_ms: u64) WindowStats {
        self.prune(now_ms);
        return self.stats();
    }

    fn refreshOpen(self: *CircuitBreaker, now_ms: u64) void {
        if (self.current_state != .open) return;

        const opened_at = self.opened_at_ms orelse now_ms;
        if (elapsed(opened_at, now_ms) < self.config.cooldown_ms) return;

        self.current_state = .half_open;
        self.half_open_in_flight = 0;
    }

    fn close(self: *CircuitBreaker) void {
        self.current_state = .closed;
        self.opened_at_ms = null;
        self.consecutive_failures = 0;
        self.half_open_in_flight = 0;
        self.clearWindow();
    }

    fn open(self: *CircuitBreaker, now_ms: u64) void {
        self.current_state = .open;
        self.opened_at_ms = now_ms;
        self.half_open_in_flight = 0;
    }

    fn record(self: *CircuitBreaker, outcome: Outcome, now_ms: u64) void {
        self.prune(now_ms);

        if (self.event_len == max_window_events) {
            self.event_start = (self.event_start + 1) % max_window_events;
            self.event_len -= 1;
        }

        const index = (self.event_start + self.event_len) % max_window_events;
        self.events[index] = .{
            .at_ms = now_ms,
            .outcome = outcome,
        };
        self.event_len += 1;
    }

    fn prune(self: *CircuitBreaker, now_ms: u64) void {
        if (self.config.rolling_window_ms == 0) {
            self.clearWindow();
            return;
        }

        while (self.event_len > 0) {
            const oldest = self.events[self.event_start];
            if (elapsed(oldest.at_ms, now_ms) <= self.config.rolling_window_ms) break;
            self.event_start = (self.event_start + 1) % max_window_events;
            self.event_len -= 1;
        }
    }

    fn stats(self: CircuitBreaker) WindowStats {
        var out: WindowStats = .{};
        var i: usize = 0;
        while (i < self.event_len) : (i += 1) {
            const event = self.events[(self.event_start + i) % max_window_events];
            out.total += 1;
            if (event.outcome == .failure) out.failures += 1;
        }
        return out;
    }

    fn windowTrips(self: *CircuitBreaker, now_ms: u64) bool {
        const current = self.windowStats(now_ms);
        if (current.total < self.config.min_window_calls) return false;

        const failures = @as(u64, current.failures) * 100;
        const threshold = @as(u64, current.total) * self.config.failure_rate_percent;
        return failures >= threshold;
    }

    fn clearWindow(self: *CircuitBreaker) void {
        self.event_start = 0;
        self.event_len = 0;
    }
};

fn elapsed(start_ms: u64, now_ms: u64) u64 {
    if (now_ms >= start_ms) return now_ms - start_ms;
    return 0;
}

fn saturatingAdd(value: u32, amount: u32) u32 {
    const result, const overflow = @addWithOverflow(value, amount);
    return if (overflow == 0) result else std.math.maxInt(u32);
}

test "trips open after consecutive failure threshold" {
    var breaker = CircuitBreaker.init(.{
        .failure_threshold = 3,
        .cooldown_ms = 100,
        .min_window_calls = 100,
    });

    try std.testing.expectEqual(BreakerState.closed, breaker.state());
    try std.testing.expect(breaker.allow(10));
    breaker.onFailure(10);
    try std.testing.expectEqual(BreakerState.closed, breaker.state());

    try std.testing.expect(breaker.allow(11));
    breaker.onFailure(11);
    try std.testing.expectEqual(BreakerState.closed, breaker.state());

    try std.testing.expect(breaker.allow(12));
    breaker.onFailure(12);
    try std.testing.expectEqual(BreakerState.open, breaker.state());
}

test "rejects calls while open" {
    var breaker = CircuitBreaker.init(.{
        .failure_threshold = 1,
        .cooldown_ms = 50,
    });

    try std.testing.expect(breaker.allow(1));
    breaker.onFailure(1);

    try std.testing.expectEqual(BreakerState.open, breaker.state());
    try std.testing.expect(!breaker.allow(49));
    try std.testing.expect(!breaker.allow(50));
}

test "transitions to half-open after cooldown and closes on probe success" {
    var breaker = CircuitBreaker.init(.{
        .failure_threshold = 1,
        .cooldown_ms = 50,
        .half_open_max_probes = 1,
    });

    try std.testing.expect(breaker.allow(100));
    breaker.onFailure(100);
    try std.testing.expect(!breaker.allow(149));

    try std.testing.expect(breaker.allow(150));
    try std.testing.expectEqual(BreakerState.half_open, breaker.state());
    try std.testing.expect(!breaker.allow(151));

    breaker.onSuccess();
    try std.testing.expectEqual(BreakerState.closed, breaker.state());
    try std.testing.expect(breaker.allow(152));
}

test "half-open probe failure reopens immediately" {
    var breaker = CircuitBreaker.init(.{
        .failure_threshold = 1,
        .cooldown_ms = 10,
    });

    try std.testing.expect(breaker.allow(1));
    breaker.onFailure(1);
    try std.testing.expect(breaker.allow(11));
    try std.testing.expectEqual(BreakerState.half_open, breaker.state());

    breaker.onFailure(12);
    try std.testing.expectEqual(BreakerState.open, breaker.state());
    try std.testing.expect(!breaker.allow(21));
    try std.testing.expect(breaker.allow(22));
    try std.testing.expectEqual(BreakerState.half_open, breaker.state());
}

test "rolling failure-rate window trips open" {
    var breaker = CircuitBreaker.init(.{
        .failure_threshold = 100,
        .cooldown_ms = 100,
        .rolling_window_ms = 1_000,
        .min_window_calls = 4,
        .failure_rate_percent = 50,
    });

    try std.testing.expect(breaker.allow(1));
    breaker.onSuccess();
    try std.testing.expect(breaker.allow(2));
    breaker.onFailure(2);
    try std.testing.expect(breaker.allow(3));
    breaker.onSuccess();
    try std.testing.expectEqual(BreakerState.closed, breaker.state());

    try std.testing.expect(breaker.allow(4));
    breaker.onFailure(4);
    try std.testing.expectEqual(BreakerState.open, breaker.state());
}

test "rolling window resets when samples age out" {
    var breaker = CircuitBreaker.init(.{
        .failure_threshold = 100,
        .cooldown_ms = 100,
        .rolling_window_ms = 10,
        .min_window_calls = 3,
        .failure_rate_percent = 50,
    });

    try std.testing.expect(breaker.allow(1));
    breaker.onFailure(1);
    try std.testing.expect(breaker.allow(2));
    breaker.onFailure(2);

    var stats = breaker.windowStats(2);
    try std.testing.expectEqual(@as(u32, 2), stats.total);
    try std.testing.expectEqual(@as(u32, 2), stats.failures);

    try std.testing.expect(breaker.allow(20));
    breaker.onSuccess();
    stats = breaker.windowStats(20);
    try std.testing.expectEqual(@as(u32, 1), stats.total);
    try std.testing.expectEqual(@as(u32, 0), stats.failures);
    try std.testing.expectEqual(BreakerState.closed, breaker.state());
}

test "deterministic timestamps drive cooldown exactly" {
    var a = CircuitBreaker.init(.{
        .failure_threshold = 1,
        .cooldown_ms = 7,
    });
    var b = CircuitBreaker.init(.{
        .failure_threshold = 1,
        .cooldown_ms = 7,
    });

    try std.testing.expect(a.allow(5));
    try std.testing.expect(b.allow(5));
    a.onFailure(5);
    b.onFailure(5);

    try std.testing.expectEqual(a.state(), b.state());
    try std.testing.expectEqual(a.allow(11), b.allow(11));
    try std.testing.expectEqual(BreakerState.open, a.state());
    try std.testing.expectEqual(BreakerState.open, b.state());

    try std.testing.expectEqual(a.allow(12), b.allow(12));
    try std.testing.expectEqual(BreakerState.half_open, a.state());
    try std.testing.expectEqual(BreakerState.half_open, b.state());
}
