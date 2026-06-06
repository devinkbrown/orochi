//! Pure per-connection timeout state machine for client liveness.
//!
//! This module is distinct from `connection_class`: that registry holds *static*
//! per-class configuration (caps, queue sizes, a nominal ping cadence), whereas
//! `timeout_policy` tracks the *dynamic* liveness of a single connection over
//! time. It answers one question on each `tick`: given the current clock, should
//! the caller send a keepalive PING, or drop the connection because it failed to
//! register in time or stopped answering pings?
//!
//! The state machine is fully deterministic and clock-injected — every method
//! that reasons about elapsed time takes an explicit monotonic millisecond
//! timestamp. It allocates nothing and owns no resources, so it needs no
//! `deinit`. Callers embed a `ConnTimer` value per connection.
//!
//! Lifecycle:
//!   var timer = ConnTimer.init(policy, connected_at_ms);
//!   // on inbound traffic:
//!   timer.recordActivity(now_ms);
//!   // on successful NICK + USER:
//!   timer.markRegistered(now_ms);
//!   // on PONG:
//!   timer.recordPong(now_ms);
//!   // periodically:
//!   switch (timer.tick(now_ms)) { ... }

const std = @import("std");

/// Tunable timeout windows, all expressed in milliseconds.
///
/// All fields must be non-zero; `validate` rejects degenerate policies that
/// would either disable a timeout or busy-loop the caller.
pub const Policy = struct {
    /// Time an unregistered connection has to complete NICK + USER.
    ///
    /// Measured from the connection's `connected_at` timestamp. If the
    /// connection has not registered before this elapses, `tick` returns
    /// `.drop_registration_timeout`.
    registration_ms: u64 = 30_000,

    /// Idle window after which a keepalive PING is sent.
    ///
    /// Measured from the last recorded inbound activity. Only applies once the
    /// connection is registered; unregistered connections are governed solely by
    /// `registration_ms`.
    ping_interval_ms: u64 = 120_000,

    /// Grace window for a PONG after a PING has been emitted.
    ///
    /// Measured from the moment `tick` returned `.send_ping` and the caller
    /// recorded it via `recordPingSent`. If no PONG (or other inbound activity)
    /// arrives within this window, `tick` returns `.drop_ping_timeout`.
    ping_timeout_ms: u64 = 60_000,
};

/// Errors returned when constructing or validating a policy.
pub const PolicyError = error{
    /// A required window was zero.
    ZeroWindow,
};

/// The action a caller should take after a `tick`.
pub const Action = enum {
    /// Nothing to do; the connection is within all windows.
    none,
    /// Emit a keepalive PING and call `recordPingSent` with the same clock.
    send_ping,
    /// The connection never registered in time; close it.
    drop_registration_timeout,
    /// A PING went unanswered within `ping_timeout_ms`; close it.
    drop_ping_timeout,
};

/// Validate a policy, returning it unchanged when every window is non-zero.
pub fn validate(policy: Policy) PolicyError!Policy {
    if (policy.registration_ms == 0) return error.ZeroWindow;
    if (policy.ping_interval_ms == 0) return error.ZeroWindow;
    if (policy.ping_timeout_ms == 0) return error.ZeroWindow;
    return policy;
}

/// Per-connection liveness state machine.
///
/// Holds no allocations; copy or embed it freely. All timestamps are caller
/// supplied monotonic millisecond values; the timer never reads a real clock.
pub const ConnTimer = struct {
    /// Timeout windows governing this connection.
    policy: Policy,

    /// Last timestamp at which inbound bytes were observed.
    ///
    /// Seeded to the connection time and advanced by `recordActivity`,
    /// `recordPong`, and `markRegistered`.
    last_activity_ms: u64,

    /// Timestamp at which the connection was opened.
    ///
    /// The registration deadline is measured relative to this value.
    connected_at_ms: u64,

    /// Timestamp at which an unanswered PING was emitted, if any.
    ///
    /// `null` means no PING is currently outstanding. Set by `recordPingSent`
    /// and cleared by any inbound activity.
    ping_sent_ms: ?u64 = null,

    /// Whether NICK + USER registration has completed.
    registered: bool = false,

    /// Initialize a timer for a freshly accepted connection.
    ///
    /// `connected_at_ms` anchors the registration deadline and seeds the
    /// activity clock so an idle-from-birth connection is treated consistently.
    pub fn init(policy: Policy, connected_at_ms: u64) ConnTimer {
        return .{
            .policy = policy,
            .last_activity_ms = connected_at_ms,
            .connected_at_ms = connected_at_ms,
        };
    }

    /// Record inbound activity, refreshing the idle clock and clearing any
    /// outstanding PING (the peer is demonstrably alive).
    pub fn recordActivity(self: *ConnTimer, now_ms: u64) void {
        self.last_activity_ms = now_ms;
        self.ping_sent_ms = null;
    }

    /// Record a PONG. Semantically identical to other inbound activity but named
    /// for call-site clarity.
    pub fn recordPong(self: *ConnTimer, now_ms: u64) void {
        self.recordActivity(now_ms);
    }

    /// Mark the connection as registered (NICK + USER complete).
    ///
    /// This also counts as activity, so a connection that registers right at the
    /// deadline is not immediately dropped.
    pub fn markRegistered(self: *ConnTimer, now_ms: u64) void {
        self.registered = true;
        self.recordActivity(now_ms);
    }

    /// Record that the caller emitted the PING requested by a prior `tick`.
    ///
    /// Starts the `ping_timeout_ms` grace window. Idempotent transitions are the
    /// caller's responsibility: only call this after `tick` returned
    /// `.send_ping`.
    pub fn recordPingSent(self: *ConnTimer, now_ms: u64) void {
        self.ping_sent_ms = now_ms;
    }

    /// Evaluate liveness at `now_ms` and return the action the caller should
    /// take. Pure: calling `tick` never mutates the timer, so it is safe to call
    /// repeatedly. Callers drive state via the `record*`/`mark*` methods.
    ///
    /// Precedence:
    ///   1. Unregistered + past registration deadline -> drop_registration_timeout
    ///   2. Outstanding PING past its grace window      -> drop_ping_timeout
    ///   3. Registered + idle past ping interval (no PING outstanding) -> send_ping
    ///   4. Otherwise                                   -> none
    ///
    /// Timestamps that move backwards (a non-monotonic clock) are treated as
    /// "no time elapsed" via saturating subtraction, so a clock glitch can never
    /// manufacture a spurious drop.
    pub fn tick(self: *const ConnTimer, now_ms: u64) Action {
        if (!self.registered) {
            if (saturatingSince(now_ms, self.connected_at_ms) >= self.policy.registration_ms) {
                return .drop_registration_timeout;
            }
            return .none;
        }

        if (self.ping_sent_ms) |sent| {
            if (saturatingSince(now_ms, sent) >= self.policy.ping_timeout_ms) {
                return .drop_ping_timeout;
            }
            // A PING is outstanding but still within grace; nothing new to do.
            return .none;
        }

        if (saturatingSince(now_ms, self.last_activity_ms) >= self.policy.ping_interval_ms) {
            return .send_ping;
        }

        return .none;
    }
};

/// Elapsed milliseconds from `then` to `now`, saturating to zero when the clock
/// appears to have moved backwards.
fn saturatingSince(now_ms: u64, then_ms: u64) u64 {
    return if (now_ms > then_ms) now_ms - then_ms else 0;
}

const testing = std.testing;

test "validate rejects zero windows" {
    try testing.expectError(error.ZeroWindow, validate(.{ .registration_ms = 0 }));
    try testing.expectError(error.ZeroWindow, validate(.{ .ping_interval_ms = 0 }));
    try testing.expectError(error.ZeroWindow, validate(.{ .ping_timeout_ms = 0 }));

    const ok = try validate(.{});
    try testing.expectEqual(@as(u64, 30_000), ok.registration_ms);
}

test "unregistered connection stays alive before the registration deadline" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    const timer = ConnTimer.init(policy, 100);

    try testing.expectEqual(Action.none, timer.tick(100));
    try testing.expectEqual(Action.none, timer.tick(999 + 100));
}

test "unregistered connection drops at the registration deadline" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    const timer = ConnTimer.init(policy, 100);

    // Exactly at the deadline counts as expired.
    try testing.expectEqual(Action.drop_registration_timeout, timer.tick(1100));
    try testing.expectEqual(Action.drop_registration_timeout, timer.tick(5000));
}

test "registering before the deadline suppresses the registration drop" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    var timer = ConnTimer.init(policy, 0);

    timer.markRegistered(500);
    // Even well past the original registration window, a registered connection
    // is governed by ping timing, not the registration deadline.
    try testing.expectEqual(Action.none, timer.tick(2000));
}

test "idle registered connection requests a ping after the interval" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    var timer = ConnTimer.init(policy, 0);
    timer.markRegistered(0);

    // Before the interval: nothing.
    try testing.expectEqual(Action.none, timer.tick(4999));
    // At the interval: send a ping.
    try testing.expectEqual(Action.send_ping, timer.tick(5000));
}

test "recording activity resets the idle ping clock" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    var timer = ConnTimer.init(policy, 0);
    timer.markRegistered(0);

    timer.recordActivity(4000);
    // The idle window now restarts from 4000, so 5000 is only 1000ms idle.
    try testing.expectEqual(Action.none, timer.tick(5000));
    try testing.expectEqual(Action.send_ping, timer.tick(9000));
}

test "outstanding ping with no pong drops at the ping timeout" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    var timer = ConnTimer.init(policy, 0);
    timer.markRegistered(0);

    try testing.expectEqual(Action.send_ping, timer.tick(5000));
    timer.recordPingSent(5000);

    // Within grace: no new action while waiting for the pong.
    try testing.expectEqual(Action.none, timer.tick(6999));
    // At the grace deadline: drop.
    try testing.expectEqual(Action.drop_ping_timeout, timer.tick(7000));
}

test "a pong before the ping timeout keeps the connection alive" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    var timer = ConnTimer.init(policy, 0);
    timer.markRegistered(0);

    try testing.expectEqual(Action.send_ping, timer.tick(5000));
    timer.recordPingSent(5000);

    timer.recordPong(6000);
    // Pong clears the outstanding ping and resets the idle clock.
    try testing.expectEqual(Action.none, timer.tick(7000));
    // The next ping is due an interval after the pong, not after the old ping.
    try testing.expectEqual(Action.send_ping, timer.tick(11_000));
}

test "registration drop takes precedence over a stale ping window" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    const timer = ConnTimer.init(policy, 0);

    // Never registered, so the registration deadline governs regardless of how
    // far past the ping windows we are.
    try testing.expectEqual(Action.drop_registration_timeout, timer.tick(100_000));
}

test "non-monotonic clock never manufactures a drop" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    var timer = ConnTimer.init(policy, 10_000);
    timer.markRegistered(10_000);
    timer.recordPingSent(10_000);

    // Clock moved backwards relative to the recorded timestamps.
    try testing.expectEqual(Action.none, timer.tick(5000));
}

test "tick is pure and repeatable" {
    const policy = Policy{ .registration_ms = 1000, .ping_interval_ms = 5000, .ping_timeout_ms = 2000 };
    var timer = ConnTimer.init(policy, 0);
    timer.markRegistered(0);

    // Calling tick many times must not change the outcome.
    try testing.expectEqual(Action.send_ping, timer.tick(5000));
    try testing.expectEqual(Action.send_ping, timer.tick(5000));
    try testing.expectEqual(Action.send_ping, timer.tick(5000));
    // And the timer's observable fields are unchanged by tick.
    try testing.expectEqual(@as(?u64, null), timer.ping_sent_ms);
    try testing.expectEqual(@as(u64, 0), timer.last_activity_ms);
}
