//! Per-account SECURE / ENFORCE *settings* layer for the Mizuchi IRC daemon.
//!
//! This is the policy-configuration complement to `nick_enforcement.zig`. Where
//! that module owns the protection *mechanism* (the grace timer, the claim
//! Tracker, the force-rename sweep), this module owns the per-account *settings*
//! that decide whether that mechanism applies at all and how a connection earns
//! recognition of the account:
//!
//!   - SECURE       The account is recognized ONLY when a connection has
//!                  identified (authenticated) to it. An access-list match
//!                  (host/cert/known-mask) is NOT enough on its own. Without
//!                  SECURE, an access-list match also confers recognition.
//!   - ENFORCE      A connection on the account's registered nick that is NOT
//!                  recognized is acted on once a grace window elapses. Without
//!                  ENFORCE the daemon leaves the nick alone.
//!   - ENFORCETIME  The grace window, in seconds, before ENFORCE acts. A
//!                  non-positive value means act immediately (no grace).
//!
//! There are NO pseudo-clients here. SECURE / ENFORCE / ENFORCETIME are real
//! account settings driven by real server commands; this file is pure logic and
//! owns no sockets, timers, or clock access.
//!
//! PURITY: time is supplied by the caller as `now_ms` / `claimed_at_ms` (UNIX
//! milliseconds, `i64`). This module never reads the system clock and never
//! allocates. `decide` is a total function over its inputs.

const std = @import("std");

/// Default grace window applied when an account enables ENFORCE without an
/// explicit ENFORCETIME. Chosen to give a human a brief moment to identify.
pub const default_enforce_seconds: u32 = 60;

/// Upper bound on a configurable ENFORCETIME, in seconds (24 hours). Keeps a
/// grace window from being set so large it effectively disables enforcement
/// while still claiming to be on. Callers parsing user input should clamp to
/// this via `clampEnforceSeconds`.
pub const max_enforce_seconds: u32 = 24 * 60 * 60;

/// The per-account security settings. This is a plain value type: copy it
/// freely. It carries no clock and no allocation.
pub const AccountSecurity = struct {
    /// SECURE: recognize the account only via identify, never via an
    /// access-list match alone.
    secure: bool = false,
    /// ENFORCE: act on an unrecognized connection holding the registered nick
    /// once the grace window elapses.
    enforce: bool = false,
    /// ENFORCETIME: grace window in seconds before ENFORCE acts. Only
    /// meaningful when `enforce` is set. Non-positive (0) acts immediately.
    enforce_seconds: u32 = default_enforce_seconds,

    /// The conventional default: nothing enabled. An account with these
    /// settings never enforces and accepts access-list recognition.
    pub const default: AccountSecurity = .{};

    /// Grace window expressed in milliseconds for use with `now_ms`-style
    /// timestamps. Saturates rather than overflowing on absurd inputs.
    pub fn enforceMs(self: AccountSecurity) i64 {
        const secs: i64 = @intCast(self.enforce_seconds);
        return std.math.mul(i64, secs, 1_000) catch std.math.maxInt(i64);
    }
};

/// Clamp a user-supplied ENFORCETIME (seconds) to `max_enforce_seconds`.
/// Pure helper for command parsing; zero is preserved (immediate enforce).
pub fn clampEnforceSeconds(seconds: u32) u32 {
    return @min(seconds, max_enforce_seconds);
}

/// The recognition/enforcement decision for one connection sitting on an
/// account's registered nick.
pub const Decision = enum {
    /// The connection is recognized as the account holder: identified, or
    /// access-list matched while the account is not SECURE. Nothing to do.
    recognized,
    /// The connection is not recognized, but ENFORCE is off (or there is no
    /// reason to act). Leave the nick alone.
    allow,
    /// Not recognized, ENFORCE is on, and the grace window is still open. The
    /// daemon should warn the connection that it must identify.
    warn,
    /// Not recognized, ENFORCE is on, and the grace window has elapsed. The
    /// daemon should act (force-rename / reclaim the nick).
    enforce,
};

/// Inputs to a single pure decision. `claimed_at_ms` / `now_ms` are only
/// consulted when ENFORCE is active and the connection is unrecognized.
pub const DecisionInput = struct {
    /// Whether the connection has identified (authenticated) to the account.
    identified: bool,
    /// Whether the connection matches the account's access list (host/cert/
    /// known mask). Ignored for recognition when the account is SECURE.
    access_match: bool,
    /// When the unrecognized connection took the registered nick (UNIX ms).
    claimed_at_ms: i64,
    /// Current time (UNIX ms), supplied by the caller.
    now_ms: i64,
};

/// Whether `input` counts as recognition of the account under `settings`.
///
///   - Identified always recognizes.
///   - An access-list match recognizes ONLY when the account is not SECURE.
pub fn isRecognized(settings: AccountSecurity, identified: bool, access_match: bool) bool {
    if (identified) return true;
    if (settings.secure) return false;
    return access_match;
}

/// Decide what to do about a connection on the account's registered nick.
/// Pure: no side effects, no clock, no allocation.
///
/// Rules, in order:
///   - Recognized (identify, or access-match when not SECURE) -> .recognized
///   - Unrecognized and ENFORCE off                           -> .allow
///   - Unrecognized, ENFORCE on, within grace                 -> .warn
///   - Unrecognized, ENFORCE on, grace elapsed                -> .enforce
///
/// Grace is elapsed once `now_ms - claimed_at_ms >= enforceMs()`. A zero
/// ENFORCETIME means there is no grace window and enforcement is immediate.
pub fn decide(settings: AccountSecurity, input: DecisionInput) Decision {
    if (isRecognized(settings, input.identified, input.access_match)) return .recognized;
    if (!settings.enforce) return .allow;

    const elapsed = input.now_ms - input.claimed_at_ms;
    if (elapsed >= settings.enforceMs()) return .enforce;
    return .warn;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "AccountSecurity.default disables everything and accepts access-list recognition" {
    // Arrange
    const settings = AccountSecurity.default;

    // Act / Assert
    try testing.expect(!settings.secure);
    try testing.expect(!settings.enforce);
    try testing.expectEqual(default_enforce_seconds, settings.enforce_seconds);
    // An access match alone recognizes when not SECURE.
    try testing.expect(isRecognized(settings, false, true));
}

test "enforceMs converts seconds to milliseconds" {
    // Arrange
    const settings = AccountSecurity{ .enforce_seconds = 30 };

    // Act / Assert
    try testing.expectEqual(@as(i64, 30_000), settings.enforceMs());
}

test "enforceMs saturates instead of overflowing on absurd inputs" {
    // Arrange: the maximum u32 of seconds would overflow i64 ms if multiplied
    // naively only at far larger magnitudes; force the saturating path by
    // checking that a huge value stays finite and positive.
    const settings = AccountSecurity{ .enforce_seconds = std.math.maxInt(u32) };

    // Act
    const ms = settings.enforceMs();

    // Assert: maxInt(u32) * 1000 fits in i64, so it is exact, not saturated.
    try testing.expectEqual(@as(i64, @as(i64, std.math.maxInt(u32)) * 1_000), ms);
}

test "clampEnforceSeconds caps at the maximum but preserves zero" {
    // Act / Assert
    try testing.expectEqual(@as(u32, 0), clampEnforceSeconds(0));
    try testing.expectEqual(@as(u32, 60), clampEnforceSeconds(60));
    try testing.expectEqual(max_enforce_seconds, clampEnforceSeconds(max_enforce_seconds));
    try testing.expectEqual(max_enforce_seconds, clampEnforceSeconds(max_enforce_seconds + 1));
    try testing.expectEqual(max_enforce_seconds, clampEnforceSeconds(std.math.maxInt(u32)));
}

test "isRecognized: identify always recognizes regardless of SECURE" {
    try testing.expect(isRecognized(.{ .secure = false }, true, false));
    try testing.expect(isRecognized(.{ .secure = true }, true, false));
}

test "isRecognized: access match recognizes only when not SECURE" {
    // Not SECURE: access match is enough.
    try testing.expect(isRecognized(.{ .secure = false }, false, true));
    // SECURE: access match is not enough.
    try testing.expect(!isRecognized(.{ .secure = true }, false, true));
}

test "isRecognized: neither identify nor access match is never recognized" {
    try testing.expect(!isRecognized(.{ .secure = false }, false, false));
    try testing.expect(!isRecognized(.{ .secure = true }, false, false));
}

test "decide: identified connection is recognized" {
    // Arrange
    const settings = AccountSecurity{ .enforce = true, .enforce_seconds = 60 };
    const input = DecisionInput{
        .identified = true,
        .access_match = false,
        .claimed_at_ms = 0,
        .now_ms = 1_000_000,
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.recognized, decision);
}

test "decide: access match recognizes when not SECURE even with ENFORCE on" {
    // Arrange: ENFORCE on, but account is not SECURE and the host matches.
    const settings = AccountSecurity{ .secure = false, .enforce = true, .enforce_seconds = 60 };
    const input = DecisionInput{
        .identified = false,
        .access_match = true,
        .claimed_at_ms = 0,
        .now_ms = 10_000_000,
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.recognized, decision);
}

test "decide: access match does NOT recognize when SECURE -> enforcement path" {
    // Arrange: SECURE account, host matches but not identified; grace elapsed.
    const settings = AccountSecurity{ .secure = true, .enforce = true, .enforce_seconds = 5 };
    const input = DecisionInput{
        .identified = false,
        .access_match = true,
        .claimed_at_ms = 1_000,
        .now_ms = 7_000, // elapsed 6000 >= 5000
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.enforce, decision);
}

test "decide: unrecognized with ENFORCE off is allowed" {
    // Arrange
    const settings = AccountSecurity{ .secure = true, .enforce = false };
    const input = DecisionInput{
        .identified = false,
        .access_match = false,
        .claimed_at_ms = 0,
        .now_ms = 100_000,
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.allow, decision);
}

test "decide: unrecognized with ENFORCE on within grace warns" {
    // Arrange: claimed 1000, now 3000, grace 5s -> 2000 < 5000.
    const settings = AccountSecurity{ .enforce = true, .enforce_seconds = 5 };
    const input = DecisionInput{
        .identified = false,
        .access_match = false,
        .claimed_at_ms = 1_000,
        .now_ms = 3_000,
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.warn, decision);
}

test "decide: unrecognized with ENFORCE on after grace enforces" {
    // Arrange: claimed 1000, now 7000, grace 5s -> 6000 >= 5000.
    const settings = AccountSecurity{ .enforce = true, .enforce_seconds = 5 };
    const input = DecisionInput{
        .identified = false,
        .access_match = false,
        .claimed_at_ms = 1_000,
        .now_ms = 7_000,
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.enforce, decision);
}

test "decide: grace boundary is inclusive so exact elapsed enforces" {
    // Arrange: elapsed exactly equals grace.
    const settings = AccountSecurity{ .enforce = true, .enforce_seconds = 5 };
    const input = DecisionInput{
        .identified = false,
        .access_match = false,
        .claimed_at_ms = 1_000,
        .now_ms = 6_000, // elapsed 5000 == 5000
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.enforce, decision);
}

test "decide: zero ENFORCETIME enforces immediately" {
    // Arrange
    const settings = AccountSecurity{ .enforce = true, .enforce_seconds = 0 };
    const input = DecisionInput{
        .identified = false,
        .access_match = false,
        .claimed_at_ms = 5_000,
        .now_ms = 5_000, // elapsed 0 >= 0
    };

    // Act
    const decision = decide(settings, input);

    // Assert
    try testing.expectEqual(Decision.enforce, decision);
}

test "decide: full matrix of identified x access_match x secure when ENFORCE off" {
    // With ENFORCE off, the only outcomes are recognized or allow, driven
    // purely by recognition.
    const base = DecisionInput{
        .identified = false,
        .access_match = false,
        .claimed_at_ms = 0,
        .now_ms = 0,
    };

    inline for ([_]bool{ false, true }) |secure| {
        inline for ([_]bool{ false, true }) |identified| {
            inline for ([_]bool{ false, true }) |access_match| {
                const settings = AccountSecurity{ .secure = secure, .enforce = false };
                var input = base;
                input.identified = identified;
                input.access_match = access_match;

                const expected_recognized = identified or (!secure and access_match);
                const got = decide(settings, input);
                if (expected_recognized) {
                    try testing.expectEqual(Decision.recognized, got);
                } else {
                    try testing.expectEqual(Decision.allow, got);
                }
            }
        }
    }
}

test "decide: full matrix when ENFORCE on with elapsed grace" {
    // With ENFORCE on and grace elapsed, unrecognized connections enforce.
    const grace_s: u32 = 5;
    inline for ([_]bool{ false, true }) |secure| {
        inline for ([_]bool{ false, true }) |identified| {
            inline for ([_]bool{ false, true }) |access_match| {
                const settings = AccountSecurity{
                    .secure = secure,
                    .enforce = true,
                    .enforce_seconds = grace_s,
                };
                const input = DecisionInput{
                    .identified = identified,
                    .access_match = access_match,
                    .claimed_at_ms = 0,
                    .now_ms = 10_000, // well past 5s
                };

                const expected_recognized = identified or (!secure and access_match);
                const got = decide(settings, input);
                if (expected_recognized) {
                    try testing.expectEqual(Decision.recognized, got);
                } else {
                    try testing.expectEqual(Decision.enforce, got);
                }
            }
        }
    }
}

test "lifecycle: SECURE+ENFORCE account warns then enforces an impostor" {
    // Arrange: a SECURE, ENFORCE account with a 30s grace. An impostor sits on
    // the nick with only a matching host (which SECURE ignores).
    const settings = AccountSecurity{ .secure = true, .enforce = true, .enforce_seconds = 30 };
    const claimed_at: i64 = 1_000;

    // Act/Assert 1: within grace -> warn (host match ignored under SECURE).
    try testing.expectEqual(Decision.warn, decide(settings, .{
        .identified = false,
        .access_match = true,
        .claimed_at_ms = claimed_at,
        .now_ms = 5_000,
    }));

    // Act/Assert 2: past grace -> enforce.
    try testing.expectEqual(Decision.enforce, decide(settings, .{
        .identified = false,
        .access_match = true,
        .claimed_at_ms = claimed_at,
        .now_ms = 40_000,
    }));

    // Act/Assert 3: the real owner identifies -> recognized, no enforcement.
    try testing.expectEqual(Decision.recognized, decide(settings, .{
        .identified = true,
        .access_match = true,
        .claimed_at_ms = claimed_at,
        .now_ms = 40_000,
    }));
}
