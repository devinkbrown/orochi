//! Registered-nickname protection policy for Mizuchi.
//!
//! This module is pure decision logic. It does not inspect sockets, timers,
//! accounts, or world state; callers supply the policy, authentication state,
//! and remaining grace time for the current nickname claim.

const std = @import("std");

/// Protection behavior configured for a registered nickname.
pub const Protection = enum {
    /// Warn only, even after the grace window has elapsed.
    default_,
    /// Rename an unauthenticated holder after grace expires.
    rename,
    /// Disconnect an unauthenticated holder after grace expires.
    disconnect,
    /// Deny unauthenticated use immediately, including during grace.
    unusable,
};

/// Pure action selected for a nickname claim.
pub const Decision = enum {
    allow,
    warn,
    force_rename,
    disconnect,
    deny_use,
};

/// Decide how Mizuchi should treat a registered nickname claim.
///
/// Authenticated users are always allowed. The `.unusable` policy denies
/// unauthenticated use before grace handling because the nickname cannot be
/// held pre-auth. Positive `grace_remaining_ms` means the grace window remains
/// open; zero or negative means it has elapsed.
pub fn decide(policy: Protection, authenticated: bool, grace_remaining_ms: i64) Decision {
    if (authenticated) return .allow;

    return switch (policy) {
        .unusable => .deny_use,
        .default_ => if (grace_remaining_ms > 0) .warn else .warn,
        .rename => if (grace_remaining_ms > 0) .warn else .force_rename,
        .disconnect => if (grace_remaining_ms > 0) .warn else .disconnect,
    };
}

/// Format a deterministic fallback nickname as `Guest-NNNNN`.
///
/// The numeric suffix is derived from `seed` modulo 100000 so every output fits
/// the same width. The returned slice borrows `buf`.
pub fn guestNick(buf: []u8, seed: u64) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "Guest-{d:0>5}", .{seed % 100_000});
}

test "decide covers every policy and authentication/grace path" {
    const Case = struct {
        policy: Protection,
        authenticated: bool,
        grace_remaining_ms: i64,
        expected: Decision,
    };

    const cases = [_]Case{
        .{ .policy = .default_, .authenticated = true, .grace_remaining_ms = 25, .expected = .allow },
        .{ .policy = .default_, .authenticated = false, .grace_remaining_ms = 25, .expected = .warn },
        .{ .policy = .default_, .authenticated = false, .grace_remaining_ms = 0, .expected = .warn },

        .{ .policy = .rename, .authenticated = true, .grace_remaining_ms = 25, .expected = .allow },
        .{ .policy = .rename, .authenticated = false, .grace_remaining_ms = 25, .expected = .warn },
        .{ .policy = .rename, .authenticated = false, .grace_remaining_ms = 0, .expected = .force_rename },

        .{ .policy = .disconnect, .authenticated = true, .grace_remaining_ms = 25, .expected = .allow },
        .{ .policy = .disconnect, .authenticated = false, .grace_remaining_ms = 25, .expected = .warn },
        .{ .policy = .disconnect, .authenticated = false, .grace_remaining_ms = 0, .expected = .disconnect },

        .{ .policy = .unusable, .authenticated = true, .grace_remaining_ms = 25, .expected = .allow },
        .{ .policy = .unusable, .authenticated = false, .grace_remaining_ms = 25, .expected = .deny_use },
        .{ .policy = .unusable, .authenticated = false, .grace_remaining_ms = 0, .expected = .deny_use },
    };

    for (cases) |case| {
        try std.testing.expectEqual(
            case.expected,
            decide(case.policy, case.authenticated, case.grace_remaining_ms),
        );
    }
}

test "decide treats negative grace as expired" {
    try std.testing.expectEqual(
        Decision.force_rename,
        decide(.rename, false, -1),
    );
    try std.testing.expectEqual(
        Decision.disconnect,
        decide(.disconnect, false, -500),
    );
}

test "unusable denies unauthenticated use before grace rules" {
    try std.testing.expectEqual(
        Decision.deny_use,
        decide(.unusable, false, 60_000),
    );
    try std.testing.expectEqual(
        Decision.allow,
        decide(.unusable, true, -1),
    );
}

test "guestNick format and stability" {
    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;

    const nick_a = try guestNick(&first, 42);
    const nick_b = try guestNick(&second, 42);

    try std.testing.expectEqualStrings("Guest-00042", nick_a);
    try std.testing.expectEqualStrings(nick_a, nick_b);
    try std.testing.expectEqual(@as(usize, 11), nick_a.len);
}

test "guestNick keeps a fixed five digit suffix" {
    var low: [16]u8 = undefined;
    var high: [16]u8 = undefined;

    try std.testing.expectEqualStrings("Guest-00000", try guestNick(&low, 0));
    try std.testing.expectEqualStrings("Guest-99999", try guestNick(&high, 99_999));
}

test "guestNick folds large seeds into the fixed range" {
    var buf: [16]u8 = undefined;

    try std.testing.expectEqualStrings("Guest-00001", try guestNick(&buf, 100_001));
}

test "guestNick reports insufficient buffer space" {
    var too_small: [10]u8 = undefined;

    try std.testing.expectError(error.NoSpaceLeft, guestNick(&too_small, 1));
}
