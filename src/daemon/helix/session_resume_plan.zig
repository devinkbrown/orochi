// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free post-Helix-upgrade session resume planner.
//!
//! After an in-place Helix upgrade, the successor process is handed back two
//! things: the decoded per-account session capsules (the durable bouncer /
//! multi-session registry, see `session_capsule.zig`) and the set of live
//! connections that were successfully migrated, identified by client id. This
//! planner reconstructs, for every session across every account, whether that
//! session is now ATTACHED (its underlying connection survived the migration
//! and appears in the live set) or DETACHED (the connection did not survive, so
//! a replay buffer must be drained when a client re-attaches).
//!
//! The planner is pure and std-only: it never allocates. It flattens all
//! sessions across the supplied capsules into a caller-provided `out` slice,
//! borrowing the account and token string slices from the input capsules, so
//! both the capsules and `out` must outlive the returned plan.
//!
//! Inconsistencies detected:
//!   - `error.TooMany`        when the flattened session count exceeds `out.len`
//!   - `error.DuplicateToken` when one token crosses ASCII-folded account
//!                            boundaries. Multiple physical attachments within
//!                            the same account deliberately share one token and
//!                            remain distinct rows in the returned plan.

const std = @import("std");
const session_capsule = @import("session_capsule.zig");

/// Errors produced by the planner.
pub const Error = error{
    /// The flattened session count exceeded the caller-supplied `out` slice.
    TooMany,
    /// One token appeared under two different ASCII-folded accounts.
    DuplicateToken,
};

/// The resolved post-upgrade state of a single session.
///
/// `account` and `token` borrow the input capsules; `attached` reflects whether
/// the session's client id was present in the migrated live-client set.
pub const SessionState = struct {
    account: []const u8,
    token: []const u8,
    signon_unix: i64,
    attached: bool,
    /// The detached session's encoded restore snapshot (v2 capsules; empty when
    /// none). Passed through verbatim so a resumed bouncer session restores
    /// byte-identically instead of degrading to a bare reclaim token.
    snapshot: []const u8 = &.{},
};

/// Reconstruct the multi-session registry's attach/detach state after a Helix
/// upgrade.
///
/// For every session in every capsule, the session is `attached` iff its
/// `client` id appears in `live_client_ids` (the connections that successfully
/// migrated); otherwise it is detached and will need its replay buffer drained.
/// All sessions are flattened, in capsule-then-session order, into `out`.
///
/// Returns:
///   - `error.TooMany`        if the total session count exceeds `out.len`
///   - `error.DuplicateToken` if a token crosses folded account boundaries
///
/// Validation is transactional: on either error, `out` is unchanged. On success
/// returns the written prefix of `out` in capsule-then-session order, including
/// every physical attachment in a same-account reusable-token group.
pub fn plan(
    capsules: []const session_capsule.SessionCapsule,
    live_client_ids: []const u64,
    out: []SessionState,
) Error![]SessionState {
    // Size and token-authority validation happen before the first output write.
    // This makes a failed handoff retry safe even when the caller reuses `out`.
    var total: usize = 0;
    for (capsules) |capsule| {
        if (capsule.sessions.len > out.len - total) return error.TooMany;
        total += capsule.sessions.len;
    }

    // A reusable token is one logical session with potentially many physical
    // attachments. It may therefore repeat under the same folded account, but
    // it must never grant authority across account boundaries. Entries within
    // one capsule necessarily share its account, so only earlier capsules need
    // comparison.
    for (capsules, 0..) |capsule, capsule_index| {
        for (capsule.sessions) |entry| {
            for (capsules[0..capsule_index]) |previous_capsule| {
                for (previous_capsule.sessions) |previous_entry| {
                    if (std.mem.eql(u8, previous_entry.token, entry.token) and
                        !std.ascii.eqlIgnoreCase(previous_capsule.account, capsule.account))
                    {
                        return error.DuplicateToken;
                    }
                }
            }
        }
    }

    var n: usize = 0;
    for (capsules) |capsule| {
        for (capsule.sessions) |entry| {
            out[n] = .{
                .account = capsule.account,
                .token = entry.token,
                .signon_unix = entry.signon_unix,
                .attached = containsClient(live_client_ids, entry.client),
                .snapshot = entry.snapshot,
            };
            n += 1;
        }
    }

    return out[0..n];
}

/// Count the sessions resolved to ATTACHED.
pub fn countAttached(states: []const SessionState) usize {
    var count: usize = 0;
    for (states) |s| {
        if (s.attached) count += 1;
    }
    return count;
}

/// Count the sessions resolved to DETACHED (replay buffer needed).
pub fn countDetached(states: []const SessionState) usize {
    var count: usize = 0;
    for (states) |s| {
        if (!s.attached) count += 1;
    }
    return count;
}

/// Linear membership test over the live-client id set.
fn containsClient(live_client_ids: []const u64, client: u64) bool {
    for (live_client_ids) |id| {
        if (id == client) return true;
    }
    return false;
}

// --- tests ------------------------------------------------------------------

const SessionEntry = session_capsule.SessionEntry;
const SessionCapsule = session_capsule.SessionCapsule;

test "plan attaches sessions whose client migrated and detaches the rest" {
    const alice_sessions = [_]SessionEntry{
        .{ .token = "alice-tok-1", .signon_unix = 1_700_000_001, .detached = false, .client = 10 },
        .{ .token = "alice-tok-2", .signon_unix = 1_700_000_002, .detached = true, .client = 20, .snapshot = "alice-restore-blob" },
    };
    const bob_sessions = [_]SessionEntry{
        .{ .token = "bob-tok-1", .signon_unix = 1_700_000_003, .detached = false, .client = 30 },
        .{ .token = "bob-tok-2", .signon_unix = 1_700_000_004, .detached = true, .client = 40 },
        .{ .token = "bob-tok-3", .signon_unix = 1_700_000_005, .detached = false, .client = 50 },
    };

    const capsules = [_]SessionCapsule{
        .{ .account = "alice", .sessions = &alice_sessions },
        .{ .account = "bob", .sessions = &bob_sessions },
    };

    // Clients 10, 30, 50 survived the migration; 20 and 40 did not.
    const live = [_]u64{ 10, 30, 50 };

    var out: [16]SessionState = undefined;
    const states = try plan(&capsules, &live, &out);

    try std.testing.expectEqual(@as(usize, 5), states.len);

    // alice-tok-1 (client 10) -> attached
    try std.testing.expectEqualStrings("alice", states[0].account);
    try std.testing.expectEqualStrings("alice-tok-1", states[0].token);
    try std.testing.expectEqual(@as(i64, 1_700_000_001), states[0].signon_unix);
    try std.testing.expectEqual(true, states[0].attached);

    // alice-tok-2 (client 20) -> detached; restore snapshot passes through verbatim.
    try std.testing.expectEqualStrings("alice-tok-2", states[1].token);
    try std.testing.expectEqual(false, states[1].attached);
    try std.testing.expectEqualSlices(u8, "alice-restore-blob", states[1].snapshot);

    // bob-tok-1 (client 30) -> attached
    try std.testing.expectEqualStrings("bob", states[2].account);
    try std.testing.expectEqualStrings("bob-tok-1", states[2].token);
    try std.testing.expectEqual(true, states[2].attached);

    // bob-tok-2 (client 40) -> detached
    try std.testing.expectEqualStrings("bob-tok-2", states[3].token);
    try std.testing.expectEqual(false, states[3].attached);

    // bob-tok-3 (client 50) -> attached
    try std.testing.expectEqualStrings("bob-tok-3", states[4].token);
    try std.testing.expectEqual(true, states[4].attached);

    try std.testing.expectEqual(@as(usize, 3), countAttached(states));
    try std.testing.expectEqual(@as(usize, 2), countDetached(states));
}

test "plan with empty live set detaches everything" {
    const sessions = [_]SessionEntry{
        .{ .token = "t1", .signon_unix = 1, .detached = false, .client = 1 },
        .{ .token = "t2", .signon_unix = 2, .detached = false, .client = 2 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "acct", .sessions = &sessions },
    };

    const live = [_]u64{};

    var out: [4]SessionState = undefined;
    const states = try plan(&capsules, &live, &out);

    try std.testing.expectEqual(@as(usize, 2), states.len);
    try std.testing.expectEqual(@as(usize, 0), countAttached(states));
    try std.testing.expectEqual(@as(usize, 2), countDetached(states));
}

test "plan preserves same-account reusable-token attachments in input order" {
    const first = [_]SessionEntry{
        .{ .token = "shared-tok", .signon_unix = 1, .detached = false, .client = 1 },
        .{ .token = "shared-tok", .signon_unix = 2, .detached = true, .client = 2 },
    };
    const later_case_variant = [_]SessionEntry{
        .{ .token = "shared-tok", .signon_unix = 3, .detached = false, .client = 3 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "Alice", .sessions = &first },
        .{ .account = "ALICE", .sessions = &later_case_variant },
    };
    const live = [_]u64{ 1, 3 };

    var out: [3]SessionState = undefined;
    const states = try plan(&capsules, &live, &out);
    try std.testing.expectEqual(@as(usize, 3), states.len);
    try std.testing.expectEqual(@as(i64, 1), states[0].signon_unix);
    try std.testing.expectEqual(@as(i64, 2), states[1].signon_unix);
    try std.testing.expectEqual(@as(i64, 3), states[2].signon_unix);
    try std.testing.expectEqualStrings("Alice", states[0].account);
    try std.testing.expectEqualStrings("Alice", states[1].account);
    try std.testing.expectEqualStrings("ALICE", states[2].account);
    try std.testing.expectEqualStrings("shared-tok", states[0].token);
    try std.testing.expectEqualStrings("shared-tok", states[1].token);
    try std.testing.expectEqualStrings("shared-tok", states[2].token);
    try std.testing.expect(states[0].attached);
    try std.testing.expect(!states[1].attached);
    try std.testing.expect(states[2].attached);
    try std.testing.expectEqual(@as(usize, 2), countAttached(states));
    try std.testing.expectEqual(@as(usize, 1), countDetached(states));
}

test "plan rejects reusable-token authority crossing account boundaries without partial output" {
    const alice_sessions = [_]SessionEntry{
        .{ .token = "shared-tok", .signon_unix = 1, .detached = false, .client = 1 },
    };
    const bob_sessions = [_]SessionEntry{
        .{ .token = "shared-tok", .signon_unix = 2, .detached = true, .client = 2 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "alice", .sessions = &alice_sessions },
        .{ .account = "bob", .sessions = &bob_sessions },
    };

    const live = [_]u64{ 1, 2 };

    const sentinel = SessionState{
        .account = "untouched",
        .token = "sentinel",
        .signon_unix = -9,
        .attached = false,
        .snapshot = "still-here",
    };
    var out: [8]SessionState = @splat(sentinel);
    try std.testing.expectError(error.DuplicateToken, plan(&capsules, &live, &out));
    for (out) |state| try std.testing.expectEqualDeep(sentinel, state);
}

test "plan returns TooMany when out is too small" {
    const sessions = [_]SessionEntry{
        .{ .token = "a", .signon_unix = 1, .detached = false, .client = 1 },
        .{ .token = "b", .signon_unix = 2, .detached = false, .client = 2 },
        .{ .token = "c", .signon_unix = 3, .detached = false, .client = 3 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "acct", .sessions = &sessions },
    };

    const live = [_]u64{1};

    const sentinel = SessionState{
        .account = "untouched",
        .token = "sentinel",
        .signon_unix = -9,
        .attached = false,
        .snapshot = "still-here",
    };
    var out: [2]SessionState = @splat(sentinel); // too small for 3 sessions
    try std.testing.expectError(error.TooMany, plan(&capsules, &live, &out));
    for (out) |state| try std.testing.expectEqualDeep(sentinel, state);
}

test "plan over zero capsules yields an empty plan" {
    const capsules = [_]SessionCapsule{};
    const live = [_]u64{ 1, 2, 3 };

    var out: [4]SessionState = undefined;
    const states = try plan(&capsules, &live, &out);

    try std.testing.expectEqual(@as(usize, 0), states.len);
    try std.testing.expectEqual(@as(usize, 0), countAttached(states));
    try std.testing.expectEqual(@as(usize, 0), countDetached(states));
}
