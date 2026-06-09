//! Per-action operator MODE/override decision matrix.
//!
//! This module answers a single, pure question: given an operator's override
//! privilege flags and one requested privileged channel action, may the daemon
//! permit it, and if not, why? It is the stateless policy companion to two
//! existing pieces of the oper subsystem:
//!
//!   * `oper.zig` owns the canonical capability registry — it maps a verified
//!     SASL account to an `OperPrivileges` capability set. That answers *what an
//!     operator is allowed to be*.
//!   * `oper_override.zig` owns the time-boxed, audited override *session* — it
//!     gates whether a bypass session is currently engaged. That answers *when*
//!     a bypass window is open.
//!
//! Neither of those decides, per concrete action, whether a given flag set
//! permits that action with a stable machine-readable reason. That gap is what
//! this module fills. It deliberately models the override privileges as a small
//! local flag struct (`OperPrivs`) injected by the caller, so it can be unit
//! tested in isolation and reused at any call site without dragging in the
//! account registry, the clock, or the audit ring.
//!
//! The module is pure: no allocation, no I/O, no global state. Every decision is
//! a total function of `(OperPrivs, Action)`.

const std = @import("std");

/// Override privilege flags an operator may hold.
///
/// These are the *override-relevant* capabilities, distinct from the broad
/// capability set in `oper.zig`. They map onto the natural override axes an
/// operator exercises against channel state:
///
///   * `can_override`      — engage override at all; the master gate. Without
///                           it, every override-requiring action is denied.
///   * `can_kick_immune`   — kick a member who outranks the operator (or who is
///                           otherwise kick-protected).
///   * `can_see_secret`    — view/join channels that are secret or hidden.
///   * `can_mode_any`      — set channel modes without holding channel status
///                           (op/owner), i.e. force a MODE change.
///
/// All default to `false`: an unprivileged operator is the safe default.
pub const OperPrivs = struct {
    can_override: bool = false,
    can_kick_immune: bool = false,
    can_see_secret: bool = false,
    can_mode_any: bool = false,

    /// No override privileges at all.
    pub const none: OperPrivs = .{};

    /// Every override privilege granted.
    pub const all: OperPrivs = .{
        .can_override = true,
        .can_kick_immune = true,
        .can_see_secret = true,
        .can_mode_any = true,
    };

    /// True if this operator holds the master override gate.
    pub fn hasOverride(self: OperPrivs) bool {
        return self.can_override;
    }
};

/// A requested privileged channel action whose permissibility we must decide.
///
/// The set is closed on purpose: an override must never bypass anything not
/// enumerated here. Each variant names a concrete thing an operator may try to
/// do that ordinarily requires status, an invite, a key, or visibility.
pub const Action = enum {
    /// Join a `+k` keyed channel without supplying the key.
    join_keyed,
    /// Join a `+i` invite-only channel without an invite.
    join_inviteonly,
    /// Join a channel the operator is `+b` banned from.
    join_banned,
    /// Kick a member who outranks the operator / is kick-protected.
    kick_higher,
    /// Set a channel mode without holding op/owner status.
    set_mode_without_status,
    /// See (enumerate/join) a secret or hidden channel.
    see_secret,
    /// View the current modes of a channel the operator is not on.
    view_modes,

    /// Stable lowercase token naming this action.
    pub fn token(self: Action) []const u8 {
        return switch (self) {
            .join_keyed => "join_keyed",
            .join_inviteonly => "join_inviteonly",
            .join_banned => "join_banned",
            .kick_higher => "kick_higher",
            .set_mode_without_status => "set_mode_without_status",
            .see_secret => "see_secret",
            .view_modes => "view_modes",
        };
    }

    /// Parse an action token case-insensitively, or `null` if unknown.
    pub fn parse(raw: []const u8) ?Action {
        inline for (@typeInfo(Action).@"enum".fields) |field| {
            const action: Action = @enumFromInt(field.value);
            if (std.ascii.eqlIgnoreCase(raw, action.token())) return action;
        }
        return null;
    }
};

/// Why an action was allowed or denied. Stable and machine-readable so the
/// command layer can map it onto IRCv3 standard replies / numerics.
pub const Reason = enum {
    /// The action is permitted: the operator holds every flag it requires.
    allowed,
    /// Denied: the operator lacks the master `can_override` gate.
    no_override_privilege,
    /// Denied: the operator may override generally but lacks the specific
    /// flag this action requires (kick-immune / mode-any / see-secret).
    missing_action_privilege,
    /// Allowed without override: the action requires no special privilege.
    no_privilege_required,

    /// Stable lowercase token naming this reason.
    pub fn token(self: Reason) []const u8 {
        return switch (self) {
            .allowed => "allowed",
            .no_override_privilege => "no_override_privilege",
            .missing_action_privilege => "missing_action_privilege",
            .no_privilege_required => "no_privilege_required",
        };
    }
};

/// The outcome of a single `permits` decision.
pub const Decision = struct {
    /// Whether the action is permitted.
    allow: bool,
    /// The machine-readable rationale.
    reason: Reason,

    /// Convenience: a permitted decision with the given reason.
    fn permit(reason: Reason) Decision {
        return .{ .allow = true, .reason = reason };
    }

    /// Convenience: a denied decision with the given reason.
    fn deny(reason: Reason) Decision {
        return .{ .allow = false, .reason = reason };
    }
};

/// The override flag an action specifically requires beyond the master gate.
/// `null` means the action requires only the master `can_override` gate.
const RequiredFlag = enum { kick_immune, see_secret, mode_any };

/// Map an action to the specific override flag it needs, plus whether the action
/// requires override at all. `view_modes` is intentionally privilege-free: an
/// operator viewing modes leaks nothing a normal member could not also see, so
/// it never consumes an override.
fn requirementFor(action: Action) ?RequiredFlag {
    return switch (action) {
        // Master-gate-only actions: any engaged override may bypass these.
        .join_keyed, .join_inviteonly, .join_banned => null,
        // Flag-specific actions.
        .kick_higher => .kick_immune,
        .set_mode_without_status => .mode_any,
        .see_secret => .see_secret,
        // Privilege-free; handled before this function is consulted, but listed
        // for switch exhaustiveness.
        .view_modes => null,
    };
}

/// True if `action` needs no privilege whatsoever (it is always allowed).
fn isPrivilegeFree(action: Action) bool {
    return action == .view_modes;
}

/// Decide whether `privs` permits `action`.
///
/// Decision order:
///   1. Privilege-free actions (e.g. `view_modes`) are always allowed.
///   2. Otherwise the master `can_override` gate is required.
///   3. Flag-specific actions additionally require their specific flag.
pub fn permits(privs: OperPrivs, action: Action) Decision {
    if (isPrivilegeFree(action)) {
        return Decision.permit(.no_privilege_required);
    }

    if (!privs.can_override) {
        return Decision.deny(.no_override_privilege);
    }

    const required = requirementFor(action) orelse {
        // Master-gate-only action and the gate is held.
        return Decision.permit(.allowed);
    };

    const has_flag = switch (required) {
        .kick_immune => privs.can_kick_immune,
        .see_secret => privs.can_see_secret,
        .mode_any => privs.can_mode_any,
    };

    return if (has_flag)
        Decision.permit(.allowed)
    else
        Decision.deny(.missing_action_privilege);
}

/// Convenience boolean wrapper for call sites that only need allow/deny.
pub fn isPermitted(privs: OperPrivs, action: Action) bool {
    return permits(privs, action).allow;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectDecision(privs: OperPrivs, action: Action, allow: bool, reason: Reason) !void {
    const d = permits(privs, action);
    try testing.expectEqual(allow, d.allow);
    try testing.expectEqual(reason, d.reason);
}

test "view_modes is always allowed without any privilege" {
    try expectDecision(OperPrivs.none, .view_modes, true, .no_privilege_required);
    try expectDecision(OperPrivs.all, .view_modes, true, .no_privilege_required);
    try expectDecision(
        .{ .can_override = true },
        .view_modes,
        true,
        .no_privilege_required,
    );
}

test "no override gate denies every override-requiring action" {
    const privs = OperPrivs.none;
    const gated = [_]Action{
        .join_keyed,
        .join_inviteonly,
        .join_banned,
        .kick_higher,
        .set_mode_without_status,
        .see_secret,
    };
    for (gated) |action| {
        try expectDecision(privs, action, false, .no_override_privilege);
    }
}

test "kick_immune flag specifically gates kick_higher" {
    // Has override but not kick_immune -> denied with missing flag.
    try expectDecision(
        .{ .can_override = true },
        .kick_higher,
        false,
        .missing_action_privilege,
    );
    // Override + kick_immune -> allowed.
    try expectDecision(
        .{ .can_override = true, .can_kick_immune = true },
        .kick_higher,
        true,
        .allowed,
    );
    // kick_immune without the master gate is still denied.
    try expectDecision(
        .{ .can_kick_immune = true },
        .kick_higher,
        false,
        .no_override_privilege,
    );
}

test "mode_any flag specifically gates set_mode_without_status" {
    try expectDecision(
        .{ .can_override = true },
        .set_mode_without_status,
        false,
        .missing_action_privilege,
    );
    try expectDecision(
        .{ .can_override = true, .can_mode_any = true },
        .set_mode_without_status,
        true,
        .allowed,
    );
    try expectDecision(
        .{ .can_mode_any = true },
        .set_mode_without_status,
        false,
        .no_override_privilege,
    );
}

test "see_secret flag specifically gates see_secret action" {
    try expectDecision(
        .{ .can_override = true },
        .see_secret,
        false,
        .missing_action_privilege,
    );
    try expectDecision(
        .{ .can_override = true, .can_see_secret = true },
        .see_secret,
        true,
        .allowed,
    );
    try expectDecision(
        .{ .can_see_secret = true },
        .see_secret,
        false,
        .no_override_privilege,
    );
}

test "master gate alone permits keyed, invite-only, and banned joins" {
    const privs = OperPrivs{ .can_override = true };
    try expectDecision(privs, .join_keyed, true, .allowed);
    try expectDecision(privs, .join_inviteonly, true, .allowed);
    try expectDecision(privs, .join_banned, true, .allowed);
}

test "all privileges permit the full action matrix" {
    const privs = OperPrivs.all;
    const actions = [_]Action{
        .join_keyed,
        .join_inviteonly,
        .join_banned,
        .kick_higher,
        .set_mode_without_status,
        .see_secret,
    };
    for (actions) |action| {
        const d = permits(privs, action);
        try testing.expect(d.allow);
        try testing.expectEqual(Reason.allowed, d.reason);
    }
    // view_modes remains privilege-free even with all flags.
    try expectDecision(privs, .view_modes, true, .no_privilege_required);
}

test "isPermitted mirrors permits().allow across the matrix" {
    const flag_sets = [_]OperPrivs{
        OperPrivs.none,
        .{ .can_override = true },
        .{ .can_override = true, .can_kick_immune = true },
        .{ .can_override = true, .can_mode_any = true },
        .{ .can_override = true, .can_see_secret = true },
        OperPrivs.all,
    };
    inline for (@typeInfo(Action).@"enum".fields) |field| {
        const action: Action = @enumFromInt(field.value);
        for (flag_sets) |privs| {
            try testing.expectEqual(permits(privs, action).allow, isPermitted(privs, action));
        }
    }
}

test "OperPrivs.hasOverride reflects the master gate" {
    try testing.expect(!OperPrivs.none.hasOverride());
    try testing.expect(OperPrivs.all.hasOverride());
    try testing.expect((OperPrivs{ .can_override = true }).hasOverride());
}

test "Action.parse round-trips every token case-insensitively" {
    inline for (@typeInfo(Action).@"enum".fields) |field| {
        const action: Action = @enumFromInt(field.value);
        try testing.expectEqual(action, Action.parse(action.token()).?);
    }
    try testing.expectEqual(Action.kick_higher, Action.parse("KICK_HIGHER").?);
    try testing.expectEqual(Action.see_secret, Action.parse("See_Secret").?);
    try testing.expectEqual(@as(?Action, null), Action.parse("nonexistent"));
}

test "Reason tokens are stable and distinct" {
    try testing.expectEqualStrings("allowed", Reason.allowed.token());
    try testing.expectEqualStrings("no_override_privilege", Reason.no_override_privilege.token());
    try testing.expectEqualStrings("missing_action_privilege", Reason.missing_action_privilege.token());
    try testing.expectEqualStrings("no_privilege_required", Reason.no_privilege_required.token());
}
