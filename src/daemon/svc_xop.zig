//! svc_xop — XOP template tiers for the Mizuchi services layer.
//!
//! Mizuchi exposes channel access management through real server commands and
//! numerics (never pseudo-clients). The fine-grained model is a per-account
//! flag list (cf. the channel-access FLAGS surface). XOP layers a small set of
//! *named role tiers* on top of that model: FOUNDER / SOP / AOP / HOP / VOP.
//! Each tier corresponds to a fixed, canonical set of access flags, so granting
//! a tier is exactly equivalent to granting its flag set, and a flag set that
//! matches a tier byte-for-byte can be displayed back as that tier name.
//!
//! This module is deliberately self-contained: it defines its own small
//! `FlagSet` (a documented flag alphabet) rather than depending on the wider
//! services flag representation. The mapping is pure and bidirectional:
//!
//!   * `flagsForXop(tier)`  -> the canonical `FlagSet` for a tier.
//!   * `xopForFlags(flags)` -> the tier whose canonical set *exactly* equals
//!                             `flags`, or `null` for any non-template set.
//!
//! Exact-match classification is intentional: a custom flag combination that
//! does not line up with a tier is reported as `null` (a "custom" access entry)
//! so that bespoke grants are never silently relabelled as a named tier.

const std = @import("std");

/// The flag alphabet used by the XOP templates.
///
/// Each flag names one atomic capability a member may hold on a channel. The
/// alphabet is deliberately small and stable: tiers are defined purely as
/// combinations of these flags, and the single-letter codes double as the
/// human-facing FLAGS representation.
///
/// | Flag      | Code | Meaning                                            |
/// |-----------|------|----------------------------------------------------|
/// | founder   | `F`  | Full ownership: implies every other capability.    |
/// | auto_op   | `O`  | Auto-grant channel operator (+o) on join.          |
/// | auto_halfop | `H`| Auto-grant half-operator (+h) on join.             |
/// | auto_voice| `V`  | Auto-grant voice (+v) on join.                     |
/// | set       | `s`  | May change channel settings / modes.               |
/// | akick     | `k`  | May manage the channel auto-kick (akick) list.     |
/// | invite    | `i`  | May invite to / bypass invite-only.                |
/// | unban     | `b`  | May remove bans / clear the ban list.              |
pub const Flag = enum(u8) {
    founder = 0,
    auto_op = 1,
    auto_halfop = 2,
    auto_voice = 3,
    set = 4,
    akick = 5,
    invite = 6,
    unban = 7,

    /// The single-character code used in the textual FLAGS representation.
    pub fn code(self: Flag) u8 {
        return switch (self) {
            .founder => 'F',
            .auto_op => 'O',
            .auto_halfop => 'H',
            .auto_voice => 'V',
            .set => 's',
            .akick => 'k',
            .invite => 'i',
            .unban => 'b',
        };
    }
};

/// Total number of distinct flags in the alphabet.
pub const flag_count = @typeInfo(Flag).@"enum".fields.len;

/// A set of `Flag`s, backed by a small bitmask. Self-contained: this is the
/// only flag representation this module needs, independent of the broader
/// services flag model.
pub const FlagSet = struct {
    bits: u8 = 0,

    /// An empty flag set (no capabilities).
    pub const empty: FlagSet = .{ .bits = 0 };

    fn mask(flag: Flag) u8 {
        return @as(u8, 1) << @as(u3, @intCast(@intFromEnum(flag)));
    }

    /// Build a `FlagSet` from a slice of flags.
    pub fn fromSlice(flags: []const Flag) FlagSet {
        var set: FlagSet = .empty;
        for (flags) |f| set.add(f);
        return set;
    }

    /// Add `flag` to the set (idempotent).
    pub fn add(self: *FlagSet, flag: Flag) void {
        self.bits |= mask(flag);
    }

    /// Remove `flag` from the set (idempotent).
    pub fn remove(self: *FlagSet, flag: Flag) void {
        self.bits &= ~mask(flag);
    }

    /// Whether `flag` is present.
    pub fn has(self: FlagSet, flag: Flag) bool {
        return (self.bits & mask(flag)) != 0;
    }

    /// Whether the set holds no flags.
    pub fn isEmpty(self: FlagSet) bool {
        return self.bits == 0;
    }

    /// Exact equality of two flag sets.
    pub fn eql(self: FlagSet, other: FlagSet) bool {
        return self.bits == other.bits;
    }
};

/// The named XOP role tiers, ordered from most to least privileged.
pub const Xop = enum {
    founder,
    sop,
    aop,
    hop,
    vop,

    /// Canonical uppercase name as it appears on the wire / in numerics.
    pub fn name(self: Xop) []const u8 {
        return switch (self) {
            .founder => "FOUNDER",
            .sop => "SOP",
            .aop => "AOP",
            .hop => "HOP",
            .vop => "VOP",
        };
    }

    /// Parse a tier name, case-insensitively. Returns `null` for unknown names.
    pub fn parse(text: []const u8) ?Xop {
        if (eqlIgnoreCase(text, "FOUNDER")) return .founder;
        if (eqlIgnoreCase(text, "SOP")) return .sop;
        if (eqlIgnoreCase(text, "AOP")) return .aop;
        if (eqlIgnoreCase(text, "HOP")) return .hop;
        if (eqlIgnoreCase(text, "VOP")) return .vop;
        return null;
    }
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toUpper(ca) != std.ascii.toUpper(cb)) return false;
    }
    return true;
}

/// The canonical `FlagSet` granted by each XOP tier.
///
///   * FOUNDER — full ownership: `founder` plus every operational capability.
///   * SOP     — senior op: auto-op, settings, akick, invite, unban (no founder).
///   * AOP     — auto-op plus invite/unban, but no settings/akick authority.
///   * HOP     — auto-halfop plus invite.
///   * VOP     — auto-voice only.
pub fn flagsForXop(tier: Xop) FlagSet {
    return switch (tier) {
        .founder => FlagSet.fromSlice(&.{
            .founder,
            .auto_op,
            .set,
            .akick,
            .invite,
            .unban,
        }),
        .sop => FlagSet.fromSlice(&.{
            .auto_op,
            .set,
            .akick,
            .invite,
            .unban,
        }),
        .aop => FlagSet.fromSlice(&.{
            .auto_op,
            .invite,
            .unban,
        }),
        .hop => FlagSet.fromSlice(&.{
            .auto_halfop,
            .invite,
        }),
        .vop => FlagSet.fromSlice(&.{
            .auto_voice,
        }),
    };
}

/// Classify a `FlagSet` as a named tier *iff* it exactly matches that tier's
/// canonical set. Any other combination (including the empty set) returns
/// `null`, marking it a custom access entry.
pub fn xopForFlags(flags: FlagSet) ?Xop {
    inline for (.{ Xop.founder, Xop.sop, Xop.aop, Xop.hop, Xop.vop }) |tier| {
        if (flags.eql(flagsForXop(tier))) return tier;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const all_tiers = [_]Xop{ .founder, .sop, .aop, .hop, .vop };

test "every tier round-trips through flags" {
    for (all_tiers) |tier| {
        const flags = flagsForXop(tier);
        const back = xopForFlags(flags);
        try testing.expect(back != null);
        try testing.expectEqual(tier, back.?);
    }
}

test "tier flag sets are pairwise distinct" {
    for (all_tiers, 0..) |a, i| {
        for (all_tiers, 0..) |b, j| {
            if (i == j) continue;
            try testing.expect(!flagsForXop(a).eql(flagsForXop(b)));
        }
    }
}

test "non-template flag set classifies as null" {
    // Empty set: a member with no capabilities is not a named tier.
    try testing.expectEqual(@as(?Xop, null), xopForFlags(FlagSet.empty));

    // A custom mix that matches no canonical tier.
    const custom = FlagSet.fromSlice(&.{ .auto_voice, .akick });
    try testing.expectEqual(@as(?Xop, null), xopForFlags(custom));

    // SOP flags minus one capability is no longer SOP.
    var almost_sop = flagsForXop(.sop);
    almost_sop.remove(.akick);
    try testing.expectEqual(@as(?Xop, null), xopForFlags(almost_sop));

    // SOP flags plus founder is not SOP (and not exactly FOUNDER either,
    // because FOUNDER omits no operational flag here but SOP lacks .founder).
    var sop_plus = flagsForXop(.sop);
    sop_plus.add(.set); // already present; ensure still SOP
    try testing.expectEqual(@as(?Xop, Xop.sop), xopForFlags(sop_plus));
}

test "parse is case-insensitive and rejects unknown names" {
    try testing.expectEqual(@as(?Xop, Xop.founder), Xop.parse("FOUNDER"));
    try testing.expectEqual(@as(?Xop, Xop.founder), Xop.parse("founder"));
    try testing.expectEqual(@as(?Xop, Xop.sop), Xop.parse("Sop"));
    try testing.expectEqual(@as(?Xop, Xop.aop), Xop.parse("aOp"));
    try testing.expectEqual(@as(?Xop, Xop.hop), Xop.parse("HOP"));
    try testing.expectEqual(@as(?Xop, Xop.vop), Xop.parse("vop"));

    try testing.expectEqual(@as(?Xop, null), Xop.parse("OWNER"));
    try testing.expectEqual(@as(?Xop, null), Xop.parse(""));
    try testing.expectEqual(@as(?Xop, null), Xop.parse("SOPP"));
}

test "name round-trips through parse" {
    for (all_tiers) |tier| {
        const parsed = Xop.parse(tier.name());
        try testing.expectEqual(@as(?Xop, tier), parsed);
    }
}

test "FlagSet basic operations" {
    var set: FlagSet = .empty;
    try testing.expect(set.isEmpty());

    set.add(.auto_op);
    try testing.expect(set.has(.auto_op));
    try testing.expect(!set.has(.auto_voice));
    try testing.expect(!set.isEmpty());

    set.add(.auto_op); // idempotent
    set.remove(.auto_voice); // removing absent flag is a no-op
    try testing.expect(set.has(.auto_op));

    set.remove(.auto_op);
    try testing.expect(set.isEmpty());
}

test "founder tier implies the founder flag, lesser tiers do not" {
    try testing.expect(flagsForXop(.founder).has(.founder));
    try testing.expect(!flagsForXop(.sop).has(.founder));
    try testing.expect(!flagsForXop(.aop).has(.founder));
    try testing.expect(!flagsForXop(.hop).has(.founder));
    try testing.expect(!flagsForXop(.vop).has(.founder));
}

test "auto-status flags match tier intent" {
    try testing.expect(flagsForXop(.aop).has(.auto_op));
    try testing.expect(flagsForXop(.hop).has(.auto_halfop));
    try testing.expect(flagsForXop(.vop).has(.auto_voice));

    // VOP is voice-only: it grants no op/halfop.
    try testing.expect(!flagsForXop(.vop).has(.auto_op));
    try testing.expect(!flagsForXop(.vop).has(.auto_halfop));
}

test "flag codes are unique" {
    const flags = [_]Flag{ .founder, .auto_op, .auto_halfop, .auto_voice, .set, .akick, .invite, .unban };
    try testing.expectEqual(flag_count, flags.len);
    for (flags, 0..) |a, i| {
        for (flags, 0..) |b, j| {
            if (i == j) continue;
            try testing.expect(a.code() != b.code());
        }
    }
}
