// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account nick RECOVER / RELEASE decision logic for the Orochi IRC daemon.
//!
//! Orochi services are REAL server commands, NEVER pseudo-clients. There is no
//! NickServ. An account owner issues RECOVER or RELEASE as first-class server
//! commands and the daemon answers with numerics. This module is the PURE state
//! machine that decides what the daemon should *do* in response — it performs no
//! I/O, owns no sockets, reads no clock, and imports only `std`.
//!
//! Two distinct reclaim flows are modeled:
//!
//!   RECOVER  — "someone else is holding my registered nick; force them off it."
//!              The contested nick may be held by a live but unauthenticated
//!              connection. RECOVER decides whether that holder must be ejected
//!              from the nick (force-rename to a guest nick) so the owner can
//!              take it. RECOVER is rejected unless the requester has proven they
//!              own the account that owns the nick.
//!
//!   RELEASE  — "drop the server-held reservation on my nick early." After a
//!              holder is forced off (or after the owner quits), the daemon may
//!              keep the nick reserved for a hold window so a straggler cannot
//!              snatch it. RELEASE lets the verified owner end that hold ahead of
//!              time, making the nick immediately available again.
//!
//! PURITY: this module is a complement to the storage primitive in
//! `reserved_nick.zig` (which owns the nick->account map) and the grace-timer
//! enforcement policy in `nick_enforcement.zig` (allow/warn/enforce against an
//! unauthenticated holder). Neither of those decides the RECOVER-vs-RELEASE
//! command outcome; this file does. All inputs, including time, are supplied by
//! the caller. Nicks and account names are compared case-insensitively via ASCII
//! lowercase folding.

const std = @import("std");

/// Maximum length (bytes) of a nickname or account name this module will fold.
/// Bounds the on-stack fold buffers so no heap allocation is ever needed.
pub const max_name_len: usize = 64;

/// Which reclaim command the requester issued.
pub const Command = enum {
    /// Force a holder off the owner's registered nick.
    recover,
    /// Drop a server-held reservation on the owner's nick early.
    release,
};

/// The outcome the daemon should act on. Each variant maps cleanly to a numeric
/// reply or a concrete daemon action; this module chooses which, it does not
/// emit it.
pub const Decision = enum {
    /// The target nick is not registered to any account. The daemon should
    /// reply with the "no such account / nick not registered" numeric.
    no_such_account,
    /// The nick is registered, but the requester has NOT proven ownership of the
    /// owning account. The daemon should reply with the "access denied" numeric
    /// and MUST NOT alter any state.
    not_owner,
    /// The verified owner asked to reclaim, but there is nothing to do: no other
    /// connection is holding the nick (RECOVER), or no server-held reservation
    /// exists to drop (RELEASE). The daemon should reply with an informational
    /// "nothing to recover / release" numeric.
    nothing_to_recover,
    /// RECOVER granted: a live, unauthenticated connection is holding the owner's
    /// nick. The daemon should force that holder off the nick (rename to guest)
    /// and may then place a hold reservation so the owner can reclaim it.
    recover_holder,
    /// RELEASE granted: a server-held reservation exists and the verified owner
    /// asked to drop it early. The daemon should remove the reservation, making
    /// the nick immediately available.
    release_reservation,
};

/// Inputs to a single pure decision. The caller gathers these from the live
/// nick/account tables and the request; this module never reads them itself.
pub const Params = struct {
    /// Which command the requester issued.
    command: Command,

    /// Whether the target nick maps to a registered account at all. If false the
    /// decision is always `.no_such_account` regardless of every other field.
    nick_is_registered: bool,

    /// Whether the requester has proven they own the account that owns the nick
    /// (e.g. authenticated to it this session, or supplied a valid credential).
    /// If false (and the nick is registered) the decision is `.not_owner`.
    requester_owns_account: bool,

    /// RECOVER only: whether some OTHER live connection is currently holding the
    /// nick. Ignored for RELEASE.
    holder_present: bool,

    /// RECOVER only: whether the present holder is itself authenticated to the
    /// owning account. A holder that is the legitimate owner's own other session
    /// must NOT be forced off — there is nothing to recover. Ignored for RELEASE
    /// and when `holder_present` is false.
    holder_authenticated_to_owner: bool,

    /// RELEASE only: whether a server-held reservation currently exists on the
    /// nick that could be dropped early. Ignored for RECOVER.
    reservation_held: bool,
};

/// Fold an ASCII name to lowercase into `buf`, returning the written slice.
/// Returns `error.NameTooLong` if `name` exceeds `buf.len`.
fn foldInto(name: []const u8, buf: []u8) error{NameTooLong}![]u8 {
    if (name.len > buf.len) return error.NameTooLong;
    for (name, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..name.len];
}

/// Case-insensitive (ASCII lowercase) equality for names. Names longer than
/// `max_name_len` can never match a folded comparison and compare as unequal.
pub fn namesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.len > max_name_len) return false;
    var ba: [max_name_len]u8 = undefined;
    var bb: [max_name_len]u8 = undefined;
    const fa = foldInto(a, &ba) catch return false;
    const fb = foldInto(b, &bb) catch return false;
    return std.mem.eql(u8, fa, fb);
}

/// Decide what the daemon should do for a RECOVER or RELEASE request. Pure: no
/// side effects, no allocation, no clock access.
///
/// Decision order (gates apply to BOTH commands first):
///   1. Nick not registered                  -> .no_such_account
///   2. Requester has not proven ownership    -> .not_owner
/// Then, per command:
///   RECOVER:
///     3. No other holder, or holder is the owner's own authed session
///                                            -> .nothing_to_recover
///     4. A live unauthenticated holder exists -> .recover_holder
///   RELEASE:
///     3. No server-held reservation exists    -> .nothing_to_recover
///     4. A reservation exists                 -> .release_reservation
pub fn decide(p: Params) Decision {
    // Ownership gates apply identically to both commands.
    if (!p.nick_is_registered) return .no_such_account;
    if (!p.requester_owns_account) return .not_owner;

    return switch (p.command) {
        .recover => blk: {
            // Nothing to do if no one else holds it, or the holder is the
            // owner's own authenticated session (never force the owner off).
            if (!p.holder_present) break :blk .nothing_to_recover;
            if (p.holder_authenticated_to_owner) break :blk .nothing_to_recover;
            break :blk .recover_holder;
        },
        .release => if (p.reservation_held) .release_reservation else .nothing_to_recover,
    };
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

const t = std.testing;

test "unregistered nick yields no_such_account for both commands" {
    // RECOVER on an unregistered nick.
    try t.expectEqual(Decision.no_such_account, decide(.{
        .command = .recover,
        .nick_is_registered = false,
        .requester_owns_account = true,
        .holder_present = true,
        .holder_authenticated_to_owner = false,
        .reservation_held = true,
    }));
    // RELEASE on an unregistered nick.
    try t.expectEqual(Decision.no_such_account, decide(.{
        .command = .release,
        .nick_is_registered = false,
        .requester_owns_account = true,
        .holder_present = false,
        .holder_authenticated_to_owner = false,
        .reservation_held = true,
    }));
}

test "no_such_account takes priority even when ownership is unproven" {
    // Registration gate is checked before the ownership gate.
    try t.expectEqual(Decision.no_such_account, decide(.{
        .command = .recover,
        .nick_is_registered = false,
        .requester_owns_account = false,
        .holder_present = true,
        .holder_authenticated_to_owner = false,
        .reservation_held = false,
    }));
}

test "registered nick but unproven ownership yields not_owner" {
    try t.expectEqual(Decision.not_owner, decide(.{
        .command = .recover,
        .nick_is_registered = true,
        .requester_owns_account = false,
        .holder_present = true,
        .holder_authenticated_to_owner = false,
        .reservation_held = true,
    }));
    try t.expectEqual(Decision.not_owner, decide(.{
        .command = .release,
        .nick_is_registered = true,
        .requester_owns_account = false,
        .holder_present = false,
        .holder_authenticated_to_owner = false,
        .reservation_held = true,
    }));
}

test "RECOVER forces off a live unauthenticated holder" {
    try t.expectEqual(Decision.recover_holder, decide(.{
        .command = .recover,
        .nick_is_registered = true,
        .requester_owns_account = true,
        .holder_present = true,
        .holder_authenticated_to_owner = false,
        .reservation_held = false,
    }));
}

test "RECOVER with no holder has nothing to recover" {
    try t.expectEqual(Decision.nothing_to_recover, decide(.{
        .command = .recover,
        .nick_is_registered = true,
        .requester_owns_account = true,
        .holder_present = false,
        .holder_authenticated_to_owner = false,
        .reservation_held = true, // a reservation is irrelevant to RECOVER
    }));
}

test "RECOVER never forces off the owner's own authenticated session" {
    // The holder IS authenticated to the owning account (the owner's other
    // connection). It must not be ejected.
    try t.expectEqual(Decision.nothing_to_recover, decide(.{
        .command = .recover,
        .nick_is_registered = true,
        .requester_owns_account = true,
        .holder_present = true,
        .holder_authenticated_to_owner = true,
        .reservation_held = false,
    }));
}

test "RELEASE drops an existing server-held reservation" {
    try t.expectEqual(Decision.release_reservation, decide(.{
        .command = .release,
        .nick_is_registered = true,
        .requester_owns_account = true,
        .holder_present = false,
        .holder_authenticated_to_owner = false,
        .reservation_held = true,
    }));
}

test "RELEASE with no reservation has nothing to release" {
    try t.expectEqual(Decision.nothing_to_recover, decide(.{
        .command = .release,
        .nick_is_registered = true,
        .requester_owns_account = true,
        .holder_present = true, // a live holder is irrelevant to RELEASE
        .holder_authenticated_to_owner = false,
        .reservation_held = false,
    }));
}

test "RELEASE ignores holder fields entirely" {
    // Same reservation state, opposite holder fields -> identical decision.
    const base = Params{
        .command = .release,
        .nick_is_registered = true,
        .requester_owns_account = true,
        .holder_present = false,
        .holder_authenticated_to_owner = false,
        .reservation_held = true,
    };
    var with_holder = base;
    with_holder.holder_present = true;
    with_holder.holder_authenticated_to_owner = true;
    try t.expectEqual(decide(base), decide(with_holder));
    try t.expectEqual(Decision.release_reservation, decide(with_holder));
}

test "RECOVER ignores reservation field entirely" {
    const base = Params{
        .command = .recover,
        .nick_is_registered = true,
        .requester_owns_account = true,
        .holder_present = true,
        .holder_authenticated_to_owner = false,
        .reservation_held = false,
    };
    var with_resv = base;
    with_resv.reservation_held = true;
    try t.expectEqual(decide(base), decide(with_resv));
    try t.expectEqual(Decision.recover_holder, decide(with_resv));
}

test "ownership gate beats the nothing-to-do outcome" {
    // Even when there is genuinely nothing to recover, an unverified requester
    // is told not_owner (no information leak about holder state) rather than
    // nothing_to_recover.
    try t.expectEqual(Decision.not_owner, decide(.{
        .command = .recover,
        .nick_is_registered = true,
        .requester_owns_account = false,
        .holder_present = false,
        .holder_authenticated_to_owner = false,
        .reservation_held = false,
    }));
}

test "namesEqual folds ASCII case" {
    try t.expect(namesEqual("Spirit", "spirit"));
    try t.expect(namesEqual("MOONGAZER", "moongazer"));
    try t.expect(namesEqual("mIxEd", "MiXeD"));
    try t.expect(!namesEqual("alpha", "beta"));
    try t.expect(!namesEqual("short", "longer"));
}

test "namesEqual rejects over-length names" {
    const long = "x" ** (max_name_len + 1);
    try t.expect(!namesEqual(long, long));
}

test "every decision variant is reachable from decide" {
    var seen = std.EnumSet(Decision).initEmpty();
    seen.insert(decide(.{ .command = .recover, .nick_is_registered = false, .requester_owns_account = true, .holder_present = false, .holder_authenticated_to_owner = false, .reservation_held = false }));
    seen.insert(decide(.{ .command = .recover, .nick_is_registered = true, .requester_owns_account = false, .holder_present = false, .holder_authenticated_to_owner = false, .reservation_held = false }));
    seen.insert(decide(.{ .command = .recover, .nick_is_registered = true, .requester_owns_account = true, .holder_present = false, .holder_authenticated_to_owner = false, .reservation_held = false }));
    seen.insert(decide(.{ .command = .recover, .nick_is_registered = true, .requester_owns_account = true, .holder_present = true, .holder_authenticated_to_owner = false, .reservation_held = false }));
    seen.insert(decide(.{ .command = .release, .nick_is_registered = true, .requester_owns_account = true, .holder_present = false, .holder_authenticated_to_owner = false, .reservation_held = true }));

    try t.expect(seen.contains(.no_such_account));
    try t.expect(seen.contains(.not_owner));
    try t.expect(seen.contains(.nothing_to_recover));
    try t.expect(seen.contains(.recover_holder));
    try t.expect(seen.contains(.release_reservation));
}
