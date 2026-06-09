//! svc_killpath — pure decision + formatting for the oper KILL path.
//!
//! This module holds two side-effect-free pieces of the KILL command that are
//! easy to get subtly wrong and worth testing in isolation:
//!
//!   1. `canKill` — the authority matrix. Only opers may KILL, and services
//!      are protected (mapping to ERR_CANTKILLSERVER on the wire). Opers MAY
//!      kill other opers.
//!
//!   2. The wire formatting of the kill path: the QUIT/kill reason line
//!      "Killed (<actor> (<reason>))" and the victim-facing notice. Both strip
//!      control bytes from caller-supplied text and clamp lengths so a single
//!      KILL can never overrun the daemon's reply buffers or smuggle CR/LF
//!      into the protocol stream.
//!
//! Pure: imports only `std`. No I/O, no allocation, no daemon state.

const std = @import("std");

/// Outcome of the KILL authority check.
pub const KillDecision = enum {
    /// Actor is an oper and the target is a killable client.
    allow,
    /// Actor is not an operator — maps to ERR_NOPRIVILEGES.
    not_oper,
    /// Target is a service/network pseudo-entity — maps to ERR_CANTKILLSERVER.
    cannot_kill_service,
};

/// Decide whether `actor` may KILL `target`.
///
/// Rules (in priority order):
///   - A non-oper actor is always refused (`not_oper`), regardless of target.
///     The actor's own lack of privilege is reported before leaking anything
///     about the target.
///   - An oper may not kill a service (`cannot_kill_service`).
///   - Otherwise the kill is permitted (`allow`), including oper-on-oper.
pub fn canKill(
    actor_is_oper: bool,
    target_is_oper: bool,
    target_is_service: bool,
) KillDecision {
    _ = target_is_oper; // Opers are killable; kept explicit for the call site.
    if (!actor_is_oper) return .not_oper;
    if (target_is_service) return .cannot_kill_service;
    return .allow;
}

/// Default reason applied when an oper supplies an empty KILL reason.
pub const default_reason = "Killed";

/// Upper bound on a caller-supplied reason once sanitized. Generous enough for
/// real moderator notes but small enough that the composed kill-path line and
/// the victim notice always fit a single IRC message with room for the prefix
/// and the "Killed (actor (...))" wrapper.
pub const max_reason_len = 307;

/// Upper bound on the actor display name embedded in the kill path. Matches a
/// generous nick!user@host envelope.
pub const max_actor_len = 128;

/// Strip bytes that must never appear inside an IRC parameter (CR, LF, NUL)
/// and any other ASCII control byte, copying the survivors into `out`. The
/// copy stops at `max_len` source-accepted bytes so the result is always
/// bounded. Returns the sanitized slice (a prefix of `out`).
///
/// Control bytes commonly used for IRC formatting are intentionally treated as
/// control here as well, since a kill reason is server-originated text that
/// should not carry client formatting into the protocol envelope.
fn sanitize(src: []const u8, out: []u8, max_len: usize) []const u8 {
    var n: usize = 0;
    const limit = @min(max_len, out.len);
    for (src) |b| {
        if (n >= limit) break;
        // Reject C0 controls (incl. CR/LF/NUL/TAB) and DEL.
        if (b < 0x20 or b == 0x7f) continue;
        out[n] = b;
        n += 1;
    }
    return out[0..n];
}

/// Sanitize and clamp a KILL reason, substituting the default when the caller
/// gives nothing usable. Writes into `out` and returns the resulting slice.
/// `out` must be at least `max_reason_len` bytes.
pub fn formatReason(raw: []const u8, out: []u8) []const u8 {
    std.debug.assert(out.len >= max_reason_len);
    const cleaned = sanitize(raw, out, max_reason_len);
    if (cleaned.len == 0) return default_reason;
    return cleaned;
}

/// Total bytes a `formatKillPath` line needs in the worst case:
/// "Killed (" + actor + " (" + reason + "))".
pub const kill_path_max = "Killed (".len + max_actor_len + " (".len + max_reason_len + "))".len;

/// Build the canonical kill-path string `Killed (<actor> (<reason>))`.
///
/// Both `actor` and `reason` are sanitized (control bytes stripped) and clamped
/// before composition, so the output can never carry CR/LF or overrun `out`.
/// `out` must be at least `kill_path_max` bytes. Returns the composed slice.
pub fn formatKillPath(actor: []const u8, reason: []const u8, out: []u8) []const u8 {
    std.debug.assert(out.len >= kill_path_max);

    var actor_buf: [max_actor_len]u8 = undefined;
    var reason_buf: [max_reason_len]u8 = undefined;
    const a = sanitize(actor, &actor_buf, max_actor_len);
    const r = blk: {
        const cleaned = sanitize(reason, &reason_buf, max_reason_len);
        break :blk if (cleaned.len == 0) default_reason else cleaned;
    };

    // Composition is bounded by the sanitized lengths above, so bufPrint can
    // never fail given a `kill_path_max`-sized `out`.
    return std.fmt.bufPrint(out, "Killed ({s} ({s}))", .{ a, r }) catch unreachable;
}

/// Worst-case length of the victim notice produced by `formatVictimNotice`.
pub const victim_notice_max = "You have been killed by ".len + max_actor_len + ": ".len + max_reason_len;

/// Build the victim-facing notice text (the human-readable body an operator's
/// KILL delivers to the target before the link closes). Sanitized + clamped.
/// `out` must be at least `victim_notice_max` bytes. Returns the composed slice.
pub fn formatVictimNotice(actor: []const u8, reason: []const u8, out: []u8) []const u8 {
    std.debug.assert(out.len >= victim_notice_max);

    var actor_buf: [max_actor_len]u8 = undefined;
    var reason_buf: [max_reason_len]u8 = undefined;
    const a = sanitize(actor, &actor_buf, max_actor_len);
    const r = blk: {
        const cleaned = sanitize(reason, &reason_buf, max_reason_len);
        break :blk if (cleaned.len == 0) default_reason else cleaned;
    };

    return std.fmt.bufPrint(out, "You have been killed by {s}: {s}", .{ a, r }) catch unreachable;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "authority matrix: non-oper actor is always refused" {
    // Non-oper cannot kill regardless of what the target is.
    try testing.expectEqual(KillDecision.not_oper, canKill(false, false, false));
    try testing.expectEqual(KillDecision.not_oper, canKill(false, true, false));
    try testing.expectEqual(KillDecision.not_oper, canKill(false, false, true));
    try testing.expectEqual(KillDecision.not_oper, canKill(false, true, true));
}

test "authority matrix: oper may kill regular client and other opers" {
    try testing.expectEqual(KillDecision.allow, canKill(true, false, false));
    try testing.expectEqual(KillDecision.allow, canKill(true, true, false));
}

test "authority matrix: services are protected from opers" {
    try testing.expectEqual(KillDecision.cannot_kill_service, canKill(true, false, true));
    try testing.expectEqual(KillDecision.cannot_kill_service, canKill(true, true, true));
}

test "authority: non-oper refusal takes priority over service protection" {
    // The actor's own lack of privilege is reported first; we never leak that
    // the target was a service to an unprivileged caller.
    try testing.expectEqual(KillDecision.not_oper, canKill(false, false, true));
}

test "reason formatting: passes normal text through" {
    var buf: [max_reason_len]u8 = undefined;
    const r = formatReason("spamming the channel", &buf);
    try testing.expectEqualStrings("spamming the channel", r);
}

test "reason formatting: empty reason falls back to default" {
    var buf: [max_reason_len]u8 = undefined;
    try testing.expectEqualStrings(default_reason, formatReason("", &buf));
}

test "reason formatting: all-control reason falls back to default" {
    var buf: [max_reason_len]u8 = undefined;
    try testing.expectEqualStrings(default_reason, formatReason("\r\n\x00\x01", &buf));
}

test "kill path: canonical composition" {
    var buf: [kill_path_max]u8 = undefined;
    const line = formatKillPath("oper!o@admin", "abuse", &buf);
    try testing.expectEqualStrings("Killed (oper!o@admin (abuse))", line);
}

test "kill path: empty reason uses default inside wrapper" {
    var buf: [kill_path_max]u8 = undefined;
    const line = formatKillPath("nova", "", &buf);
    try testing.expectEqualStrings("Killed (nova (Killed))", line);
}

test "kill path: strips CR/LF so injection is impossible" {
    var buf: [kill_path_max]u8 = undefined;
    const line = formatKillPath("evil\r\nNICK x", "go\raway\n", &buf);
    // No CR or LF survive in the composed line.
    try testing.expect(std.mem.indexOfScalar(u8, line, '\r') == null);
    try testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
    try testing.expectEqualStrings("Killed (evilNICK x (goaway))", line);
}

test "kill path: strips NUL and other C0 control bytes" {
    var buf: [kill_path_max]u8 = undefined;
    const line = formatKillPath("a\x00b", "x\x02y\x1fz", &buf);
    try testing.expectEqualStrings("Killed (ab (xyz))", line);
}

test "bounds: oversized reason is clamped and line stays within buffer" {
    var big: [4096]u8 = undefined;
    @memset(&big, 'A');

    var rbuf: [max_reason_len]u8 = undefined;
    const r = formatReason(&big, &rbuf);
    try testing.expectEqual(max_reason_len, r.len);

    var buf: [kill_path_max]u8 = undefined;
    const line = formatKillPath("op", &big, &buf);
    try testing.expect(line.len <= kill_path_max);
    // Reason portion is clamped to max_reason_len.
    try testing.expect(std.mem.indexOf(u8, line, "AAAA") != null);
}

test "bounds: oversized actor is clamped" {
    var big: [4096]u8 = undefined;
    @memset(&big, 'N');
    var buf: [kill_path_max]u8 = undefined;
    const line = formatKillPath(&big, "reason", &buf);
    try testing.expect(line.len <= kill_path_max);
    try testing.expect(std.mem.endsWith(u8, line, "(reason))"));
}

test "victim notice: canonical composition" {
    var buf: [victim_notice_max]u8 = undefined;
    const n = formatVictimNotice("admin", "ban evasion", &buf);
    try testing.expectEqualStrings("You have been killed by admin: ban evasion", n);
}

test "victim notice: empty reason uses default and strips control bytes" {
    var buf: [victim_notice_max]u8 = undefined;
    const n = formatVictimNotice("ad\rmin", "\n", &buf);
    try testing.expectEqualStrings("You have been killed by admin: Killed", n);
}

test "victim notice: oversized inputs stay within buffer" {
    var big: [4096]u8 = undefined;
    @memset(&big, 'Z');
    var buf: [victim_notice_max]u8 = undefined;
    const n = formatVictimNotice(&big, &big, &buf);
    try testing.expect(n.len <= victim_notice_max);
}
