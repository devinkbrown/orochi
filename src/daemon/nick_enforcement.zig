//! Account-owned nickname enforcement policy for the Mizuchi IRC daemon.
//!
//! Modern services behavior: when a connection uses a nickname that maps to a
//! registered account but the connection is NOT authenticated to that account,
//! the daemon starts a grace timer. While the grace window is open the daemon
//! emits a warning notice; once it elapses the daemon force-renames the user to
//! a fallback "Guest" nick. There is NO pseudo-client here — this module is
//! pure server-side policy. The daemon drives it; this file owns no sockets,
//! timers, or clock access.
//!
//! PURITY: every time value is supplied by the caller as `now_ms` (UNIX
//! milliseconds, `i64`). This module never reads the system clock. The
//! `Tracker` may allocate to own its duped nick keys; nothing else allocates.
//!
//! Nicks are compared case-insensitively using ASCII lowercase folding, so
//! `Spirit`, `spirit`, and `SPIRIT` are the same tracked claim.

const std = @import("std");

/// Maximum length (bytes) of a nickname this module will track or fold. Bounds
/// the on-stack fold buffer so no heap allocation is needed for comparison.
pub const max_nick_len: usize = 64;

/// The policy decision for a single connection holding a given nick.
pub const Decision = enum {
    /// The nick is free, or the connection IS authenticated to the owning
    /// account. Nothing to do.
    allow,
    /// The nick is owned by a registered account, the connection is NOT
    /// authenticated to it, and the grace window is still open. The daemon
    /// should emit a warning notice.
    warn,
    /// Grace has elapsed for an owned-but-unauthenticated nick. The daemon
    /// should force-rename the connection to a guest nick.
    enforce,
};

/// Inputs to a single pure policy evaluation.
pub const Params = struct {
    /// Whether the nick maps to a registered account.
    nick_is_registered: bool,
    /// Whether this connection is authenticated to the account that owns the nick.
    authenticated_to_owner: bool,
    /// When the unauthenticated user took the nick (UNIX ms). Only meaningful
    /// when `nick_is_registered` and not `authenticated_to_owner`.
    claimed_at_ms: i64,
    /// Current time (UNIX ms), supplied by the caller.
    now_ms: i64,
    /// Length of the grace window in milliseconds.
    grace_ms: i64,
};

/// Decide what to do about a connection's current nick. Pure: no side effects.
///
/// Rules, in order:
///   - Unregistered nick                 -> .allow (anyone may use it)
///   - Registered + authenticated owner   -> .allow
///   - Registered + unauth, within grace  -> .warn
///   - Registered + unauth, grace elapsed -> .enforce
///
/// Grace is considered elapsed once `now_ms - claimed_at_ms >= grace_ms`. A
/// non-positive `grace_ms` means there is no grace window: an owned-but-unauth
/// nick enforces immediately.
pub fn evaluate(params: Params) Decision {
    if (!params.nick_is_registered) return .allow;
    if (params.authenticated_to_owner) return .allow;

    const elapsed = params.now_ms - params.claimed_at_ms;
    if (elapsed >= params.grace_ms) return .enforce;
    return .warn;
}

/// Fold an ASCII nick to lowercase into `buf`, returning the written slice.
/// Returns `error.NoSpaceLeft` if `nick` does not fit in `buf`.
fn foldInto(nick: []const u8, buf: []u8) error{NoSpaceLeft}![]u8 {
    if (nick.len > buf.len) return error.NoSpaceLeft;
    for (nick, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..nick.len];
}

/// Format a fallback guest nick like "Guest12345" into `buf`.
///
/// Returns the written slice, or `error.NoSpaceLeft` if `buf` is too small.
/// `seed` is supplied by the caller (e.g. a connection id or counter); this
/// helper performs no randomness and reads no clock.
pub fn guestNick(buf: []u8, seed: u64) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "Guest{d}", .{seed});
}

/// Tracks claim timestamps for nicks that are owned-but-unauthenticated, so the
/// daemon can sweep for grace-expired claims and act on them.
///
/// Keys are heap-owned, case-folded (lowercase) nick copies; values are the
/// claim timestamp in UNIX ms. All keys are freed on `deinit`.
pub const Tracker = struct {
    allocator: std.mem.Allocator,
    /// folded nick -> claimed_at_ms
    claims: std.StringHashMapUnmanaged(i64),

    /// A nick whose grace has elapsed, returned by `sweepEnforceable`.
    ///
    /// `nick` borrows the Tracker's owned key and stays valid until the claim
    /// is released, re-claimed, authenticated, or the Tracker is deinitialized.
    pub const Enforceable = struct {
        nick: []const u8,
        claimed_at_ms: i64,
    };

    /// Initialize an empty tracker backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) Tracker {
        return .{ .allocator = allocator, .claims = .empty };
    }

    /// Free every owned key, then the backing map.
    pub fn deinit(self: *Tracker) void {
        var it = self.claims.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.claims.deinit(self.allocator);
    }

    /// Record (or refresh) that an unauthenticated connection took `nick` at
    /// `now_ms`. Idempotent on the key: re-claiming an already-tracked nick
    /// updates the timestamp without duplicating the owned key.
    pub fn claim(self: *Tracker, nick: []const u8, now_ms: i64) !void {
        var fold_buf: [max_nick_len]u8 = undefined;
        const folded = try foldInto(nick, &fold_buf);

        const gop = try self.claims.getOrPut(self.allocator, folded);
        if (gop.found_existing) {
            gop.value_ptr.* = now_ms;
            return;
        }
        // New key: own a stable copy. On dupe failure, undo the slot so the map
        // never references freed/temporary memory.
        const key = self.allocator.dupe(u8, folded) catch |err| {
            _ = self.claims.remove(folded);
            return err;
        };
        gop.key_ptr.* = key;
        gop.value_ptr.* = now_ms;
    }

    /// Stop tracking `nick` (e.g. the user left it or QUIT). Returns whether a
    /// claim was actually removed.
    pub fn release(self: *Tracker, nick: []const u8) bool {
        return self.removeFolded(nick);
    }

    /// Stop tracking `nick` because the connection authenticated to the owning
    /// account. Returns whether a claim was actually removed. (Semantically a
    /// success transition, distinct from `release`'s give-up transition.)
    pub fn authenticated(self: *Tracker, nick: []const u8) bool {
        return self.removeFolded(nick);
    }

    fn removeFolded(self: *Tracker, nick: []const u8) bool {
        var fold_buf: [max_nick_len]u8 = undefined;
        const folded = foldInto(nick, &fold_buf) catch return false;
        if (self.claims.fetchRemove(folded)) |removed| {
            self.allocator.free(removed.key);
            return true;
        }
        return false;
    }

    /// Return the claim timestamp for `nick`, or `null` if not tracked.
    pub fn pending(self: *const Tracker, nick: []const u8) ?i64 {
        var fold_buf: [max_nick_len]u8 = undefined;
        const folded = foldInto(nick, &fold_buf) catch return null;
        return self.claims.get(folded);
    }

    /// Number of nicks currently tracked.
    pub fn count(self: *const Tracker) usize {
        return self.claims.count();
    }

    /// Fill `out` with every tracked nick whose grace window has elapsed at
    /// `now_ms` for the given `grace_ms`, and return how many were written.
    ///
    /// A claim is enforceable when `now_ms - claimed_at_ms >= grace_ms`, the
    /// same boundary as `evaluate`. Writing stops once `out` is full; the
    /// return value is capped at `out.len`. Entries are NOT removed here — the
    /// daemon should `release` each after acting on the rename.
    pub fn sweepEnforceable(self: *const Tracker, now_ms: i64, grace_ms: i64, out: []Enforceable) usize {
        var written: usize = 0;
        var it = self.claims.iterator();
        while (it.next()) |entry| {
            if (written >= out.len) break;
            const claimed_at = entry.value_ptr.*;
            if (now_ms - claimed_at >= grace_ms) {
                out[written] = .{ .nick = entry.key_ptr.*, .claimed_at_ms = claimed_at };
                written += 1;
            }
        }
        return written;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "evaluate: a free (unregistered) nick is allowed" {
    // Arrange
    const params = Params{
        .nick_is_registered = false,
        .authenticated_to_owner = false,
        .claimed_at_ms = 0,
        .now_ms = 10_000,
        .grace_ms = 5_000,
    };

    // Act
    const decision = evaluate(params);

    // Assert
    try std.testing.expectEqual(Decision.allow, decision);
}

test "evaluate: an authenticated owner of a registered nick is allowed" {
    // Arrange
    const params = Params{
        .nick_is_registered = true,
        .authenticated_to_owner = true,
        .claimed_at_ms = 0,
        .now_ms = 1_000_000,
        .grace_ms = 5_000,
    };

    // Act
    const decision = evaluate(params);

    // Assert
    try std.testing.expectEqual(Decision.allow, decision);
}

test "evaluate: owned-but-unauthenticated within grace warns" {
    // Arrange: claimed at 1000ms, now 3000ms, grace 5000ms -> 2000 < 5000.
    const params = Params{
        .nick_is_registered = true,
        .authenticated_to_owner = false,
        .claimed_at_ms = 1_000,
        .now_ms = 3_000,
        .grace_ms = 5_000,
    };

    // Act
    const decision = evaluate(params);

    // Assert
    try std.testing.expectEqual(Decision.warn, decision);
}

test "evaluate: owned-but-unauthenticated after grace enforces" {
    // Arrange: claimed at 1000ms, now 7000ms, grace 5000ms -> 6000 >= 5000.
    const params = Params{
        .nick_is_registered = true,
        .authenticated_to_owner = false,
        .claimed_at_ms = 1_000,
        .now_ms = 7_000,
        .grace_ms = 5_000,
    };

    // Act
    const decision = evaluate(params);

    // Assert
    try std.testing.expectEqual(Decision.enforce, decision);
}

test "evaluate: grace boundary is inclusive so exact elapsed enforces" {
    // Arrange: elapsed exactly equals grace.
    const params = Params{
        .nick_is_registered = true,
        .authenticated_to_owner = false,
        .claimed_at_ms = 1_000,
        .now_ms = 6_000,
        .grace_ms = 5_000,
    };

    // Act
    const decision = evaluate(params);

    // Assert
    try std.testing.expectEqual(Decision.enforce, decision);
}

test "evaluate: zero grace enforces an owned-but-unauth nick immediately" {
    // Arrange
    const params = Params{
        .nick_is_registered = true,
        .authenticated_to_owner = false,
        .claimed_at_ms = 5_000,
        .now_ms = 5_000,
        .grace_ms = 0,
    };

    // Act
    const decision = evaluate(params);

    // Assert
    try std.testing.expectEqual(Decision.enforce, decision);
}

test "Tracker: claim records a pending timestamp" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Act
    try tracker.claim("Spirit", 1_000);

    // Assert
    try std.testing.expectEqual(@as(?i64, 1_000), tracker.pending("Spirit"));
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
}

test "Tracker: claim matches nicks case-insensitively" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.claim("MoonGazer", 2_000);

    // Act / Assert: all casings resolve to the one claim.
    try std.testing.expectEqual(@as(?i64, 2_000), tracker.pending("moongazer"));
    try std.testing.expectEqual(@as(?i64, 2_000), tracker.pending("MOONGAZER"));
    try std.testing.expectEqual(@as(?i64, 2_000), tracker.pending("mOoNgAzEr"));
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
}

test "Tracker: re-claiming a nick updates the timestamp without duplicating the key" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.claim("Drake", 1_000);

    // Act: a different casing re-claims later.
    try tracker.claim("drake", 9_000);

    // Assert: single entry, refreshed timestamp.
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
    try std.testing.expectEqual(@as(?i64, 9_000), tracker.pending("DRAKE"));
}

test "Tracker: release stops tracking and reports removal" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.claim("Tide", 1_000);

    // Act / Assert
    try std.testing.expect(tracker.release("tide"));
    try std.testing.expectEqual(@as(?i64, null), tracker.pending("Tide"));
    try std.testing.expectEqual(@as(usize, 0), tracker.count());

    // Releasing an untracked nick reports false.
    try std.testing.expect(!tracker.release("Tide"));
}

test "Tracker: authenticated clears the claim like a success transition" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.claim("Luna", 1_000);

    // Act
    try std.testing.expect(tracker.authenticated("LUNA"));

    // Assert
    try std.testing.expectEqual(@as(?i64, null), tracker.pending("Luna"));
    try std.testing.expect(!tracker.authenticated("Luna"));
}

test "Tracker: sweepEnforceable returns only grace-expired claims" {
    // Arrange: three claims at different times.
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.claim("Expired", 1_000); // elapsed 9000 >= 5000 -> enforceable
    try tracker.claim("AlsoOld", 2_000); // elapsed 8000 >= 5000 -> enforceable
    try tracker.claim("Fresh", 9_000); //   elapsed 1000 <  5000 -> not yet

    // Act
    var out: [8]Tracker.Enforceable = undefined;
    const n = tracker.sweepEnforceable(10_000, 5_000, &out);

    // Assert: exactly the two expired claims, none of the fresh one.
    try std.testing.expectEqual(@as(usize, 2), n);
    var saw_expired = false;
    var saw_also_old = false;
    for (out[0..n]) |e| {
        if (std.ascii.eqlIgnoreCase(e.nick, "expired")) saw_expired = true;
        if (std.ascii.eqlIgnoreCase(e.nick, "alsoold")) saw_also_old = true;
        try std.testing.expect(!std.ascii.eqlIgnoreCase(e.nick, "fresh"));
    }
    try std.testing.expect(saw_expired);
    try std.testing.expect(saw_also_old);
}

test "Tracker: sweepEnforceable respects the output buffer capacity" {
    // Arrange: two enforceable claims but room for only one.
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.claim("One", 0);
    try tracker.claim("Two", 0);

    // Act
    var out: [1]Tracker.Enforceable = undefined;
    const n = tracker.sweepEnforceable(100_000, 1_000, &out);

    // Assert: capped at buffer length.
    try std.testing.expectEqual(@as(usize, 1), n);
}

test "Tracker: sweepEnforceable returns nothing when all claims are fresh" {
    // Arrange
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.claim("A", 9_000);
    try tracker.claim("B", 9_500);

    // Act
    var out: [4]Tracker.Enforceable = undefined;
    const n = tracker.sweepEnforceable(10_000, 5_000, &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "guestNick: formats a Guest nick from the seed" {
    // Arrange
    var buf: [max_nick_len]u8 = undefined;

    // Act
    const nick = try guestNick(&buf, 12_345);

    // Assert
    try std.testing.expectEqualStrings("Guest12345", nick);
}

test "guestNick: reports NoSpaceLeft when the buffer is too small" {
    // Arrange: "Guest9" needs 6 bytes; give it 3.
    var buf: [3]u8 = undefined;

    // Act / Assert
    try std.testing.expectError(error.NoSpaceLeft, guestNick(&buf, 9));
}

test "policy flow: claim then sweep then release mirrors the enforce lifecycle" {
    // Arrange: an unauth user takes a registered nick.
    var tracker = Tracker.init(std.testing.allocator);
    defer tracker.deinit();
    const grace_ms: i64 = 30_000;
    try tracker.claim("Captain", 1_000);

    // Act/Assert 1: within grace, evaluate warns and sweep finds nothing.
    try std.testing.expectEqual(Decision.warn, evaluate(.{
        .nick_is_registered = true,
        .authenticated_to_owner = false,
        .claimed_at_ms = tracker.pending("Captain").?,
        .now_ms = 5_000,
        .grace_ms = grace_ms,
    }));
    var out: [4]Tracker.Enforceable = undefined;
    try std.testing.expectEqual(@as(usize, 0), tracker.sweepEnforceable(5_000, grace_ms, &out));

    // Act/Assert 2: past grace, evaluate enforces and sweep yields the nick.
    try std.testing.expectEqual(Decision.enforce, evaluate(.{
        .nick_is_registered = true,
        .authenticated_to_owner = false,
        .claimed_at_ms = tracker.pending("Captain").?,
        .now_ms = 40_000,
        .grace_ms = grace_ms,
    }));
    const n = tracker.sweepEnforceable(40_000, grace_ms, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(std.ascii.eqlIgnoreCase(out[0].nick, "captain"));

    // Act/Assert 3: daemon force-renames and releases the claim.
    try std.testing.expect(tracker.release(out[0].nick));
    try std.testing.expectEqual(@as(usize, 0), tracker.count());
}
