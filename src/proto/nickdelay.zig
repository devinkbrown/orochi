//! Nick-reservation and nick-change throttling ("nickdelay" + temporary holds).
//!
//! When a nick QUITs or a client changes away from a nick, that nick can be
//! briefly reserved so another connection cannot immediately reclaim it.
//! Operators and services can also place explicit, timed HOLDs on a nick.
//!
//! This module is PURE: it never reads the system clock. Every call that needs
//! the current time accepts a caller-supplied timestamp. All timestamps in this
//! module are UNIX seconds (`i64`); `until` is the absolute second past which a
//! hold is considered expired (a hold is active while `now < until`).
//!
//! Nicks are handled case-insensitively: every hold is keyed by the canonical
//! lowercase form of the nick.

const std = @import("std");

/// IRC numerics emitted when a reclaim attempt is rejected by a live hold.
pub const NickDelayNumeric = enum(u16) {
    /// Nick is temporarily unavailable (held); reclaim was refused.
    ERR_UNAVAILRESOURCE = 437,
};

/// Why a nick is currently being held.
///
/// `quit_delay` and `change_delay` are applied automatically using the
/// configured delay windows; `services_hold` and `oper_hold` are explicit,
/// caller-timed holds.
pub const Reason = enum(u2) {
    /// Held briefly after the owning client QUIT.
    quit_delay,
    /// Held briefly after the owning client changed away from this nick.
    change_delay,
    /// Held by a services pseudo-client (e.g. registered-nick enforcement).
    services_hold,
    /// Held explicitly by an operator.
    oper_hold,
};

/// A single active or scheduled reservation for one nick.
///
/// `nick` and `note` are owned heap allocations and are freed by the owning
/// `NickDelay` when the hold is released, swept, or replaced.
pub const Hold = struct {
    /// Canonical lowercase nick that this hold reserves (owned).
    nick: []const u8,
    /// Reason the hold exists.
    reason: Reason,
    /// Absolute UNIX second past which the hold is expired (active while now < until).
    until: i64,
    /// Free-form annotation, e.g. who placed the hold (owned, may be empty).
    note: []const u8,
};

/// Tunable limits and default delay windows for a `NickDelay` store.
pub const Params = struct {
    /// Seconds a nick stays reserved after its owner QUITs.
    quit_delay_secs: i64 = 60,
    /// Seconds a nick stays reserved after its owner changes away from it.
    change_delay_secs: i64 = 30,
    /// Maximum number of distinct nicks that may be held simultaneously.
    max_holds: usize = 4096,
    /// Maximum byte length of an accepted nick.
    max_nick_bytes: usize = 64,
    /// Maximum byte length of an accepted note.
    max_note_bytes: usize = 256,
};

/// Errors surfaced by `NickDelay` operations.
pub const NickDelayError = std.mem.Allocator.Error || error{
    /// The supplied nick was empty or contained an invalid byte.
    InvalidNick,
    /// The supplied nick exceeded `Params.max_nick_bytes`.
    NickTooLong,
    /// The supplied note exceeded `Params.max_note_bytes`.
    NoteTooLong,
    /// Adding a new hold would exceed `Params.max_holds`.
    TooManyHolds,
};

/// Case-insensitive nick reservation store.
///
/// Keyed by the canonical lowercase nick. Both the map key and each stored
/// `Hold` (including its `note`) are heap-owned and freed in `deinit`,
/// `release`, `sweepExpired`, or when an existing hold is replaced.
pub const NickDelay = struct {
    allocator: std.mem.Allocator,
    params: Params,
    holds: std.StringHashMap(Hold),

    /// Create an empty store. Caller retains ownership of `allocator`.
    pub fn init(allocator: std.mem.Allocator, params: Params) NickDelay {
        return .{
            .allocator = allocator,
            .params = params,
            .holds = std.StringHashMap(Hold).init(allocator),
        };
    }

    /// Free every stored hold and the backing map. Leaves the value undefined.
    pub fn deinit(self: *NickDelay) void {
        self.clear();
        self.holds.deinit();
        self.* = undefined;
    }

    /// Remove and free every hold, retaining the map's allocated capacity.
    pub fn clear(self: *NickDelay) void {
        var it = self.holds.iterator();
        while (it.next()) |entry| {
            self.freeHold(entry.key_ptr.*, entry.value_ptr.*);
        }
        self.holds.clearRetainingCapacity();
    }

    /// Reserve `nick` for `quit_delay_secs` starting at `now` (QUIT reservation).
    pub fn holdQuit(self: *NickDelay, nick: []const u8, now: i64) NickDelayError!void {
        return self.holdExplicit(nick, .quit_delay, now + self.params.quit_delay_secs, "");
    }

    /// Reserve `nick` for `change_delay_secs` starting at `now` (NICK-change reservation).
    pub fn holdChange(self: *NickDelay, nick: []const u8, now: i64) NickDelayError!void {
        return self.holdExplicit(nick, .change_delay, now + self.params.change_delay_secs, "");
    }

    /// Place (or replace) an explicit hold on `nick` expiring at absolute `until`.
    ///
    /// `note` is copied; an empty note is allowed. Replacing an existing hold
    /// reuses its map slot and frees the prior note, so it never counts against
    /// `max_holds`.
    pub fn holdExplicit(
        self: *NickDelay,
        nick: []const u8,
        reason: Reason,
        until: i64,
        note: []const u8,
    ) NickDelayError!void {
        var key_buf: [maxNickBufLen]u8 = undefined;
        const key = try self.normalize(nick, &key_buf);
        if (note.len > self.params.max_note_bytes) return error.NoteTooLong;

        if (self.holds.getPtr(key)) |existing| {
            const owned_note = try self.allocator.dupe(u8, note);
            self.allocator.free(existing.note);
            existing.reason = reason;
            existing.until = until;
            existing.note = owned_note;
            return;
        }

        if (self.holds.count() >= self.params.max_holds) return error.TooManyHolds;

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        const owned_note = try self.allocator.dupe(u8, note);
        errdefer self.allocator.free(owned_note);

        try self.holds.putNoClobber(owned_key, .{
            .nick = owned_key,
            .reason = reason,
            .until = until,
            .note = owned_note,
        });
    }

    /// Return the active reason holding `nick` at `now`, or null.
    ///
    /// Expired holds are treated as absent (but are not removed here; use
    /// `sweepExpired` to reclaim their memory).
    pub fn isHeld(self: *const NickDelay, nick: []const u8, now: i64) ?Reason {
        var key_buf: [maxNickBufLen]u8 = undefined;
        const key = self.normalize(nick, &key_buf) catch return null;
        const hold = self.holds.get(key) orelse return null;
        if (now >= hold.until) return null;
        return hold.reason;
    }

    /// Return a pointer to the live hold for `nick` at `now`, or null.
    ///
    /// The pointer is valid until the next mutating call. Expired holds are
    /// reported as absent.
    pub fn get(self: *const NickDelay, nick: []const u8, now: i64) ?*const Hold {
        var key_buf: [maxNickBufLen]u8 = undefined;
        const key = self.normalize(nick, &key_buf) catch return null;
        const hold = self.holds.getPtr(key) orelse return null;
        if (now >= hold.until) return null;
        return hold;
    }

    /// Remove and free any hold on `nick`. Returns true if a hold existed.
    ///
    /// Releases regardless of expiry; an expired-but-not-swept hold is removed too.
    pub fn release(self: *NickDelay, nick: []const u8) bool {
        var key_buf: [maxNickBufLen]u8 = undefined;
        const key = self.normalize(nick, &key_buf) catch return false;
        const removed = self.holds.fetchRemove(key) orelse return false;
        self.freeHold(removed.key, removed.value);
        return true;
    }

    /// Remove and free every hold expired at `now`. Returns the number reaped.
    pub fn sweepExpired(self: *NickDelay, now: i64) usize {
        var reaped: usize = 0;
        var it = self.holds.iterator();
        while (it.next()) |entry| {
            if (now < entry.value_ptr.until) continue;
            self.freeHold(entry.key_ptr.*, entry.value_ptr.*);
            self.holds.removeByPtr(entry.key_ptr);
            reaped += 1;
            it = self.holds.iterator();
        }
        return reaped;
    }

    /// Number of stored holds, including any that are expired but unswept.
    pub fn count(self: *const NickDelay) usize {
        return self.holds.count();
    }

    /// Validate `nick` and write its canonical lowercase form into `out`.
    fn normalize(self: *const NickDelay, nick: []const u8, out: *[maxNickBufLen]u8) NickDelayError![]const u8 {
        if (nick.len == 0) return error.InvalidNick;
        if (nick.len > self.params.max_nick_bytes) return error.NickTooLong;
        if (nick.len > out.len) return error.NickTooLong;
        for (nick, 0..) |byte, index| {
            if (!validNickByte(byte)) return error.InvalidNick;
            out[index] = std.ascii.toLower(byte);
        }
        return out[0..nick.len];
    }

    /// Free both the owned map key and the owned note for one removed hold.
    ///
    /// `key` and `hold.nick` alias the same allocation, so only the note is
    /// freed in addition to the key.
    fn freeHold(self: *NickDelay, key: []const u8, hold: Hold) void {
        self.allocator.free(key);
        self.allocator.free(hold.note);
    }
};

/// Upper bound on any normalization scratch buffer this module uses.
const maxNickBufLen: usize = 64;

/// Whether `byte` is permitted in a nick under the modern protocol charset.
fn validNickByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

test "holdQuit sets a hold that expires after the configured window" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{ .quit_delay_secs = 60 });
    defer nd.deinit();
    const now: i64 = 1_000;

    // Act
    try nd.holdQuit("Alice", now);

    // Assert
    try std.testing.expectEqual(Reason.quit_delay, nd.isHeld("alice", now).?);
    try std.testing.expectEqual(Reason.quit_delay, nd.isHeld("alice", now + 59).?);
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("alice", now + 60));
    try std.testing.expectEqual(@as(usize, 1), nd.count());
}

test "holdChange uses the change_delay window" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{ .change_delay_secs = 30 });
    defer nd.deinit();
    const now: i64 = 500;

    // Act
    try nd.holdChange("Bob", now);

    // Assert
    try std.testing.expectEqual(Reason.change_delay, nd.isHeld("bob", now).?);
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("bob", now + 30));
}

test "isHeld respects now for active versus expired holds" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();

    // Act
    try nd.holdExplicit("carol", .oper_hold, 2_000, "by oper");

    // Assert: active for any now < until (2_000), expired at/after it
    try std.testing.expectEqual(Reason.oper_hold, nd.isHeld("carol", 0).?);
    try std.testing.expectEqual(Reason.oper_hold, nd.isHeld("carol", 1_999).?);
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("carol", 2_000));
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("carol", 5_000));
}

test "explicit hold stores reason note and until" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();

    // Act
    try nd.holdExplicit("Dave", .services_hold, 9_999, "registered nick");

    // Assert
    const hold = nd.get("DAVE", 100).?;
    try std.testing.expectEqual(Reason.services_hold, hold.reason);
    try std.testing.expectEqual(@as(i64, 9_999), hold.until);
    try std.testing.expectEqualStrings("dave", hold.nick);
    try std.testing.expectEqualStrings("registered nick", hold.note);
}

test "holdExplicit replaces an existing hold without leaking" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();
    try nd.holdExplicit("eve", .quit_delay, 100, "first note");

    // Act
    try nd.holdExplicit("EVE", .oper_hold, 500, "second note");

    // Assert
    try std.testing.expectEqual(@as(usize, 1), nd.count());
    const hold = nd.get("eve", 0).?;
    try std.testing.expectEqual(Reason.oper_hold, hold.reason);
    try std.testing.expectEqual(@as(i64, 500), hold.until);
    try std.testing.expectEqualStrings("second note", hold.note);
}

test "release removes a hold and reports prior existence" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();
    try nd.holdExplicit("frank", .oper_hold, 1_000, "note");

    // Act
    const released = nd.release("FRANK");
    const released_again = nd.release("frank");

    // Assert
    try std.testing.expect(released);
    try std.testing.expect(!released_again);
    try std.testing.expectEqual(@as(usize, 0), nd.count());
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("frank", 0));
}

test "release frees an expired but unswept hold" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();
    try nd.holdExplicit("grace", .quit_delay, 100, "");

    // Act: hold is expired at now=200 but still resident
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("grace", 200));
    const released = nd.release("grace");

    // Assert
    try std.testing.expect(released);
    try std.testing.expectEqual(@as(usize, 0), nd.count());
}

test "sweepExpired frees only expired holds" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();
    try nd.holdExplicit("aaa", .quit_delay, 100, "");
    try nd.holdExplicit("bbb", .oper_hold, 1_000, "keep");
    try nd.holdExplicit("ccc", .change_delay, 200, "");

    // Act
    const reaped = nd.sweepExpired(200);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), reaped); // aaa and ccc expired at 200
    try std.testing.expectEqual(@as(usize, 1), nd.count());
    try std.testing.expectEqual(Reason.oper_hold, nd.isHeld("bbb", 200).?);
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("aaa", 200));
}

test "sweepExpired on empty store reaps nothing" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();

    // Act
    const reaped = nd.sweepExpired(10_000);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), reaped);
    try std.testing.expectEqual(@as(usize, 0), nd.count());
}

test "lookups are case insensitive across the API" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();

    // Act
    try nd.holdExplicit("MixedCase", .oper_hold, 1_000, "");

    // Assert
    try std.testing.expectEqual(Reason.oper_hold, nd.isHeld("mixedcase", 0).?);
    try std.testing.expectEqual(Reason.oper_hold, nd.isHeld("MIXEDCASE", 0).?);
    try std.testing.expect(nd.get("mIxEdCaSe", 0) != null);
    try std.testing.expect(nd.release("MIXEDCASE"));
}

test "max_holds limit is enforced with a typed error" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{ .max_holds = 2 });
    defer nd.deinit();

    // Act
    try nd.holdExplicit("one", .oper_hold, 100, "");
    try nd.holdExplicit("two", .oper_hold, 100, "");

    // Assert
    try std.testing.expectError(error.TooManyHolds, nd.holdExplicit("three", .oper_hold, 100, ""));
    // Replacing an existing nick is allowed even at capacity.
    try nd.holdExplicit("two", .quit_delay, 200, "replaced");
    try std.testing.expectEqual(@as(usize, 2), nd.count());
}

test "invalid and oversized inputs are rejected" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{ .max_nick_bytes = 8, .max_note_bytes = 4 });
    defer nd.deinit();

    // Act / Assert
    try std.testing.expectError(error.InvalidNick, nd.holdExplicit("", .oper_hold, 100, ""));
    try std.testing.expectError(error.InvalidNick, nd.holdExplicit("bad nick", .oper_hold, 100, ""));
    try std.testing.expectError(error.NickTooLong, nd.holdExplicit("toolongnick", .oper_hold, 100, ""));
    try std.testing.expectError(error.NoteTooLong, nd.holdExplicit("ok", .oper_hold, 100, "toolong"));
    // Invalid nick in read paths is reported as absent, not an error.
    try std.testing.expectEqual(@as(?Reason, null), nd.isHeld("bad nick", 0));
    try std.testing.expect(!nd.release("bad nick"));
}

test "clear empties the store without leaking" {
    // Arrange
    var nd = NickDelay.init(std.testing.allocator, .{});
    defer nd.deinit();
    try nd.holdExplicit("x", .oper_hold, 100, "note-x");
    try nd.holdExplicit("y", .services_hold, 200, "note-y");

    // Act
    nd.clear();

    // Assert
    try std.testing.expectEqual(@as(usize, 0), nd.count());
    // Reusing the cleared store still works.
    try nd.holdExplicit("z", .quit_delay, 300, "note-z");
    try std.testing.expectEqual(@as(usize, 1), nd.count());
}
