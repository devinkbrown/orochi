// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-account login/seen history — a small, fixed-capacity ring of recent
//! authentication events used to answer an `INFO`/`LASTSEEN` services reply.
//!
//! Each account keeps a bounded ring of `{timestamp, hostmask, event}` records.
//! Recording past capacity evicts the oldest entry, so memory is fully bounded
//! and no allocator is involved — every record stores its hostmask inline in a
//! fixed byte buffer. The ring also tracks the most recent overall activity
//! (`last_seen`) and the most recent *successful* login (`last_login`) so those
//! common queries are O(1) and survive eviction of the underlying record.
//!
//! This module is pure logic: callers pass the wall-clock timestamp (Unix-epoch
//! milliseconds, matching `substrate/platform.realtimeMillis`) so the history is
//! deterministic and trivially testable. Wiring into the account store and the
//! command surface is done by the caller; this file imports only `std`.

const std = @import("std");

/// Maximum number of history records retained per account. Recording beyond
/// this evicts the oldest. Kept small: this is a recent-activity tail, not an
/// audit log.
pub const ring_capacity: usize = 8;

/// Maximum stored hostmask length (`nick!user@host`). Longer masks are
/// truncated to fit the inline buffer; the recorded mask is always valid UTF-8
/// bytes as supplied, just bounded.
pub const max_hostmask_len: usize = 128;

/// Default number of records rendered by `render` when the caller does not
/// constrain it further.
pub const default_render_count: usize = 5;

/// Kind of authentication event recorded in the history ring.
pub const EventKind = enum(u8) {
    /// A successful login (password, SASL, EXTERNAL, session reclaim, …).
    login,
    /// A clean logout / session end.
    logout,
    /// A failed authentication attempt against this account.
    fail,

    /// Short lowercase label for rendering.
    pub fn label(self: EventKind) []const u8 {
        return switch (self) {
            .login => "login",
            .logout => "logout",
            .fail => "fail",
        };
    }
};

/// A single history record. Plain value type; the hostmask is stored inline so
/// records can live in a fixed array without any heap ownership.
pub const Record = struct {
    /// Wall-clock time of the event, Unix-epoch milliseconds.
    timestamp: i64,
    /// Inline hostmask storage; only `mask_len` bytes are valid.
    mask_buf: [max_hostmask_len]u8 = [_]u8{0} ** max_hostmask_len,
    /// Number of valid bytes in `mask_buf`.
    mask_len: usize = 0,
    /// What happened.
    event: EventKind,

    /// The recorded hostmask as a slice into the inline buffer.
    pub fn hostmask(self: *const Record) []const u8 {
        return self.mask_buf[0..self.mask_len];
    }
};

/// Fixed-capacity ring of recent authentication events for one account.
///
/// All state is inline (no allocator). `head` is the index where the next
/// record will be written; `count` is how many slots are currently valid (it
/// saturates at `ring_capacity`). Oldest-first iteration starts at
/// `head - count` (mod capacity).
pub const SeenHistory = struct {
    records: [ring_capacity]Record = undefined,
    /// Index of the next write slot (mod `ring_capacity`).
    head: usize = 0,
    /// Number of valid records (0..=ring_capacity).
    count: usize = 0,
    /// Most recent timestamp of any event, or null if none recorded.
    last_seen_ts: ?i64 = null,
    /// Most recent timestamp of a successful `login`, or null if none.
    last_login_ts: ?i64 = null,

    /// A fresh, empty history.
    pub fn init() SeenHistory {
        return .{};
    }

    /// Record an event, evicting the oldest record once at capacity.
    ///
    /// `mask` is copied (truncated to `max_hostmask_len`). `timestamp` is
    /// caller-supplied wall-clock ms. `last_seen` always advances to the most
    /// recent timestamp seen; `last_login` advances only on `.login`.
    pub fn record(self: *SeenHistory, timestamp: i64, mask: []const u8, event: EventKind) void {
        var rec = Record{ .timestamp = timestamp, .event = event };
        const copy_len = @min(mask.len, max_hostmask_len);
        @memcpy(rec.mask_buf[0..copy_len], mask[0..copy_len]);
        rec.mask_len = copy_len;

        self.records[self.head] = rec;
        self.head = (self.head + 1) % ring_capacity;
        if (self.count < ring_capacity) self.count += 1;

        // last_seen advances monotonically toward the newest event we've been
        // told about (guard against out-of-order timestamps).
        if (self.last_seen_ts == null or timestamp > self.last_seen_ts.?) {
            self.last_seen_ts = timestamp;
        }
        if (event == .login) {
            if (self.last_login_ts == null or timestamp > self.last_login_ts.?) {
                self.last_login_ts = timestamp;
            }
        }
    }

    /// Index of the oldest valid record in `records`, or null when empty.
    fn oldestIndex(self: *const SeenHistory) ?usize {
        if (self.count == 0) return null;
        // head points at the next write slot; oldest is `count` slots behind.
        return (self.head + ring_capacity - self.count) % ring_capacity;
    }

    /// The most recent record, or null when empty.
    pub fn latest(self: *const SeenHistory) ?*const Record {
        if (self.count == 0) return null;
        const idx = (self.head + ring_capacity - 1) % ring_capacity;
        return &self.records[idx];
    }

    /// Most recent activity timestamp (any event), or null.
    pub fn lastSeen(self: *const SeenHistory) ?i64 {
        return self.last_seen_ts;
    }

    /// Most recent successful-login timestamp, or null.
    pub fn lastLogin(self: *const SeenHistory) ?i64 {
        return self.last_login_ts;
    }

    /// Number of valid records currently retained.
    pub fn len(self: *const SeenHistory) usize {
        return self.count;
    }

    /// Copy up to `want` of the most-recent records into `out`, newest first.
    /// Returns the number written (`min(want, len, out.len)`). Pure: does not
    /// mutate the history.
    pub fn recent(self: *const SeenHistory, want: usize, out: []Record) usize {
        const n = @min(@min(want, self.count), out.len);
        if (n == 0) return 0;
        // Walk backwards from the newest record.
        var i: usize = 0;
        var idx = (self.head + ring_capacity - 1) % ring_capacity;
        while (i < n) : (i += 1) {
            out[i] = self.records[idx];
            idx = (idx + ring_capacity - 1) % ring_capacity;
        }
        return n;
    }

    /// Render the most-recent `count` records as a human-readable, newest-first
    /// reply body suitable for an `INFO`/`LASTSEEN` numeric. Each line is
    /// `<event> <timestamp> <hostmask>`. Writes into `writer`; returns the
    /// number of lines emitted. `count` of 0 uses `default_render_count`.
    pub fn render(self: *const SeenHistory, writer: anytype, count: usize) !usize {
        const want = if (count == 0) default_render_count else count;
        var buf: [ring_capacity]Record = undefined;
        const n = self.recent(want, buf[0..]);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const r = &buf[i];
            if (i != 0) try writer.writeByte('\n');
            try writer.print("{s} {d} {s}", .{ r.event.label(), r.timestamp, r.hostmask() });
        }
        return n;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "empty history reports no activity" {
    var h = SeenHistory.init();
    try testing.expectEqual(@as(usize, 0), h.len());
    try testing.expectEqual(@as(?i64, null), h.lastSeen());
    try testing.expectEqual(@as(?i64, null), h.lastLogin());
    try testing.expect(h.latest() == null);
}

test "record tracks last_seen and last_login independently" {
    var h = SeenHistory.init();
    h.record(100, "nick!user@host", .login);
    try testing.expectEqual(@as(?i64, 100), h.lastSeen());
    try testing.expectEqual(@as(?i64, 100), h.lastLogin());

    // A later fail advances last_seen but NOT last_login.
    h.record(200, "nick!user@host", .fail);
    try testing.expectEqual(@as(?i64, 200), h.lastSeen());
    try testing.expectEqual(@as(?i64, 100), h.lastLogin());

    // A logout advances last_seen but not last_login.
    h.record(300, "nick!user@host", .logout);
    try testing.expectEqual(@as(?i64, 300), h.lastSeen());
    try testing.expectEqual(@as(?i64, 100), h.lastLogin());

    // A new login advances both.
    h.record(400, "nick!user@host", .login);
    try testing.expectEqual(@as(?i64, 400), h.lastSeen());
    try testing.expectEqual(@as(?i64, 400), h.lastLogin());
}

test "fail before any login leaves last_login null" {
    var h = SeenHistory.init();
    h.record(10, "a!b@c", .fail);
    h.record(20, "a!b@c", .fail);
    try testing.expectEqual(@as(?i64, 20), h.lastSeen());
    try testing.expectEqual(@as(?i64, null), h.lastLogin());
}

test "out-of-order timestamps do not regress last_seen" {
    var h = SeenHistory.init();
    h.record(500, "x!y@z", .login);
    h.record(100, "x!y@z", .login); // stale event arrives late
    try testing.expectEqual(@as(?i64, 500), h.lastSeen());
    try testing.expectEqual(@as(?i64, 500), h.lastLogin());
}

test "ring evicts oldest beyond capacity" {
    var h = SeenHistory.init();
    // Write capacity+3 records; timestamps 0..capacity+2.
    const total = ring_capacity + 3;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        h.record(@intCast(i), "n!u@h", .login);
    }
    try testing.expectEqual(ring_capacity, h.len());

    // Newest record is the last written.
    const newest = h.latest().?;
    try testing.expectEqual(@as(i64, @intCast(total - 1)), newest.timestamp);

    // recent() returns exactly the last `ring_capacity`, newest first.
    var buf: [ring_capacity]Record = undefined;
    const got = h.recent(ring_capacity, buf[0..]);
    try testing.expectEqual(ring_capacity, got);
    var j: usize = 0;
    while (j < got) : (j += 1) {
        const expected: i64 = @intCast(total - 1 - j);
        try testing.expectEqual(expected, buf[j].timestamp);
    }
    // The three oldest (0,1,2) must have been evicted.
    try testing.expect(buf[got - 1].timestamp == @as(i64, @intCast(total - ring_capacity)));
}

test "recent honors want and out bounds" {
    var h = SeenHistory.init();
    h.record(1, "a", .login);
    h.record(2, "b", .login);
    h.record(3, "c", .login);

    var small: [2]Record = undefined;
    // want larger than available and larger than out -> clamped to out.len.
    try testing.expectEqual(@as(usize, 2), h.recent(10, small[0..]));
    try testing.expectEqual(@as(i64, 3), small[0].timestamp);
    try testing.expectEqual(@as(i64, 2), small[1].timestamp);

    // want smaller than available.
    var one: [1]Record = undefined;
    try testing.expectEqual(@as(usize, 1), h.recent(1, one[0..]));
    try testing.expectEqual(@as(i64, 3), one[0].timestamp);

    // want zero -> nothing.
    try testing.expectEqual(@as(usize, 0), h.recent(0, small[0..]));
}

test "hostmask is copied and truncated to capacity" {
    var h = SeenHistory.init();
    const short = "nick!user@host";
    h.record(1, short, .login);
    try testing.expectEqualStrings(short, h.latest().?.hostmask());

    // Over-long mask is truncated, not overflowing.
    const long = "x" ** (max_hostmask_len + 50);
    h.record(2, long, .login);
    try testing.expectEqual(max_hostmask_len, h.latest().?.hostmask().len);
}

test "render emits newest-first lines and respects default count" {
    var h = SeenHistory.init();
    h.record(10, "a!u@h", .login);
    h.record(20, "b!u@h", .fail);
    h.record(30, "c!u@h", .logout);

    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(buf[0..]);
    const lines = try h.render(&writer, 0); // 0 -> default
    try testing.expectEqual(@as(usize, 3), lines);

    const out = writer.buffered();
    const expected =
        "logout 30 c!u@h\n" ++
        "fail 20 b!u@h\n" ++
        "login 10 a!u@h";
    try testing.expectEqualStrings(expected, out);
}

test "render clamps to a requested count smaller than length" {
    var h = SeenHistory.init();
    var i: usize = 0;
    while (i < ring_capacity) : (i += 1) {
        h.record(@intCast(i), "m!u@h", .login);
    }
    var buf: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(buf[0..]);
    const lines = try h.render(&writer, 2);
    try testing.expectEqual(@as(usize, 2), lines);
    // Two newest only.
    const out = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "login 7 ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "login 6 ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "login 5 ") == null);
}

test "render on empty history emits nothing" {
    var h = SeenHistory.init();
    var buf: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(buf[0..]);
    const lines = try h.render(&writer, 5);
    try testing.expectEqual(@as(usize, 0), lines);
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "EventKind labels" {
    try testing.expectEqualStrings("login", EventKind.login.label());
    try testing.expectEqualStrings("logout", EventKind.logout.label());
    try testing.expectEqualStrings("fail", EventKind.fail.label());
}
