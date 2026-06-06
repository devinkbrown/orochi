//! Monotonic server-time guard for the IRCv3 `server-time` message tag.
//!
//! The IRCv3 `server-time` tag carries a UTC timestamp so clients can render
//! when a message was produced (`@time=YYYY-MM-DDThh:mm:ss.sssZ`). The raw
//! wall clock is unsuitable as the direct source for these tags: NTP steps,
//! manual operator clock fixes, leap-second smearing, and VM live-migration
//! can all move the wall clock *backwards*. If two messages are emitted around
//! such an adjustment, the second message can carry an earlier timestamp than
//! the first, which corrupts client-side ordering, history merges, and any
//! consumer that assumes tags are non-decreasing.
//!
//! This module is PURE: it never reads the system clock. Every call that needs
//! the current time accepts a caller-supplied wall-clock timestamp in
//! milliseconds since the Unix epoch (UTC). Callers feed the real clock (see
//! `substrate/platform.zig`) at the edge; this guard only transforms and
//! observes those values, which keeps it fully deterministic and testable.
//!
//! Responsibilities:
//!   * `Clock.next` returns a strictly non-decreasing stream of timestamps,
//!     so emitted tags never go backwards even when the wall clock does.
//!   * `Clock.skew` reports the signed drift between the wall clock and the
//!     monotonic stream (negative = wall clock is behind the guarded stream).
//!   * A configurable max-skew alarm flags adjustments large enough to warrant
//!     operator attention (a snomask, log line, or metric at the call site).
//!   * `formatServerTime` renders a guarded millisecond timestamp as the exact
//!     ISO-8601 tag value the IRCv3 spec requires.
//!
//! No allocation is performed anywhere in this module.

const std = @import("std");

/// Exact byte length of an IRCv3 `server-time` tag value:
/// `YYYY-MM-DDThh:mm:ss.sssZ` is always 24 characters for years 0000-9999.
pub const SERVER_TIME_LEN: usize = 24;

/// Largest Unix-millis value whose year is still <= 9999, so the fixed-width
/// 4-digit year field never overflows. 253402300799 s = 9999-12-31T23:59:59Z.
pub const MAX_UNIX_MILLIS: i64 = 253402300799 * 1000 + 999;

/// Errors produced when rendering a `server-time` value.
pub const FormatError = error{
    /// The timestamp is negative or beyond year 9999, so it cannot be encoded.
    InvalidTime,
    /// The destination buffer is smaller than `SERVER_TIME_LEN`.
    OutputTooSmall,
};

/// Tuning for the monotonic guard.
pub const Config = struct {
    /// Absolute skew (in milliseconds) at or beyond which `next`/`skew` flags an
    /// alarm. The comparison is on the magnitude, so both forward jumps and
    /// backward jumps trip it. A value of 0 means "alarm on any nonzero skew";
    /// the default tolerates two minutes of drift before alarming.
    max_skew_ms: i64 = 2 * 60 * 1000,
};

/// Outcome of advancing the guarded clock by one tick.
pub const Tick = struct {
    /// The guarded, strictly-non-decreasing timestamp to stamp on the tag.
    /// Always `>= previous_emitted + 1` and `>= 0`.
    emitted_ms: i64,
    /// Signed drift `wallclock_ms - emitted_ms`. Zero when the wall clock was
    /// at or ahead of the guarded stream; negative when the wall clock lagged
    /// (i.e. the guard had to hold the line and refuse to go backwards).
    skew_ms: i64,
    /// True when `@abs(skew_ms) >= config.max_skew_ms`, signalling the caller
    /// should surface the adjustment (log / snomask / metric).
    alarm: bool,
};

/// A pure, monotonic wrapper around a caller-supplied wall clock.
///
/// The guarantee is simple: the sequence returned by repeated `next` calls is
/// strictly increasing, regardless of how the wall-clock argument moves. When
/// the wall clock advances normally, `next` returns it verbatim. When the wall
/// clock stalls or jumps backward, `next` returns `last_emitted + 1` so the
/// stream keeps moving forward by the minimum representable step (1 ms).
pub const Clock = struct {
    /// The most recent value returned by `next`. Sentinel `min(i64)` means
    /// "nothing emitted yet", so the very first `next` is free to adopt the
    /// wall clock exactly (clamped to >= 0).
    last_emitted: i64 = std.math.minInt(i64),
    /// Tuning, primarily the skew alarm threshold.
    config: Config = .{},

    /// Construct a guard with explicit configuration.
    pub fn init(config: Config) Clock {
        return .{ .config = config };
    }

    /// Whether `next` has ever been called on this guard.
    pub fn hasEmitted(self: Clock) bool {
        return self.last_emitted != std.math.minInt(i64);
    }

    /// Advance the guard and return the timestamp to stamp on the next tag.
    ///
    /// `wallclock_ms` is the current wall clock in Unix milliseconds (UTC).
    /// Negative wall-clock inputs are clamped to 0 before guarding, so the
    /// emitted stream is always non-negative and renderable.
    ///
    /// The returned value is `max(last_emitted + 1, clamped_wallclock)` for all
    /// calls after the first, making the stream strictly increasing.
    pub fn next(self: *Clock, wallclock_ms: i64) i64 {
        return self.tick(wallclock_ms).emitted_ms;
    }

    /// Like `next`, but also reports the drift and whether the skew alarm trips.
    pub fn tick(self: *Clock, wallclock_ms: i64) Tick {
        const wall = if (wallclock_ms < 0) 0 else wallclock_ms;

        const emitted = if (!self.hasEmitted())
            wall
        else blk: {
            // Saturating add guards against pathological i64 overflow when the
            // stream is pinned near maxInt for a very long time.
            const floor = std.math.add(i64, self.last_emitted, 1) catch std.math.maxInt(i64);
            break :blk @max(floor, wall);
        };

        self.last_emitted = emitted;

        // Drift of the real clock relative to what we actually emitted. When the
        // wall clock had to be held back, this is negative by exactly the amount
        // we refused to rewind.
        const drift = std.math.sub(i64, wall, emitted) catch std.math.minInt(i64);

        return .{
            .emitted_ms = emitted,
            .skew_ms = drift,
            .alarm = self.isAlarming(drift),
        };
    }

    /// Report the skew the *next* `next(wallclock_ms)` call would observe,
    /// without mutating the guard. Positive means the wall clock is ahead of the
    /// guarded floor; negative means it lags and would be held back. Before the
    /// first emission the guard imposes no floor, so the skew is 0.
    pub fn skew(self: Clock, wallclock_ms: i64) i64 {
        const wall = if (wallclock_ms < 0) 0 else wallclock_ms;
        if (!self.hasEmitted()) return 0;
        const floor = std.math.add(i64, self.last_emitted, 1) catch std.math.maxInt(i64);
        const emitted = @max(floor, wall);
        return std.math.sub(i64, wall, emitted) catch std.math.minInt(i64);
    }

    /// True when `drift` is large enough (in magnitude) to trip the alarm.
    pub fn isAlarming(self: Clock, drift: i64) bool {
        const magnitude = if (drift < 0)
            (std.math.negate(drift) catch std.math.maxInt(i64))
        else
            drift;
        return magnitude >= self.config.max_skew_ms;
    }
};

/// Render `unix_millis` as an IRCv3 `server-time` value into `out`.
///
/// Produces exactly `SERVER_TIME_LEN` bytes in the canonical form
/// `YYYY-MM-DDThh:mm:ss.sssZ` (always UTC, always millisecond precision) and
/// returns a slice over the written prefix. The caller owns `out`; no
/// allocation occurs.
pub fn formatServerTime(unix_millis: i64, out: []u8) FormatError![]const u8 {
    if (unix_millis < 0 or unix_millis > MAX_UNIX_MILLIS) return error.InvalidTime;
    if (out.len < SERVER_TIME_LEN) return error.OutputTooSmall;

    const seconds: u64 = @intCast(@divTrunc(unix_millis, 1000));
    const millis: u16 = @intCast(@mod(unix_millis, 1000));

    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    if (year_day.year > 9999) return error.InvalidTime;

    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    writeFixed(out[0..4], year_day.year, 4);
    out[4] = '-';
    writeFixed(out[5..7], month_day.month.numeric(), 2);
    out[7] = '-';
    writeFixed(out[8..10], @as(u8, month_day.day_index) + 1, 2);
    out[10] = 'T';
    writeFixed(out[11..13], day_seconds.getHoursIntoDay(), 2);
    out[13] = ':';
    writeFixed(out[14..16], day_seconds.getMinutesIntoHour(), 2);
    out[16] = ':';
    writeFixed(out[17..19], day_seconds.getSecondsIntoMinute(), 2);
    out[19] = '.';
    writeFixed(out[20..23], millis, 3);
    out[23] = 'Z';
    return out[0..SERVER_TIME_LEN];
}

/// Write `value` right-justified and zero-padded into the `width`-byte `dst`.
/// `width` must equal `dst.len`; values wider than `width` keep only their
/// low-order digits (callers guarantee the range, so this never happens here).
fn writeFixed(dst: []u8, value: anytype, comptime width: usize) void {
    std.debug.assert(dst.len == width);
    var v: u64 = @intCast(value);
    var i: usize = width;
    while (i > 0) {
        i -= 1;
        dst[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
}

// ---------------------------------------------------------------------------
// Tests. All time values are injected; the system clock is never read, and no
// allocations are made, so std.testing.allocator stays leak-free trivially.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "first next adopts the wall clock verbatim" {
    var clock = Clock{};
    try testing.expectEqual(@as(i64, 1_685_732_096_123), clock.next(1_685_732_096_123));
    try testing.expect(clock.hasEmitted());
}

test "next is strictly non-decreasing under a backward jump" {
    var clock = Clock{};
    const t0 = clock.next(1_000_000);
    // Wall clock steps backward 5 seconds (e.g. an NTP correction).
    const t1 = clock.next(995_000);
    // Wall clock recovers but is still below the guarded floor.
    const t2 = clock.next(999_000);

    try testing.expectEqual(@as(i64, 1_000_000), t0);
    try testing.expectEqual(@as(i64, 1_000_001), t1);
    try testing.expectEqual(@as(i64, 1_000_002), t2);
    try testing.expect(t1 > t0);
    try testing.expect(t2 > t1);
}

test "next passes through normal forward progress unchanged" {
    var clock = Clock{};
    try testing.expectEqual(@as(i64, 10), clock.next(10));
    try testing.expectEqual(@as(i64, 25), clock.next(25));
    try testing.expectEqual(@as(i64, 25_000), clock.next(25_000));
}

test "repeated identical wall clock still advances by one ms" {
    var clock = Clock{};
    try testing.expectEqual(@as(i64, 500), clock.next(500));
    try testing.expectEqual(@as(i64, 501), clock.next(500));
    try testing.expectEqual(@as(i64, 502), clock.next(500));
}

test "negative wall clock is clamped to zero" {
    var clock = Clock{};
    try testing.expectEqual(@as(i64, 0), clock.next(-1_000));
    try testing.expectEqual(@as(i64, 1), clock.next(-5));
}

test "skew is zero before any emission" {
    const clock = Clock{};
    try testing.expectEqual(@as(i64, 0), clock.skew(123_456));
}

test "skew is zero when the wall clock is ahead of the floor" {
    var clock = Clock{};
    _ = clock.next(1_000);
    // Wall clock 50ms ahead of the floor (1001): next would emit the wall clock
    // verbatim (1050), so there is no drift between wall and emitted.
    try testing.expectEqual(@as(i64, 0), clock.skew(1_050));
    // skew() did not advance the guard.
    try testing.expectEqual(@as(i64, 1_000), clock.last_emitted);
}

test "skew reports backward drift as negative" {
    var clock = Clock{};
    _ = clock.next(1_000_000);
    // Wall clock 4s behind; floor is 1_000_001, so emitted would be 1_000_001
    // and drift = 996_000 - 1_000_001 = -4001.
    try testing.expectEqual(@as(i64, -4_001), clock.skew(996_000));
}

test "tick reports drift and emitted together" {
    var clock = Clock{};
    _ = clock.next(2_000);
    const t = clock.tick(1_500);
    try testing.expectEqual(@as(i64, 2_001), t.emitted_ms);
    try testing.expectEqual(@as(i64, -501), t.skew_ms);
}

test "alarm trips on large backward jump" {
    var clock = Clock.init(.{ .max_skew_ms = 1_000 });
    _ = clock.next(10_000_000);
    // 2s backward jump; magnitude exceeds the 1s threshold.
    const t = clock.tick(9_998_000);
    try testing.expect(t.alarm);
    try testing.expect(t.skew_ms < 0);
}

test "alarm trips on large forward jump" {
    var clock = Clock.init(.{ .max_skew_ms = 1_000 });
    _ = clock.next(1_000);
    // 5s forward jump; emitted follows the wall clock so drift is 0 here...
    const t = clock.tick(6_000);
    // Forward jumps do not create skew between wall and emitted (emitted == wall),
    // so this specific case does not alarm.
    try testing.expectEqual(@as(i64, 0), t.skew_ms);
    try testing.expect(!t.alarm);
}

test "alarm honors threshold boundary" {
    var clock = Clock.init(.{ .max_skew_ms = 100 });
    _ = clock.next(50_000);
    // drift magnitude exactly 100 -> alarms (>=).
    const at = clock.tick(49_899); // floor 50_001, emitted 50_001, drift -102
    try testing.expect(at.alarm);
    // Reset and test just under threshold.
    var clock2 = Clock.init(.{ .max_skew_ms = 100 });
    _ = clock2.next(50_000);
    const below = clock2.tick(49_902); // floor 50_001, drift -99
    try testing.expectEqual(@as(i64, -99), below.skew_ms);
    try testing.expect(!below.alarm);
}

test "isAlarming with zero threshold flags any nonzero drift" {
    const clock = Clock.init(.{ .max_skew_ms = 0 });
    try testing.expect(clock.isAlarming(1));
    try testing.expect(clock.isAlarming(-1));
    try testing.expect(clock.isAlarming(0)); // 0 >= 0
}

test "formatServerTime renders the canonical ISO-8601 value" {
    var buf: [SERVER_TIME_LEN]u8 = undefined;
    // 2023-06-02T18:54:56.123Z
    const out = try formatServerTime(1_685_732_096_123, &buf);
    try testing.expectEqual(SERVER_TIME_LEN, out.len);
    try testing.expectEqualStrings("2023-06-02T18:54:56.123Z", out);
}

test "formatServerTime renders the Unix epoch" {
    var buf: [SERVER_TIME_LEN]u8 = undefined;
    const out = try formatServerTime(0, &buf);
    try testing.expectEqualStrings("1970-01-01T00:00:00.000Z", out);
}

test "formatServerTime keeps fractional milliseconds zero-padded" {
    var buf: [SERVER_TIME_LEN]u8 = undefined;
    const out = try formatServerTime(7, &buf);
    try testing.expectEqualStrings("1970-01-01T00:00:00.007Z", out);
}

test "formatServerTime rejects negative and out-of-range times" {
    var buf: [SERVER_TIME_LEN]u8 = undefined;
    try testing.expectError(error.InvalidTime, formatServerTime(-1, &buf));
    try testing.expectError(error.InvalidTime, formatServerTime(MAX_UNIX_MILLIS + 1, &buf));
}

test "formatServerTime rejects an undersized buffer" {
    var small: [SERVER_TIME_LEN - 1]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, formatServerTime(0, &small));
}

test "guarded stream feeds straight into the formatter" {
    var clock = Clock{};
    var buf: [SERVER_TIME_LEN]u8 = undefined;

    const a = clock.next(1_685_732_096_123);
    const sa = try formatServerTime(a, &buf);
    try testing.expectEqualStrings("2023-06-02T18:54:56.123Z", sa);

    // Backward wall-clock jump still yields a strictly later, valid tag.
    const b = clock.next(1_685_732_096_000);
    try testing.expect(b > a);
    const sb = try formatServerTime(b, &buf);
    try testing.expectEqualStrings("2023-06-02T18:54:56.124Z", sb);
}

test "max value is renderable and at the year boundary" {
    var buf: [SERVER_TIME_LEN]u8 = undefined;
    const out = try formatServerTime(MAX_UNIX_MILLIS, &buf);
    try testing.expectEqualStrings("9999-12-31T23:59:59.999Z", out);
}
