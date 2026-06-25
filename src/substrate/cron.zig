// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! cron.zig — 5-field cron expression parser + next-fire calculator.
//!
//! Supports: ranges (1-5), steps (*/15, 10-30/5), lists (1,2,3),
//! names (JAN-DEC, SUN-SAT), wildcards (*).  Standard dom/dow OR semantics.
//!
//! All dates are proleptic Gregorian UTC.  No system clock is used.
//! Call `nextAfter(expr, unix_secs)` → unix_secs of the next matching minute.

const std = @import("std");

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

pub const CronError = error{
    InvalidExpression,
    InvalidField,
    InvalidRange,
    InvalidStep,
    OutOfRange,
};

// ---------------------------------------------------------------------------
// Field value sets (bit-fields)
// ---------------------------------------------------------------------------

/// A set of allowed values for a single cron field.
/// Stored as a 64-bit mask (more than enough for any field).
const FieldSet = struct {
    bits: u64 = 0,

    fn set(self: *FieldSet, v: u6) void {
        self.bits |= @as(u64, 1) << v;
    }

    fn contains(self: FieldSet, v: u6) bool {
        return (self.bits >> v) & 1 == 1;
    }

    fn any(self: FieldSet) bool {
        return self.bits != 0;
    }
};

// ---------------------------------------------------------------------------
// Parsed cron expression
// ---------------------------------------------------------------------------

pub const Cron = struct {
    minutes: FieldSet, // 0-59
    hours: FieldSet, // 0-23
    doms: FieldSet, // 1-31
    months: FieldSet, // 1-12
    dows: FieldSet, // 0-6 (Sunday=0)
    dom_star: bool, // true when DOM field was bare '*'
    dow_star: bool, // true when DOW field was bare '*'
};

// ---------------------------------------------------------------------------
// Month / weekday name tables
// ---------------------------------------------------------------------------

const month_names = [_][]const u8{
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
    "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
};

const dow_names = [_][]const u8{
    "SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT",
};

fn parseMonthName(s: []const u8) ?u8 {
    var buf: [3]u8 = undefined;
    if (s.len != 3) return null;
    for (s, 0..) |c, i| buf[i] = std.ascii.toUpper(c);
    for (month_names, 0..) |name, i| {
        if (std.mem.eql(u8, &buf, name)) return @intCast(i + 1);
    }
    return null;
}

fn parseDowName(s: []const u8) ?u8 {
    var buf: [3]u8 = undefined;
    if (s.len != 3) return null;
    for (s, 0..) |c, i| buf[i] = std.ascii.toUpper(c);
    for (dow_names, 0..) |name, i| {
        if (std.mem.eql(u8, &buf, name)) return @intCast(i);
    }
    return null;
}

// ---------------------------------------------------------------------------
// Token / value parsing helpers
// ---------------------------------------------------------------------------

/// Parse a single numeric token or a 3-letter name.
/// `is_month` and `is_dow` select the name table.
fn parseValue(tok: []const u8, is_month: bool, is_dow: bool) CronError!u8 {
    if (is_month) {
        if (parseMonthName(tok)) |v| return v;
    }
    if (is_dow) {
        if (parseDowName(tok)) |v| return v;
    }
    const n = std.fmt.parseInt(u8, tok, 10) catch return CronError.InvalidField;
    return n;
}

/// Parse one segment (no commas).  A segment is one of:
///   value
///   value-value
///   value-value/step
///   */step
///   *
fn parseSegment(
    seg: []const u8,
    min_val: u8,
    max_val: u8,
    is_month: bool,
    is_dow: bool,
    out: *FieldSet,
) CronError!void {
    // Split on '/'
    const slash = std.mem.indexOfScalar(u8, seg, '/');
    const range_part = if (slash) |s| seg[0..s] else seg;
    const step_part = if (slash) |s| seg[s + 1 ..] else null;

    const step: u8 = if (step_part) |sp| blk: {
        const s = std.fmt.parseInt(u8, sp, 10) catch return CronError.InvalidStep;
        if (s == 0) return CronError.InvalidStep;
        break :blk s;
    } else 1;

    var lo: u8 = undefined;
    var hi: u8 = undefined;

    if (std.mem.eql(u8, range_part, "*")) {
        lo = min_val;
        hi = max_val;
    } else {
        // Check for '-'
        const dash = std.mem.indexOfScalar(u8, range_part, '-');
        if (dash) |d| {
            // Handle names that contain a dash only if they are actually names
            // (no name contains '-', so this is safe).
            const lo_tok = range_part[0..d];
            const hi_tok = range_part[d + 1 ..];
            lo = try parseValue(lo_tok, is_month, is_dow);
            hi = try parseValue(hi_tok, is_month, is_dow);
        } else {
            lo = try parseValue(range_part, is_month, is_dow);
            hi = lo;
        }
    }

    if (lo < min_val or hi > max_val or lo > hi) return CronError.OutOfRange;

    var v: u8 = lo;
    while (v <= hi) : (v += step) {
        if (v > max_val) break;
        out.set(@intCast(v));
    }
}

/// Parse a full field (may contain commas).
/// Returns whether the original token was a bare '*'.
fn parseField(
    field: []const u8,
    min_val: u8,
    max_val: u8,
    is_month: bool,
    is_dow: bool,
    out: *FieldSet,
) CronError!bool {
    const bare_star = std.mem.eql(u8, field, "*");
    var it = std.mem.splitScalar(u8, field, ',');
    while (it.next()) |seg| {
        try parseSegment(seg, min_val, max_val, is_month, is_dow, out);
    }
    if (!out.any()) return CronError.InvalidField;
    return bare_star;
}

// ---------------------------------------------------------------------------
// Public: parse
// ---------------------------------------------------------------------------

/// Parse a 5-field cron expression string.
pub fn parse(expr: []const u8) CronError!Cron {
    var fields: [5][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeScalar(u8, expr, ' ');
    while (it.next()) |f| {
        if (count >= 5) return CronError.InvalidExpression;
        fields[count] = f;
        count += 1;
    }
    if (count != 5) return CronError.InvalidExpression;

    var c: Cron = undefined;
    c.minutes = .{};
    c.hours = .{};
    c.doms = .{};
    c.months = .{};
    c.dows = .{};

    _ = try parseField(fields[0], 0, 59, false, false, &c.minutes);
    _ = try parseField(fields[1], 0, 23, false, false, &c.hours);
    c.dom_star = try parseField(fields[2], 1, 31, false, false, &c.doms);
    c.months.bits = 0;
    _ = try parseField(fields[3], 1, 12, true, false, &c.months);
    c.dow_star = try parseField(fields[4], 0, 6, false, true, &c.dows);

    return c;
}

// ---------------------------------------------------------------------------
// Proleptic Gregorian calendar arithmetic
// ---------------------------------------------------------------------------

/// True if `y` is a leap year.
fn isLeap(y: i32) bool {
    return (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
}

/// Days in month `m` (1-12) of year `y`.
fn daysInMonth(y: i32, m: u8) u8 {
    return switch (m) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeap(y)) 29 else 28,
        else => unreachable,
    };
}

/// Day-of-week for a given (y, m, d).  Returns 0=Sun … 6=Sat.
/// Uses Tomohiko Sakamoto's algorithm.
fn weekday(y_in: i32, m: u8, d: u8) u8 {
    const t = [_]i32{ 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    var y = y_in;
    if (m < 3) y -= 1;
    const dow = @mod(y + @divTrunc(y, 4) - @divTrunc(y, 100) + @divTrunc(y, 400) + t[@as(usize, m - 1)] + d, 7);
    return @intCast(dow);
}

/// Calendar date + time.
const DateTime = struct {
    year: i32,
    month: u8, // 1-12
    day: u8, // 1-31
    hour: u8, // 0-23
    minute: u8, // 0-59
};

/// Convert Unix epoch (seconds, UTC) to DateTime.
/// Epoch is 1970-01-01 00:00:00 UTC.
/// Algorithm: Howard Hinnant's civil_from_days (http://howardhinnant.github.io/date_algorithms.html)
fn unixToDateTime(unix: i64) DateTime {
    const minute: u8 = @intCast(@mod(@divFloor(unix, 60), 60));
    const hour: u8 = @intCast(@mod(@divFloor(unix, 3600), 24));
    // days since unix epoch (floor division handles negative)
    var z: i64 = @divFloor(unix, 86400);
    // Shift to proleptic Gregorian epoch (Mar 1, year 0).
    z += 719468;
    const era: i64 = if (z >= 0) @divFloor(z, 146097) else @divFloor(z - 146096, 146097);
    const doe: i64 = z - era * 146097; // [0, 146096]
    const yoe: i64 = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y_era: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: i64 = @divFloor(5 * doy + 2, 153);
    const d: u8 = @intCast(doy - @divFloor(153 * mp + 2, 5) + 1);
    const m: u8 = if (mp < 10) @intCast(mp + 3) else @intCast(mp - 9);
    const y: i32 = @intCast(if (m <= 2) y_era + 1 else y_era);

    return .{
        .year = y,
        .month = m,
        .day = d,
        .hour = hour,
        .minute = minute,
    };
}

/// Convert DateTime to Unix epoch (seconds).
/// Algorithm: Howard Hinnant's days_from_civil.
fn dateTimeToUnix(dt: DateTime) i64 {
    var y: i64 = dt.year;
    var m: i64 = dt.month;
    // Shift Jan/Feb to previous year so year starts on Mar 1.
    if (m <= 2) {
        y -= 1;
        m += 9;
    } else {
        m -= 3;
    }
    const era: i64 = @divFloor(y, 400);
    const yoe: i64 = y - era * 400; // [0, 399]
    const doy: i64 = @divFloor(153 * m + 2, 5) + dt.day - 1; // [0, 365]
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days: i64 = era * 146097 + doe - 719468;

    return days * 86400 + @as(i64, dt.hour) * 3600 + @as(i64, dt.minute) * 60;
}

// ---------------------------------------------------------------------------
// Public: nextAfter
// ---------------------------------------------------------------------------

/// Return the Unix timestamp (seconds) of the next cron firing strictly after
/// `unix_secs`.  Searches up to 4 years ahead before giving up.
pub fn nextAfter(cron: Cron, unix_secs: i64) ?i64 {
    // Advance one minute past the current time.
    var t = unix_secs + 60;
    // Truncate to minute boundary.
    t = @divFloor(t, 60) * 60;

    const limit = unix_secs + 4 * 366 * 24 * 3600; // 4-year safety bound

    while (t <= limit) {
        const dt = unixToDateTime(t);

        // Check month first — if wrong, jump to next month.
        if (!cron.months.contains(@intCast(dt.month))) {
            // Advance to first day of next month.
            var nm: u8 = dt.month + 1;
            var ny: i32 = dt.year;
            if (nm > 12) {
                nm = 1;
                ny += 1;
            }
            const next = dateTimeToUnix(.{ .year = ny, .month = nm, .day = 1, .hour = 0, .minute = 0 });
            t = next;
            continue;
        }

        // Check DOM / DOW with OR semantics.
        // OR semantics: if *both* fields are restricted (not bare '*'), the day
        // matches if EITHER dom matches OR dow matches.  If only one is
        // restricted, use that one.
        const dom_match = cron.doms.contains(@intCast(dt.day));
        const dow_val = weekday(dt.year, dt.month, dt.day);
        const dow_match = cron.dows.contains(@intCast(dow_val));

        const day_match = if (cron.dom_star and cron.dow_star)
            true
        else if (cron.dom_star)
            dow_match
        else if (cron.dow_star)
            dom_match
        else
            dom_match or dow_match;

        if (!day_match) {
            // Advance to next calendar day.
            var nd: u8 = dt.day + 1;
            var nm: u8 = dt.month;
            var ny: i32 = dt.year;
            if (nd > daysInMonth(ny, nm)) {
                nd = 1;
                nm += 1;
                if (nm > 12) {
                    nm = 1;
                    ny += 1;
                }
            }
            const next = dateTimeToUnix(.{ .year = ny, .month = nm, .day = nd, .hour = 0, .minute = 0 });
            t = next;
            continue;
        }

        // Check hour — if wrong, advance to next hour.
        if (!cron.hours.contains(@intCast(dt.hour))) {
            const next_hour: u8 = blk: {
                var h: u8 = dt.hour + 1;
                while (h <= 23) : (h += 1) {
                    if (cron.hours.contains(@intCast(h))) break :blk h;
                }
                break :blk 255; // sentinel: no more hours today
            };
            if (next_hour == 255) {
                // Advance to next day.
                var nd: u8 = dt.day + 1;
                var nm: u8 = dt.month;
                var ny: i32 = dt.year;
                if (nd > daysInMonth(ny, nm)) {
                    nd = 1;
                    nm += 1;
                    if (nm > 12) {
                        nm = 1;
                        ny += 1;
                    }
                }
                t = dateTimeToUnix(.{ .year = ny, .month = nm, .day = nd, .hour = 0, .minute = 0 });
            } else {
                t = dateTimeToUnix(.{ .year = dt.year, .month = dt.month, .day = dt.day, .hour = next_hour, .minute = 0 });
            }
            continue;
        }

        // Check minute.
        if (!cron.minutes.contains(@intCast(dt.minute))) {
            const next_min: u8 = blk: {
                var m: u8 = dt.minute + 1;
                while (m <= 59) : (m += 1) {
                    if (cron.minutes.contains(@intCast(m))) break :blk m;
                }
                break :blk 255;
            };
            if (next_min == 255) {
                // Advance to next hour.
                t = dateTimeToUnix(.{ .year = dt.year, .month = dt.month, .day = dt.day, .hour = dt.hour, .minute = 0 }) + 3600;
            } else {
                t = dateTimeToUnix(.{ .year = dt.year, .month = dt.month, .day = dt.day, .hour = dt.hour, .minute = next_min });
            }
            continue;
        }

        return t;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parse: wildcard expression" {
    const c = try parse("* * * * *");
    try std.testing.expect(c.dom_star);
    try std.testing.expect(c.dow_star);
    // All minutes set
    var m: u6 = 0;
    while (m < 60) : (m += 1) try std.testing.expect(c.minutes.contains(m));
}

test "parse: step */15 in minutes" {
    const c = try parse("*/15 * * * *");
    try std.testing.expect(c.minutes.contains(0));
    try std.testing.expect(c.minutes.contains(15));
    try std.testing.expect(c.minutes.contains(30));
    try std.testing.expect(c.minutes.contains(45));
    try std.testing.expect(!c.minutes.contains(1));
    try std.testing.expect(!c.minutes.contains(16));
}

test "parse: range with step 10-30/5" {
    const c = try parse("10-30/5 * * * *");
    try std.testing.expect(c.minutes.contains(10));
    try std.testing.expect(c.minutes.contains(15));
    try std.testing.expect(c.minutes.contains(20));
    try std.testing.expect(c.minutes.contains(25));
    try std.testing.expect(c.minutes.contains(30));
    try std.testing.expect(!c.minutes.contains(9));
    try std.testing.expect(!c.minutes.contains(11));
    try std.testing.expect(!c.minutes.contains(31));
}

test "parse: list 1,2,3" {
    const c = try parse("1,2,3 * * * *");
    try std.testing.expect(c.minutes.contains(1));
    try std.testing.expect(c.minutes.contains(2));
    try std.testing.expect(c.minutes.contains(3));
    try std.testing.expect(!c.minutes.contains(0));
    try std.testing.expect(!c.minutes.contains(4));
}

test "parse: month names" {
    const c = try parse("0 0 1 JAN,JUL *");
    try std.testing.expect(c.months.contains(1));
    try std.testing.expect(c.months.contains(7));
    try std.testing.expect(!c.months.contains(2));
}

test "parse: dow names MON-FRI" {
    const c = try parse("0 9 * * MON-FRI");
    try std.testing.expect(c.dows.contains(1)); // MON
    try std.testing.expect(c.dows.contains(5)); // FRI
    try std.testing.expect(!c.dows.contains(0)); // SUN
    try std.testing.expect(!c.dows.contains(6)); // SAT
    try std.testing.expect(!c.dow_star);
}

test "parse: invalid expression — wrong field count" {
    try std.testing.expectError(CronError.InvalidExpression, parse("* * * *"));
    try std.testing.expectError(CronError.InvalidExpression, parse("* * * * * *"));
}

test "parse: invalid — step zero" {
    try std.testing.expectError(CronError.InvalidStep, parse("*/0 * * * *"));
}

test "parse: invalid — out of range minute" {
    try std.testing.expectError(CronError.OutOfRange, parse("60 * * * *"));
}

test "parse: invalid — out of range hour" {
    try std.testing.expectError(CronError.OutOfRange, parse("* 24 * * *"));
}

test "parse: invalid — out of range dom" {
    try std.testing.expectError(CronError.OutOfRange, parse("* * 32 * *"));
}

test "parse: invalid — empty expression" {
    try std.testing.expectError(CronError.InvalidExpression, parse(""));
}

// ---------------------------------------------------------------------------
// Calendar helpers tests
// ---------------------------------------------------------------------------

test "calendar: unixToDateTime epoch" {
    const dt = unixToDateTime(0);
    try std.testing.expectEqual(@as(i32, 1970), dt.year);
    try std.testing.expectEqual(@as(u8, 1), dt.month);
    try std.testing.expectEqual(@as(u8, 1), dt.day);
    try std.testing.expectEqual(@as(u8, 0), dt.hour);
    try std.testing.expectEqual(@as(u8, 0), dt.minute);
}

test "calendar: round-trip" {
    const cases = [_]DateTime{
        .{ .year = 1970, .month = 1, .day = 1, .hour = 0, .minute = 0 },
        .{ .year = 2000, .month = 2, .day = 29, .hour = 12, .minute = 30 }, // leap
        .{ .year = 2024, .month = 2, .day = 29, .hour = 23, .minute = 59 }, // leap
        .{ .year = 2023, .month = 12, .day = 31, .hour = 23, .minute = 59 },
        .{ .year = 2026, .month = 6, .day = 5, .hour = 8, .minute = 0 },
    };
    for (cases) |dt| {
        const unix = dateTimeToUnix(dt);
        const rt = unixToDateTime(unix);
        try std.testing.expectEqual(dt.year, rt.year);
        try std.testing.expectEqual(dt.month, rt.month);
        try std.testing.expectEqual(dt.day, rt.day);
        try std.testing.expectEqual(dt.hour, rt.hour);
        try std.testing.expectEqual(dt.minute, rt.minute);
    }
}

test "calendar: weekday known values" {
    // 1970-01-01 was a Thursday (4).
    try std.testing.expectEqual(@as(u8, 4), weekday(1970, 1, 1));
    // 2000-01-01 was a Saturday (6).
    try std.testing.expectEqual(@as(u8, 6), weekday(2000, 1, 1));
    // 2024-01-01 was a Monday (1).
    try std.testing.expectEqual(@as(u8, 1), weekday(2024, 1, 1));
    // 2024-02-29 exists (2024 is leap) — Thursday (4).
    try std.testing.expectEqual(@as(u8, 4), weekday(2024, 2, 29));
}

test "calendar: isLeap" {
    try std.testing.expect(isLeap(2000));
    try std.testing.expect(isLeap(2024));
    try std.testing.expect(!isLeap(1900));
    try std.testing.expect(!isLeap(2023));
}

// ---------------------------------------------------------------------------
// nextAfter tests
// ---------------------------------------------------------------------------

/// Return a unix timestamp for a UTC datetime.
fn ts(year: i32, month: u8, day: u8, hour: u8, minute: u8) i64 {
    return dateTimeToUnix(.{ .year = year, .month = month, .day = day, .hour = hour, .minute = minute });
}

test "nextAfter: */15 fires every 15 minutes" {
    const c = try parse("*/15 * * * *");
    // Start at 2026-06-05 08:00:00
    const base = ts(2026, 6, 5, 8, 0);
    const t1 = nextAfter(c, base).?;
    try std.testing.expectEqual(ts(2026, 6, 5, 8, 15), t1);
    const t2 = nextAfter(c, t1).?;
    try std.testing.expectEqual(ts(2026, 6, 5, 8, 30), t2);
    const t3 = nextAfter(c, t2).?;
    try std.testing.expectEqual(ts(2026, 6, 5, 8, 45), t3);
    const t4 = nextAfter(c, t3).?;
    try std.testing.expectEqual(ts(2026, 6, 5, 9, 0), t4);
}

test "nextAfter: */15 from mid-minute boundary" {
    const c = try parse("*/15 * * * *");
    // 08:07:30 — next fire is 08:15
    const base = ts(2026, 6, 5, 8, 7) + 30;
    const t1 = nextAfter(c, base).?;
    try std.testing.expectEqual(ts(2026, 6, 5, 8, 15), t1);
}

test "nextAfter: 0 9 * * MON-FRI weekday 9am" {
    const c = try parse("0 9 * * MON-FRI");
    // 2026-06-05 is a Friday.  After 09:00 on Friday → next is Monday 2026-06-08.
    const after_fri_9am = ts(2026, 6, 5, 9, 0);
    const t1 = nextAfter(c, after_fri_9am).?;
    // 2026-06-08 is Monday.
    try std.testing.expectEqual(ts(2026, 6, 8, 9, 0), t1);
    // After Monday 9am → Tuesday.
    const t2 = nextAfter(c, t1).?;
    try std.testing.expectEqual(ts(2026, 6, 9, 9, 0), t2);
}

test "nextAfter: 0 9 * * MON-FRI before 9am" {
    const c = try parse("0 9 * * MON-FRI");
    // 2026-06-05 08:59 (Friday) → fires at 09:00 same day
    const before = ts(2026, 6, 5, 8, 59);
    const t = nextAfter(c, before).?;
    try std.testing.expectEqual(ts(2026, 6, 5, 9, 0), t);
}

test "nextAfter: 0 0 1 * * month start" {
    const c = try parse("0 0 1 * *");
    // Start just before midnight on 2026-05-31 → fires 2026-06-01 00:00
    const before = ts(2026, 5, 31, 23, 59);
    const t = nextAfter(c, before).?;
    try std.testing.expectEqual(ts(2026, 6, 1, 0, 0), t);
    // Then 2026-07-01
    const t2 = nextAfter(c, t).?;
    try std.testing.expectEqual(ts(2026, 7, 1, 0, 0), t2);
}

test "nextAfter: year rollover" {
    const c = try parse("0 0 1 1 *");
    // 2026-12-31 23:59 → next is 2027-01-01 00:00
    const before = ts(2026, 12, 31, 23, 59);
    const t = nextAfter(c, before).?;
    try std.testing.expectEqual(ts(2027, 1, 1, 0, 0), t);
}

test "nextAfter: leap year Feb 29" {
    // Fires only on Feb 29 — use DOM-only (dow_star=true).
    const c = try parse("0 0 29 2 *");
    // 2024 is a leap year.  After 2024-02-28 23:59 → 2024-02-29 00:00.
    const before = ts(2024, 2, 28, 23, 59);
    const t = nextAfter(c, before).?;
    try std.testing.expectEqual(ts(2024, 2, 29, 0, 0), t);
    // Next occurrence: 2028-02-29.
    const t2 = nextAfter(c, t).?;
    try std.testing.expectEqual(ts(2028, 2, 29, 0, 0), t2);
}

test "nextAfter: dom/dow OR semantics" {
    // "0 0 1 * MON" — fires on 1st of month OR any Monday.
    const c = try parse("0 0 1 * MON");
    try std.testing.expect(!c.dom_star);
    try std.testing.expect(!c.dow_star);
    // 2026-06-01 is a Monday → fires.
    const before_jun1 = ts(2026, 5, 31, 23, 59);
    const t1 = nextAfter(c, before_jun1).?;
    try std.testing.expectEqual(ts(2026, 6, 1, 0, 0), t1);
    // Next after 2026-06-01: next Monday is 2026-06-08.
    const t2 = nextAfter(c, t1).?;
    try std.testing.expectEqual(ts(2026, 6, 8, 0, 0), t2);
    // 2026-07-01 is a Wednesday — not a Monday, but IS 1st of month.
    // We need to reach it; skip past some Mondays.
    // Mondays in June after 6/1: 6/8, 6/15, 6/22, 6/29.
    // After 6/29 the next 1st-of-month is 7/1.
    const after_jun29 = ts(2026, 6, 29, 0, 1); // just after the Monday 00:00
    const t3 = nextAfter(c, after_jun29).?;
    try std.testing.expectEqual(ts(2026, 7, 1, 0, 0), t3);
}

test "nextAfter: deterministic sequence for 0 * * * *" {
    const c = try parse("0 * * * *");
    var t = ts(2026, 6, 5, 0, 0);
    var i: usize = 0;
    while (i < 24) : (i += 1) {
        const nxt = nextAfter(c, t).?;
        const dt = unixToDateTime(nxt);
        try std.testing.expectEqual(@as(u8, 0), dt.minute);
        t = nxt;
    }
}

test "nextAfter: invalid expression propagates" {
    try std.testing.expectError(CronError.InvalidExpression, parse("bad"));
}
