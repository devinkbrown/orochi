//! Allocation-free human-readable formatters that render into caller-owned
//! buffers.
//!
//! Every function in this module writes its output into a `[]u8` slice supplied
//! by the caller and returns the populated sub-slice. No allocator is touched,
//! no global state is mutated, and the only failure mode is `error.NoSpace` when
//! the destination buffer is too small. Callers size their buffers from the
//! `*_MAX` constants below to guarantee success.
//!
//! These helpers exist for operator-facing diagnostics (STATS, LINKS, server
//! notices) where compact, readable magnitudes are friendlier than raw integer
//! byte counts and millisecond durations.

const std = @import("std");

/// Returned when the destination buffer cannot hold the formatted output.
pub const Error = error{NoSpace};

/// Upper bound on bytes written by `bytes` (e.g. "1023.0 KiB" plus headroom for
/// the largest binary unit). 24 bytes covers any `u64` magnitude.
pub const BYTES_MAX: usize = 24;

/// Upper bound on bytes written by `bytesSI`.
pub const BYTES_SI_MAX: usize = 24;

/// Upper bound on bytes written by `duration` (two units, e.g. "11574d 1h").
pub const DURATION_MAX: usize = 32;

/// Upper bound on bytes written by `count` (e.g. "18446744073.7G").
pub const COUNT_MAX: usize = 16;

const KIB: u64 = 1024;
const KB: u64 = 1000;

const MS_PER_SECOND: u64 = 1000;
const MS_PER_MINUTE: u64 = 60 * MS_PER_SECOND;
const MS_PER_HOUR: u64 = 60 * MS_PER_MINUTE;
const MS_PER_DAY: u64 = 24 * MS_PER_HOUR;

const binary_units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
const si_units = [_][]const u8{ "B", "kB", "MB", "GB", "TB", "PB", "EB" };

/// Render `n` bytes using binary (IEC) units with one decimal place, e.g.
/// `1536` becomes "1.5 KiB" and `3_355_443` becomes "3.2 MiB". Values below one
/// kibibyte are printed as a plain byte count with no decimal: "512 B".
///
/// Returns the populated slice of `out`, or `error.NoSpace` if `out` is smaller
/// than the formatted result. A buffer of `BYTES_MAX` always suffices.
pub fn bytes(n: u64, out: []u8) Error![]u8 {
    return scaled(n, KIB, &binary_units, out);
}

/// Render `n` bytes using SI (decimal) units with one decimal place, e.g.
/// `1500` becomes "1.5 kB" and `3_200_000` becomes "3.2 MB". Values below one
/// kilobyte are printed as a plain byte count: "512 B".
///
/// Returns the populated slice of `out`, or `error.NoSpace`. A buffer of
/// `BYTES_SI_MAX` always suffices.
pub fn bytesSI(n: u64, out: []u8) Error![]u8 {
    return scaled(n, KB, &si_units, out);
}

/// Shared implementation for `bytes` and `bytesSI`. Selects the largest unit
/// whose divisor does not exceed `n`, then prints the scaled value with one
/// decimal (or no decimal for the base unit). Rounding to one decimal can push
/// a value up to the next unit (e.g. 1023.95 KiB -> 1.0 MiB); we re-check the
/// threshold so the printed mantissa never reaches the divisor.
fn scaled(n: u64, divisor: u64, units: []const []const u8, out: []u8) Error![]u8 {
    if (n < divisor) {
        return bufPrint(out, "{d} {s}", .{ n, units[0] });
    }

    var value: f64 = @floatFromInt(n);
    var unit_index: usize = 0;
    const div_f: f64 = @floatFromInt(divisor);

    while (value >= div_f and unit_index + 1 < units.len) {
        value /= div_f;
        unit_index += 1;
    }

    // Guard against one-decimal rounding tipping the mantissa to the divisor
    // (e.g. 1023.97 displayed as "1024.0"). Promote to the next unit instead.
    if (value >= div_f - 0.05 and unit_index + 1 < units.len) {
        value /= div_f;
        unit_index += 1;
    }

    return bufPrint(out, "{d:.1} {s}", .{ value, units[unit_index] });
}

/// Render a duration given in milliseconds as the largest one or two units,
/// e.g. `7_500_000` becomes "2h 5m", `360_000_000` becomes "4d 4h", and
/// `500` becomes "500ms". Sub-second durations render as raw milliseconds;
/// once at least one second has elapsed the millisecond remainder is dropped
/// and the two most significant non-zero units are shown.
///
/// Returns the populated slice of `out`, or `error.NoSpace`. A buffer of
/// `DURATION_MAX` always suffices.
pub fn duration(ms: u64, out: []u8) Error![]u8 {
    if (ms < MS_PER_SECOND) {
        return bufPrint(out, "{d}ms", .{ms});
    }

    const days = ms / MS_PER_DAY;
    const hours = (ms % MS_PER_DAY) / MS_PER_HOUR;
    const minutes = (ms % MS_PER_HOUR) / MS_PER_MINUTE;
    const seconds = (ms % MS_PER_MINUTE) / MS_PER_SECOND;

    // Ordered largest-to-smallest; emit the first two units starting at the
    // most significant non-zero one.
    const Unit = struct { value: u64, suffix: []const u8 };
    const ordered = [_]Unit{
        .{ .value = days, .suffix = "d" },
        .{ .value = hours, .suffix = "h" },
        .{ .value = minutes, .suffix = "m" },
        .{ .value = seconds, .suffix = "s" },
    };

    var start: usize = 0;
    while (start < ordered.len and ordered[start].value == 0) : (start += 1) {}
    // ms >= 1 second guarantees at least the seconds slot is non-zero.
    std.debug.assert(start < ordered.len);

    const first = ordered[start];
    const has_second = start + 1 < ordered.len and ordered[start + 1].value != 0;
    if (has_second) {
        const second = ordered[start + 1];
        return bufPrint(out, "{d}{s} {d}{s}", .{
            first.value, first.suffix, second.value, second.suffix,
        });
    }
    return bufPrint(out, "{d}{s}", .{ first.value, first.suffix });
}

/// Render a raw count using compact magnitude suffixes with one decimal place,
/// e.g. `1234` becomes "1.2k", `3_400_000` becomes "3.4M". Values below one
/// thousand render as a plain integer: "999".
///
/// Returns the populated slice of `out`, or `error.NoSpace`. A buffer of
/// `COUNT_MAX` always suffices.
pub fn count(n: u64, out: []u8) Error![]u8 {
    const suffixes = [_][]const u8{ "", "k", "M", "G", "T", "P", "E" };
    if (n < KB) {
        return bufPrint(out, "{d}", .{n});
    }

    var value: f64 = @floatFromInt(n);
    var index: usize = 0;
    const kb_f: f64 = @floatFromInt(KB);

    while (value >= kb_f and index + 1 < suffixes.len) {
        value /= kb_f;
        index += 1;
    }

    if (value >= kb_f - 0.05 and index + 1 < suffixes.len) {
        value /= kb_f;
        index += 1;
    }

    return bufPrint(out, "{d:.1}{s}", .{ value, suffixes[index] });
}

/// Thin wrapper translating `std.fmt.bufPrint`'s `NoSpaceLeft` into this
/// module's `Error.NoSpace`, so callers see a single error set.
fn bufPrint(out: []u8, comptime fmt: []const u8, args: anytype) Error![]u8 {
    return std.fmt.bufPrint(out, fmt, args) catch error.NoSpace;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Helper: format with a heap-allocated buffer sized to the relevant `*_MAX`
/// so allocation failures and `error.NoSpace` are surfaced by the allocator's
/// leak checker rather than masked.
fn expectFormat(
    comptime f: fn (u64, []u8) Error![]u8,
    n: u64,
    cap: usize,
    expected: []const u8,
) !void {
    const buf = try testing.allocator.alloc(u8, cap);
    defer testing.allocator.free(buf);
    const got = try f(n, buf);
    try testing.expectEqualStrings(expected, got);
}

test "bytes: sub-kibibyte values print as plain bytes" {
    try expectFormat(bytes, 0, BYTES_MAX, "0 B");
    try expectFormat(bytes, 1, BYTES_MAX, "1 B");
    try expectFormat(bytes, 512, BYTES_MAX, "512 B");
    // Boundary: 1023 is still bytes, 1024 crosses into KiB.
    try expectFormat(bytes, 1023, BYTES_MAX, "1023 B");
}

test "bytes: kibibyte boundary and one decimal" {
    try expectFormat(bytes, 1024, BYTES_MAX, "1.0 KiB");
    try expectFormat(bytes, 1536, BYTES_MAX, "1.5 KiB");
    // A value just shy of a full MiB would round to a misleading "1024.0 KiB"
    // at one decimal, so the rounding guard promotes it to the next unit.
    try expectFormat(bytes, 1024 * 1024 - 1, BYTES_MAX, "1.0 MiB");
    // A value comfortably inside KiB range still shows the higher mantissa.
    try expectFormat(bytes, 1000 * 1024, BYTES_MAX, "1000.0 KiB");
}

test "bytes: mebibyte and larger" {
    try expectFormat(bytes, 1024 * 1024, BYTES_MAX, "1.0 MiB");
    try expectFormat(bytes, 3_355_443, BYTES_MAX, "3.2 MiB");
    try expectFormat(bytes, 1024 * 1024 * 1024, BYTES_MAX, "1.0 GiB");
}

test "bytes: maximum u64 fits in BYTES_MAX" {
    const buf = try testing.allocator.alloc(u8, BYTES_MAX);
    defer testing.allocator.free(buf);
    const got = try bytes(std.math.maxInt(u64), buf);
    // 2^64 - 1 ~= 16.0 EiB; exact mantissa is implementation-detail of f64.
    try testing.expect(std.mem.endsWith(u8, got, " EiB"));
}

test "bytesSI: decimal units" {
    try expectFormat(bytesSI, 0, BYTES_SI_MAX, "0 B");
    try expectFormat(bytesSI, 999, BYTES_SI_MAX, "999 B");
    try expectFormat(bytesSI, 1000, BYTES_SI_MAX, "1.0 kB");
    try expectFormat(bytesSI, 1500, BYTES_SI_MAX, "1.5 kB");
    try expectFormat(bytesSI, 3_200_000, BYTES_SI_MAX, "3.2 MB");
    try expectFormat(bytesSI, 1_000_000_000, BYTES_SI_MAX, "1.0 GB");
}

test "bytesSI: rounding guard promotes near-boundary values" {
    // 999_999 would round to "1000.0 kB"; the guard promotes it to "1.0 MB".
    try expectFormat(bytesSI, 999_999, BYTES_SI_MAX, "1.0 MB");
    // A value safely inside kB range keeps the higher mantissa.
    try expectFormat(bytesSI, 990_000, BYTES_SI_MAX, "990.0 kB");
}

test "duration: sub-second renders as milliseconds" {
    try expectFormat(duration, 0, DURATION_MAX, "0ms");
    try expectFormat(duration, 1, DURATION_MAX, "1ms");
    try expectFormat(duration, 500, DURATION_MAX, "500ms");
    try expectFormat(duration, 999, DURATION_MAX, "999ms");
}

test "duration: seconds boundary" {
    try expectFormat(duration, 1000, DURATION_MAX, "1s");
    try expectFormat(duration, 59_000, DURATION_MAX, "59s");
}

test "duration: two-unit composition picks largest pair" {
    // 2h 5m 0s -> "2h 5m"
    try expectFormat(duration, 2 * MS_PER_HOUR + 5 * MS_PER_MINUTE, DURATION_MAX, "2h 5m");
    // 3d 4h -> "3d 4h"
    try expectFormat(duration, 3 * MS_PER_DAY + 4 * MS_PER_HOUR, DURATION_MAX, "3d 4h");
    // 1m 30s -> "1m 30s"
    try expectFormat(duration, MS_PER_MINUTE + 30 * MS_PER_SECOND, DURATION_MAX, "1m 30s");
}

test "duration: skips zero middle units" {
    // 1d 0h 0m 5s -> most significant pair is "1d" then "5s" only if adjacent;
    // adjacency rule means second unit must be the next slot (hours), which is
    // zero, so only the day is shown.
    try expectFormat(duration, MS_PER_DAY + 5 * MS_PER_SECOND, DURATION_MAX, "1d");
    // 1h 0m 5s -> hours then minutes(0): single unit "1h".
    try expectFormat(duration, MS_PER_HOUR + 5 * MS_PER_SECOND, DURATION_MAX, "1h");
    // 1h 5m 0s -> "1h 5m".
    try expectFormat(duration, MS_PER_HOUR + 5 * MS_PER_MINUTE, DURATION_MAX, "1h 5m");
}

test "duration: large multi-day value fits in DURATION_MAX" {
    const buf = try testing.allocator.alloc(u8, DURATION_MAX);
    defer testing.allocator.free(buf);
    const got = try duration(std.math.maxInt(u64), buf);
    try testing.expect(std.mem.indexOfScalar(u8, got, 'd') != null);
}

test "count: sub-thousand plain integers" {
    try expectFormat(count, 0, COUNT_MAX, "0");
    try expectFormat(count, 42, COUNT_MAX, "42");
    try expectFormat(count, 999, COUNT_MAX, "999");
}

test "count: compact magnitude suffixes" {
    try expectFormat(count, 1000, COUNT_MAX, "1.0k");
    try expectFormat(count, 1200, COUNT_MAX, "1.2k");
    try expectFormat(count, 3_400_000, COUNT_MAX, "3.4M");
    try expectFormat(count, 1_000_000_000, COUNT_MAX, "1.0G");
}

test "count: maximum u64 fits in COUNT_MAX" {
    const buf = try testing.allocator.alloc(u8, COUNT_MAX);
    defer testing.allocator.free(buf);
    const got = try count(std.math.maxInt(u64), buf);
    try testing.expect(std.mem.endsWith(u8, got, "E"));
}

test "all formatters: undersized buffer yields NoSpace" {
    var tiny: [1]u8 = undefined;
    try testing.expectError(error.NoSpace, bytes(1024 * 1024, &tiny));
    try testing.expectError(error.NoSpace, bytesSI(1_000_000, &tiny));
    try testing.expectError(error.NoSpace, duration(2 * MS_PER_HOUR + 5 * MS_PER_MINUTE, &tiny));
    try testing.expectError(error.NoSpace, count(3_400_000, &tiny));
}
