//! ASN.1 DER time codec for X.509 validity fields.
//!
//! Encoders write complete DER TLVs into caller-provided buffers. Returned
//! slices borrow from that buffer. The decoder accepts exactly one UTCTime or
//! GeneralizedTime TLV and returns Unix epoch seconds.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("ASN.1 time codec requires a 64-bit target");
}

pub const utc_tag: u8 = 0x17;
pub const generalized_tag: u8 = 0x18;

pub const utc_value_len: usize = 13;
pub const generalized_value_len: usize = 15;
pub const utc_der_len: usize = 2 + utc_value_len;
pub const generalized_der_len: usize = 2 + generalized_value_len;

pub const Error = error{
    InvalidTag,
    InvalidLength,
    InvalidTime,
    NoSpaceLeft,
    Oversize,
    Truncated,
    TrailingData,
};

pub const TimeKind = enum {
    utc,
    generalized,
};

pub const UTCTime = struct {
    der_tlv: []const u8,
    value: []const u8,
    unix_secs: i64,
};

pub const GeneralizedTime = struct {
    der_tlv: []const u8,
    value: []const u8,
    unix_secs: i64,
};

pub const ValidityTime = union(TimeKind) {
    utc: UTCTime,
    generalized: GeneralizedTime,

    pub fn derTlv(self: ValidityTime) []const u8 {
        return switch (self) {
            .utc => |time| time.der_tlv,
            .generalized => |time| time.der_tlv,
        };
    }

    pub fn value(self: ValidityTime) []const u8 {
        return switch (self) {
            .utc => |time| time.value,
            .generalized => |time| time.value,
        };
    }
};

const Civil = struct {
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

pub fn encodeUtcTime(out: []u8, unix_secs: i64) Error!UTCTime {
    if (out.len < utc_der_len) return error.NoSpaceLeft;
    const civil = civilFromEpochSeconds(unix_secs);
    if (civil.year < 1950 or civil.year > 2049) return error.InvalidTime;

    out[0] = utc_tag;
    out[1] = utc_value_len;
    const value = out[2..utc_der_len];
    writeTwoDigits(value[0..2], @intCast(@mod(civil.year, 100)));
    writeTwoDigits(value[2..4], civil.month);
    writeTwoDigits(value[4..6], civil.day);
    writeTwoDigits(value[6..8], civil.hour);
    writeTwoDigits(value[8..10], civil.minute);
    writeTwoDigits(value[10..12], civil.second);
    value[12] = 'Z';

    return .{
        .der_tlv = out[0..utc_der_len],
        .value = value,
        .unix_secs = unix_secs,
    };
}

pub fn encodeGeneralizedTime(out: []u8, unix_secs: i64) Error!GeneralizedTime {
    if (out.len < generalized_der_len) return error.NoSpaceLeft;
    const civil = civilFromEpochSeconds(unix_secs);
    if (civil.year < 0 or civil.year > 9999) return error.InvalidTime;

    out[0] = generalized_tag;
    out[1] = generalized_value_len;
    const value = out[2..generalized_der_len];
    writeFourDigits(value[0..4], @intCast(civil.year));
    writeTwoDigits(value[4..6], civil.month);
    writeTwoDigits(value[6..8], civil.day);
    writeTwoDigits(value[8..10], civil.hour);
    writeTwoDigits(value[10..12], civil.minute);
    writeTwoDigits(value[12..14], civil.second);
    value[14] = 'Z';

    return .{
        .der_tlv = out[0..generalized_der_len],
        .value = value,
        .unix_secs = unix_secs,
    };
}

pub fn chooseValidityTime(out: []u8, unix_secs: i64) Error!ValidityTime {
    const civil = civilFromEpochSeconds(unix_secs);
    if (civil.year < 2050) {
        return .{ .utc = try encodeUtcTime(out, unix_secs) };
    }
    return .{ .generalized = try encodeGeneralizedTime(out, unix_secs) };
}

pub fn parseTime(der_tlv: []const u8) Error!i64 {
    if (der_tlv.len < 2) return error.Truncated;
    const tag = der_tlv[0];
    if (tag != utc_tag and tag != generalized_tag) return error.InvalidTag;

    const len = try readShortDerLength(der_tlv);
    const expected_len: usize = switch (tag) {
        utc_tag => utc_value_len,
        generalized_tag => generalized_value_len,
        else => unreachable,
    };
    if (len > expected_len) return error.Oversize;
    if (len != expected_len) return error.InvalidTime;
    if (der_tlv.len < 2 + len) return error.Truncated;
    if (der_tlv.len != 2 + len) return error.TrailingData;

    const value = der_tlv[2..];
    return switch (tag) {
        utc_tag => parseUtcValue(value),
        generalized_tag => parseGeneralizedValue(value),
        else => unreachable,
    };
}

fn readShortDerLength(der_tlv: []const u8) Error!usize {
    const first = der_tlv[1];
    if ((first & 0x80) != 0) return error.InvalidLength;
    return first;
}

fn parseUtcValue(value: []const u8) Error!i64 {
    if (value.len != utc_value_len or value[12] != 'Z') return error.InvalidTime;
    const yy = try parseTwoDigits(value[0..2], 0, 99);
    const year: i64 = if (yy >= 50) 1900 + @as(i64, yy) else 2000 + @as(i64, yy);
    return epochSeconds(
        year,
        try parseTwoDigits(value[2..4], 1, 12),
        try parseTwoDigits(value[4..6], 1, 31),
        try parseTwoDigits(value[6..8], 0, 23),
        try parseTwoDigits(value[8..10], 0, 59),
        try parseTwoDigits(value[10..12], 0, 59),
    );
}

fn parseGeneralizedValue(value: []const u8) Error!i64 {
    if (value.len != generalized_value_len or value[14] != 'Z') return error.InvalidTime;
    return epochSeconds(
        try parseFourDigits(value[0..4]),
        try parseTwoDigits(value[4..6], 1, 12),
        try parseTwoDigits(value[6..8], 1, 31),
        try parseTwoDigits(value[8..10], 0, 23),
        try parseTwoDigits(value[10..12], 0, 59),
        try parseTwoDigits(value[12..14], 0, 59),
    );
}

fn parseTwoDigits(bytes: []const u8, min: u8, max: u8) Error!u8 {
    if (bytes.len != 2) return error.InvalidTime;
    if (!isDigit(bytes[0]) or !isDigit(bytes[1])) return error.InvalidTime;
    const value = (bytes[0] - '0') * 10 + (bytes[1] - '0');
    if (value < min or value > max) return error.InvalidTime;
    return value;
}

fn parseFourDigits(bytes: []const u8) Error!i64 {
    if (bytes.len != 4) return error.InvalidTime;
    var value: i64 = 0;
    for (bytes) |byte| {
        if (!isDigit(byte)) return error.InvalidTime;
        value = value * 10 + @as(i64, byte - '0');
    }
    return value;
}

fn isDigit(byte: u8) bool {
    return byte >= '0' and byte <= '9';
}

fn writeTwoDigits(out: []u8, value: u8) void {
    out[0] = '0' + value / 10;
    out[1] = '0' + value % 10;
}

fn writeFourDigits(out: []u8, value: u16) void {
    out[0] = '0' + @as(u8, @intCast(value / 1000));
    out[1] = '0' + @as(u8, @intCast(value / 100 % 10));
    out[2] = '0' + @as(u8, @intCast(value / 10 % 10));
    out[3] = '0' + @as(u8, @intCast(value % 10));
}

fn epochSeconds(year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8) Error!i64 {
    if (day > daysInMonth(year, month)) return error.InvalidTime;

    const days = daysFromCivil(year, month, day);
    return days * seconds_per_day +
        @as(i64, hour) * seconds_per_hour +
        @as(i64, minute) * seconds_per_minute +
        @as(i64, second);
}

fn civilFromEpochSeconds(unix_secs: i64) Civil {
    const days = @divFloor(unix_secs, seconds_per_day);
    const seconds_of_day = unix_secs - days * seconds_per_day;
    const date = civilFromDays(days);
    return .{
        .year = date.year,
        .month = date.month,
        .day = date.day,
        .hour = @intCast(@divFloor(seconds_of_day, seconds_per_hour)),
        .minute = @intCast(@divFloor(@mod(seconds_of_day, seconds_per_hour), seconds_per_minute)),
        .second = @intCast(@mod(seconds_of_day, seconds_per_minute)),
    };
}

fn civilFromDays(days: i64) struct { year: i64, month: u8, day: u8 } {
    const shifted = days + civil_epoch_offset_days;
    const era = @divFloor(shifted, days_per_era);
    const day_of_era = shifted - era * days_per_era;
    const year_of_era = @divFloor(day_of_era - @divFloor(day_of_era, 1460) + @divFloor(day_of_era, 36524) - @divFloor(day_of_era, 146096), 365);
    const year_base = year_of_era + era * 400;
    const day_of_year = day_of_era - (365 * year_of_era + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100));
    const month_param = @divFloor(5 * day_of_year + 2, 153);
    const day = day_of_year - @divFloor(153 * month_param + 2, 5) + 1;
    const month = month_param + if (month_param < 10) @as(i64, 3) else @as(i64, -9);
    const year = year_base + if (month <= 2) @as(i64, 1) else @as(i64, 0);

    return .{
        .year = year,
        .month = @intCast(month),
        .day = @intCast(day),
    };
}

fn daysFromCivil(year: i64, month: u8, day: u8) i64 {
    const month_i: i64 = month;
    const day_i: i64 = day;
    const adjusted_year = year - if (month_i <= 2) @as(i64, 1) else @as(i64, 0);
    const era = @divFloor(adjusted_year, 400);
    const year_of_era = adjusted_year - era * 400;
    const month_for_year = month_i + if (month_i > 2) @as(i64, -3) else @as(i64, 9);
    const day_of_year = @divFloor(153 * month_for_year + 2, 5) + day_i - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * days_per_era + day_of_era - civil_epoch_offset_days;
}

fn daysInMonth(year: i64, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: i64) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

const seconds_per_minute: i64 = 60;
const seconds_per_hour: i64 = 60 * seconds_per_minute;
const seconds_per_day: i64 = 24 * seconds_per_hour;
const days_per_era: i64 = 146_097;
const civil_epoch_offset_days: i64 = 719_468;

test "encode UTCTime known answers at RFC 5280 year boundaries" {
    // Arrange
    var earliest_buf: [utc_der_len]u8 = undefined;
    var latest_buf: [utc_der_len]u8 = undefined;

    // Act
    const earliest = try encodeUtcTime(&earliest_buf, -631_152_000);
    const latest = try encodeUtcTime(&latest_buf, 2_524_607_999);

    // Assert
    try expectEncoded(utc_tag, "500101000000Z", earliest.der_tlv);
    try std.testing.expectEqualStrings("500101000000Z", earliest.value);
    try expectEncoded(utc_tag, "491231235959Z", latest.der_tlv);
    try std.testing.expectEqualStrings("491231235959Z", latest.value);
}

test "encode GeneralizedTime known answers include leap day and 2050 boundary" {
    // Arrange
    var leap_buf: [generalized_der_len]u8 = undefined;
    var boundary_buf: [generalized_der_len]u8 = undefined;

    // Act
    const leap = try encodeGeneralizedTime(&leap_buf, 951_782_400);
    const boundary = try encodeGeneralizedTime(&boundary_buf, 2_524_608_000);

    // Assert
    try expectEncoded(generalized_tag, "20000229000000Z", leap.der_tlv);
    try std.testing.expectEqualStrings("20000229000000Z", leap.value);
    try expectEncoded(generalized_tag, "20500101000000Z", boundary.der_tlv);
}

test "chooseValidityTime uses UTCTime before 2050 and GeneralizedTime starting in 2050" {
    // Arrange
    var utc_buf: [generalized_der_len]u8 = undefined;
    var generalized_buf: [generalized_der_len]u8 = undefined;

    // Act
    const before = try chooseValidityTime(&utc_buf, 2_524_607_999);
    const at_boundary = try chooseValidityTime(&generalized_buf, 2_524_608_000);

    // Assert
    try std.testing.expectEqual(TimeKind.utc, std.meta.activeTag(before));
    try expectEncoded(utc_tag, "491231235959Z", before.derTlv());
    try std.testing.expectEqual(TimeKind.generalized, std.meta.activeTag(at_boundary));
    try expectEncoded(generalized_tag, "20500101000000Z", at_boundary.derTlv());
}

test "parseTime round-trips encoded UTC and generalized values" {
    // Arrange
    const cases = [_]i64{
        -631_152_000,
        0,
        951_825_600,
        2_524_607_999,
        2_524_608_000,
        4_102_444_799,
    };

    // Act / Assert
    for (cases) |unix_secs| {
        var buf: [generalized_der_len]u8 = undefined;
        const encoded = try chooseValidityTime(&buf, unix_secs);
        try std.testing.expectEqual(unix_secs, try parseTime(encoded.derTlv()));
    }
}

test "parseTime rejects malformed tags lengths truncation oversize and trailing data" {
    // Arrange
    const bad_tag = [_]u8{ 0x05, utc_value_len, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
    const long_form = [_]u8{ utc_tag, 0x81, utc_value_len, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
    const truncated_header = [_]u8{utc_tag};
    const truncated_value = [_]u8{ utc_tag, utc_value_len, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0' };
    const oversized = [_]u8{ utc_tag, utc_value_len + 1, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z', 'Z' };
    const trailing = [_]u8{ utc_tag, utc_value_len, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z', 0 };

    // Act / Assert
    try std.testing.expectError(error.InvalidTag, parseTime(&bad_tag));
    try std.testing.expectError(error.InvalidLength, parseTime(&long_form));
    try std.testing.expectError(error.Truncated, parseTime(&truncated_header));
    try std.testing.expectError(error.Truncated, parseTime(&truncated_value));
    try std.testing.expectError(error.Oversize, parseTime(&oversized));
    try std.testing.expectError(error.TrailingData, parseTime(&trailing));
}

test "parseTime rejects invalid dates while accepting leap years" {
    // Arrange
    const valid_leap = [_]u8{ generalized_tag, generalized_value_len, '2', '0', '2', '4', '0', '2', '2', '9', '2', '3', '5', '9', '5', '9', 'Z' };
    const invalid_non_leap = [_]u8{ generalized_tag, generalized_value_len, '2', '0', '2', '3', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z' };
    const invalid_century = [_]u8{ generalized_tag, generalized_value_len, '1', '9', '0', '0', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z' };
    const valid_century = [_]u8{ generalized_tag, generalized_value_len, '2', '0', '0', '0', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z' };
    const invalid_second = [_]u8{ utc_tag, utc_value_len, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '6', '0', 'Z' };

    // Act / Assert
    try std.testing.expectEqual(@as(i64, 1_709_251_199), try parseTime(&valid_leap));
    try std.testing.expectError(error.InvalidTime, parseTime(&invalid_non_leap));
    try std.testing.expectError(error.InvalidTime, parseTime(&invalid_century));
    try std.testing.expectEqual(@as(i64, 951_782_400), try parseTime(&valid_century));
    try std.testing.expectError(error.InvalidTime, parseTime(&invalid_second));
}

test "encoders report NoSpaceLeft and invalid year ranges" {
    // Arrange
    var small_utc: [utc_der_len - 1]u8 = undefined;
    var small_generalized: [generalized_der_len - 1]u8 = undefined;
    var utc_buf: [utc_der_len]u8 = undefined;
    var generalized_buf: [generalized_der_len]u8 = undefined;

    // Act / Assert
    try std.testing.expectError(error.NoSpaceLeft, encodeUtcTime(&small_utc, 0));
    try std.testing.expectError(error.NoSpaceLeft, encodeGeneralizedTime(&small_generalized, 0));
    try std.testing.expectError(error.InvalidTime, encodeUtcTime(&utc_buf, -631_152_001));
    try std.testing.expectError(error.InvalidTime, encodeUtcTime(&utc_buf, 2_524_608_000));
    try std.testing.expectError(error.InvalidTime, encodeGeneralizedTime(&generalized_buf, -62_167_219_201));
}

fn expectEncoded(tag: u8, value: []const u8, actual: []const u8) !void {
    var expected: [generalized_der_len]u8 = undefined;
    expected[0] = tag;
    expected[1] = @intCast(value.len);
    @memcpy(expected[2 .. 2 + value.len], value);
    try std.testing.expectEqualSlices(u8, expected[0 .. 2 + value.len], actual);
}

test {
    std.testing.refAllDecls(@This());
}
