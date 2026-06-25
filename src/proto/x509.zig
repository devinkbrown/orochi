// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal defensive X.509 DER field reader.
//!
//! This module only walks enough DER to extract the subject common name, the
//! validity window, and the SHA-256 digest of the SubjectPublicKeyInfo TLV.
//! It does not verify signatures, validate trust, or own transport state.
const std = @import("std");

/// SHA-256 digest byte count used for SubjectPublicKeyInfo fingerprints.
pub const digest_len: usize = std.crypto.hash.sha2.Sha256.digest_length;

/// SHA-256 digest bytes for a certificate's SubjectPublicKeyInfo TLV.
pub const Digest = [digest_len]u8;

/// Runtime limits for the DER field reader.
pub const Params = struct {
    /// Maximum certificate DER bytes accepted by `parseCertificateWith`.
    max_der_bytes: usize = 64 * 1024,
    /// Maximum subject common-name bytes returned from the DER input.
    max_common_name_bytes: usize = 255,
};

/// Errors returned while walking or decoding certificate DER.
pub const Error = error{
    CertificateTooLarge,
    CommonNameTooLong,
    InvalidDer,
    InvalidLength,
    InvalidTag,
    InvalidTime,
    LengthOverflow,
    MissingCommonName,
    MissingField,
    Truncated,
    UnsupportedCommonNameString,
};

/// Parsed certificate fields borrowed from or derived from the input DER.
pub const ParsedCertificate = struct {
    /// Subject commonName bytes borrowed from the certificate DER.
    subject_common_name: []const u8,
    /// notBefore as Unix epoch seconds.
    not_before: i64,
    /// notAfter as Unix epoch seconds.
    not_after: i64,
    /// SHA-256 digest of the encoded SubjectPublicKeyInfo TLV.
    subject_public_key_info_sha256: Digest,
};

/// Reusable no-allocation X.509 field reader.
pub const Reader = struct {
    params: Params,

    /// Initialize a reader with caller-selected limits.
    pub fn init(params: Params) Reader {
        return .{ .params = params };
    }

    /// Release reader state.
    pub fn deinit(self: *Reader) void {
        self.* = undefined;
    }

    /// Parse one DER-encoded certificate and extract the supported fields.
    pub fn parse(self: *const Reader, der: []const u8) Error!ParsedCertificate {
        return parseCertificateWith(self.params, der);
    }
};

/// Parse one DER-encoded certificate using default limits.
pub fn parseCertificate(der: []const u8) Error!ParsedCertificate {
    return parseCertificateWith(.{}, der);
}

/// Parse one DER-encoded certificate using caller-selected limits.
pub fn parseCertificateWith(params: Params, der: []const u8) Error!ParsedCertificate {
    if (der.len == 0) return error.Truncated;
    if (der.len > params.max_der_bytes) return error.CertificateTooLarge;

    var cursor: usize = 0;
    const certificate = try readTlv(der, &cursor);
    try expectTag(certificate, tag_sequence);
    if (cursor != der.len) return error.InvalidDer;

    var cert_cursor: usize = 0;
    const tbs_certificate = try readTlv(certificate.content, &cert_cursor);
    try expectTag(tbs_certificate, tag_sequence);
    return parseTbsCertificate(params, tbs_certificate.content);
}

const tag_integer: u8 = 0x02;
const tag_bit_string: u8 = 0x03;
const tag_oid: u8 = 0x06;
const tag_utf8_string: u8 = 0x0c;
const tag_printable_string: u8 = 0x13;
const tag_utc_time: u8 = 0x17;
const tag_generalized_time: u8 = 0x18;
const tag_ia5_string: u8 = 0x16;
const tag_sequence: u8 = 0x30;
const tag_set: u8 = 0x31;
const tag_version_explicit: u8 = 0xa0;

const common_name_oid = [_]u8{ 0x55, 0x04, 0x03 };

const Tlv = struct {
    tag: u8,
    content: []const u8,
    encoded: []const u8,
};

fn parseTbsCertificate(params: Params, input: []const u8) Error!ParsedCertificate {
    var cursor: usize = 0;

    if (try peekTag(input, cursor) == tag_version_explicit) {
        _ = try readTlv(input, &cursor);
    }

    try skipExpected(input, &cursor, tag_integer);
    try skipExpected(input, &cursor, tag_sequence);
    try skipExpected(input, &cursor, tag_sequence);

    const validity = try readTlv(input, &cursor);
    try expectTag(validity, tag_sequence);
    const times = try parseValidity(validity.content);

    const subject = try readTlv(input, &cursor);
    try expectTag(subject, tag_sequence);
    const common_name = try parseSubjectCommonName(params, subject.content);

    const spki = try readTlv(input, &cursor);
    try expectTag(spki, tag_sequence);

    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(spki.encoded, &digest, .{});

    return .{
        .subject_common_name = common_name,
        .not_before = times.not_before,
        .not_after = times.not_after,
        .subject_public_key_info_sha256 = digest,
    };
}

const Validity = struct {
    not_before: i64,
    not_after: i64,
};

fn parseValidity(input: []const u8) Error!Validity {
    var cursor: usize = 0;
    const not_before = try readTlv(input, &cursor);
    const not_after = try readTlv(input, &cursor);
    if (cursor != input.len) return error.InvalidDer;

    return .{
        .not_before = try parseTime(not_before),
        .not_after = try parseTime(not_after),
    };
}

fn parseSubjectCommonName(params: Params, input: []const u8) Error![]const u8 {
    var cursor: usize = 0;

    while (cursor < input.len) {
        const set = try readTlv(input, &cursor);
        try expectTag(set, tag_set);

        var set_cursor: usize = 0;
        while (set_cursor < set.content.len) {
            const attr = try readTlv(set.content, &set_cursor);
            try expectTag(attr, tag_sequence);

            var attr_cursor: usize = 0;
            const oid = try readTlv(attr.content, &attr_cursor);
            try expectTag(oid, tag_oid);
            const value = try readTlv(attr.content, &attr_cursor);
            if (attr_cursor != attr.content.len) return error.InvalidDer;

            if (!std.mem.eql(u8, oid.content, common_name_oid[0..])) continue;
            try expectCommonNameString(value.tag);
            if (value.content.len > params.max_common_name_bytes) return error.CommonNameTooLong;
            return value.content;
        }
    }

    return error.MissingCommonName;
}

fn readTlv(input: []const u8, cursor: *usize) Error!Tlv {
    const start = cursor.*;
    if (input.len - start < 2) return error.Truncated;

    const tag = input[cursor.*];
    cursor.* += 1;
    if (tag & 0x1f == 0x1f) return error.InvalidTag;

    const len = try readLength(input, cursor);
    const content_start = cursor.*;
    if (len > input.len - content_start) return error.Truncated;
    cursor.* += len;

    return .{
        .tag = tag,
        .content = input[content_start..cursor.*],
        .encoded = input[start..cursor.*],
    };
}

fn readLength(input: []const u8, cursor: *usize) Error!usize {
    if (cursor.* >= input.len) return error.Truncated;

    const first = input[cursor.*];
    cursor.* += 1;
    if (first & 0x80 == 0) return @as(usize, first);

    const count = first & 0x7f;
    if (count == 0) return error.InvalidLength;
    if (count > @sizeOf(usize)) return error.LengthOverflow;
    if (count > input.len - cursor.*) return error.Truncated;
    if (input[cursor.*] == 0) return error.InvalidLength;

    var len: usize = 0;
    for (input[cursor.* .. cursor.* + count]) |byte| {
        if (len > (std.math.maxInt(usize) - @as(usize, byte)) / 256) return error.LengthOverflow;
        len = len * 256 + @as(usize, byte);
    }
    cursor.* += count;

    if (len < 128) return error.InvalidLength;
    return len;
}

fn peekTag(input: []const u8, cursor: usize) Error!u8 {
    if (cursor >= input.len) return error.MissingField;
    return input[cursor];
}

fn skipExpected(input: []const u8, cursor: *usize, tag: u8) Error!void {
    const tlv = try readTlv(input, cursor);
    if (tlv.tag != tag) return error.InvalidTag;
}

fn expectTag(tlv: Tlv, tag: u8) Error!void {
    if (tlv.tag != tag) return error.InvalidTag;
}

fn expectCommonNameString(tag: u8) Error!void {
    return switch (tag) {
        tag_utf8_string, tag_printable_string, tag_ia5_string => {},
        else => error.UnsupportedCommonNameString,
    };
}

fn parseTime(tlv: Tlv) Error!i64 {
    return switch (tlv.tag) {
        tag_utc_time => parseUtcTime(tlv.content),
        tag_generalized_time => parseGeneralizedTime(tlv.content),
        else => error.InvalidTime,
    };
}

fn parseUtcTime(input: []const u8) Error!i64 {
    if (input.len != 13 or input[12] != 'Z') return error.InvalidTime;

    const yy = try parseDecimal(input[0..2]);
    const year: i64 = if (yy >= 50) 1900 + @as(i64, yy) else 2000 + @as(i64, yy);
    return epochSeconds(
        year,
        try parseDecimal(input[2..4]),
        try parseDecimal(input[4..6]),
        try parseDecimal(input[6..8]),
        try parseDecimal(input[8..10]),
        try parseDecimal(input[10..12]),
    );
}

fn parseGeneralizedTime(input: []const u8) Error!i64 {
    if (input.len != 15 or input[14] != 'Z') return error.InvalidTime;

    const year = try parseDecimal(input[0..4]);
    return epochSeconds(
        @as(i64, year),
        try parseDecimal(input[4..6]),
        try parseDecimal(input[6..8]),
        try parseDecimal(input[8..10]),
        try parseDecimal(input[10..12]),
        try parseDecimal(input[12..14]),
    );
}

fn parseDecimal(input: []const u8) Error!u16 {
    var value: u16 = 0;
    for (input) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidTime;
        value = value * 10 + @as(u16, byte - '0');
    }
    return value;
}

fn epochSeconds(year: i64, month: u16, day: u16, hour: u16, minute: u16, second: u16) Error!i64 {
    if (month < 1 or month > 12) return error.InvalidTime;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidTime;

    const max_day = daysInMonth(year, month);
    if (day < 1 or day > max_day) return error.InvalidTime;

    const days = daysFromCivil(year, @as(i64, month), @as(i64, day));
    return days * 86_400 + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + @as(i64, second);
}

fn daysInMonth(year: i64, month: u16) u16 {
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

fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const adjusted_year = year - if (month <= 2) @as(i64, 1) else @as(i64, 0);
    const era = @divFloor(adjusted_year, 400);
    const year_of_era = adjusted_year - era * 400;
    const month_for_year = month + if (month > 2) @as(i64, -3) else @as(i64, 9);
    const day_of_year = @divFloor(153 * month_for_year + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * 146_097 + day_of_era - 719_468;
}

const minimal_certificate =
    [_]u8{ 0x30, 0x55, 0x30, 0x4a, 0x02, 0x01, 0x01, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x30, 0x00, 0x30, 0x1e, 0x17, 0x0d } ++
    "240101000000Z" ++
    [_]u8{ 0x17, 0x0d } ++
    "250101000000Z" ++
    [_]u8{ 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07 } ++
    "test-cn" ++
    [_]u8{ 0x30, 0x0a, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x03, 0x00, 0x01, 0x02, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x02, 0x00, 0x00 };

const versioned_generalized_certificate =
    [_]u8{ 0x30, 0x5e, 0x30, 0x53, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x30, 0x00, 0x30, 0x22, 0x18, 0x0f } ++
    "20240101000000Z" ++
    [_]u8{ 0x18, 0x0f } ++
    "20250101000000Z" ++
    [_]u8{ 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x07 } ++
    "test-cn" ++
    [_]u8{ 0x30, 0x0a, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x03, 0x00, 0x01, 0x02, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x02, 0x00, 0x00 };

const certificate_without_common_name =
    [_]u8{ 0x30, 0x55, 0x30, 0x4a, 0x02, 0x01, 0x01, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x30, 0x00, 0x30, 0x1e, 0x17, 0x0d } ++
    "240101000000Z" ++
    [_]u8{ 0x17, 0x0d } ++
    "250101000000Z" ++
    [_]u8{ 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x06, 0x0c, 0x07 } ++
    "test-cn" ++
    [_]u8{ 0x30, 0x0a, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x03, 0x00, 0x01, 0x02, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x02, 0x00, 0x00 };

fn expectedSpkiDigest() Digest {
    const spki = [_]u8{ 0x30, 0x0a, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x03, 0x00, 0x01, 0x02 };
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(spki[0..], &digest, .{});
    return digest;
}

test "parse minimal DER certificate extracts CN validity and SPKI digest" {
    const allocator = std.testing.allocator;
    const der = try allocator.dupe(u8, minimal_certificate[0..]);
    defer allocator.free(der);

    const parsed = try parseCertificate(der);

    try std.testing.expectEqualStrings("test-cn", parsed.subject_common_name);
    try std.testing.expectEqual(@as(i64, 1_704_067_200), parsed.not_before);
    try std.testing.expectEqual(@as(i64, 1_735_689_600), parsed.not_after);
    try std.testing.expectEqualSlices(u8, expectedSpkiDigest()[0..], parsed.subject_public_key_info_sha256[0..]);
}

test "reader accepts explicit version and generalized time fields" {
    const allocator = std.testing.allocator;
    const der = try allocator.dupe(u8, versioned_generalized_certificate[0..]);
    defer allocator.free(der);

    var reader = Reader.init(.{ .max_der_bytes = 256, .max_common_name_bytes = 16 });
    defer reader.deinit();
    const parsed = try reader.parse(der);

    try std.testing.expectEqualStrings("test-cn", parsed.subject_common_name);
    try std.testing.expectEqual(@as(i64, 1_704_067_200), parsed.not_before);
    try std.testing.expectEqual(@as(i64, 1_735_689_600), parsed.not_after);
    try std.testing.expectEqualSlices(u8, expectedSpkiDigest()[0..], parsed.subject_public_key_info_sha256[0..]);
}

test "bounds and DER errors are rejected without allocation ownership" {
    const allocator = std.testing.allocator;
    const der = try allocator.dupe(u8, minimal_certificate[0..]);
    defer allocator.free(der);

    try std.testing.expectError(error.CertificateTooLarge, parseCertificateWith(.{ .max_der_bytes = der.len - 1 }, der));
    try std.testing.expectError(error.Truncated, parseCertificate(der[0 .. der.len - 1]));

    var bad_length = try allocator.dupe(u8, minimal_certificate[0..]);
    defer allocator.free(bad_length);
    bad_length[1] = 0x81;
    try std.testing.expectError(error.InvalidLength, parseCertificate(bad_length));
}

test "subject common name validation reports missing and oversized values" {
    const allocator = std.testing.allocator;
    const missing_cn = try allocator.dupe(u8, certificate_without_common_name[0..]);
    defer allocator.free(missing_cn);
    const der = try allocator.dupe(u8, minimal_certificate[0..]);
    defer allocator.free(der);

    try std.testing.expectError(error.MissingCommonName, parseCertificate(missing_cn));
    try std.testing.expectError(error.CommonNameTooLong, parseCertificateWith(.{ .max_common_name_bytes = 6 }, der));
}

test "time parser rejects malformed dates" {
    const allocator = std.testing.allocator;
    var der = try allocator.dupe(u8, minimal_certificate[0..]);
    defer allocator.free(der);

    der[18] = 'x';
    try std.testing.expectError(error.InvalidTime, parseCertificate(der));

    der[18] = '2';
    der[22] = '3';
    der[23] = '2';
    try std.testing.expectError(error.InvalidTime, parseCertificate(der));
}

test {
    std.testing.refAllDecls(@This());
}
