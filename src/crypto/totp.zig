// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const Algorithm = enum {
    sha1,
    sha256,
    sha512,
};

pub const Error = error{
    InvalidDigits,
    InvalidStep,
    TimeBeforeEpoch,
    InvalidBase32,
    OutOfMemory,
};

const default_step_seconds: u64 = 30;
const default_t0: i64 = 0;
const max_digits: u8 = 9;

pub fn hotp(secret: []const u8, counter: u64, digits: u8) Error!u32 {
    return hotpWithAlgorithm(secret, counter, digits, .sha1);
}

pub fn hotpWithAlgorithm(secret: []const u8, counter: u64, digits: u8, algo: Algorithm) Error!u32 {
    try validateDigits(digits);

    var msg: [8]u8 = undefined;
    writeBigEndianU64(&msg, counter);

    return switch (algo) {
        .sha1 => hotpDigest(std.crypto.auth.hmac.HmacSha1, secret, &msg, digits),
        .sha256 => hotpDigest(std.crypto.auth.hmac.sha2.HmacSha256, secret, &msg, digits),
        .sha512 => hotpDigest(std.crypto.auth.hmac.sha2.HmacSha512, secret, &msg, digits),
    };
}

pub fn totp(secret: []const u8, unix_time: i64, step: u64, t0: i64, digits: u8, algo: Algorithm) Error!u32 {
    if (step == 0) return error.InvalidStep;
    if (unix_time < t0) return error.TimeBeforeEpoch;

    const delta: u64 = @intCast(unix_time - t0);
    return hotpWithAlgorithm(secret, delta / step, digits, algo);
}

pub fn verify(secret: []const u8, code: []const u8, now: i64, window: u8) Error!bool {
    if (code.len == 0 or code.len > max_digits) return error.InvalidDigits;
    for (code) |c| {
        if (c < '0' or c > '9') return false;
    }

    const digits: u8 = @intCast(code.len);
    const skew: i64 = @intCast(window);
    var offset: i64 = -skew;
    while (offset <= skew) : (offset += 1) {
        const candidate_time = now + offset * @as(i64, @intCast(default_step_seconds));
        if (candidate_time < default_t0) continue;

        const candidate = try totp(secret, candidate_time, default_step_seconds, default_t0, digits, .sha1);
        var buf: [max_digits]u8 = undefined;
        const generated = try formatCode(&buf, candidate, digits);
        if (constantTimeEql(code, generated)) return true;
    }

    return false;
}

pub fn decodeBase32(allocator: std.mem.Allocator, encoded: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var acc: u16 = 0;
    var bits: u4 = 0;
    var symbols: usize = 0;
    var padding: usize = 0;
    var seen_padding = false;

    for (encoded) |c| {
        if (isAsciiSpace(c)) continue;

        if (c == '=') {
            seen_padding = true;
            padding += 1;
            continue;
        }

        if (seen_padding) return error.InvalidBase32;

        const value = base32Value(c) orelse return error.InvalidBase32;
        symbols += 1;
        acc = (acc << 5) | value;
        bits += 5;

        while (bits >= 8) {
            bits -= 8;
            try out.append(allocator, @intCast((acc >> bits) & 0xff));
        }
    }

    try validateBase32Tail(acc, bits, symbols, padding);
    return out.toOwnedSlice(allocator);
}

fn hotpDigest(comptime Hmac: type, secret: []const u8, msg: *const [8]u8, digits: u8) u32 {
    var mac: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&mac, msg, secret);

    const offset: usize = mac[mac.len - 1] & 0x0f;
    const binary: u32 =
        (@as(u32, mac[offset] & 0x7f) << 24) |
        (@as(u32, mac[offset + 1]) << 16) |
        (@as(u32, mac[offset + 2]) << 8) |
        @as(u32, mac[offset + 3]);

    return binary % pow10(digits);
}

fn validateDigits(digits: u8) Error!void {
    if (digits == 0 or digits > max_digits) return error.InvalidDigits;
}

fn pow10(digits: u8) u32 {
    var value: u32 = 1;
    var i: u8 = 0;
    while (i < digits) : (i += 1) {
        value *= 10;
    }
    return value;
}

fn writeBigEndianU64(out: *[8]u8, value: u64) void {
    var shift: u6 = 56;
    for (out) |*byte| {
        byte.* = @intCast((value >> shift) & 0xff);
        if (shift == 0) break;
        shift -= 8;
    }
}

fn formatCode(buf: *[max_digits]u8, value: u32, digits: u8) Error![]const u8 {
    try validateDigits(digits);

    var remaining = value;
    var i: usize = digits;
    while (i > 0) {
        i -= 1;
        buf[i] = @intCast('0' + remaining % 10);
        remaining /= 10;
    }

    return buf[0..digits];
}

fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

fn base32Value(c: u8) ?u16 {
    return switch (c) {
        'A'...'Z' => c - 'A',
        'a'...'z' => c - 'a',
        '2'...'7' => c - '2' + 26,
        else => null,
    };
}

fn isAsciiSpace(c: u8) bool {
    return switch (c) {
        ' ', '\t', '\n', '\r' => true,
        else => false,
    };
}

fn validateBase32Tail(acc: u16, bits: u4, symbols: usize, padding: usize) Error!void {
    const rem = symbols % 8;
    const expected_padding: usize = switch (rem) {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        else => return error.InvalidBase32,
    };

    if (padding != 0) {
        if (padding != expected_padding) return error.InvalidBase32;
        if ((symbols + padding) % 8 != 0) return error.InvalidBase32;
    }

    if (bits != 0) {
        const mask: u16 = (@as(u16, 1) << bits) - 1;
        if ((acc & mask) != 0) return error.InvalidBase32;
    }
}

test "RFC 4226 HOTP test vectors" {
    const secret = "12345678901234567890";
    const expected = [_]u32{
        755224,
        287082,
        359152,
        969429,
        338314,
        254676,
        287922,
        162583,
        399871,
        520489,
    };

    for (expected, 0..) |want, counter| {
        try std.testing.expectEqual(want, try hotp(secret, counter, 6));
    }
}

test "RFC 6238 TOTP SHA1 SHA256 SHA512 test vectors" {
    const Vector = struct {
        timestamp: i64,
        sha1: u32,
        sha256: u32,
        sha512: u32,
    };

    const vectors = [_]Vector{
        .{ .timestamp = 59, .sha1 = 94287082, .sha256 = 46119246, .sha512 = 90693936 },
        .{ .timestamp = 1111111109, .sha1 = 7081804, .sha256 = 68084774, .sha512 = 25091201 },
        .{ .timestamp = 1111111111, .sha1 = 14050471, .sha256 = 67062674, .sha512 = 99943326 },
        .{ .timestamp = 1234567890, .sha1 = 89005924, .sha256 = 91819424, .sha512 = 93441116 },
        .{ .timestamp = 2000000000, .sha1 = 69279037, .sha256 = 90698825, .sha512 = 38618901 },
        .{ .timestamp = 20000000000, .sha1 = 65353130, .sha256 = 77737706, .sha512 = 47863826 },
    };

    const sha1_secret = "12345678901234567890";
    const sha256_secret = "12345678901234567890123456789012";
    const sha512_secret = "1234567890123456789012345678901234567890123456789012345678901234";

    for (vectors) |v| {
        try std.testing.expectEqual(v.sha1, try totp(sha1_secret, v.timestamp, 30, 0, 8, .sha1));
        try std.testing.expectEqual(v.sha256, try totp(sha256_secret, v.timestamp, 30, 0, 8, .sha256));
        try std.testing.expectEqual(v.sha512, try totp(sha512_secret, v.timestamp, 30, 0, 8, .sha512));
    }
}

test "verify accepts codes inside skew window and rejects outside" {
    const secret = "12345678901234567890";

    try std.testing.expect(try verify(secret, "755224", 0, 0));
    try std.testing.expect(try verify(secret, "755224", 30, 1));
    try std.testing.expect(!try verify(secret, "755224", 60, 1));
    try std.testing.expect(!try verify(secret, "nototp", 0, 1));
}

test "base32 decode RFC 4648 padding and lowercase" {
    const allocator = std.testing.allocator;

    const cases = [_]struct {
        encoded: []const u8,
        decoded: []const u8,
    }{
        .{ .encoded = "", .decoded = "" },
        .{ .encoded = "MY======", .decoded = "f" },
        .{ .encoded = "MZXQ====", .decoded = "fo" },
        .{ .encoded = "MZXW6===", .decoded = "foo" },
        .{ .encoded = "MZXW6YQ=", .decoded = "foob" },
        .{ .encoded = "MZXW6YTB", .decoded = "fooba" },
        .{ .encoded = "MZXW6YTBOI======", .decoded = "foobar" },
        .{ .encoded = "mzxw6ytboi", .decoded = "foobar" },
        .{ .encoded = "JBSW Y3DP\nEB3W64TMMQQQ====", .decoded = "Hello world!" },
    };

    for (cases) |case| {
        const got = try decodeBase32(allocator, case.encoded);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(case.decoded, got);
    }
}

test "base32 rejects invalid padding and symbols" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidBase32, decodeBase32(allocator, "M======="));
    try std.testing.expectError(error.InvalidBase32, decodeBase32(allocator, "MY====="));
    try std.testing.expectError(error.InvalidBase32, decodeBase32(allocator, "MY======A"));
    try std.testing.expectError(error.InvalidBase32, decodeBase32(allocator, "MZXW6Y!B"));
}

test "digit truncation supports six and eight digit output" {
    const secret = "12345678901234567890";

    try std.testing.expectEqual(@as(u32, 755224), try hotp(secret, 0, 6));
    try std.testing.expectEqual(@as(u32, 84755224), try hotp(secret, 0, 8));
    try std.testing.expect(try verify(secret, "84755224", 0, 0));
    try std.testing.expectError(error.InvalidDigits, hotp(secret, 0, 0));
    try std.testing.expectError(error.InvalidDigits, hotp(secret, 0, 10));
}
