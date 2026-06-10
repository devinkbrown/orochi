//! Time-based one-time password support for Orochi account safeguards.
//!
//! The module keeps the protocol surface small: RFC 4648 base32 decoding,
//! RFC 4226 HOTP, RFC 6238 TOTP, skew-window verification, and otpauth URI
//! construction for enrollment clients.

const std = @import("std");

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Algorithm = enum {
    sha1,
    sha256,
};

pub const Error = error{
    InvalidBase32,
    InvalidDigits,
    InvalidPeriod,
    TimeBeforeEpoch,
    OutOfMemory,
};

const max_digits: u8 = 9;

pub fn decodeBase32(allocator: std.mem.Allocator, encoded: []const u8) Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var buffer: u32 = 0;
    var bit_count: u5 = 0;
    var symbols: usize = 0;
    var padding: usize = 0;
    var seen_padding = false;

    for (encoded) |byte| {
        if (isSpace(byte)) continue;

        if (byte == '=') {
            seen_padding = true;
            padding += 1;
            continue;
        }
        if (seen_padding) return error.InvalidBase32;

        const value = base32Value(byte) orelse return error.InvalidBase32;
        symbols += 1;
        buffer = (buffer << 5) | value;
        bit_count += 5;

        while (bit_count >= 8) {
            bit_count -= 8;
            try out.append(allocator, @intCast((buffer >> bit_count) & 0xff));
            buffer = keepLowBits(buffer, bit_count);
        }
    }

    try validateBase32End(buffer, bit_count, symbols, padding);
    return out.toOwnedSlice(allocator);
}

pub fn hotp(secret: []const u8, counter: u64, digits: u8) Error!u32 {
    return hotpWithAlgorithm(.sha1, secret, counter, digits);
}

pub fn hotpWithAlgorithm(algo: Algorithm, secret: []const u8, counter: u64, digits: u8) Error!u32 {
    try validateDigits(digits);

    var message: [8]u8 = undefined;
    writeBigEndianU64(&message, counter);

    return switch (algo) {
        .sha1 => hotpDigest(HmacSha1, secret, &message, digits),
        .sha256 => hotpDigest(HmacSha256, secret, &message, digits),
    };
}

pub fn totp(secret: []const u8, unix: i64, period: u64, digits: u8) Error!u32 {
    return totpWithAlgorithm(.sha1, secret, unix, period, digits);
}

pub fn totpWithAlgorithm(algo: Algorithm, secret: []const u8, unix: i64, period: u64, digits: u8) Error!u32 {
    const counter = try counterFromUnix(unix, period);
    return hotpWithAlgorithm(algo, secret, counter, digits);
}

pub fn verify(
    secret: []const u8,
    code: []const u8,
    unix: i64,
    period: u64,
    digits: u8,
    skew_steps: u8,
) Error!bool {
    try validateDigits(digits);
    if (code.len != digits) return false;
    for (code) |byte| {
        if (byte < '0' or byte > '9') return false;
    }

    const base_counter = try counterFromUnix(unix, period);
    const skew: i64 = @intCast(skew_steps);
    var offset = -skew;
    while (offset <= skew) : (offset += 1) {
        const counter = counterWithOffset(base_counter, offset) orelse continue;
        const candidate = try hotp(secret, counter, digits);

        var rendered: [max_digits]u8 = undefined;
        const candidate_code = try formatCode(&rendered, candidate, digits);
        if (constantTimeEqual(code, candidate_code)) return true;
    }

    return false;
}

pub fn provisioningUri(
    allocator: std.mem.Allocator,
    label: []const u8,
    issuer: []const u8,
    secret_b32: []const u8,
) Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "otpauth://totp/");
    if (issuer.len != 0) {
        try appendPercentEncoded(allocator, &out, issuer);
        try out.append(allocator, ':');
    }
    try appendPercentEncoded(allocator, &out, label);
    try out.appendSlice(allocator, "?secret=");
    try appendPercentEncoded(allocator, &out, secret_b32);
    if (issuer.len != 0) {
        try out.appendSlice(allocator, "&issuer=");
        try appendPercentEncoded(allocator, &out, issuer);
    }

    return out.toOwnedSlice(allocator);
}

fn counterFromUnix(unix: i64, period: u64) Error!u64 {
    if (period == 0) return error.InvalidPeriod;
    if (unix < 0) return error.TimeBeforeEpoch;
    return @as(u64, @intCast(unix)) / period;
}

fn counterWithOffset(counter: u64, offset: i64) ?u64 {
    if (offset < 0) {
        const back: u64 = @intCast(-offset);
        if (back > counter) return null;
        return counter - back;
    }
    return counter + @as(u64, @intCast(offset));
}

fn hotpDigest(comptime Hmac: type, secret: []const u8, message: *const [8]u8, digits: u8) u32 {
    var mac: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&mac, message, secret);

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
    var result: u32 = 1;
    var i: u8 = 0;
    while (i < digits) : (i += 1) result *= 10;
    return result;
}

fn writeBigEndianU64(out: *[8]u8, value: u64) void {
    var shift: u6 = 56;
    for (out) |*byte| {
        byte.* = @intCast((value >> shift) & 0xff);
        if (shift == 0) break;
        shift -= 8;
    }
}

fn formatCode(out: *[max_digits]u8, value: u32, digits: u8) Error![]const u8 {
    try validateDigits(digits);

    var remaining = value;
    var index: usize = digits;
    while (index > 0) {
        index -= 1;
        out[index] = @intCast('0' + (remaining % 10));
        remaining /= 10;
    }

    return out[0..digits];
}

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |left, right| diff |= left ^ right;
    return diff == 0;
}

fn base32Value(byte: u8) ?u32 {
    return switch (byte) {
        'A'...'Z' => byte - 'A',
        'a'...'z' => byte - 'a',
        '2'...'7' => byte - '2' + 26,
        else => null,
    };
}

fn isSpace(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\n', '\r' => true,
        else => false,
    };
}

fn keepLowBits(value: u32, bits: u5) u32 {
    if (bits == 0) return 0;
    return value & ((@as(u32, 1) << bits) - 1);
}

fn validateBase32End(buffer: u32, bit_count: u5, symbols: usize, padding: usize) Error!void {
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
    if (bit_count != 0 and buffer != 0) return error.InvalidBase32;
}

fn appendPercentEncoded(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    text: []const u8,
) Error!void {
    const hex = "0123456789ABCDEF";
    for (text) |byte| {
        if (isUriUnreserved(byte)) {
            try out.append(allocator, byte);
        } else {
            try out.append(allocator, '%');
            try out.append(allocator, hex[byte >> 4]);
            try out.append(allocator, hex[byte & 0x0f]);
        }
    }
}

fn isUriUnreserved(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

test "base32 decodes RFC 4648 text without padding" {
    const got = try decodeBase32(std.testing.allocator, "JBSWY3DPEHPK3PXP");
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualSlices(u8, "Hello!\xde\xad\xbe\xef", got);
}

test "RFC 6238 SHA-1 vectors" {
    const Vector = struct {
        unix: i64,
        code: u32,
    };
    const vectors = [_]Vector{
        .{ .unix = 59, .code = 94287082 },
        .{ .unix = 1111111109, .code = 7081804 },
        .{ .unix = 1111111111, .code = 14050471 },
        .{ .unix = 1234567890, .code = 89005924 },
        .{ .unix = 2000000000, .code = 69279037 },
        .{ .unix = 20000000000, .code = 65353130 },
    };

    const secret = "12345678901234567890";
    for (vectors) |vector| {
        try std.testing.expectEqual(vector.code, try totp(secret, vector.unix, 30, 8));
    }
}

test "skew window accepts adjacent step and rejects distant code" {
    const secret = "12345678901234567890";

    try std.testing.expect(try verify(secret, "94287082", 89, 30, 8, 1));
    try std.testing.expect(!try verify(secret, "94287082", 119, 30, 8, 1));
}

test "provisioning URI percent encodes label and issuer" {
    const uri = try provisioningUri(std.testing.allocator, "alice@example.net", "Orochi Core", "JBSWY3DPEHPK3PXP");
    defer std.testing.allocator.free(uri);
    try std.testing.expectEqualStrings(
        "otpauth://totp/Orochi%20Core:alice%40example.net?secret=JBSWY3DPEHPK3PXP&issuer=Orochi%20Core",
        uri,
    );
}
