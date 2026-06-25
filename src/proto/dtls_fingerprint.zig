// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS certificate fingerprints for SDP `a=fingerprint` attributes.
const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha1 = std.crypto.hash.Sha1;

pub const Algorithm = enum {
    sha256,
    sha1,

    pub fn token(self: Algorithm) []const u8 {
        return switch (self) {
            .sha256 => "sha-256",
            .sha1 => "sha-1",
        };
    }
};

pub const Error = error{
    BufferTooSmall,
    BadFormat,
    Unsupported,
};

pub const Parsed = struct {
    alg: Algorithm,
    digest_hex: []const u8,
};

pub fn compute(alg: Algorithm, der_cert: []const u8, out_digest: []u8) Error![]const u8 {
    const len = digestLen(alg);
    if (out_digest.len < len) return error.BufferTooSmall;

    switch (alg) {
        .sha256 => {
            var digest: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(der_cert, &digest, .{});
            @memcpy(out_digest[0..digest.len], digest[0..]);
        },
        .sha1 => {
            var digest: [Sha1.digest_length]u8 = undefined;
            Sha1.hash(der_cert, &digest, .{});
            @memcpy(out_digest[0..digest.len], digest[0..]);
        },
    }

    return out_digest[0..len];
}

pub fn format(alg: Algorithm, der_cert: []const u8, out: []u8) Error![]const u8 {
    var digest_buf: [Sha256.digest_length]u8 = undefined;
    const digest = try compute(alg, der_cert, digest_buf[0..]);
    return formatDigest(alg, digest, out);
}

pub fn formatDigest(alg: Algorithm, digest: []const u8, out: []u8) Error![]const u8 {
    if (digest.len != digestLen(alg)) return error.BadFormat;

    const token = alg.token();
    const needed = formattedLen(alg);
    if (out.len < needed) return error.BufferTooSmall;

    var cursor: usize = 0;
    @memcpy(out[cursor .. cursor + token.len], token);
    cursor += token.len;
    out[cursor] = ' ';
    cursor += 1;

    for (digest, 0..) |byte, index| {
        if (index != 0) {
            out[cursor] = ':';
            cursor += 1;
        }
        out[cursor] = upperHex(byte >> 4);
        out[cursor + 1] = upperHex(byte & 0x0f);
        cursor += 2;
    }

    return out[0..cursor];
}

pub fn parse(line: []const u8) Error!Parsed {
    const space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.BadFormat;
    if (space == 0 or space + 1 >= line.len) return error.BadFormat;

    const alg = parseAlgorithm(line[0..space]) catch return error.Unsupported;
    const digest_hex = line[space + 1 ..];
    try validateDigestHex(alg, digest_hex);

    return .{
        .alg = alg,
        .digest_hex = digest_hex,
    };
}

fn parseAlgorithm(token: []const u8) error{Unsupported}!Algorithm {
    if (std.mem.eql(u8, token, "sha-256")) return .sha256;
    if (std.mem.eql(u8, token, "sha-1")) return .sha1;
    return error.Unsupported;
}

fn validateDigestHex(alg: Algorithm, digest_hex: []const u8) Error!void {
    if (digest_hex.len != digestHexLen(alg)) return error.BadFormat;

    for (digest_hex, 0..) |ch, index| {
        if ((index + 1) % 3 == 0) {
            if (ch != ':') return error.BadFormat;
        } else if (!isHex(ch)) {
            return error.BadFormat;
        }
    }
}

fn digestLen(alg: Algorithm) usize {
    return switch (alg) {
        .sha256 => Sha256.digest_length,
        .sha1 => Sha1.digest_length,
    };
}

fn digestHexLen(alg: Algorithm) usize {
    return digestLen(alg) * 3 - 1;
}

fn formattedLen(alg: Algorithm) usize {
    return alg.token().len + 1 + digestHexLen(alg);
}

fn isHex(ch: u8) bool {
    return switch (ch) {
        '0'...'9', 'a'...'f', 'A'...'F' => true,
        else => false,
    };
}

fn upperHex(nibble: u8) u8 {
    return "0123456789ABCDEF"[nibble & 0x0f];
}

test "compute sha-256 matches std" {
    const cert = "orochi dtls certificate";
    var expected: [Sha256.digest_length]u8 = undefined;
    var actual: [Sha256.digest_length]u8 = undefined;

    Sha256.hash(cert, &expected, .{});
    const digest = try compute(.sha256, cert, &actual);

    try std.testing.expectEqualSlices(u8, expected[0..], digest);
}

test "format sha-256 has prefix uppercase colon hex and parses back" {
    const cert = "orochi dtls certificate";
    var out: [128]u8 = undefined;

    const line = try format(.sha256, cert, &out);
    try std.testing.expect(std.mem.startsWith(u8, line, "sha-256 "));
    try std.testing.expectEqual(@as(usize, "sha-256 ".len + 95), line.len);

    const hex = line["sha-256 ".len..];
    var pairs: usize = 0;
    for (hex, 0..) |ch, index| {
        if ((index + 1) % 3 == 0) {
            try std.testing.expectEqual(@as(u8, ':'), ch);
        } else {
            try std.testing.expect((ch >= '0' and ch <= '9') or (ch >= 'A' and ch <= 'F'));
        }
        if (index % 3 == 0) pairs += 1;
    }
    try std.testing.expectEqual(@as(usize, 32), pairs);

    const parsed = try parse(line);
    try std.testing.expectEqual(Algorithm.sha256, parsed.alg);
    try std.testing.expectEqualStrings(hex, parsed.digest_hex);
}

test "formatDigest accepts sha-1 digest" {
    const cert = "orochi dtls certificate";
    var digest: [Sha1.digest_length]u8 = undefined;
    var out: [80]u8 = undefined;

    Sha1.hash(cert, &digest, .{});
    const line = try formatDigest(.sha1, &digest, &out);

    try std.testing.expect(std.mem.startsWith(u8, line, "sha-1 "));
    try std.testing.expectEqual(@as(usize, "sha-1 ".len + 59), line.len);
    try std.testing.expectEqual(Algorithm.sha1, (try parse(line)).alg);
}

test "parse rejects unsupported token" {
    try std.testing.expectError(
        error.Unsupported,
        parse("md5 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"),
    );
}

test "buffer too small" {
    const cert = "orochi dtls certificate";
    var digest: [Sha256.digest_length - 1]u8 = undefined;
    var out: ["sha-256 ".len + 95 - 1]u8 = undefined;

    try std.testing.expectError(error.BufferTooSmall, compute(.sha256, cert, &digest));
    try std.testing.expectError(error.BufferTooSmall, format(.sha256, cert, &out));
}
