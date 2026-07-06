// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded SFrame media-frame protection for AES_128_GCM_SHA256.

const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const Error = error{ ShortBuffer, AuthFailed, BadHeader, Unsupported };

pub const Keys = struct {
    key: [16]u8,
    salt: [12]u8,
};

pub const ParsedHeader = struct {
    kid: u3,
    ctr: u64,
    len: usize,
};

const tag_len = Aes128Gcm.tag_length;
const max_header_len = 1 + 8;
const nonce_len = 12;

// Derive the AES-GCM key and SFrame salt from sender base key material.
pub fn deriveKeys(base_key: []const u8) Keys {
    const prk = HkdfSha256.extract("", base_key);
    var keys: Keys = undefined;
    HkdfSha256.expand(&keys.key, "SFrame 1.0 Secret key", prk);
    HkdfSha256.expand(&keys.salt, "SFrame 1.0 Secret salt", prk);
    return keys;
}

// Return the encoded byte length for the short SFrame header.
pub fn headerLen(ctr: u64) usize {
    return 1 + intByteLen(ctr);
}

// Encode the short SFrame header into out and return the encoded slice.
pub fn encodeHeader(kid: u3, ctr: u64, out: []u8) Error![]const u8 {
    const ctr_len = intByteLen(ctr);
    const len = 1 + ctr_len;
    if (out.len < len) return Error.ShortBuffer;

    out[0] = (@as(u8, @intCast(ctr_len - 1)) << 4) | @as(u8, kid);
    writeInt(out[1..][0..ctr_len], ctr);
    return out[0..len];
}

// Decode a short SFrame header from the start of sframe.
pub fn decodeHeader(sframe: []const u8) Error!ParsedHeader {
    if (sframe.len == 0) return Error.BadHeader;

    const config = sframe[0];
    const reserved = (config & 0x80) != 0;
    const extended_kid = (config & 0x08) != 0;
    if (reserved or extended_kid) return Error.Unsupported;

    const ctr_len = @as(usize, (config >> 4) & 0x07) + 1;
    if (sframe.len < 1 + ctr_len) return Error.BadHeader;

    const ctr = readInt(sframe[1..][0..ctr_len]);
    if (ctr_len > 1 and sframe[1] == 0) return Error.BadHeader;

    return .{
        .kid = @intCast(config & 0x07),
        .ctr = ctr,
        .len = 1 + ctr_len,
    };
}

// Protect a media frame as SFrame header || ciphertext || tag.
pub fn protect(keys: Keys, kid: u3, ctr: u64, plaintext: []const u8, out: []u8) Error![]const u8 {
    const hdr_len = headerLen(ctr);
    const total_len = hdr_len + plaintext.len + tag_len;
    if (out.len < total_len) return Error.ShortBuffer;

    const header = try encodeHeader(kid, ctr, out[0..hdr_len]);
    const ciphertext = out[hdr_len..][0..plaintext.len];
    const tag_out = out[hdr_len + plaintext.len ..][0..tag_len];
    const nonce = nonceFor(keys.salt, ctr);

    var tag: [tag_len]u8 = undefined;
    Aes128Gcm.encrypt(ciphertext, &tag, plaintext, header, nonce, keys.key);
    @memcpy(tag_out, &tag);

    return out[0..total_len];
}

// Verify and open an SFrame into out, returning the plaintext slice.
pub fn unprotect(keys: Keys, sframe: []const u8, out: []u8) Error![]const u8 {
    const parsed = try decodeHeader(sframe);
    if (sframe.len < parsed.len + tag_len) return Error.BadHeader;

    const plaintext_len = sframe.len - parsed.len - tag_len;
    if (out.len < plaintext_len) return Error.ShortBuffer;

    const header = sframe[0..parsed.len];
    const ciphertext = sframe[parsed.len..][0..plaintext_len];
    const tag = sframe[parsed.len + plaintext_len ..][0..tag_len].*;
    const nonce = nonceFor(keys.salt, parsed.ctr);

    Aes128Gcm.decrypt(out[0..plaintext_len], ciphertext, tag, header, nonce, keys.key) catch return Error.AuthFailed;
    return out[0..plaintext_len];
}

fn nonceFor(salt: [nonce_len]u8, ctr: u64) [nonce_len]u8 {
    var ctr_bytes = @as([nonce_len]u8, @splat(0));
    std.mem.writeInt(u64, ctr_bytes[nonce_len - 8 ..][0..8], ctr, .big);

    var nonce = salt;
    for (&nonce, ctr_bytes) |*n, c| {
        n.* ^= c;
    }
    return nonce;
}

fn intByteLen(value: u64) usize {
    var n: usize = 1;
    var v = value;
    while (v > 0xff) : (v >>= 8) {
        n += 1;
    }
    return n;
}

fn writeInt(out: []u8, value: u64) void {
    std.debug.assert(out.len >= 1 and out.len <= 8);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const shift: u6 = @intCast((out.len - 1 - i) * 8);
        out[i] = @intCast((value >> shift) & 0xff);
    }
}

fn readInt(bytes: []const u8) u64 {
    std.debug.assert(bytes.len >= 1 and bytes.len <= 8);
    var value: u64 = 0;
    for (bytes) |b| {
        value = (value << 8) | b;
    }
    return value;
}

test "derive protect unprotect and authenticate" {
    const base_key = "sender base key material";
    const keys = deriveKeys(base_key);
    const plaintext = "encoded media frame bytes";

    var protected_buf: [128]u8 = undefined;
    const protected = try protect(keys, 2, 5, plaintext, &protected_buf);

    var opened_buf: [plaintext.len]u8 = undefined;
    const opened = try unprotect(keys, protected, &opened_buf);
    try std.testing.expectEqualSlices(u8, plaintext, opened);

    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..protected.len], protected);
    tampered[protected.len - tag_len - 1] ^= 0x01;
    try std.testing.expectError(Error.AuthFailed, unprotect(keys, tampered[0..protected.len], &opened_buf));
}

test "short header encodes and decodes kid and counter" {
    var header_buf: [max_header_len]u8 = undefined;
    const header = try encodeHeader(2, 5, &header_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x05 }, header);

    const parsed = try decodeHeader(header);
    try std.testing.expectEqual(@as(u3, 2), parsed.kid);
    try std.testing.expectEqual(@as(u64, 5), parsed.ctr);
    try std.testing.expectEqual(@as(usize, 2), parsed.len);

    const wide = try encodeHeader(7, 0x0102_0304_0506_0708, &header_buf);
    try std.testing.expectEqual(@as(u8, 0x70 | 0x07), wide[0]);
    const parsed_wide = try decodeHeader(wide);
    try std.testing.expectEqual(@as(u3, 7), parsed_wide.kid);
    try std.testing.expectEqual(@as(u64, 0x0102_0304_0506_0708), parsed_wide.ctr);
    try std.testing.expectEqual(wide.len, parsed_wide.len);
}

test "short buffers are rejected" {
    const keys = deriveKeys("base key");
    var out: [1]u8 = undefined;

    try std.testing.expectError(Error.ShortBuffer, protect(keys, 2, 5, "frame", &out));
    try std.testing.expectError(Error.ShortBuffer, encodeHeader(2, 0x0100, &out));

    var protected_buf: [64]u8 = undefined;
    const protected = try protect(keys, 2, 5, "frame", &protected_buf);
    try std.testing.expectError(Error.ShortBuffer, unprotect(keys, protected, &out));
}

test "bad and unsupported headers are rejected" {
    try std.testing.expectError(Error.BadHeader, decodeHeader(""));
    try std.testing.expectError(Error.BadHeader, decodeHeader(&[_]u8{0x10}));
    try std.testing.expectError(Error.BadHeader, decodeHeader(&[_]u8{ 0x10, 0x00, 0x01 }));
    try std.testing.expectError(Error.Unsupported, decodeHeader(&[_]u8{ 0x80, 0x00 }));
    try std.testing.expectError(Error.Unsupported, decodeHeader(&[_]u8{ 0x08, 0x00 }));
}
