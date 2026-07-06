// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SRTP packet protection (RFC 3711): AES-128 Counter Mode encryption of the
//! RTP payload plus an HMAC-SHA1-80 authentication tag over the packet and the
//! rollover counter. Includes the AES-CM key-derivation function that expands a
//! master key/salt into the per-session cipher key, cipher salt, and auth key.
//!
//! This is the transform core only — pure and allocation-free. Key agreement
//! (DTLS-SRTP or SDES over the signaling channel) and per-stream rollover-
//! counter tracking live in the layers that drive it.
const std = @import("std");
const aes = std.crypto.core.aes;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

pub const master_key_len: usize = 16;
pub const master_salt_len: usize = 14;
pub const cipher_key_len: usize = 16;
pub const session_salt_len: usize = 14;
pub const auth_key_len: usize = 20;
/// HMAC-SHA1-80: the 160-bit MAC truncated to the leftmost 80 bits.
pub const auth_tag_len: usize = 10;
/// RTP fixed header length (no CSRCs / extensions).
pub const rtp_header_len: usize = 12;

pub const Error = error{ PacketTooShort, BufferTooSmall, AuthFailed };

/// Per-session keys derived from a master key/salt via the SRTP KDF.
pub const SessionKeys = struct {
    cipher: [cipher_key_len]u8,
    salt: [session_salt_len]u8,
    auth: [auth_key_len]u8,
};

/// XOR an AES-128 Counter-Mode keystream into `buf` in place, starting from
/// block counter 0 (the low 16 bits of `iv`). Used for both the KDF (against a
/// zeroed buffer → raw keystream) and payload encryption (symmetric: encrypt
/// and decrypt are the same operation).
fn aesCmXor(key: [16]u8, iv: [16]u8, buf: []u8) void {
    const ctx = aes.Aes128.initEnc(key);
    var counter = iv;
    var ks: [16]u8 = undefined;
    var i: usize = 0;
    while (i < buf.len) : (i += 16) {
        ctx.encrypt(&ks, &counter);
        const n = @min(@as(usize, 16), buf.len - i);
        for (0..n) |j| buf[i + j] ^= ks[j];
        const c = std.mem.readInt(u16, counter[14..16], .big);
        std.mem.writeInt(u16, counter[14..16], c +% 1, .big);
    }
}

/// Derive one keystream output for KDF label `label` (RFC 3711 §4.3.1, with
/// key-derivation rate 0 so the packet index does not enter the key id).
fn deriveOne(master_key: [16]u8, master_salt: [master_salt_len]u8, label: u8, out: []u8) void {
    var iv = @as([16]u8, @splat(0));
    @memcpy(iv[0..master_salt_len], &master_salt);
    iv[7] ^= label; // key_id = label || index(=0); aligns to salt byte 7
    @memset(out, 0);
    aesCmXor(master_key, iv, out);
}

/// Expand a master key/salt into the session cipher key, salt, and auth key.
pub fn deriveSessionKeys(master_key: [master_key_len]u8, master_salt: [master_salt_len]u8) SessionKeys {
    var keys: SessionKeys = undefined;
    deriveOne(master_key, master_salt, 0x00, &keys.cipher); // <label 0> encryption key
    deriveOne(master_key, master_salt, 0x02, &keys.salt); //  <label 2> salt
    deriveOne(master_key, master_salt, 0x01, &keys.auth); //  <label 1> auth key
    return keys;
}

/// Build the AES-CM IV for an RTP packet (RFC 3711 §4.1.1):
/// IV = (salt << 16) XOR (SSRC << 64) XOR (index << 16), index = ROC*2^16 + SEQ.
fn srtpIv(salt: [session_salt_len]u8, ssrc: u32, index: u64) [16]u8 {
    var iv = @as([16]u8, @splat(0));
    @memcpy(iv[0..session_salt_len], &salt);
    var ssrc_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &ssrc_be, ssrc, .big);
    for (0..4) |i| iv[4 + i] ^= ssrc_be[i];
    var idx_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &idx_be, index, .big); // low 6 bytes = 48-bit index
    for (0..6) |i| iv[8 + i] ^= idx_be[2 + i];
    return iv;
}

fn authTag(keys: SessionKeys, body: []const u8, roc: u32, tag: *[auth_tag_len]u8) void {
    var roc_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &roc_be, roc, .big);
    var mac: [HmacSha1.mac_length]u8 = undefined;
    var h = HmacSha1.init(&keys.auth);
    h.update(body);
    h.update(&roc_be);
    h.final(&mac);
    @memcpy(tag, mac[0..auth_tag_len]);
}

/// Protect an RTP packet into `out` (length `rtp.len + auth_tag_len`): encrypt
/// the payload with AES-CM and append the HMAC-SHA1-80 tag. `roc` is the
/// caller-tracked rollover counter for this stream. Returns the SRTP slice.
pub fn protect(keys: SessionKeys, roc: u32, rtp: []const u8, out: []u8) Error![]const u8 {
    if (rtp.len < rtp_header_len) return error.PacketTooShort;
    if (out.len < rtp.len + auth_tag_len) return error.BufferTooSmall;
    @memcpy(out[0..rtp.len], rtp);

    const ssrc = std.mem.readInt(u32, rtp[8..12], .big);
    const seq = std.mem.readInt(u16, rtp[2..4], .big);
    const index = (@as(u64, roc) << 16) | seq;
    aesCmXor(keys.cipher, srtpIv(keys.salt, ssrc, index), out[rtp_header_len..rtp.len]);

    var tag: [auth_tag_len]u8 = undefined;
    authTag(keys, out[0..rtp.len], roc, &tag);
    @memcpy(out[rtp.len..][0..auth_tag_len], &tag);
    return out[0 .. rtp.len + auth_tag_len];
}

/// Verify and decrypt an SRTP packet into `out`. Returns the recovered RTP
/// slice, or error.AuthFailed if the tag does not validate (checked before
/// decryption, in constant time).
pub fn unprotect(keys: SessionKeys, roc: u32, srtp: []const u8, out: []u8) Error![]const u8 {
    if (srtp.len < rtp_header_len + auth_tag_len) return error.PacketTooShort;
    const body_len = srtp.len - auth_tag_len;
    if (out.len < body_len) return error.BufferTooSmall;

    var expected: [auth_tag_len]u8 = undefined;
    authTag(keys, srtp[0..body_len], roc, &expected);
    if (!std.crypto.timing_safe.eql([auth_tag_len]u8, expected, srtp[body_len..][0..auth_tag_len].*))
        return error.AuthFailed;

    @memcpy(out[0..body_len], srtp[0..body_len]);
    const ssrc = std.mem.readInt(u32, srtp[8..12], .big);
    const seq = std.mem.readInt(u16, srtp[2..4], .big);
    const index = (@as(u64, roc) << 16) | seq;
    aesCmXor(keys.cipher, srtpIv(keys.salt, ssrc, index), out[rtp_header_len..body_len]);
    return out[0..body_len];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "KDF matches RFC 3711 Appendix B.3 test vectors" {
    const mk = hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139");
    const ms = hexBytes("0EC675AD498AFEEBB6960B3AABE6");
    const keys = deriveSessionKeys(mk, ms);
    try testing.expectEqualSlices(u8, &hexBytes("C61E7A93744F39EE10734AFE3FF7A087"), &keys.cipher);
    try testing.expectEqualSlices(u8, &hexBytes("30CBBC08863D8C85D49DB34A9AE1"), &keys.salt);
    try testing.expectEqualSlices(u8, &hexBytes("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4"), &keys.auth);
}

test "protect then unprotect round-trips the RTP packet" {
    const keys = deriveSessionKeys(
        hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139"),
        hexBytes("0EC675AD498AFEEBB6960B3AABE6"),
    );
    // RTP: version2, PT96, seq=0x1234, ts, ssrc=0xCAFEBABE, then payload.
    const rtp = hexBytes("8060123400000064CAFEBABE") ++ "kaguravox-audio-frame".*;
    var protected: [rtp.len + auth_tag_len]u8 = undefined;
    const srtp = try protect(keys, 0, &rtp, &protected);
    try testing.expectEqual(@as(usize, rtp.len + auth_tag_len), srtp.len);
    // Payload must actually be encrypted (differs from plaintext).
    try testing.expect(!std.mem.eql(u8, srtp[rtp_header_len..rtp.len], rtp[rtp_header_len..]));

    var recovered: [rtp.len]u8 = undefined;
    const back = try unprotect(keys, 0, srtp, &recovered);
    try testing.expectEqualSlices(u8, &rtp, back);
}

test "unprotect rejects a tampered packet" {
    const keys = deriveSessionKeys(
        hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139"),
        hexBytes("0EC675AD498AFEEBB6960B3AABE6"),
    );
    const rtp = hexBytes("8060000100000064CAFEBABE") ++ "secret".*;
    var protected: [rtp.len + auth_tag_len]u8 = undefined;
    const srtp = try protect(keys, 0, &rtp, &protected);

    var tampered: [rtp.len + auth_tag_len]u8 = undefined;
    @memcpy(&tampered, srtp);
    tampered[rtp_header_len] ^= 0x01; // flip a ciphertext bit
    var recovered: [rtp.len]u8 = undefined;
    try testing.expectError(error.AuthFailed, unprotect(keys, 0, &tampered, &recovered));
}
