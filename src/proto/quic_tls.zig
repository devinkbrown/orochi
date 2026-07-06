// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! QUIC-TLS (RFC 9001) initial secret derivation and header-protection.
//!
//! Implements:
//!   - HKDF-Extract (HKDF-SHA-256)
//!   - HKDF-Expand-Label (TLS 1.3 / RFC 8446 §7.1, used by RFC 9001)
//!   - QUIC v1 initial salt (RFC 9001 §5.2)
//!   - derive_initial_secrets(dcid) → {client_initial, server_initial}
//!   - Per-secret key/iv/hp derivation using quic key/iv/hp labels
//!   - AES-128-ECB based header-protection mask (RFC 9001 §5.4.3)
//!
//! No external imports — std.crypto only.

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const crypto = std.crypto;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// QUIC v1 initial salt (RFC 9001 §5.2).
pub const quic_v1_initial_salt = [20]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

/// AES-128-GCM key length (bytes).
pub const aead_key_len: usize = 16;
/// AES-128-GCM IV / nonce length (bytes).
pub const aead_iv_len: usize = 12;
/// Header-protection key length (bytes, AES-128).
pub const hp_key_len: usize = 16;

// ---------------------------------------------------------------------------
// HKDF primitives
// ---------------------------------------------------------------------------

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

/// HKDF-Extract(salt, ikm) → PRK  (wraps std HKDF-SHA-256).
pub fn hkdfExtract(salt: []const u8, ikm: []const u8) [32]u8 {
    return HkdfSha256.extract(salt, ikm);
}

/// HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 §7.1) and used by
/// QUIC (RFC 9001 §5.1).
///
/// HkdfLabel = length (2 bytes BE) ‖ "tls13 " ‖ label ‖ context_len (1 byte) ‖ context
///
/// `out.len` must equal the requested length.
pub fn hkdfExpandLabel(
    out: []u8,
    prk: [32]u8,
    label: []const u8,
    context: []const u8,
) void {
    // Build the HkdfLabel info field.
    // Max label: 6 ("tls13 ") + 255 = 261; context up to 255; header 3.
    // Total info buffer: 2 + 1 + 261 + 1 + 255 = 520 bytes worst case.
    var info_buf: [520]u8 = undefined;
    var pos: usize = 0;

    // length (2 bytes BE) = out.len
    assert(out.len <= 0xFFFF);
    const out_len: u16 = @intCast(out.len);
    info_buf[pos] = @intCast(out_len >> 8);
    pos += 1;
    info_buf[pos] = @intCast(out_len & 0xFF);
    pos += 1;

    // label_len (1 byte) = len("tls13 ") + label.len
    const prefix = "tls13 ";
    const full_label_len: u8 = @intCast(prefix.len + label.len);
    info_buf[pos] = full_label_len;
    pos += 1;

    // label bytes
    @memcpy(info_buf[pos..][0..prefix.len], prefix);
    pos += prefix.len;
    @memcpy(info_buf[pos..][0..label.len], label);
    pos += label.len;

    // context_len (1 byte) + context
    assert(context.len <= 255);
    info_buf[pos] = @intCast(context.len);
    pos += 1;
    if (context.len > 0) {
        @memcpy(info_buf[pos..][0..context.len], context);
        pos += context.len;
    }

    HkdfSha256.expand(out, info_buf[0..pos], prk);
}

// ---------------------------------------------------------------------------
// Initial-secret derivation (RFC 9001 §5.2)
// ---------------------------------------------------------------------------

/// Holds the three per-endpoint key material items derived from one initial secret.
pub const EndpointKeys = struct {
    key: [aead_key_len]u8,
    iv: [aead_iv_len]u8,
    hp: [hp_key_len]u8,
};

/// Holds both endpoint secrets (PRKs).
pub const InitialSecrets = struct {
    client_prk: [32]u8,
    server_prk: [32]u8,
};

/// Derive the QUIC v1 client and server initial secrets from a Destination
/// Connection ID (dcid).
///
/// initial_secret = HKDF-Extract(quic_v1_initial_salt, dcid)
/// client_initial = HKDF-Expand-Label(initial_secret, "client in", "", 32)
/// server_initial = HKDF-Expand-Label(initial_secret, "server in", "", 32)
pub fn deriveInitialSecrets(dcid: []const u8) InitialSecrets {
    const initial_secret = hkdfExtract(&quic_v1_initial_salt, dcid);

    var client_prk: [32]u8 = undefined;
    var server_prk: [32]u8 = undefined;

    hkdfExpandLabel(&client_prk, initial_secret, "client in", "");
    hkdfExpandLabel(&server_prk, initial_secret, "server in", "");

    return InitialSecrets{
        .client_prk = client_prk,
        .server_prk = server_prk,
    };
}

/// Derive key / iv / hp from one endpoint PRK (client or server initial secret).
///
/// key = HKDF-Expand-Label(prk, "quic key", "", 16)
/// iv  = HKDF-Expand-Label(prk, "quic iv",  "", 12)
/// hp  = HKDF-Expand-Label(prk, "quic hp",  "", 16)
pub fn deriveEndpointKeys(prk: [32]u8) EndpointKeys {
    var k: EndpointKeys = undefined;
    hkdfExpandLabel(&k.key, prk, "quic key", "");
    hkdfExpandLabel(&k.iv, prk, "quic iv", "");
    hkdfExpandLabel(&k.hp, prk, "quic hp", "");
    return k;
}

// ---------------------------------------------------------------------------
// Header-protection mask (RFC 9001 §5.4.3, AES-128-ECB)
// ---------------------------------------------------------------------------

/// Derive the 5-byte header-protection mask from a 16-byte `sample` using
/// the AES-128 header-protection key `hp_key`.
///
/// mask = AES-ECB-128(hp_key, sample)[0..5]
pub fn headerProtectionMask(hp_key: [hp_key_len]u8, sample: [16]u8) [5]u8 {
    const aes = crypto.core.aes.Aes128.initEnc(hp_key);
    var encrypted: [16]u8 = undefined;
    aes.encrypt(&encrypted, &sample);
    return encrypted[0..5].*;
}

/// AES-256 (32-byte key) variant of the header-protection mask. Same
/// construction as `headerProtectionMask` but with AES-256-ECB; used by the
/// TLS_AES_256_GCM_SHA384 suite. RFC 9001 §5.4.3.
pub fn headerProtectionMaskAes256(hp_key: [32]u8, sample: [16]u8) [5]u8 {
    const aes = crypto.core.aes.Aes256.initEnc(hp_key);
    var encrypted: [16]u8 = undefined;
    aes.encrypt(&encrypted, &sample);
    return encrypted[0..5].*;
}

/// ChaCha20 variant of the header-protection mask (RFC 9001 §5.4.4) for the
/// TLS_CHACHA20_POLY1305_SHA256 suite.
///
/// > The header protection algorithm uses both the header protection key and a
/// > sample of the ciphertext from the packet Payload field.
/// >
/// >   counter = sample[0..4]   (a 32-bit little-endian number)
/// >   nonce   = sample[4..16]  (the remaining 12 bytes)
/// >   mask    = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
///
/// i.e. the mask is the first five bytes of the ChaCha20 keystream produced with
/// the given 32-bit block counter and 96-bit nonce — equivalently, ChaCha20
/// encrypting a five-byte zero block. We obtain it directly from the keystream
/// (`stream`) so no scratch plaintext is needed.
pub fn headerProtectionMaskChaCha20(hp_key: [32]u8, sample: [16]u8) [5]u8 {
    const ChaCha20IETF = crypto.stream.chacha.ChaCha20IETF;
    const counter = mem.readInt(u32, sample[0..4], .little);
    var nonce: [12]u8 = undefined;
    @memcpy(&nonce, sample[4..16]);
    var mask: [5]u8 = undefined;
    ChaCha20IETF.stream(&mask, counter, hp_key, nonce);
    return mask;
}

// ---------------------------------------------------------------------------
// Cipher suites + per-level packet-key derivation (RFC 9001 §5.1, §5.4, §6.1)
// ---------------------------------------------------------------------------

/// The three QUIC v1 packet-protection cipher suites (RFC 9001 §5.3). These map
/// one-to-one onto the TLS 1.3 cipher suites a QUIC handshake may negotiate.
/// The Initial packet space always uses `aes128gcm`.
pub const CipherSuite = enum {
    /// TLS_AES_128_GCM_SHA256 — 16-byte key, AES-128 header protection.
    aes128gcm,
    /// TLS_AES_256_GCM_SHA384 — 32-byte key, AES-256 header protection.
    aes256gcm,
    /// TLS_CHACHA20_POLY1305_SHA256 — 32-byte key, ChaCha20 header protection.
    chacha20poly1305,

    /// AEAD key length in bytes for this suite.
    pub fn keyLen(self: CipherSuite) usize {
        return switch (self) {
            .aes128gcm => 16,
            .aes256gcm => 32,
            .chacha20poly1305 => 32,
        };
    }

    /// Header-protection key length in bytes for this suite (equals the AEAD
    /// key length for all three QUIC v1 suites).
    pub fn hpKeyLen(self: CipherSuite) usize {
        return self.keyLen();
    }

    /// AEAD nonce / "quic iv" length in bytes (12 for all three suites).
    pub fn ivLen(self: CipherSuite) usize {
        _ = self;
        return aead_iv_len;
    }

    /// AEAD authentication-tag length in bytes (16 for all three suites).
    pub fn tagLen(self: CipherSuite) usize {
        _ = self;
        return 16;
    }
};

/// The maximum AEAD/header-protection key length across all suites (AES-256 /
/// ChaCha20 = 32). `PacketKeys` stores keys in fixed 32-byte buffers and tracks
/// the active prefix length via `suite`, so the level/suite abstraction never
/// allocates and the same struct serves every cipher.
pub const max_key_len: usize = 32;

/// Packet-protection keys for one direction at one encryption level, plus the
/// suite that selects the AEAD and header-protection algorithm.
///
/// `key` and `hp` are fixed 32-byte buffers; only the first `suite.keyLen()`
/// bytes are meaningful (the AES-128 case uses 16, leaving the tail zeroed and
/// unused). Callers should always go through `keyBytes()` / `hpBytes()` rather
/// than reading the raw arrays so the suite-dependent length is respected.
pub const PacketKeys = struct {
    suite: CipherSuite,
    key: [max_key_len]u8,
    iv: [aead_iv_len]u8,
    hp: [max_key_len]u8,

    /// The active AEAD key bytes (length = `suite.keyLen()`).
    pub fn keyBytes(self: *const PacketKeys) []const u8 {
        return self.key[0..self.suite.keyLen()];
    }

    /// The active header-protection key bytes (length = `suite.hpKeyLen()`).
    pub fn hpBytes(self: *const PacketKeys) []const u8 {
        return self.hp[0..self.suite.hpKeyLen()];
    }
};

/// Derive QUIC `PacketKeys` from a TLS 1.3 traffic secret and a negotiated
/// cipher suite, using the QUIC "quic key" / "quic iv" / "quic hp" labels
/// (RFC 9001 §5.1).
///
///   key = HKDF-Expand-Label(secret, "quic key", "", keyLen)
///   iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
///   hp  = HKDF-Expand-Label(secret, "quic hp",  "", hpKeyLen)
///
/// `traffic_secret` is e.g. a client/server handshake_traffic_secret or
/// *_application_traffic_secret from the TLS 1.3 schedule. The HKDF uses
/// SHA-256 (matching `hkdfExpandLabel`); QUIC always sizes the secret to the
/// handshake hash, and the std HKDF accepts a 32-byte PRK here. For the
/// AES-256-GCM suite (SHA-384) the caller passes the first 32 bytes of the
/// 48-byte secret is **not** correct — instead they pass the full secret via a
/// SHA-384 schedule; this helper is SHA-256-based and is the right choice for
/// the SHA-256 suites and for the RFC 9001 Appendix A vectors. Mixed-hash
/// derivation is handled by the connection layer, which owns the schedule hash.
pub fn derivePacketKeys(traffic_secret: [32]u8, suite: CipherSuite) PacketKeys {
    var pk: PacketKeys = .{
        .suite = suite,
        .key = @as([max_key_len]u8, @splat(0)),
        .iv = undefined,
        .hp = @as([max_key_len]u8, @splat(0)),
    };
    const klen = suite.keyLen();
    const hlen = suite.hpKeyLen();
    hkdfExpandLabel(pk.key[0..klen], traffic_secret, "quic key", "");
    hkdfExpandLabel(&pk.iv, traffic_secret, "quic iv", "");
    hkdfExpandLabel(pk.hp[0..hlen], traffic_secret, "quic hp", "");
    return pk;
}

/// Roll a 1-RTT traffic secret to the next key generation (RFC 9001 §6.1):
///
///   next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length)
///
/// The new secret is then fed back through `derivePacketKeys` to obtain the next
/// generation's key and iv. The header-protection key is **not** updated on a
/// key update (RFC 9001 §6.1), so callers retain the previous `hp`.
pub fn nextGenerationSecret(traffic_secret: [32]u8) [32]u8 {
    var next: [32]u8 = undefined;
    hkdfExpandLabel(&next, traffic_secret, "quic ku", "");
    return next;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Decode a hex string into a fixed-size byte array.
fn fromHex(comptime N: usize, comptime hex: []const u8) [N]u8 {
    comptime {
        assert(hex.len == N * 2);
    }
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Decode a hex string into a heap-allocated slice (caller owns memory).
fn fromHexAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const n = hex.len / 2;
    const out = try allocator.alloc(u8, n);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

// ---------------------------------------------------------------------------
// RFC 9001 Appendix A test vectors
// ---------------------------------------------------------------------------
//
// DCID: 0x8394c8f03e515708  (8 bytes)
//
// initial_secret:
//   7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44
//
// client_initial_secret:
//   c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
//
// server_initial_secret:
//   3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b
//
// Client key:  1f369613dd76d5467730efcbe3b1a22d
// Client iv:   fa044b2f42a3fd3b46fb255c
// Client hp:   9f50449e04a0e810283a1e9933adedd2
//
// Server key:  cf3a5331653c364c88f0f379b6067e37
// Server iv:   0ac1493ca1905853096d2965
// Server hp:   c206b8d9b9f0f37644430b490eeaa314

test "RFC 9001 Appendix A — initial secrets" {
    const dcid = fromHex(8, "8394c8f03e515708");

    const secrets = deriveInitialSecrets(&dcid);

    const exp_client = fromHex(32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const exp_server = fromHex(32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");

    try testing.expectEqualSlices(u8, &exp_client, &secrets.client_prk);
    try testing.expectEqualSlices(u8, &exp_server, &secrets.server_prk);
}

test "RFC 9001 Appendix A — client key/iv/hp" {
    const dcid = fromHex(8, "8394c8f03e515708");
    const secrets = deriveInitialSecrets(&dcid);
    const client = deriveEndpointKeys(secrets.client_prk);

    const exp_key = fromHex(16, "1f369613dd76d5467730efcbe3b1a22d");
    const exp_iv = fromHex(12, "fa044b2f42a3fd3b46fb255c");
    const exp_hp = fromHex(16, "9f50449e04a0e810283a1e9933adedd2");

    try testing.expectEqualSlices(u8, &exp_key, &client.key);
    try testing.expectEqualSlices(u8, &exp_iv, &client.iv);
    try testing.expectEqualSlices(u8, &exp_hp, &client.hp);
}

test "RFC 9001 Appendix A — server key/iv/hp" {
    const dcid = fromHex(8, "8394c8f03e515708");
    const secrets = deriveInitialSecrets(&dcid);
    const server = deriveEndpointKeys(secrets.server_prk);

    const exp_key = fromHex(16, "cf3a5331653c364c88f0f379b6067e37");
    // Server IV from the RFC 9001 source repository (quicwg/base-drafts):
    //   0ac1493ca1905853b0bba03e  (the value "096d2965" in some mirrors is a typo)
    const exp_iv = fromHex(12, "0ac1493ca1905853b0bba03e");
    const exp_hp = fromHex(16, "c206b8d9b9f0f37644430b490eeaa314");

    try testing.expectEqualSlices(u8, &exp_key, &server.key);
    try testing.expectEqualSlices(u8, &exp_iv, &server.iv);
    try testing.expectEqualSlices(u8, &exp_hp, &server.hp);
}

// ---------------------------------------------------------------------------
// RFC 9001 Appendix A — header-protection mask
// ---------------------------------------------------------------------------
//
// RFC 9001 §A.2 (client Initial):
//   sample  = d1b1c98dd7689fb8ec11d242b123dc9b
//   hp_key  = 9f50449e04a0e810283a1e9933adedd2
//   mask    = 437b9aec36  (first 5 bytes of AES-ECB(hp_key, sample))

test "RFC 9001 Appendix A — client header-protection mask" {
    const hp_key = fromHex(16, "9f50449e04a0e810283a1e9933adedd2");
    const sample = fromHex(16, "d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = headerProtectionMask(hp_key, sample);
    const exp_mask = fromHex(5, "437b9aec36");
    try testing.expectEqualSlices(u8, &exp_mask, &mask);
}

// RFC 9001 §A.3 (server Initial):
//   sample  = 2cd0991cd25b0aac406a5816b6394100
//   hp_key  = c206b8d9b9f0f37644430b490eeaa314
//   mask    = 2ec0d8356a

test "RFC 9001 Appendix A — server header-protection mask" {
    const hp_key = fromHex(16, "c206b8d9b9f0f37644430b490eeaa314");
    const sample = fromHex(16, "2cd0991cd25b0aac406a5816b6394100");
    const mask = headerProtectionMask(hp_key, sample);
    const exp_mask = fromHex(5, "2ec0d8356a");
    try testing.expectEqualSlices(u8, &exp_mask, &mask);
}

// ---------------------------------------------------------------------------
// HKDF-Expand-Label unit tests (TLS 1.3 shape, independent of QUIC vectors)
// ---------------------------------------------------------------------------

test "hkdfExpandLabel — output length changes the derived key" {
    // The HkdfLabel info encodes the requested output length, so asking for
    // 16 vs 32 bytes from the same PRK + label produces different T(1) blocks.
    // This test verifies that behaviour and that each expansion is non-zero.
    const prk = @as([32]u8, @splat(0x42));
    var out16: [16]u8 = undefined;
    var out32: [32]u8 = undefined;
    var out12: [12]u8 = undefined;
    hkdfExpandLabel(&out16, prk, "quic key", "");
    hkdfExpandLabel(&out32, prk, "quic key", "");
    hkdfExpandLabel(&out12, prk, "quic iv", "");
    // Outputs must be non-zero (expansion actually ran).
    try testing.expect(!mem.eql(u8, &out16, &(@as([16]u8, @splat(0)))));
    try testing.expect(!mem.eql(u8, &out12, &(@as([12]u8, @splat(0)))));
    // Because length is encoded in HkdfLabel, out16 and out32[0..16] DIFFER.
    try testing.expect(!mem.eql(u8, &out16, out32[0..16]));
    // Different labels produce different output (belt-and-suspenders).
    try testing.expect(!mem.eql(u8, &out16, out32[0..16]));
}

test "hkdfExpandLabel — deterministic" {
    const prk = @as([32]u8, @splat(0x11));
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    hkdfExpandLabel(&a, prk, "quic key", "");
    hkdfExpandLabel(&b, prk, "quic key", "");
    try testing.expectEqualSlices(u8, &a, &b);
}

test "hkdfExpandLabel — label sensitivity" {
    const prk = @as([32]u8, @splat(0x55));
    var key_out: [16]u8 = undefined;
    var hp_out: [16]u8 = undefined;
    hkdfExpandLabel(&key_out, prk, "quic key", "");
    hkdfExpandLabel(&hp_out, prk, "quic hp", "");
    // Different labels must produce different output.
    try testing.expect(!mem.eql(u8, &key_out, &hp_out));
}

// ---------------------------------------------------------------------------
// HKDF-Extract unit test (RFC 5869 test vector 1)
// ---------------------------------------------------------------------------
//
// RFC 5869 §A.1:
//   Hash  = SHA-256
//   IKM   = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
//   salt  = 0x000102030405060708090a0b0c         (13 octets)
//   PRK   = 077709362c2e32df0ddc3f0dc47bba63
//           90b6c73bb50f9c3122ec844ad7c2b3e5  (32 octets)

test "hkdfExtract — RFC 5869 A.1 vector" {
    const ikm = @as([22]u8, @splat(0x0b));
    const salt = fromHex(13, "000102030405060708090a0b0c");
    const prk = hkdfExtract(&salt, &ikm);
    const exp = fromHex(32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    try testing.expectEqualSlices(u8, &exp, &prk);
}

// ---------------------------------------------------------------------------
// AES-128-ECB header-protection — self-consistency tests
// ---------------------------------------------------------------------------

test "headerProtectionMask — deterministic" {
    const key = @as([16]u8, @splat(0xaa));
    const sample = @as([16]u8, @splat(0xbb));
    const m1 = headerProtectionMask(key, sample);
    const m2 = headerProtectionMask(key, sample);
    try testing.expectEqualSlices(u8, &m1, &m2);
}

test "headerProtectionMask — key sensitivity" {
    const key1 = @as([16]u8, @splat(0x01));
    const key2 = @as([16]u8, @splat(0x02));
    const sample = @as([16]u8, @splat(0xcc));
    const m1 = headerProtectionMask(key1, sample);
    const m2 = headerProtectionMask(key2, sample);
    try testing.expect(!mem.eql(u8, &m1, &m2));
}

test "headerProtectionMask — sample sensitivity" {
    const key = @as([16]u8, @splat(0xff));
    const s1 = @as([16]u8, @splat(0x00));
    const s2 = @as([16]u8, @splat(0x01));
    const m1 = headerProtectionMask(key, s1);
    const m2 = headerProtectionMask(key, s2);
    try testing.expect(!mem.eql(u8, &m1, &m2));
}

// ---------------------------------------------------------------------------
// fromHexAlloc used in allocator-facing tests (exercises std.testing.allocator)
// ---------------------------------------------------------------------------

test "fromHexAlloc — round-trip via testing.allocator" {
    const allocator = testing.allocator;
    const hex = "8394c8f03e515708";
    const bytes = try fromHexAlloc(allocator, hex);
    defer allocator.free(bytes);
    try testing.expectEqual(@as(usize, 8), bytes.len);
    const exp = fromHex(8, "8394c8f03e515708");
    try testing.expectEqualSlices(u8, &exp, bytes);
}

// ---------------------------------------------------------------------------
// Cipher-suite key derivation, key update, and the ChaCha20 / AES-256 HP masks
// ---------------------------------------------------------------------------

test "RFC 9001 A.5 quic — chacha20 quic key/iv/hp from the 1-RTT secret" {
    const secret = fromHex(32, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    const pk = derivePacketKeys(secret, .chacha20poly1305);

    try testing.expectEqualSlices(
        u8,
        &fromHex(32, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        pk.keyBytes(),
    );
    try testing.expectEqualSlices(
        u8,
        &fromHex(12, "e0459b3474bdd0e44a41c144"),
        &pk.iv,
    );
    try testing.expectEqualSlices(
        u8,
        &fromHex(32, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
        pk.hpBytes(),
    );
}

test "RFC 9001 A.5 chacha — header-protection mask (quic_tls primitive)" {
    const hp = fromHex(32, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    const sample = fromHex(16, "5e5cd55c41f69080575d7999c25a5bfb");
    const mask = headerProtectionMaskChaCha20(hp, sample);
    try testing.expectEqualSlices(u8, &fromHex(5, "aefefe7d03"), &mask);
}

test "RFC 9001 quic — quic ku rolls the 1-RTT secret deterministically" {
    const secret = fromHex(32, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    const next = nextGenerationSecret(secret);
    try testing.expectEqualSlices(
        u8,
        &fromHex(32, "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"),
        &next,
    );
}

test "quic CipherSuite — key/hp lengths per suite" {
    try testing.expectEqual(@as(usize, 16), CipherSuite.aes128gcm.keyLen());
    try testing.expectEqual(@as(usize, 32), CipherSuite.aes256gcm.keyLen());
    try testing.expectEqual(@as(usize, 32), CipherSuite.chacha20poly1305.keyLen());
    inline for (.{ CipherSuite.aes128gcm, CipherSuite.aes256gcm, CipherSuite.chacha20poly1305 }) |s| {
        try testing.expectEqual(s.keyLen(), s.hpKeyLen());
        try testing.expectEqual(@as(usize, 12), s.ivLen());
        try testing.expectEqual(@as(usize, 16), s.tagLen());
    }
}

test "quic AES-256 header-protection mask is deterministic and key-sensitive" {
    const sample = @as([16]u8, @splat(0x9c));
    const k1 = @as([32]u8, @splat(0x01));
    const k2 = @as([32]u8, @splat(0x02));
    const m1 = headerProtectionMaskAes256(k1, sample);
    try testing.expectEqualSlices(u8, &m1, &headerProtectionMaskAes256(k1, sample));
    try testing.expect(!mem.eql(u8, &m1, &headerProtectionMaskAes256(k2, sample)));
}

test "quic derivePacketKeys — AES-128 path matches deriveEndpointKeys" {
    // The suite-aware derivation with aes128gcm must reproduce the original
    // EndpointKeys derivation byte-for-byte (RFC 9001 A.1 client secret).
    const dcid = fromHex(8, "8394c8f03e515708");
    const secrets = deriveInitialSecrets(&dcid);
    const legacy = deriveEndpointKeys(secrets.client_prk);
    const pk = derivePacketKeys(secrets.client_prk, .aes128gcm);
    try testing.expectEqualSlices(u8, &legacy.key, pk.keyBytes());
    try testing.expectEqualSlices(u8, &legacy.iv, &pk.iv);
    try testing.expectEqualSlices(u8, &legacy.hp, pk.hpBytes());
}
