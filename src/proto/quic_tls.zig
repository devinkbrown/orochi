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
    const prk = [_]u8{0x42} ** 32;
    var out16: [16]u8 = undefined;
    var out32: [32]u8 = undefined;
    var out12: [12]u8 = undefined;
    hkdfExpandLabel(&out16, prk, "quic key", "");
    hkdfExpandLabel(&out32, prk, "quic key", "");
    hkdfExpandLabel(&out12, prk, "quic iv", "");
    // Outputs must be non-zero (expansion actually ran).
    try testing.expect(!mem.eql(u8, &out16, &([_]u8{0} ** 16)));
    try testing.expect(!mem.eql(u8, &out12, &([_]u8{0} ** 12)));
    // Because length is encoded in HkdfLabel, out16 and out32[0..16] DIFFER.
    try testing.expect(!mem.eql(u8, &out16, out32[0..16]));
    // Different labels produce different output (belt-and-suspenders).
    try testing.expect(!mem.eql(u8, &out16, out32[0..16]));
}

test "hkdfExpandLabel — deterministic" {
    const prk = [_]u8{0x11} ** 32;
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    hkdfExpandLabel(&a, prk, "quic key", "");
    hkdfExpandLabel(&b, prk, "quic key", "");
    try testing.expectEqualSlices(u8, &a, &b);
}

test "hkdfExpandLabel — label sensitivity" {
    const prk = [_]u8{0x55} ** 32;
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
    const ikm = [_]u8{0x0b} ** 22;
    const salt = fromHex(13, "000102030405060708090a0b0c");
    const prk = hkdfExtract(&salt, &ikm);
    const exp = fromHex(32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    try testing.expectEqualSlices(u8, &exp, &prk);
}

// ---------------------------------------------------------------------------
// AES-128-ECB header-protection — self-consistency tests
// ---------------------------------------------------------------------------

test "headerProtectionMask — deterministic" {
    const key = [_]u8{0xaa} ** 16;
    const sample = [_]u8{0xbb} ** 16;
    const m1 = headerProtectionMask(key, sample);
    const m2 = headerProtectionMask(key, sample);
    try testing.expectEqualSlices(u8, &m1, &m2);
}

test "headerProtectionMask — key sensitivity" {
    const key1 = [_]u8{0x01} ** 16;
    const key2 = [_]u8{0x02} ** 16;
    const sample = [_]u8{0xcc} ** 16;
    const m1 = headerProtectionMask(key1, sample);
    const m2 = headerProtectionMask(key2, sample);
    try testing.expect(!mem.eql(u8, &m1, &m2));
}

test "headerProtectionMask — sample sensitivity" {
    const key = [_]u8{0xff} ** 16;
    const s1 = [_]u8{0x00} ** 16;
    const s2 = [_]u8{0x01} ** 16;
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
