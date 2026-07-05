// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Adversarial ("Wycheproof-style") negative tests for the crypto primitives.
//!
//! Unlike a positive KAT (which needs an INDEPENDENT known answer), every case
//! here is a REJECTION test — the correct outcome is simply "reject", so the
//! expected value is not something this same code computes. These pin the
//! security-critical edge behavior (AEAD tamper detection, low-order Diffie-
//! Hellman points, degenerate ECDSA signatures) that a from-scratch stack must
//! get right and that positive round-trip tests never exercise.
const std = @import("std");

const aead = @import("aead.zig");
const kx = @import("kx.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");

const testing = std.testing;

// ── AEAD: any single-bit change to ciphertext, tag, or nonce must fail open ──

fn aeadTamperRejected(comptime A: type) !void {
    const key: A.Key = [_]u8{0xC3} ** A.key_length;
    const nonce: A.Nonce = [_]u8{0x5A} ** A.nonce_length;
    const ad = "aead-associated-data";
    const pt = "wycheproof adversarial plaintext payload!";

    var a = A.init(key);
    defer a.deinit();

    var ct: [pt.len]u8 = undefined;
    const tag = try a.seal(nonce, ad, pt, &ct);

    var out: [pt.len]u8 = undefined;
    // Sanity: the untampered record opens.
    try a.open(nonce, ad, &ct, tag, &out);
    try testing.expectEqualSlices(u8, pt, &out);

    // Flip one ciphertext bit → AuthFailed.
    var ct_bad = ct;
    ct_bad[ct_bad.len / 2] ^= 0x01;
    try testing.expectError(error.AuthFailed, a.open(nonce, ad, &ct_bad, tag, &out));

    // Flip one tag bit → AuthFailed.
    var tag_bad = tag;
    tag_bad[0] ^= 0x80;
    try testing.expectError(error.AuthFailed, a.open(nonce, ad, &ct, tag_bad, &out));

    // Wrong nonce → AuthFailed.
    var nonce_bad = nonce;
    nonce_bad[0] ^= 0x01;
    try testing.expectError(error.AuthFailed, a.open(nonce_bad, ad, &ct, tag, &out));

    // Tampered associated data → AuthFailed.
    try testing.expectError(error.AuthFailed, a.open(nonce, "different-ad", &ct, tag, &out));
}

test "Wycheproof: AES-256-GCM rejects tampered ciphertext/tag/nonce/aad" {
    try aeadTamperRejected(aead.Aead(.aes256_gcm));
}

test "Wycheproof: ChaCha20-Poly1305 rejects tampered ciphertext/tag/nonce/aad" {
    try aeadTamperRejected(aead.Aead(.chacha20_poly1305));
}

// ── X25519: a low-order peer point (all-zero u) must be rejected, never yield
//    a usable shared secret (RFC 7748 §6.1 / the classic contributory-behavior
//    attack). Orochi's wrapper rejects an all-zero shared secret. ──

test "Wycheproof: X25519 rejects the all-zero low-order point" {
    const sk = kx.SecretKey.init([_]u8{0x33} ** 32);
    const all_zero: kx.PublicKey = [_]u8{0} ** 32;
    try testing.expectError(error.LowOrderPoint, kx.X25519Kx.sharedSecret(&sk, all_zero));
}

// ── ECDSA P-256: a signature with r == 0 or s == 0 is outside [1, n-1] and MUST
//    NOT verify, for any key or message (a classic Wycheproof malleability/edge
//    case). ──

test "Wycheproof: ECDSA-P256 rejects zero r or s" {
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const msg = "message under an adversarial signature";

    // r = 0, s = 0.
    try testing.expect(!ecdsa_p256.verify(ecdsa_p256.Signature.fromBytes([_]u8{0} ** 64), msg, kp.public_key));

    // r = 0, s = 1.
    var r0s1 = [_]u8{0} ** 64;
    r0s1[63] = 1;
    try testing.expect(!ecdsa_p256.verify(ecdsa_p256.Signature.fromBytes(r0s1), msg, kp.public_key));

    // r = 1, s = 0.
    var r1s0 = [_]u8{0} ** 64;
    r1s0[31] = 1;
    try testing.expect(!ecdsa_p256.verify(ecdsa_p256.Signature.fromBytes(r1s0), msg, kp.public_key));
}
