// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Web Push message crypto: RFC 8291 (aes128gcm content encryption) and
//! RFC 8292 (VAPID server authorization).
//!
//! This module is PURE — no I/O, no clock, no allocator surprises. The daemon
//! glue (`daemon/webpush.zig`) owns subscriptions, the delivery worker, and
//! the HTTPS POST; everything here is deterministic and pinned by the RFC 8291
//! Appendix A test vector.
//!
//!   encrypt()        — payload → aes128gcm body (header ‖ ciphertext ‖ tag)
//!   vapidJwt()       — ES256 JWT for the push service audience
//!   vapidAuthValue() — the `Authorization: vapid t=…, k=…` header value

const std = @import("std");
const ecdh = @import("ecdh_p256.zig");
const ecdsa = @import("ecdsa_p256.zig");
const rnd = @import("random.zig");

const Allocator = std.mem.Allocator;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const b64url = std.base64.url_safe_no_pad;

pub const Error = error{
    /// A subscription key failed to parse (wrong length / not a curve point).
    InvalidSubscriptionKey,
    /// Plaintext exceeds what a single aes128gcm record can carry here.
    PayloadTooLarge,
} || Allocator.Error || ecdh.EcdhError;

/// Uncompressed SEC1 P-256 point length (the `p256dh` subscription key).
pub const ua_public_length: usize = ecdh.public_length; // 65
/// Subscription auth secret length (RFC 8291 §2.1).
pub const auth_secret_length: usize = 16;
/// Single-record size we emit (also the cap on plaintext, minus overhead).
pub const record_size: u32 = 4096;
/// Room a record must reserve: 1 delimiter byte + 16-byte GCM tag.
pub const record_overhead: usize = 17;
/// Largest plaintext `encrypt` accepts.
pub const max_plaintext: usize = record_size - record_overhead;

/// aes128gcm body layout constants (RFC 8188 §2.1).
const header_length: usize = 16 + 4 + 1 + ua_public_length; // salt ‖ rs ‖ idlen ‖ keyid

// ── RFC 8291 content encryption ──────────────────────────────────────────────

/// Encrypt `plaintext` for the subscription (`ua_public`, `auth_secret`) using
/// the CALLER-SUPPLIED ephemeral key pair and salt. Deterministic — this is
/// the KAT surface; production goes through `encryptRandom`.
///
/// Returns the complete HTTP body: aes128gcm header ‖ ciphertext ‖ tag.
pub fn encrypt(
    allocator: Allocator,
    ua_public: [ua_public_length]u8,
    auth_secret: [auth_secret_length]u8,
    as_keys: ecdh.KeyPair,
    salt: [16]u8,
    plaintext: []const u8,
) Error![]u8 {
    if (plaintext.len > max_plaintext) return error.PayloadTooLarge;

    // ecdh_secret = ECDH(as_private, ua_public)
    const ecdh_secret = ecdh.sharedSecret(as_keys.secret, ua_public) catch
        return error.InvalidSubscriptionKey;

    // IKM = HKDF(salt=auth_secret, ikm=ecdh_secret,
    //            info="WebPush: info" ‖ 0x00 ‖ ua_public ‖ as_public, L=32)
    const prk_key = HkdfSha256.extract(&auth_secret, &ecdh_secret);
    var key_info: ["WebPush: info".len + 1 + ua_public_length * 2]u8 = undefined;
    @memcpy(key_info[0.."WebPush: info".len], "WebPush: info");
    key_info["WebPush: info".len] = 0;
    @memcpy(key_info["WebPush: info".len + 1 ..][0..ua_public_length], &ua_public);
    @memcpy(key_info["WebPush: info".len + 1 + ua_public_length ..][0..ua_public_length], &as_keys.public_sec1);
    var ikm: [32]u8 = undefined;
    HkdfSha256.expand(&ikm, &key_info, prk_key);

    // CEK / NONCE from HKDF(salt, IKM) with the aes128gcm info strings.
    const prk = HkdfSha256.extract(&salt, &ikm);
    var cek: [16]u8 = undefined;
    HkdfSha256.expand(&cek, "Content-Encoding: aes128gcm\x00", prk);
    var nonce: [12]u8 = undefined;
    HkdfSha256.expand(&nonce, "Content-Encoding: nonce\x00", prk);

    // Single record: plaintext ‖ 0x02 (final-record delimiter), then seal.
    const body_len = header_length + plaintext.len + record_overhead;
    const body = try allocator.alloc(u8, body_len);
    errdefer allocator.free(body);

    // Header: salt(16) ‖ rs(4, BE) ‖ idlen(1) ‖ as_public(65).
    @memcpy(body[0..16], &salt);
    std.mem.writeInt(u32, body[16..20], record_size, .big);
    body[20] = @intCast(ua_public_length);
    @memcpy(body[21..][0..ua_public_length], &as_keys.public_sec1);

    const record = try allocator.alloc(u8, plaintext.len + 1);
    defer allocator.free(record);
    @memcpy(record[0..plaintext.len], plaintext);
    record[plaintext.len] = 0x02;

    const ct = body[header_length..][0..record.len];
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(ct, &tag, record, "", nonce, cek);
    @memcpy(body[header_length + record.len ..][0..tag.len], &tag);

    return body;
}

/// Production entry: fresh ephemeral key pair + random salt per message
/// (RFC 8291 REQUIRES both to be unique per encryption).
pub fn encryptRandom(
    allocator: Allocator,
    ua_public: [ua_public_length]u8,
    auth_secret: [auth_secret_length]u8,
    plaintext: []const u8,
) Error![]u8 {
    const as_keys = try ecdh.generate();
    var salt: [16]u8 = undefined;
    rnd.fillOsEntropy(&salt) catch return error.EntropyUnavailable;
    return encrypt(allocator, ua_public, auth_secret, as_keys, salt, plaintext);
}

// ── RFC 8292 VAPID ───────────────────────────────────────────────────────────

/// Build the ES256 JWT a push service demands: header `{"typ":"JWT","alg":"ES256"}`,
/// claims `{"aud":…,"exp":…,"sub":…}`, signature raw r ‖ s (NOT DER), all
/// base64url-unpadded. `aud` must be the push endpoint's origin
/// (`https://host`), `exp` an absolute unix time ≤ 24h out.
pub fn vapidJwt(
    allocator: Allocator,
    aud: []const u8,
    sub: []const u8,
    exp: i64,
    key_pair: ecdsa.KeyPair,
) Allocator.Error![]u8 {
    const header_b64 = comptime blk: {
        const h = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}";
        var buf: [b64url.Encoder.calcSize(h.len)]u8 = undefined;
        _ = b64url.Encoder.encode(&buf, h);
        break :blk buf;
    };

    const claims = try std.fmt.allocPrint(
        allocator,
        "{{\"aud\":\"{s}\",\"exp\":{d},\"sub\":\"{s}\"}}",
        .{ aud, exp, sub },
    );
    defer allocator.free(claims);

    const claims_b64 = try allocator.alloc(u8, b64url.Encoder.calcSize(claims.len));
    defer allocator.free(claims_b64);
    _ = b64url.Encoder.encode(claims_b64, claims);

    const signing_input = try std.mem.join(allocator, ".", &.{ &header_b64, claims_b64 });
    defer allocator.free(signing_input);

    // Deterministic ECDSA (RFC 6979 path) — reproducible, no entropy needed.
    const sig = ecdsa.sign(signing_input, key_pair) catch unreachable;
    const sig_raw: [ecdsa.raw_signature_length]u8 = sig.toBytes();
    var sig_b64: [b64url.Encoder.calcSize(ecdsa.raw_signature_length)]u8 = undefined;
    _ = b64url.Encoder.encode(&sig_b64, &sig_raw);

    return std.mem.join(allocator, ".", &.{ signing_input, &sig_b64 });
}

/// The `Authorization` header value: `vapid t=<jwt>, k=<pub-b64url>`.
pub fn vapidAuthValue(allocator: Allocator, jwt: []const u8, public_sec1: [65]u8) Allocator.Error![]u8 {
    var pub_b64: [b64url.Encoder.calcSize(65)]u8 = undefined;
    _ = b64url.Encoder.encode(&pub_b64, &public_sec1);
    return std.fmt.allocPrint(allocator, "vapid t={s}, k={s}", .{ jwt, &pub_b64 });
}

// ── base64url helpers (subscription key parsing) ─────────────────────────────

pub fn decodeFixed(comptime n: usize, text: []const u8) error{InvalidSubscriptionKey}![n]u8 {
    var out: [n]u8 = undefined;
    const len = b64url.Decoder.calcSizeForSlice(text) catch return error.InvalidSubscriptionKey;
    if (len != n) return error.InvalidSubscriptionKey;
    b64url.Decoder.decode(&out, text) catch return error.InvalidSubscriptionKey;
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn b64(comptime n: usize, text: []const u8) ![n]u8 {
    return decodeFixed(n, text);
}

test "RFC 8291 Appendix A — full known-answer vector" {
    // Every input and the exact expected body come from the RFC.
    const plaintext = "When I grow up, I want to be a watermelon";
    const ua_public = try b64(65, "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
    const auth_secret = try b64(16, "BTBZMqHH6r4Tts7J_aSIgg");
    const as_private = try b64(32, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw");
    const as_public_expect = try b64(65, "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
    const salt = try b64(16, "DGv6ra1nlYgDCS1FRnbzlw");

    // The vector's private scalar is canonical, so deterministic generation
    // reproduces the vector's exact key pair.
    const as_keys = try ecdh.generateDeterministic(as_private);
    try testing.expectEqualSlices(u8, &as_public_expect, &as_keys.public_sec1);

    const body = try encrypt(testing.allocator, ua_public, auth_secret, as_keys, salt, plaintext);
    defer testing.allocator.free(body);

    const expected_b64 = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlml" ++
        "MoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3o" ++
        "ZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";
    const expected_len = try b64url.Decoder.calcSizeForSlice(expected_b64);
    const expected = try testing.allocator.alloc(u8, expected_len);
    defer testing.allocator.free(expected);
    try b64url.Decoder.decode(expected, expected_b64);

    try testing.expectEqualSlices(u8, expected, body);
}

test "encrypt rejects oversized plaintext and bad subscription keys" {
    const as_keys = try ecdh.generateDeterministic(@as([32]u8, @splat(7)));
    const salt = @as([16]u8, @splat(1));
    const auth = @as([16]u8, @splat(2));

    // Oversized payload.
    const big = try testing.allocator.alloc(u8, max_plaintext + 1);
    defer testing.allocator.free(big);
    try testing.expectError(
        error.PayloadTooLarge,
        encrypt(testing.allocator, as_keys.public_sec1, auth, as_keys, salt, big),
    );

    // Not a curve point (all-zero "public key").
    const junk = @as([65]u8, @splat(0));
    try testing.expectError(
        error.InvalidSubscriptionKey,
        encrypt(testing.allocator, junk, auth, as_keys, salt, "hi"),
    );
}

test "encryptRandom round-trips through a decryptor built from the RFC rules" {
    // Simulate the browser side: derive the same CEK/NONCE from the body's
    // header and decrypt. Proves salt/keys thread through correctly.
    const ua = try ecdh.generate();
    var auth: [16]u8 = undefined;
    try rnd.fillOsEntropy(&auth);

    const msg = "queued while you were away";
    const body = try encryptRandom(testing.allocator, ua.public_sec1, auth, msg);
    defer testing.allocator.free(body);

    // Parse header.
    const salt = body[0..16].*;
    try testing.expectEqual(record_size, std.mem.readInt(u32, body[16..20], .big));
    try testing.expectEqual(@as(u8, 65), body[20]);
    const as_public = body[21..86].*;
    const ct = body[86 .. body.len - 16];
    const tag = body[body.len - 16 ..][0..16].*;

    // UA-side derivation mirrors encrypt() with the roles swapped.
    const ecdh_secret = try ecdh.sharedSecret(ua.secret, as_public);
    const prk_key = HkdfSha256.extract(&auth, &ecdh_secret);
    var key_info: ["WebPush: info".len + 1 + 130]u8 = undefined;
    @memcpy(key_info[0..13], "WebPush: info");
    key_info[13] = 0;
    @memcpy(key_info[14..79], &ua.public_sec1);
    @memcpy(key_info[79..144], &as_public);
    var ikm: [32]u8 = undefined;
    HkdfSha256.expand(&ikm, &key_info, prk_key);
    const prk = HkdfSha256.extract(&salt, &ikm);
    var cek: [16]u8 = undefined;
    HkdfSha256.expand(&cek, "Content-Encoding: aes128gcm\x00", prk);
    var nonce: [12]u8 = undefined;
    HkdfSha256.expand(&nonce, "Content-Encoding: nonce\x00", prk);

    const record = try testing.allocator.alloc(u8, ct.len);
    defer testing.allocator.free(record);
    try Aes128Gcm.decrypt(record, ct, tag, "", nonce, cek);
    try testing.expectEqual(@as(u8, 0x02), record[record.len - 1]);
    try testing.expectEqualStrings(msg, record[0 .. record.len - 1]);
}

test "vapidJwt produces a verifiable ES256 token" {
    const kp = ecdsa.KeyPair.generate(std.testing.io);
    const jwt = try vapidJwt(testing.allocator, "https://push.example.net", "mailto:ops@eshmaki.me", 1_800_000_000, kp);
    defer testing.allocator.free(jwt);

    // Three dot-separated base64url segments, header exact.
    var it = std.mem.splitScalar(u8, jwt, '.');
    const h = it.next().?;
    const c = it.next().?;
    const s = it.next().?;
    try testing.expect(it.next() == null);

    var h_buf: [64]u8 = undefined;
    const h_len = try b64url.Decoder.calcSizeForSlice(h);
    try b64url.Decoder.decode(h_buf[0..h_len], h);
    try testing.expectEqualStrings("{\"typ\":\"JWT\",\"alg\":\"ES256\"}", h_buf[0..h_len]);

    var c_buf: [256]u8 = undefined;
    const c_len = try b64url.Decoder.calcSizeForSlice(c);
    try b64url.Decoder.decode(c_buf[0..c_len], c);
    try testing.expect(std.mem.indexOf(u8, c_buf[0..c_len], "\"aud\":\"https://push.example.net\"") != null);
    try testing.expect(std.mem.indexOf(u8, c_buf[0..c_len], "\"exp\":1800000000") != null);

    // Signature verifies over `header.claims` with the raw r‖s encoding.
    const sig_raw = try b64(64, s);
    const sig = ecdsa.Signature.fromBytes(sig_raw);
    const signing_input = jwt[0 .. h.len + 1 + c.len];
    try testing.expect(ecdsa.verify(sig, signing_input, kp.public_key));
}

test "vapidAuthValue formats the Authorization header" {
    const kp = ecdsa.KeyPair.generate(std.testing.io);
    const jwt = try vapidJwt(testing.allocator, "https://push.example.net", "mailto:ops@eshmaki.me", 1_800_000_000, kp);
    defer testing.allocator.free(jwt);
    const auth = try vapidAuthValue(testing.allocator, jwt, kp.public_key.toUncompressedSec1());
    defer testing.allocator.free(auth);
    try testing.expect(std.mem.startsWith(u8, auth, "vapid t="));
    try testing.expect(std.mem.indexOf(u8, auth, ", k=") != null);
}
