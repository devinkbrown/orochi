// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end origin authentication for direct-owned S2S state frames.
//!
//! A node's identity is SELF-CERTIFYING: its 20-byte node id is
//! `BLAKE3-160(Ed25519 public key)` ([node_identity.nodeIdFromPublicKey]) and its
//! u64 mesh routing handle is `shortId(node_id)` ([node_short_id.shortId]). So a
//! frame can carry the origin's Ed25519 public key + a signature, and a receiver
//! can verify, with NO key-distribution subsystem, both:
//!
//!   (a) `shortId(nodeIdFromPublicKey(pubkey)) == claimed origin short id`, and
//!   (b) the signature over the (frame-type-bound) payload.
//!
//! An attacker cannot forge node X's frame without X's private key; substituting
//! their own key changes the derived node id, so the (a) check fails. This is the
//! cryptographic upgrade of `s2s_peer.acceptsDirectOrigin`, which only checks the
//! claimed origin against the immediate link peer at the *link trust* level.
//!
//! Wire format of one signed envelope (emitted in place of a raw payload):
//!
//!   [pubkey: 32 bytes][ed25519 sig: 64 bytes][payload: N bytes]
//!
//! The signature covers the canonical message `frame_type_byte ++ payload` under
//! a domain label (via `sign.signCtx`), binding the frame type so a signature can
//! never be replayed across frame types and so this Ed25519 signature can never
//! be confused with a node-identity, oper-grant, or migration-token signature.
//!
//! SCOPE: this envelope authenticates DIRECT-ORIGIN frames (the sending peer IS
//! the origin): MEMBERSHIP, CHANNEL_MODE_STATE, CHANNEL_MODE_FLAGS, CHANNEL_LIST,
//! TOPIC, NICKCHANGE, and CHANNEL_PROP. Each stamps `origin_node = local node`
//! on send and is applied to the local world on recv (never re-emitted with a
//! foreign origin), so the self-certifying `originShortId(pubkey) == origin_node`
//! check holds exactly.
//!
//! NOT covered (multi-hop, explicitly deferred): MESSAGE relay and CRDT delta
//! re-broadcast, where a relay re-emits a fact AUTHORED BY A THIRD NODE with that
//! node's `origin_node` preserved. Signing those end-to-end needs per-fact
//! signature storage so the relay re-emits the ORIGINAL signer's `(pubkey, sig)`
//! rather than its own (re-signing with the relay's key would either fail the
//! receiver's origin check or erase the true author). See the FOLLOW-UP note at
//! the bottom of this file and the gap-audit doc.
const std = @import("std");

const sign = @import("../../crypto/sign.zig");
const node_identity = @import("../../daemon/node_identity.zig");
const node_short_id = @import("../../crypto/node_short_id.zig");

pub const pubkey_len = sign.public_key_len; // 32
pub const sig_len = sign.signature_len; // 64
pub const header_len = pubkey_len + sig_len; // 96

/// Domain label folded into the Ed25519 transcript (via `sign.signCtx`). Distinct
/// from every other Ed25519 use in Orochi (node identity, oper grants, migration
/// tokens), so a signed-frame signature can never validate in another context.
pub const sign_domain = "orochi-s2s-signed-frame-v1";

pub const Error = error{
    /// The byte slice is shorter than the fixed `[pubkey][sig]` header.
    Truncated,
};

/// A parsed signed envelope. All three fields BORROW from the input bytes (the
/// payload is a sub-slice); valid only while those bytes live.
pub const Unwrapped = struct {
    pubkey: sign.PublicKey,
    sig: sign.Signature,
    payload: []const u8,
};

/// Wrap `payload` into a signed envelope written to `buf`, returning the written
/// slice (`buf[0 .. header_len + payload.len]`). `buf` must hold at least
/// `header_len + payload.len` bytes. The signature binds `frame_type_byte` so a
/// signature minted for one frame type can never be replayed as another.
///
/// `kp` is the origin node's Ed25519 keypair; its public key is embedded so a
/// receiver can self-certify the origin without any key distribution.
pub fn wrap(
    buf: []u8,
    kp: *const sign.KeyPair,
    frame_type_byte: u8,
    payload: []const u8,
) ![]u8 {
    const total = header_len + payload.len;
    if (buf.len < total) return error.NoSpaceLeft;

    // Canonical signed transcript: sign_domain ++ [frame_type_byte] ++ payload,
    // streamed (no contiguous copy) by the deterministic RFC 8032 signer. Binding
    // the type byte means a signature minted for one frame type can never be
    // replayed as another, and the domain isolates it from every other Ed25519
    // use in Orochi.
    const sig = try kp.signCtxInfix(sign_domain, &[_]u8{frame_type_byte}, payload);

    @memcpy(buf[0..pubkey_len], &kp.public_key);
    @memcpy(buf[pubkey_len..header_len], &sig);
    @memcpy(buf[header_len..total], payload);
    return buf[0..total];
}

/// Parse a signed envelope. Rejects input shorter than the fixed header. The
/// returned `payload` is a borrowed sub-slice of `bytes`.
pub fn unwrap(bytes: []const u8) Error!Unwrapped {
    if (bytes.len < header_len) return error.Truncated;
    return .{
        .pubkey = bytes[0..pubkey_len].*,
        .sig = bytes[pubkey_len..header_len].*,
        .payload = bytes[header_len..],
    };
}

/// Verify a parsed envelope's signature over `frame_type_byte ++ payload` against
/// the embedded public key. Returns false on any mismatch (bad signature, wrong
/// frame type, tampered payload). Does NOT check the origin id — pair this with
/// `originShortId` to enforce self-certification.
pub fn verify(u: Unwrapped, frame_type_byte: u8) bool {
    return sign.verifyCtxInfix(sign_domain, &[_]u8{frame_type_byte}, u.payload, u.sig, u.pubkey) catch false;
}

/// The u64 mesh routing handle (origin short id) self-certified by `pubkey`:
/// `shortId(nodeIdFromPublicKey(pubkey))`. A receiver requires this to equal the
/// frame's claimed `origin_node` so a peer cannot assert another node's origin.
pub fn originShortId(pubkey: sign.PublicKey) u64 {
    return node_short_id.shortId(node_identity.nodeIdFromPublicKey(pubkey));
}

// FOLLOW-UP (multi-hop / CRDT re-broadcast): this envelope authenticates only the
// DIRECT-ORIGIN case (the sending peer IS the asserted origin). The MESSAGE relay
// and CRDT delta/BURST re-broadcast re-emit a fact learned from a THIRD node with
// that node's `origin_node` preserved; a relay re-signing with its OWN key would
// either fail the receiver's `originShortId` check or erase the true author.
// Closing multi-hop requires storing the ORIGINAL signer's `(pubkey, sig)`
// alongside each CRDT fact / relayed message and re-emitting THAT, not the
// relay's. Tracked in docs/audits/2026-06-15-orochi-vs-ophion-gap-audit.md.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testKeyPair(seed_byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed([_]u8{seed_byte} ** sign.seed_len);
}

test "wrap/unwrap round-trips and verifies" {
    var kp = try testKeyPair(0x11);
    defer kp.deinit();

    const payload = "hello-direct-origin-frame";
    var buf: [header_len + payload.len]u8 = undefined;
    const env = try wrap(&buf, &kp, 0x08, payload);
    try testing.expectEqual(header_len + payload.len, env.len);

    const u = try unwrap(env);
    try testing.expectEqualSlices(u8, &kp.public_key, &u.pubkey);
    try testing.expectEqualSlices(u8, payload, u.payload);
    try testing.expect(verify(u, 0x08));
}

test "empty payload round-trips" {
    var kp = try testKeyPair(0x22);
    defer kp.deinit();
    var buf: [header_len]u8 = undefined;
    const env = try wrap(&buf, &kp, 0x10, "");
    const u = try unwrap(env);
    try testing.expectEqual(@as(usize, 0), u.payload.len);
    try testing.expect(verify(u, 0x10));
}

test "tampered payload fails verification" {
    var kp = try testKeyPair(0x33);
    defer kp.deinit();
    const payload = "membership-event-bytes";
    var buf: [header_len + payload.len]u8 = undefined;
    const env = try wrap(&buf, &kp, 0x08, payload);
    // Flip one payload byte after signing.
    buf[header_len] ^= 0x01;
    const u = try unwrap(env);
    try testing.expect(!verify(u, 0x08));
}

test "wrong frame type fails verification (type is bound)" {
    var kp = try testKeyPair(0x44);
    defer kp.deinit();
    const payload = "topic-event-bytes";
    var buf: [header_len + payload.len]u8 = undefined;
    const env = try wrap(&buf, &kp, 0x0E, payload); // signed as TOPIC
    const u = try unwrap(env);
    try testing.expect(verify(u, 0x0E)); // correct type verifies
    try testing.expect(!verify(u, 0x08)); // replayed as MEMBERSHIP fails
    try testing.expect(!verify(u, 0x10)); // replayed as MODE_STATE fails
}

test "tampered signature fails verification" {
    var kp = try testKeyPair(0x55);
    defer kp.deinit();
    const payload = "channel-prop-bytes";
    var buf: [header_len + payload.len]u8 = undefined;
    const env = try wrap(&buf, &kp, 0x0D, payload);
    // Corrupt a signature byte.
    buf[pubkey_len] ^= 0x80;
    const u = try unwrap(env);
    try testing.expect(!verify(u, 0x0D));
}

test "truncated input is rejected" {
    var kp = try testKeyPair(0x66);
    defer kp.deinit();
    var buf: [header_len + 4]u8 = undefined;
    const env = try wrap(&buf, &kp, 0x08, "abcd");
    // Every length below the fixed header must be rejected.
    var i: usize = 0;
    while (i < header_len) : (i += 1) {
        try testing.expectError(error.Truncated, unwrap(env[0..i]));
    }
    // Exactly header_len (empty payload) is the boundary: it parses.
    _ = try unwrap(env[0..header_len]);
}

test "wrap rejects an undersized buffer" {
    var kp = try testKeyPair(0x77);
    defer kp.deinit();
    var small: [header_len]u8 = undefined; // no room for payload
    try testing.expectError(error.NoSpaceLeft, wrap(&small, &kp, 0x08, "x"));
}

test "originShortId is stable and matches node_identity derivation" {
    const seed = [_]u8{0x42} ** sign.seed_len;
    var kp = try sign.KeyPair.fromSeed(seed);
    defer kp.deinit();

    // Stable across calls.
    const a = originShortId(kp.public_key);
    const b = originShortId(kp.public_key);
    try testing.expectEqual(a, b);

    // Matches deriving the short id straight from node_identity: this is the
    // self-certifying invariant the receiver enforces against `origin_node`.
    var ident = try node_identity.fromSeed(seed, "local");
    defer ident.deinit();
    try testing.expectEqual(ident.shortId(), a);
    try testing.expectEqualSlices(u8, &ident.sign_kp.public_key, &kp.public_key);
}

test "distinct keys give distinct origin short ids (no forgery by key swap)" {
    var kp1 = try testKeyPair(0x01);
    defer kp1.deinit();
    var kp2 = try testKeyPair(0x02);
    defer kp2.deinit();
    try testing.expect(originShortId(kp1.public_key) != originShortId(kp2.public_key));
}

test "a forged envelope (attacker key) has a wrong origin short id" {
    // Victim node X.
    var victim = try testKeyPair(0xAA);
    defer victim.deinit();
    const victim_origin = originShortId(victim.public_key);

    // Attacker signs a frame claiming to be X but can only use its own key.
    var attacker = try testKeyPair(0xBB);
    defer attacker.deinit();
    const payload = "forged-membership";
    var buf: [header_len + payload.len]u8 = undefined;
    const env = try wrap(&buf, &attacker, 0x08, payload);
    const u = try unwrap(env);

    // The signature is internally valid (attacker signed it)...
    try testing.expect(verify(u, 0x08));
    // ...but the self-certified origin is the attacker's, not the victim's.
    try testing.expect(originShortId(u.pubkey) != victim_origin);
    try testing.expectEqual(originShortId(attacker.public_key), originShortId(u.pubkey));
}
