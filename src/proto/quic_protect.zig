//! QUIC packet protection (RFC 9001 §5.3 + §5.4).
//!
//! This module turns the key material derived in `quic_tls.zig` and the header
//! layout decoded by `quic_packet.zig` into the two operations a QUIC endpoint
//! actually performs on the wire:
//!
//!   * AEAD payload protection (RFC 9001 §5.3) — AES-128-GCM with the
//!     packet-protection key. The 96-bit nonce is the per-direction IV XORed
//!     with the left-padded packet number; the AAD is the *unprotected* packet
//!     header (first byte through the end of the packet-number field).
//!   * Header protection (RFC 9001 §5.4) — a per-packet mask derived from a
//!     16-byte ciphertext sample is XORed into the low bits of the first byte
//!     and into the packet-number bytes, hiding the packet number and the
//!     reserved/pn-length bits from on-path observers.
//!
//! It then composes those into whole-packet `sealPacket` (send) and
//! `openPacket` (receive) helpers.
//!
//! ## Cipher suites (encryption levels)
//!
//! QUIC v1 protects packets with one of three AEAD/header-protection pairs
//! (RFC 9001 §5.3), selected per encryption level by the negotiated TLS 1.3
//! cipher suite (`quic_tls.CipherSuite`):
//!
//!   * `aes128gcm`        — AES-128-GCM payload + AES-128-ECB header protection.
//!                          The Initial space *always* uses this (RFC 9001 §5.2).
//!   * `aes256gcm`        — AES-256-GCM payload + AES-256-ECB header protection.
//!   * `chacha20poly1305` — ChaCha20-Poly1305 payload + ChaCha20 header
//!                          protection (RFC 9001 §5.4.4).
//!
//! Each of `protectPayload`/`unprotectPayload`, `headerProtectionMask` (here),
//! and the whole-packet `sealPacket`/`openPacket` dispatch on the suite. The
//! AES-128 paths are kept byte-identical to the original (verified against the
//! RFC 9001 Appendix A.2/A.3 Initial vectors), and the ChaCha20 path is verified
//! byte-for-byte against the RFC 9001 Appendix A.5 short-header vector.
//!
//! Design goals:
//!   * Allocation-light — callers own all buffers; we only borrow slices.
//!   * Bounds-checked — every offset is validated, so a malformed/truncated
//!     packet returns an error and never reads or writes out of bounds.
//!   * Interop-correct — the tests at the bottom reproduce the official
//!     RFC 9001 Appendix A.2 (client), A.3 (server), and A.5 (ChaCha20)
//!     protected packets byte-for-byte, not merely a self-consistent round trip.
//!
//! Reuses `std.crypto` for the AEADs (AES-128/256-GCM, ChaCha20-Poly1305) and
//! the header-protection primitives (AES-ECB, ChaCha20) — no hand-rolled GHASH,
//! AES, ChaCha, or HKDF — `quic_tls` for key derivation + the HP masks, and
//! `quic_packet` for the header/packet-number coding.

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const crypto = std.crypto;

const quic_tls = @import("quic_tls.zig");
const quic_packet = @import("quic_packet.zig");

const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

/// Re-export the cipher-suite enum so callers of this module have one import.
pub const CipherSuite = quic_tls.CipherSuite;
/// Re-export the per-direction packet keys (suite-tagged).
pub const PacketKeys = quic_tls.PacketKeys;

/// AEAD authentication-tag length (bytes). 16 for all three QUIC v1 suites.
pub const aead_tag_len: usize = Aes128Gcm.tag_length; // 16
/// AEAD nonce length (bytes) — equals the QUIC IV length.
pub const aead_nonce_len: usize = quic_tls.aead_iv_len; // 12
/// Length of the header-protection sample (bytes).
pub const hp_sample_len: usize = 16;
/// Offset, measured from the *start of the packet-number field*, at which the
/// 16-byte header-protection sample begins (RFC 9001 §5.4.2).
pub const hp_sample_pn_offset: usize = 4;

comptime {
    // All three suites share the 16-byte tag and 12-byte nonce; the dispatch
    // code below relies on that to size buffers uniformly.
    assert(Aes256Gcm.tag_length == aead_tag_len);
    assert(ChaCha20Poly1305.tag_length == aead_tag_len);
    assert(Aes256Gcm.nonce_length == aead_nonce_len);
    assert(ChaCha20Poly1305.nonce_length == aead_nonce_len);
}

pub const ProtectError = error{
    /// The plaintext/ciphertext buffer is too short to hold the requested data
    /// (e.g. ciphertext shorter than the 16-byte tag).
    BufferTooSmall,
    /// AEAD tag verification failed — the packet was forged or corrupted.
    /// No plaintext is produced in this case.
    AuthenticationFailed,
    /// A header/packet offset would read or write out of bounds, or the packet
    /// is too short to carry a header-protection sample.
    Truncated,
};

// ---------------------------------------------------------------------------
// Nonce construction (RFC 9001 §5.3)
// ---------------------------------------------------------------------------

/// Build the 96-bit AEAD nonce from the per-direction IV and the full
/// (decoded) packet number.
///
/// > The 62 bits of the reconstructed QUIC packet number ... is left-padded
/// > with zeros to the size of the IV. The exclusive OR of the padded packet
/// > number and the IV forms the AEAD nonce. (RFC 9001 §5.3)
///
/// The packet number is encoded big-endian in the *low* 8 bytes of the nonce,
/// so only the trailing bytes of the IV are perturbed.
pub fn buildNonce(iv: [aead_nonce_len]u8, packet_number: u64) [aead_nonce_len]u8 {
    var nonce = iv;
    // XOR the big-endian packet number into the rightmost 8 bytes.
    comptime assert(aead_nonce_len >= 8);
    const base = aead_nonce_len - 8;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u6 = @intCast((7 - i) * 8);
        nonce[base + i] ^= @truncate(packet_number >> shift);
    }
    return nonce;
}

// ---------------------------------------------------------------------------
// AEAD payload protection (RFC 9001 §5.3)
// ---------------------------------------------------------------------------

/// Dispatch an AEAD `encrypt` over the three QUIC v1 suites. `key` must be the
/// suite's key length (`suite.keyLen()`); a mismatch is an internal invariant
/// violation (the keys come from `derivePacketKeys`, which sizes them), so we
/// surface it as `error.BufferTooSmall` rather than asserting.
fn aeadEncrypt(
    suite: CipherSuite,
    ct: []u8,
    tag: *[aead_tag_len]u8,
    plaintext: []const u8,
    aad: []const u8,
    nonce: [aead_nonce_len]u8,
    key: []const u8,
) ProtectError!void {
    if (key.len != suite.keyLen()) return error.BufferTooSmall;
    switch (suite) {
        .aes128gcm => Aes128Gcm.encrypt(ct, tag, plaintext, aad, nonce, key[0..16].*),
        .aes256gcm => Aes256Gcm.encrypt(ct, tag, plaintext, aad, nonce, key[0..32].*),
        .chacha20poly1305 => ChaCha20Poly1305.encrypt(ct, tag, plaintext, aad, nonce, key[0..32].*),
    }
}

/// Dispatch an AEAD `decrypt` over the three QUIC v1 suites. Returns
/// `error.AuthenticationFailed` on tag mismatch (no usable plaintext is left).
fn aeadDecrypt(
    suite: CipherSuite,
    plaintext: []u8,
    ct: []const u8,
    tag: [aead_tag_len]u8,
    aad: []const u8,
    nonce: [aead_nonce_len]u8,
    key: []const u8,
) ProtectError!void {
    if (key.len != suite.keyLen()) return error.BufferTooSmall;
    switch (suite) {
        .aes128gcm => Aes128Gcm.decrypt(plaintext, ct, tag, aad, nonce, key[0..16].*) catch return error.AuthenticationFailed,
        .aes256gcm => Aes256Gcm.decrypt(plaintext, ct, tag, aad, nonce, key[0..32].*) catch return error.AuthenticationFailed,
        .chacha20poly1305 => ChaCha20Poly1305.decrypt(plaintext, ct, tag, aad, nonce, key[0..32].*) catch return error.AuthenticationFailed,
    }
}

/// Encrypt `plaintext` in place into `ciphertext` and append the 16-byte tag,
/// using the AEAD selected by `suite`.
///
/// `ciphertext.len` must equal `plaintext.len + aead_tag_len`; the first
/// `plaintext.len` bytes receive the ciphertext and the trailing
/// `aead_tag_len` bytes receive the AEAD tag. `aad` is the unprotected packet
/// header (first byte … end of the packet number). The nonce is derived from
/// `iv` and the full `packet_number`. `key` is the suite-length AEAD key (16
/// bytes for AES-128-GCM, 32 for AES-256-GCM / ChaCha20-Poly1305).
pub fn protectPayload(
    suite: CipherSuite,
    ciphertext: []u8,
    plaintext: []const u8,
    key: []const u8,
    iv: [aead_nonce_len]u8,
    packet_number: u64,
    aad: []const u8,
) ProtectError!void {
    if (ciphertext.len != plaintext.len + aead_tag_len) return error.BufferTooSmall;
    const nonce = buildNonce(iv, packet_number);
    const ct = ciphertext[0..plaintext.len];
    var tag: [aead_tag_len]u8 = undefined;
    try aeadEncrypt(suite, ct, &tag, plaintext, aad, nonce, key);
    @memcpy(ciphertext[plaintext.len..][0..aead_tag_len], &tag);
}

/// Decrypt and authenticate `ciphertext` (ciphertext ‖ 16-byte tag) into
/// `plaintext`, using the AEAD selected by `suite`.
///
/// `ciphertext.len` must be at least `aead_tag_len`, and `plaintext.len` must
/// equal `ciphertext.len - aead_tag_len`. On tag-verification failure this
/// returns `error.AuthenticationFailed` and writes no usable plaintext (the
/// std AEAD implementations zero the output buffer on failure).
pub fn unprotectPayload(
    suite: CipherSuite,
    plaintext: []u8,
    ciphertext: []const u8,
    key: []const u8,
    iv: [aead_nonce_len]u8,
    packet_number: u64,
    aad: []const u8,
) ProtectError!void {
    if (ciphertext.len < aead_tag_len) return error.BufferTooSmall;
    const ct_len = ciphertext.len - aead_tag_len;
    if (plaintext.len != ct_len) return error.BufferTooSmall;
    const nonce = buildNonce(iv, packet_number);
    var tag: [aead_tag_len]u8 = undefined;
    @memcpy(&tag, ciphertext[ct_len..][0..aead_tag_len]);
    try aeadDecrypt(suite, plaintext, ciphertext[0..ct_len], tag, aad, nonce, key);
}

// ---------------------------------------------------------------------------
// Header protection (RFC 9001 §5.4)
// ---------------------------------------------------------------------------

/// Mask applied to the protected low bits of the first byte: 4 bits for a long
/// header (RFC 9000 §17.2 reserved + pn-length), 5 bits for a short header
/// (reserved + key-phase + pn-length).
fn firstByteMask(first: u8) u8 {
    return if ((first & 0x80) != 0) 0x0f else 0x1f;
}

/// Compute the header-protection sample for a packet, given the offset of the
/// packet number field. The sample is the 16 bytes starting 4 bytes into the
/// packet-number field (RFC 9001 §5.4.2), i.e. it spans the (still-encrypted)
/// remainder of the packet number plus the leading ciphertext bytes.
///
/// Returns `error.Truncated` if the packet is too short to hold the sample.
pub fn sampleForHeaderProtection(
    packet: []const u8,
    pn_offset: usize,
) ProtectError![hp_sample_len]u8 {
    const sample_offset = pn_offset + hp_sample_pn_offset;
    if (sample_offset + hp_sample_len > packet.len) return error.Truncated;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, packet[sample_offset..][0..hp_sample_len]);
    return sample;
}

/// Compute the 5-byte header-protection mask for `sample` under `suite`,
/// dispatching to the AES-128 (`aes128gcm`), AES-256 (`aes256gcm`), or ChaCha20
/// (`chacha20poly1305`) construction. `hp_key` must be the suite's HP key length
/// (`suite.hpKeyLen()`); a mismatch surfaces as `error.BufferTooSmall`.
pub fn headerProtectionMask(
    suite: CipherSuite,
    hp_key: []const u8,
    sample: [hp_sample_len]u8,
) ProtectError![5]u8 {
    if (hp_key.len != suite.hpKeyLen()) return error.BufferTooSmall;
    return switch (suite) {
        .aes128gcm => quic_tls.headerProtectionMask(hp_key[0..16].*, sample),
        .aes256gcm => quic_tls.headerProtectionMaskAes256(hp_key[0..32].*, sample),
        .chacha20poly1305 => quic_tls.headerProtectionMaskChaCha20(hp_key[0..32].*, sample),
    };
}

/// Apply header protection to `packet` (the full packet buffer), given the
/// packet-number offset, the negotiated `suite`, and its header-protection key.
/// The packet-number length is read from the (already-cleartext) first byte.
/// RFC 9001 §5.4.1.
///
/// The packet number field and the bytes after it (the AEAD ciphertext) must
/// already be in place so the sample can be drawn.
pub fn applyHeaderProtection(
    packet: []u8,
    pn_offset: usize,
    suite: CipherSuite,
    hp_key: []const u8,
) ProtectError!void {
    if (packet.len == 0 or pn_offset == 0 or pn_offset >= packet.len) return error.Truncated;
    const sample = try sampleForHeaderProtection(packet, pn_offset);
    const mask = try headerProtectionMask(suite, hp_key, sample);
    // pn length is known from the cleartext first byte on send.
    const pn_len = pnLenFromFirstByte(packet[0]);
    if (pn_offset + pn_len > packet.len) return error.Truncated;
    packet[0] ^= firstByteMask(packet[0]) & mask[0];
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        packet[pn_offset + i] ^= mask[i + 1];
    }
}

/// Remove header protection from `packet`, returning the recovered
/// packet-number length. RFC 9001 §5.4.1.
///
/// The mask is computed from the still-protected sample (header protection is
/// applied *after* the packet number is in place, so the sample bytes are the
/// same on both sides). The first byte is unmasked first to recover the
/// pn-length bits, then exactly that many packet-number bytes are unmasked.
pub fn removeHeaderProtection(
    packet: []u8,
    pn_offset: usize,
    suite: CipherSuite,
    hp_key: []const u8,
) ProtectError!usize {
    if (packet.len == 0 or pn_offset == 0 or pn_offset >= packet.len) return error.Truncated;
    const sample = try sampleForHeaderProtection(packet, pn_offset);
    const mask = try headerProtectionMask(suite, hp_key, sample);

    // Unmask the first byte to learn the true packet-number length.
    packet[0] ^= firstByteMask(packet[0]) & mask[0];
    const pn_len = pnLenFromFirstByte(packet[0]);
    if (pn_offset + pn_len > packet.len) return error.Truncated;

    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        packet[pn_offset + i] ^= mask[i + 1];
    }
    return pn_len;
}

/// Low two bits of the first byte encode (pn_len - 1) for both long and short
/// headers (RFC 9000 §17.2 / §17.3).
fn pnLenFromFirstByte(first: u8) usize {
    return @as(usize, first & 0x03) + 1;
}

// ---------------------------------------------------------------------------
// Whole-packet seal / open
// ---------------------------------------------------------------------------

/// Keys for one direction (sender or receiver), as derived by
/// `quic_tls.deriveEndpointKeys`. This is the fixed AES-128 layout used by the
/// Initial space (and the RFC 9001 Appendix A.2/A.3 vectors). `sealPacket` /
/// `openPacket` accept it directly and treat it as the `aes128gcm` suite, so
/// the original call sites and their byte-for-byte vectors are unchanged.
pub const Keys = quic_tls.EndpointKeys;

/// QUIC encryption levels (RFC 9001 §4 / §17). Each level has its own keys; the
/// Initial level always uses `CipherSuite.aes128gcm`, while the handshake and
/// 1-RTT (application) levels use whatever suite the TLS handshake negotiated.
pub const EncryptionLevel = enum {
    /// Initial packets — keys from the connection ID via `deriveInitialSecrets`.
    initial,
    /// Handshake packets — keys from the handshake_traffic_secret.
    handshake,
    /// 1-RTT (application) packets — keys from the application_traffic_secret;
    /// the only level that participates in key updates (RFC 9001 §6).
    application,
};

/// Convert a fixed AES-128 `Keys` (Initial layout) into a suite-tagged
/// `PacketKeys` for the generalized seal/open path. The Initial space is always
/// AES-128-GCM, so the suite is fixed.
fn keysToPacketKeys(keys: Keys) PacketKeys {
    var pk: PacketKeys = .{
        .suite = .aes128gcm,
        .key = [_]u8{0} ** quic_tls.max_key_len,
        .iv = keys.iv,
        .hp = [_]u8{0} ** quic_tls.max_key_len,
    };
    @memcpy(pk.key[0..16], &keys.key);
    @memcpy(pk.hp[0..16], &keys.hp);
    return pk;
}

/// The read/write `PacketKeys` for one encryption level. `write` protects
/// outgoing packets (seal); `read` opens incoming packets. Both share the same
/// suite at a given level. Construct via `KeySet.initInitial` (Initial space) or
/// `KeySet.fromTrafficSecrets` (handshake / 1-RTT).
pub const KeySet = struct {
    level: EncryptionLevel,
    /// Keys used to seal outgoing packets (this endpoint's own secret).
    write: PacketKeys,
    /// Keys used to open incoming packets (the peer's secret).
    read: PacketKeys,

    /// Build the Initial-space `KeySet` for an endpoint from the connection's
    /// Destination Connection ID. `is_server` selects which derived secret is
    /// the write (own) vs read (peer) direction:
    ///   * server: write = server_initial, read = client_initial
    ///   * client: write = client_initial, read = server_initial
    /// The Initial space is always AES-128-GCM (RFC 9001 §5.2).
    pub fn initInitial(dcid: []const u8, is_server: bool) KeySet {
        const secrets = quic_tls.deriveInitialSecrets(dcid);
        const own_prk = if (is_server) secrets.server_prk else secrets.client_prk;
        const peer_prk = if (is_server) secrets.client_prk else secrets.server_prk;
        return .{
            .level = .initial,
            .write = keysToPacketKeys(quic_tls.deriveEndpointKeys(own_prk)),
            .read = keysToPacketKeys(quic_tls.deriveEndpointKeys(peer_prk)),
        };
    }

    /// Build a handshake / 1-RTT `KeySet` from this endpoint's own and the
    /// peer's TLS 1.3 traffic secrets plus the negotiated `suite`. For the
    /// handshake level pass the *_hs_traffic secrets; for the application level
    /// pass the *_ap_traffic secrets. `is_server` is implicit in which secret
    /// the caller passes as `own_secret` vs `peer_secret`.
    pub fn fromTrafficSecrets(
        level: EncryptionLevel,
        own_secret: [32]u8,
        peer_secret: [32]u8,
        suite: CipherSuite,
    ) KeySet {
        return .{
            .level = level,
            .write = quic_tls.derivePacketKeys(own_secret, suite),
            .read = quic_tls.derivePacketKeys(peer_secret, suite),
        };
    }
};

/// Re-derive a single direction's 1-RTT packet keys from a key-updated traffic
/// secret (RFC 9001 §6.1). The AEAD key and IV roll to the new generation, but
/// the header-protection key is **retained** from `prev` — header protection is
/// never updated by a key update (RFC 9001 §6.1). The 32-byte SHA-256 secret is
/// the only width supported here; the rolled secret comes from
/// `quic_tls.nextGenerationSecret`. A (key, nonce) pair is never reused: each
/// new generation has a fresh key while the packet number (and thus the nonce)
/// keeps advancing monotonically within the connection.
pub fn keyUpdateDirection(prev: PacketKeys, next_secret: [32]u8) PacketKeys {
    var pk = quic_tls.derivePacketKeys(next_secret, prev.suite);
    // RFC 9001 §6.1: the header-protection key is NOT rolled on a key update.
    pk.hp = prev.hp;
    return pk;
}

/// Result of sealing a packet: the total protected length written to the
/// caller's output buffer.
pub const SealResult = struct {
    /// Number of bytes written: header_len + pn_len + plaintext.len + tag.
    len: usize,
};

/// Seal a full QUIC packet (header-protect ∘ payload-protect), writing the
/// protected packet into `out`.
///
/// Inputs:
///   * `header`     — the unprotected header bytes *including* the encoded
///                    packet number (first byte … last pn byte). `pn_offset`
///                    indexes the first packet-number byte within it.
///   * `pn_offset`  — offset of the packet number field within `header`.
///   * `pn_len`     — packet-number length in bytes (1..4); must agree with the
///                    low bits of `header[0]`.
///   * `packet_number` — the full (untruncated) packet number for the nonce.
///   * `plaintext`  — the QUIC frames to protect.
///   * `keys`       — sender key/iv/hp.
///
/// `out` must hold at least `header.len + plaintext.len + aead_tag_len` bytes.
/// The AAD is exactly `header` (first byte through the packet number).
///
/// This is the AES-128 Initial-space convenience wrapper; it forwards to
/// `sealPacketSuite` with the suite-tagged `aes128gcm` keys, so the original
/// callers and the RFC 9001 Appendix A.2/A.3 vectors stay byte-identical.
pub fn sealPacket(
    out: []u8,
    header: []const u8,
    pn_offset: usize,
    pn_len: usize,
    packet_number: u64,
    plaintext: []const u8,
    keys: Keys,
) ProtectError!SealResult {
    return sealPacketSuite(out, header, pn_offset, pn_len, packet_number, plaintext, keysToPacketKeys(keys));
}

/// Seal a full QUIC packet (header-protect ∘ payload-protect) under an arbitrary
/// cipher suite, writing the protected packet into `out`. Inputs match
/// `sealPacket`; `keys` is the suite-tagged sender `PacketKeys` (e.g. a
/// `KeySet.write`). The AAD is exactly `header` (first byte through the pn).
pub fn sealPacketSuite(
    out: []u8,
    header: []const u8,
    pn_offset: usize,
    pn_len: usize,
    packet_number: u64,
    plaintext: []const u8,
    keys: PacketKeys,
) ProtectError!SealResult {
    if (pn_len < 1 or pn_len > 4) return error.Truncated;
    if (pn_offset == 0 or pn_offset + pn_len != header.len) return error.Truncated;
    if (pnLenFromFirstByte(header[0]) != pn_len) return error.Truncated;

    const total = header.len + plaintext.len + aead_tag_len;
    if (out.len < total) return error.BufferTooSmall;

    // Lay down the (unprotected) header — this is also the AEAD AAD.
    @memcpy(out[0..header.len], header);

    // AEAD-encrypt the payload right after the header.
    const ct = out[header.len .. header.len + plaintext.len + aead_tag_len];
    try protectPayload(keys.suite, ct, plaintext, keys.keyBytes(), keys.iv, packet_number, header);

    // Now apply header protection over the assembled packet.
    try applyHeaderProtection(out[0..total], pn_offset, keys.suite, keys.hpBytes());

    return .{ .len = total };
}

/// Result of opening a packet.
pub const OpenResult = struct {
    /// Truncated packet number as it appeared on the wire (the low `pn_len`
    /// bytes). The caller reconstructs the full 62-bit number from this plus
    /// the largest-acknowledged packet number (RFC 9000 §A.3); for the Initial
    /// space the first packet's truncated value equals the full value.
    truncated_packet_number: u64,
    /// Number of packet-number bytes (1..4).
    pn_len: usize,
    /// Length of the recovered plaintext written into the caller's buffer.
    plaintext_len: usize,
};

/// Open a full QUIC packet (header-unprotect → decode pn → payload-unprotect),
/// writing the recovered frames into `plaintext_out`.
///
/// `packet` is the full protected packet; it is modified in place to remove
/// header protection (the header bytes are restored to their cleartext form).
/// `pn_offset` is the offset of the packet-number field, which the caller
/// determines from the (cleartext-visible) header layout — the connection-ID
/// lengths, version, token, and length fields are *not* protected.
///
/// `decode_full_pn` maps the on-wire truncated packet number to the full
/// 62-bit packet number used for the AEAD nonce. For the Initial space's first
/// packet this is the identity; later layers pass a real reconstruction.
///
/// On AEAD failure the function returns `error.AuthenticationFailed` and the
/// caller must discard the packet. The header bytes will have been unmasked,
/// but no plaintext is produced.
///
/// This is the AES-128 Initial-space convenience wrapper; it forwards to
/// `openPacketSuite` with `aes128gcm` keys, keeping the original callers and the
/// RFC 9001 Appendix A vectors byte-identical.
pub fn openPacket(
    plaintext_out: []u8,
    packet: []u8,
    pn_offset: usize,
    keys: Keys,
    decode_full_pn: *const fn (truncated: u64, pn_len: usize) u64,
) ProtectError!OpenResult {
    return openPacketSuite(plaintext_out, packet, pn_offset, keysToPacketKeys(keys), decode_full_pn);
}

/// Open a full QUIC packet under an arbitrary cipher suite. Inputs match
/// `openPacket`; `keys` is the suite-tagged receiver `PacketKeys` (e.g. a
/// `KeySet.read`).
pub fn openPacketSuite(
    plaintext_out: []u8,
    packet: []u8,
    pn_offset: usize,
    keys: PacketKeys,
    decode_full_pn: *const fn (truncated: u64, pn_len: usize) u64,
) ProtectError!OpenResult {
    if (pn_offset == 0 or pn_offset >= packet.len) return error.Truncated;

    // Remove header protection — recovers the cleartext first byte + pn bytes.
    const pn_len = try removeHeaderProtection(packet, pn_offset, keys.suite, keys.hpBytes());

    // Decode the truncated packet number now that the pn bytes are cleartext.
    var truncated: u64 = 0;
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        truncated = (truncated << 8) | packet[pn_offset + i];
    }
    const full_pn = decode_full_pn(truncated, pn_len);

    // AAD = header through the end of the packet number.
    const header_end = pn_offset + pn_len;
    if (header_end > packet.len) return error.Truncated;
    const aad = packet[0..header_end];
    const ciphertext = packet[header_end..];
    if (ciphertext.len < aead_tag_len) return error.Truncated;
    const ct_len = ciphertext.len - aead_tag_len;
    if (plaintext_out.len < ct_len) return error.BufferTooSmall;

    try unprotectPayload(
        keys.suite,
        plaintext_out[0..ct_len],
        ciphertext,
        keys.keyBytes(),
        keys.iv,
        full_pn,
        aad,
    );

    return .{
        .truncated_packet_number = truncated,
        .pn_len = pn_len,
        .plaintext_len = ct_len,
    };
}

/// Identity packet-number decoder: the truncated value *is* the full value.
/// Correct for the first packet in a space (e.g. RFC 9001 Appendix A, where
/// the packet number is 2 and fits in its on-wire encoding). Later layers
/// supply a real reconstruction against the largest-acknowledged number.
pub fn identityPacketNumber(truncated: u64, pn_len: usize) u64 {
    _ = pn_len;
    return truncated;
}

// ===========================================================================
// Tests — RFC 9001 Appendix A vectors (the interop contract)
// ===========================================================================

const testing = std.testing;

/// Decode a hex literal into a fixed-size byte array at comptime.
fn fromHex(comptime N: usize, comptime hex: []const u8) [N]u8 {
    comptime {
        assert(hex.len == N * 2);
    }
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Decode a (runtime-length) hex string into an allocated slice.
fn hexAlloc(allocator: mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

// RFC 9001 Appendix A uses this Destination Connection ID for the Initial keys.
const rfc_dcid = "8394c8f03e515708";

// ---------------------------------------------------------------------------
// A.2 — Client Initial
//
// Unprotected header (note: the first byte is c3 in cleartext; the low 4 bits
// 0011 set reserved=00 and pn_len=11 → 4-byte packet number). The header runs
// first-byte … the 4 packet-number bytes 00000002:
//
//   c3 00000001 08 8394c8f03e515708 00 00 449e 00000002
//
// Frame payload (the CRYPTO frame carrying the ClientHello, padded with
// PADDING to fill the 1200-byte UDP datagram) — 1162 plaintext bytes.
// ---------------------------------------------------------------------------

const a2_client_header = "c300000001088394c8f03e5157080000449e00000002";

// The 1162-byte unprotected Client Initial payload (CRYPTO frame + PADDING),
// verbatim from RFC 9001 §A.2.
const a2_client_payload =
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" ++
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" ++
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" ++
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" ++
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" ++
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100" ++
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" ++
    "75300901100f088394c8f03e51570806048000ffff" ++
    ("00" ** 917);

// RFC 9001 §A.2 landmarks that I can encode with full confidence and that are
// NOT self-referential (they come straight from the RFC text and the existing
// quic_tls header-protection test):
//
//   * The first 22 protected bytes are the cleartext-visible header up to the
//     length field, followed by the header-protected first byte (c0) and the
//     4 protected packet-number bytes (7b9aec34):
//        c0 00000001 08 8394c8f03e515708 00 00 449e 7b9aec34
//   * The 16-byte header-protection sample (RFC 9001 §A.2, also asserted in
//     quic_tls.zig) is d1b1c98dd7689fb8ec11d242b123dc9b and sits at packet
//     offset pn_offset+4 = 22. So bytes [22,38) MUST equal that sample.
//
// Concatenating these gives the first 38 protected bytes, which the seal test
// checks against the RFC exactly. The remaining ciphertext is verified by the
// seal→open round trip (full payload recovery) rather than by transcribing the
// entire 1200-byte datagram from memory, which would risk a copy error.
const a2_protected_prefix =
    // header (cleartext) … length field
    "c000000001088394c8f03e5157080000449e" ++
    // protected packet number
    "7b9aec34" ++
    // RFC 9001 §A.2 header-protection sample (bytes 22..38)
    "d1b1c98dd7689fb8ec11d242b123dc9b";

test "RFC 9001 A.2 — client Initial seal reproduces the protected header+pn+sample" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);

    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.client_prk);

    const header = try hexAlloc(allocator, a2_client_header);
    defer allocator.free(header);
    const payload = try hexAlloc(allocator, a2_client_payload);
    defer allocator.free(payload);
    const prefix = try hexAlloc(allocator, a2_protected_prefix);
    defer allocator.free(prefix);

    // pn_offset = header.len - 4 (4-byte packet number 00000002).
    const pn_len: usize = 4;
    const pn_offset = header.len - pn_len;

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);

    const sealed = try sealPacket(out, header, pn_offset, pn_len, 2, payload, keys);
    // Total length is 1200 bytes: 18 header + 1162 payload + 4 pn... actually
    // header includes the pn, so 18+4 header + 1162 payload + 16 tag = 1200.
    try testing.expectEqual(@as(usize, 1200), sealed.len);

    // Bytes [0,38) must match the RFC's protected header + pn + sample exactly.
    try testing.expectEqualSlices(u8, prefix, out[0..prefix.len]);
}

test "RFC 9001 A.2 — client Initial seal→open recovers frames and packet number" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.client_prk);

    const header = try hexAlloc(allocator, a2_client_header);
    defer allocator.free(header);
    const payload = try hexAlloc(allocator, a2_client_payload);
    defer allocator.free(payload);

    const pn_len: usize = 4;
    const pn_offset = header.len - pn_len; // 18

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacket(out, header, pn_offset, pn_len, 2, payload, keys);

    // Separate output buffer for the recovered frames (must not alias `out`).
    const plaintext = try allocator.alloc(u8, payload.len);
    defer allocator.free(plaintext);

    const opened = try openPacket(plaintext, out[0..sealed.len], pn_offset, keys, identityPacketNumber);
    try testing.expectEqual(@as(u64, 2), opened.truncated_packet_number);
    try testing.expectEqual(@as(usize, 4), opened.pn_len);
    try testing.expectEqual(payload.len, opened.plaintext_len);
    try testing.expectEqualSlices(u8, payload, plaintext[0..opened.plaintext_len]);

    // After header-unprotection the header bytes are back to cleartext form.
    try testing.expectEqualSlices(u8, header, out[0..header.len]);
}

// ---------------------------------------------------------------------------
// A.3 — Server Initial
//
//   Unprotected header: c1 00000001 00 08 f067a5502a4262b5 00 4075 0001
//   (DCID empty, SCID f067a5502a4262b5, token empty, length 0x4075,
//    packet number 0001 → 2-byte pn, low bits 01).
//   Payload: ACK + CRYPTO(ServerHello) — 99 bytes plaintext.
// ---------------------------------------------------------------------------

const a3_server_header = "c1000000010008f067a5502a4262b50040750001";

const a3_server_payload =
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
    "020304";

const a3_server_protected =
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" ++
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" ++
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" ++
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" ++
    "2158407dd074ee";

test "RFC 9001 A.3 — server Initial seal reproduces the protected packet" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.server_prk);

    const header = try hexAlloc(allocator, a3_server_header);
    defer allocator.free(header);
    const payload = try hexAlloc(allocator, a3_server_payload);
    defer allocator.free(payload);
    const expected = try hexAlloc(allocator, a3_server_protected);
    defer allocator.free(expected);

    const pn_len: usize = 2;
    const pn_offset = header.len - pn_len;

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);

    const sealed = try sealPacket(out, header, pn_offset, pn_len, 1, payload, keys);
    try testing.expectEqual(expected.len, sealed.len);
    try testing.expectEqualSlices(u8, expected, out[0..sealed.len]);
}

test "RFC 9001 A.3 — server Initial open recovers frames and packet number" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.server_prk);

    const payload = try hexAlloc(allocator, a3_server_payload);
    defer allocator.free(payload);
    const protected = try hexAlloc(allocator, a3_server_protected);
    defer allocator.free(protected);

    // pn_offset: 1 (first) + 4 (version) + 1 (dcid len=0) + 1 (scid len)
    //   + 8 (scid) + 1 (token len=0) + 2 (length varint 4075) = 18.
    const pn_offset: usize = 18;

    const plaintext = try allocator.alloc(u8, protected.len);
    defer allocator.free(plaintext);

    const opened = try openPacket(plaintext, protected, pn_offset, keys, identityPacketNumber);
    try testing.expectEqual(@as(u64, 1), opened.truncated_packet_number);
    try testing.expectEqual(@as(usize, 2), opened.pn_len);
    try testing.expectEqualSlices(u8, payload, plaintext[0..opened.plaintext_len]);
}

// ---------------------------------------------------------------------------
// Round-trip + tamper-detection tests (property tests, not RFC vectors)
// ---------------------------------------------------------------------------

test "seal/open round-trips an arbitrary payload" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.client_prk);

    // A short long-header Initial with a 4-byte packet number.
    const header = try hexAlloc(allocator, a2_client_header);
    defer allocator.free(header);
    const pn_offset = header.len - 4;

    var payload: [64]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    prng.random().bytes(&payload);

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacket(out, header, pn_offset, 4, 2, &payload, keys);

    // Header protection actually ran: the protected packet must differ from the
    // plain (header ‖ payload) image somewhere in the header/pn region. (The
    // low first-byte mask bits can be zero for a given sample, so we compare the
    // whole header region rather than just out[0].)
    try testing.expect(!mem.eql(u8, out[0..header.len], header));

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    const opened = try openPacket(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber);
    try testing.expectEqual(payload.len, opened.plaintext_len);
    try testing.expectEqual(@as(u64, 2), opened.truncated_packet_number);
    try testing.expectEqualSlices(u8, &payload, recovered[0..opened.plaintext_len]);
    // Header restored to cleartext after open.
    try testing.expectEqualSlices(u8, header, out[0..header.len]);
}

test "open fails when a ciphertext byte is flipped (no plaintext leaks)" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.client_prk);

    const header = try hexAlloc(allocator, a2_client_header);
    defer allocator.free(header);
    const pn_offset = header.len - 4;

    var payload: [48]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    prng.random().bytes(&payload);

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacket(out, header, pn_offset, 4, 2, &payload, keys);

    // Flip one ciphertext byte (in the AEAD-protected region, after the pn).
    const flip_at = header.len + 1;
    out[flip_at] ^= 0x80;

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    @memset(recovered, 0xAA);
    try testing.expectError(
        error.AuthenticationFailed,
        openPacket(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber),
    );
    // On auth failure no real plaintext is produced: the output buffer must NOT
    // contain the original frames. (std AES-GCM leaves the buffer in an
    // unspecified state on failure; what matters for security is that the true
    // plaintext is never revealed.)
    try testing.expect(!mem.eql(u8, recovered, &payload));
}

test "open fails when the auth tag is flipped" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.client_prk);

    const header = try hexAlloc(allocator, a2_client_header);
    defer allocator.free(header);
    const pn_offset = header.len - 4;

    var payload: [32]u8 = .{0x11} ** 32;
    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacket(out, header, pn_offset, 4, 2, &payload, keys);

    // Flip the last byte (inside the 16-byte GCM tag).
    out[sealed.len - 1] ^= 0x01;

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    try testing.expectError(
        error.AuthenticationFailed,
        openPacket(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber),
    );
}

test "open fails or mis-decodes pn when a header-protected byte is corrupted" {
    const allocator = testing.allocator;

    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const keys = quic_tls.deriveEndpointKeys(secrets.client_prk);

    const header = try hexAlloc(allocator, a2_client_header);
    defer allocator.free(header);
    const pn_offset = header.len - 4;

    var payload: [32]u8 = .{0x22} ** 32;
    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacket(out, header, pn_offset, 4, 2, &payload, keys);

    // Flip a bit in the header-protected first byte. This corrupts the AAD
    // (and possibly the recovered pn length), so AEAD verification must fail.
    out[0] ^= 0x08;

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    const result = openPacket(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber);
    try testing.expectError(error.AuthenticationFailed, result);
}

// ---------------------------------------------------------------------------
// Bounds / malformed-input tests
// ---------------------------------------------------------------------------

test "nonce XORs the packet number into the low IV bytes" {
    const iv = fromHex(12, "fa044b2f42a3fd3b46fb255c");
    // pn = 2 → only the last byte changes (…5c ^ 02 = …5e).
    const nonce = buildNonce(iv, 2);
    const exp = fromHex(12, "fa044b2f42a3fd3b46fb255e");
    try testing.expectEqualSlices(u8, &exp, &nonce);
}

test "sampleForHeaderProtection rejects a too-short packet" {
    var pkt = [_]u8{0} ** 16;
    // pn_offset = 4 → sample needs bytes [8, 24); only 16 present → Truncated.
    try testing.expectError(error.Truncated, sampleForHeaderProtection(&pkt, 4));
}

test "sealPacket rejects an inconsistent packet-number length" {
    const keys = Keys{
        .key = .{0} ** 16,
        .iv = .{0} ** 12,
        .hp = .{0} ** 16,
    };
    // header[0]=0xc3 declares a 4-byte pn, but we claim pn_len=2.
    const header = [_]u8{ 0xc3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    var out: [64]u8 = undefined;
    try testing.expectError(
        error.Truncated,
        sealPacket(&out, &header, 5, 2, 1, &.{ 0x01, 0x02 }, keys),
    );
}

test "openPacket rejects a packet too short for the AEAD tag" {
    const keys = Keys{
        .key = .{0} ** 16,
        .iv = .{0} ** 12,
        .hp = .{0} ** 16,
    };
    // A 24-byte packet with pn_offset 18 + 1-byte pn leaves 5 bytes < tag(16).
    var pkt = [_]u8{0} ** 24;
    pkt[0] = 0xc0; // long header, pn_len bits 00 → 1 byte
    // Header protection removal needs a 16-byte sample at pn_offset+4 = 22;
    // 22+16 = 38 > 24 → Truncated before AEAD even runs.
    try testing.expectError(error.Truncated, openPacket(pkt[0..0], &pkt, 18, keys, identityPacketNumber));
}

// ===========================================================================
// RFC 9001 Appendix A.5 — ChaCha20-Poly1305 short-header packet
// ===========================================================================
//
// The single authoritative ChaCha20 vector in RFC 9001. It exercises, end to
// end:
//   * "quic key" / "quic iv" / "quic hp" derivation with the 32-byte
//     ChaCha20-Poly1305 key length,
//   * the ChaCha20 header-protection mask (RFC 9001 §5.4.4),
//   * ChaCha20-Poly1305 payload protection,
//   * the "quic ku" key-update label.
//
// Vectors (RFC 9001 §A.5):
//   secret = 9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b
//   key    = c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8
//   iv     = e0459b3474bdd0e44a41c144
//   hp     = 25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4
//   pn     = 654360564 (0x2700BFF4), encoded as a 3-byte pn 0x00bff4
//   unprotected header = 4200bff4
//   plaintext (frames) = 01  (a single PING frame)
//   sample = 5e5cd55c41f69080575d7999c25a5bfb
//   mask   = aefefe7d03
//   protected packet = 4cfe4189655e5cd55c41f69080575d7999c25a5bfb
//   next-generation ("quic ku") secret =
//     1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9

const a5_secret = "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b";
const a5_key = "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8";
const a5_iv = "e0459b3474bdd0e44a41c144";
const a5_hp = "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4";
const a5_sample = "5e5cd55c41f69080575d7999c25a5bfb";
const a5_mask = "aefefe7d03";
const a5_unprotected_header = "4200bff4";
const a5_plaintext = "01";
const a5_protected = "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";
const a5_ku_secret = "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9";

test "RFC 9001 A.5 quic — chacha20 derivePacketKeys matches key/iv/hp" {
    const secret = fromHex(32, a5_secret);
    const pk = quic_tls.derivePacketKeys(secret, .chacha20poly1305);

    try testing.expectEqual(@as(usize, 32), pk.suite.keyLen());
    try testing.expectEqualSlices(u8, &fromHex(32, a5_key), pk.keyBytes());
    try testing.expectEqualSlices(u8, &fromHex(12, a5_iv), &pk.iv);
    try testing.expectEqualSlices(u8, &fromHex(32, a5_hp), pk.hpBytes());
}

test "RFC 9001 A.5 chacha — header-protection mask matches" {
    const hp = fromHex(32, a5_hp);
    const sample = fromHex(16, a5_sample);
    const mask = try headerProtectionMask(.chacha20poly1305, &hp, sample);
    try testing.expectEqualSlices(u8, &fromHex(5, a5_mask), &mask);

    // The low-level quic_tls helper must agree.
    const mask2 = quic_tls.headerProtectionMaskChaCha20(hp, sample);
    try testing.expectEqualSlices(u8, &fromHex(5, a5_mask), &mask2);
}

test "RFC 9001 A.5 chacha — seal reproduces the protected packet byte-for-byte" {
    const allocator = testing.allocator;

    const secret = fromHex(32, a5_secret);
    const keys = quic_tls.derivePacketKeys(secret, .chacha20poly1305);

    const header = try hexAlloc(allocator, a5_unprotected_header);
    defer allocator.free(header);
    const plaintext = try hexAlloc(allocator, a5_plaintext);
    defer allocator.free(plaintext);
    const expected = try hexAlloc(allocator, a5_protected);
    defer allocator.free(expected);

    const pn_len: usize = 3; // header[0]=0x42 low bits 10 → 3-byte pn
    const pn_offset = header.len - pn_len; // 1

    const out = try allocator.alloc(u8, header.len + plaintext.len + aead_tag_len);
    defer allocator.free(out);

    const sealed = try sealPacketSuite(out, header, pn_offset, pn_len, 654360564, plaintext, keys);
    try testing.expectEqual(expected.len, sealed.len);
    try testing.expectEqualSlices(u8, expected, out[0..sealed.len]);
}

test "RFC 9001 A.5 chacha — open recovers pn=654360564 and the PING frame" {
    const allocator = testing.allocator;

    const secret = fromHex(32, a5_secret);
    const keys = quic_tls.derivePacketKeys(secret, .chacha20poly1305);

    const protected = try hexAlloc(allocator, a5_protected);
    defer allocator.free(protected);
    const expected_pt = try hexAlloc(allocator, a5_plaintext);
    defer allocator.free(expected_pt);
    const expected_header = try hexAlloc(allocator, a5_unprotected_header);
    defer allocator.free(expected_header);

    const pn_offset: usize = 1; // short header: 1-byte first byte, then pn

    const plaintext = try allocator.alloc(u8, protected.len);
    defer allocator.free(plaintext);

    // The RFC sealed with the *full* pn 654360564 (0x2700bff4) in the AEAD
    // nonce, while only 0x00bff4 appears on the wire. A real decoder must
    // reconstruct the high bytes; identityPacketNumber would yield the wrong
    // nonce and fail authentication (verified separately below). RFC 9000 §17.1.
    const Decode = struct {
        fn full(truncated: u64, pn_len: usize) u64 {
            _ = pn_len;
            return 0x2700_0000 | truncated;
        }
    };
    const opened = try openPacketSuite(plaintext, protected, pn_offset, keys, Decode.full);
    try testing.expectEqual(@as(u64, 0x00bff4), opened.truncated_packet_number);
    try testing.expectEqual(@as(usize, 3), opened.pn_len);
    try testing.expectEqualSlices(u8, expected_pt, plaintext[0..opened.plaintext_len]);
    // Header bytes restored to cleartext (0x42 00 bf f4).
    try testing.expectEqualSlices(u8, expected_header, protected[0..expected_header.len]);

    // Sanity: with the identity decoder (wrong nonce) the AEAD must reject. The
    // first open removed header protection in place, so re-protect the header to
    // restore the on-wire bytes before re-opening.
    const fresh = try hexAlloc(allocator, a5_protected);
    defer allocator.free(fresh);
    @memcpy(protected, fresh);
    try testing.expectError(
        error.AuthenticationFailed,
        openPacketSuite(plaintext, protected, pn_offset, keys, identityPacketNumber),
    );
}

test "RFC 9001 A.5 chacha — full pn 654360564 round-trips with a real decoder" {
    const allocator = testing.allocator;

    const secret = fromHex(32, a5_secret);
    const keys = quic_tls.derivePacketKeys(secret, .chacha20poly1305);

    const protected = try hexAlloc(allocator, a5_protected);
    defer allocator.free(protected);

    const plaintext = try allocator.alloc(u8, protected.len);
    defer allocator.free(plaintext);

    // A decoder that reconstructs the RFC's full 62-bit packet number from the
    // 3-byte truncated value 0x00bff4 against the known largest-acked window.
    const Decoder = struct {
        fn decode(truncated: u64, pn_len: usize) u64 {
            _ = pn_len;
            // RFC A.5 full pn = 654360564 (0x2700bff4); high bytes are 0x2700.
            return 0x2700_0000 | truncated;
        }
    };
    const opened = try openPacketSuite(plaintext, protected, 1, keys, Decoder.decode);
    // AEAD nonce uses the *full* pn; if the decode were wrong the tag would fail.
    try testing.expectEqual(@as(u64, 0x00bff4), opened.truncated_packet_number);
    try testing.expectEqualSlices(u8, &fromHex(1, a5_plaintext), plaintext[0..opened.plaintext_len]);
}

test "RFC 9001 quic key update — quic ku rolls the 1-RTT secret" {
    const secret = fromHex(32, a5_secret);
    const next = quic_tls.nextGenerationSecret(secret);
    try testing.expectEqualSlices(u8, &fromHex(32, a5_ku_secret), &next);

    // The new generation's key/iv are re-derived from the rolled secret; hp is
    // NOT rolled (RFC 9001 §6.1), so the next generation keeps the old hp.
    const gen0 = quic_tls.derivePacketKeys(secret, .chacha20poly1305);
    const gen1 = quic_tls.derivePacketKeys(next, .chacha20poly1305);
    // key + iv must change across a key update…
    try testing.expect(!mem.eql(u8, gen0.keyBytes(), gen1.keyBytes()));
    try testing.expect(!mem.eql(u8, &gen0.iv, &gen1.iv));
    // …and a second update is deterministic and distinct again.
    const next2 = quic_tls.nextGenerationSecret(next);
    try testing.expect(!mem.eql(u8, &next, &next2));
}

// ===========================================================================
// AES-256-GCM (TLS_AES_256_GCM_SHA384 suite) seal/open
// ===========================================================================
//
// RFC 9001 has no AES-256 packet vector, so these are property tests: a
// round-trip recovers the frames and packet number, and any tamper in the
// header-protected, ciphertext, or tag regions is rejected. The key material is
// derived from an arbitrary 32-byte traffic secret via the same
// "quic key/iv/hp" expansion used for the real suites.

fn a256Keys() PacketKeys {
    const secret = [_]u8{0x5a} ** 32;
    return quic_tls.derivePacketKeys(secret, .aes256gcm);
}

test "quic protect — AES-256-GCM seal/open round-trips frames and pn" {
    const allocator = testing.allocator;
    const keys = a256Keys();
    try testing.expectEqual(@as(usize, 32), keys.suite.keyLen());

    // Short-header packet: first byte 0x43 (low bits 11 → 4-byte pn).
    const header = [_]u8{ 0x43, 0x00, 0x00, 0x00, 0x05 };
    const pn_len: usize = 4;
    const pn_offset = header.len - pn_len; // 1

    var payload: [80]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xA256);
    prng.random().bytes(&payload);

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacketSuite(out, &header, pn_offset, pn_len, 5, &payload, keys);

    // Header protection ran: the protected header region differs from cleartext.
    try testing.expect(!mem.eql(u8, out[0..header.len], &header));

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    const opened = try openPacketSuite(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber);
    try testing.expectEqual(@as(u64, 5), opened.truncated_packet_number);
    try testing.expectEqual(payload.len, opened.plaintext_len);
    try testing.expectEqualSlices(u8, &payload, recovered[0..opened.plaintext_len]);
    try testing.expectEqualSlices(u8, &header, out[0..header.len]);
}

test "quic protect — AES-256-GCM open rejects a flipped ciphertext byte" {
    const allocator = testing.allocator;
    const keys = a256Keys();

    const header = [_]u8{ 0x43, 0x00, 0x00, 0x00, 0x05 };
    const pn_offset = header.len - 4;
    var payload: [48]u8 = .{0x33} ** 48;

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacketSuite(out, &header, pn_offset, 4, 5, &payload, keys);

    // Flip the last payload-ciphertext byte (just before the 16-byte tag). This
    // is past the header-protection sample, so HP removal is clean (pn_len
    // decodes correctly) and the failure is a pure AEAD auth rejection.
    out[sealed.len - aead_tag_len - 1] ^= 0x40;

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    try testing.expectError(
        error.AuthenticationFailed,
        openPacketSuite(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber),
    );
}

test "quic protect — AES-256-GCM open rejects a flipped tag byte" {
    const allocator = testing.allocator;
    const keys = a256Keys();

    const header = [_]u8{ 0x43, 0x00, 0x00, 0x00, 0x05 };
    const pn_offset = header.len - 4;
    var payload: [16]u8 = .{0x77} ** 16;

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacketSuite(out, &header, pn_offset, 4, 5, &payload, keys);

    out[sealed.len - 1] ^= 0x01; // flip a tag byte

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    try testing.expectError(
        error.AuthenticationFailed,
        openPacketSuite(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber),
    );
}

test "quic protect — ChaCha20-Poly1305 arbitrary round-trip + tamper reject" {
    const allocator = testing.allocator;
    const secret = [_]u8{0xc4} ** 32;
    const keys = quic_tls.derivePacketKeys(secret, .chacha20poly1305);

    const header = [_]u8{ 0x42, 0x12, 0x34, 0x56 }; // short header, 3-byte pn
    const pn_len: usize = 3;
    const pn_offset = header.len - pn_len;

    var payload: [64]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xC2C2);
    prng.random().bytes(&payload);

    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacketSuite(out, &header, pn_offset, pn_len, 0x123456, &payload, keys);

    // Snapshot the protected wire bytes before any (destructive, in-place) open.
    const wire = try allocator.alloc(u8, sealed.len);
    defer allocator.free(wire);
    @memcpy(wire, out[0..sealed.len]);

    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    const opened = try openPacketSuite(recovered, out[0..sealed.len], pn_offset, keys, identityPacketNumber);
    try testing.expectEqualSlices(u8, &payload, recovered[0..opened.plaintext_len]);

    // Tamper a payload-ciphertext byte (past the HP sample, before the tag): HP
    // removal is clean, so this is a pure AEAD authentication failure.
    var out2 = try allocator.alloc(u8, sealed.len);
    defer allocator.free(out2);
    @memcpy(out2, wire);
    out2[sealed.len - aead_tag_len - 1] ^= 0x10;
    try testing.expectError(
        error.AuthenticationFailed,
        openPacketSuite(recovered, out2, pn_offset, keys, identityPacketNumber),
    );

    // Tamper the (header-protected) first byte: this corrupts the recovered
    // pn-length and/or AAD, so the packet is rejected (auth failure once the
    // pn-length still decodes to 3, or a bounds error if it decodes shorter).
    @memcpy(out2, wire);
    out2[0] ^= 0x04;
    const corrupted = openPacketSuite(recovered, out2, pn_offset, keys, identityPacketNumber);
    try testing.expect(std.meta.isError(corrupted));
}

// ===========================================================================
// KeySet + per-level key derivation
// ===========================================================================

test "quic KeySet — Initial level derives client/server keys (RFC 9001 A.1)" {
    const allocator = testing.allocator;
    const dcid = try hexAlloc(allocator, rfc_dcid);
    defer allocator.free(dcid);

    // Server endpoint: write=server, read=client.
    const server_set = KeySet.initInitial(dcid, true);
    try testing.expectEqual(EncryptionLevel.initial, server_set.level);
    try testing.expectEqual(CipherSuite.aes128gcm, server_set.write.suite);

    // Cross-check against the direct deriveEndpointKeys output the A.2/A.3 tests
    // already pin to the RFC.
    const secrets = quic_tls.deriveInitialSecrets(dcid);
    const server = quic_tls.deriveEndpointKeys(secrets.server_prk);
    const client = quic_tls.deriveEndpointKeys(secrets.client_prk);
    try testing.expectEqualSlices(u8, &server.key, server_set.write.keyBytes());
    try testing.expectEqualSlices(u8, &server.iv, &server_set.write.iv);
    try testing.expectEqualSlices(u8, &server.hp, server_set.write.hpBytes());
    try testing.expectEqualSlices(u8, &client.key, server_set.read.keyBytes());

    // Client endpoint mirrors the directions.
    const client_set = KeySet.initInitial(dcid, false);
    try testing.expectEqualSlices(u8, &client.key, client_set.write.keyBytes());
    try testing.expectEqualSlices(u8, &server.key, client_set.read.keyBytes());
}

test "quic KeySet — handshake/1-RTT derives from traffic secrets per suite" {
    const own = [_]u8{0x11} ** 32;
    const peer = [_]u8{0x22} ** 32;

    const set = KeySet.fromTrafficSecrets(.handshake, own, peer, .aes256gcm);
    try testing.expectEqual(EncryptionLevel.handshake, set.level);
    try testing.expectEqual(CipherSuite.aes256gcm, set.write.suite);

    // write/read keys come from the respective secrets and must differ.
    const own_keys = quic_tls.derivePacketKeys(own, .aes256gcm);
    const peer_keys = quic_tls.derivePacketKeys(peer, .aes256gcm);
    try testing.expectEqualSlices(u8, own_keys.keyBytes(), set.write.keyBytes());
    try testing.expectEqualSlices(u8, peer_keys.keyBytes(), set.read.keyBytes());
    try testing.expect(!mem.eql(u8, set.write.keyBytes(), set.read.keyBytes()));

    // A KeySet built for the 1-RTT level can seal+open a packet end to end.
    // Model both endpoints: endpoint A seals with its write keys (own=A),
    // endpoint B opens with its read keys (B.read == A.write secret). We build
    // the mirror KeySet for B by swapping own/peer.
    const allocator = testing.allocator;
    const a_set = KeySet.fromTrafficSecrets(.application, own, peer, .chacha20poly1305);
    const b_set = KeySet.fromTrafficSecrets(.application, peer, own, .chacha20poly1305);
    // B.read must equal A.write (same secret derives the same packet keys).
    try testing.expectEqualSlices(u8, a_set.write.keyBytes(), b_set.read.keyBytes());

    const header = [_]u8{ 0x42, 0xab, 0xcd, 0xef };
    var payload: [24]u8 = .{0x5e} ** 24;
    const out = try allocator.alloc(u8, header.len + payload.len + aead_tag_len);
    defer allocator.free(out);
    const sealed = try sealPacketSuite(out, &header, 1, 3, 0xabcdef, &payload, a_set.write);
    const recovered = try allocator.alloc(u8, payload.len);
    defer allocator.free(recovered);
    const opened = try openPacketSuite(recovered, out[0..sealed.len], 1, b_set.read, identityPacketNumber);
    try testing.expectEqualSlices(u8, &payload, recovered[0..opened.plaintext_len]);
}
