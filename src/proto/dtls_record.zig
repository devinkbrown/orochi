// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.3 record layer (RFC 9147).
//!
//! Covers the DTLSCiphertext unified header (connection-id-less variant),
//! sequence-number mask application (analogous to QUIC header protection),
//! a 64-slot sliding-window anti-replay filter, and AEAD seal/open using
//! ChaCha20-Poly1305 with the per-record nonce derived as (write_iv XOR seq).
//!
//! Only `std` and the HKDF primitive (`hash.zig`) are imported — the latter for
//! the RFC 9147 §4.2.3 traffic-key / record-number-encryption key derivation.
//! No heap allocations.
const std = @import("std");
const hash = @import("../crypto/hash.zig");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum serialised header size (16-bit seq + length field present).
pub const max_header_len: usize = 5;

/// ChaCha20-Poly1305 tag length.
pub const tag_len: usize = 16;

/// Anti-replay window width in bits (must be a multiple of 64).
pub const window_bits: usize = 64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    BufferTooShort,
    InvalidFixedBit,
    Replay,
    TooOld,
    AuthenticationFailed,
    PlaintextTooShort,
};

pub const EncodeError = error{
    BufferTooSmall,
    SeqTooLarge,
};

// ---------------------------------------------------------------------------
// Header types
// ---------------------------------------------------------------------------

/// Which form of sequence number is carried in the header.
pub const SeqLen = enum(u1) {
    /// Only the low 8 bits of the epoch-scoped sequence number.
    short = 0,
    /// The low 16 bits of the epoch-scoped sequence number.
    long = 1,
};

/// The DTLSCiphertext unified header (RFC 9147 §4).
///
/// Bit layout of the first byte (B0):
///
///   7   6   5   4   3   2   1   0
///  ┌───┬───┬───┬───┬───┬───┬───┬───┐
///  │ 0 │ 0 │ 1 │ C │ S │ L │epoch L│
///  └───┴───┴───┴───┴───┴───┴───┴───┘
///
///  Bits [7:5] fixed pattern = 0b001 (distinguishes from TLS/DTLS 1.2).
///  Bit  4 (C): Connection ID present — always 0 in the CID-less variant.
///  Bit  3 (S): Sequence-number length — 0 = 8-bit, 1 = 16-bit.
///  Bit  2 (L): Length field present — 0 = record extends to end of datagram.
///  Bits [1:0]: Low 2 bits of the current epoch.
pub const Header = struct {
    /// Low 2 bits of the DTLS epoch (bits 1–0 of B0).
    epoch_low: u2,
    /// Full epoch-scoped sequence number (only low 8 or 16 bits are encoded).
    seq: u64,
    /// How many bits of `seq` go on the wire.
    seq_len: SeqLen,
    /// Whether a 2-byte length field is appended after the sequence number.
    length_present: bool,
    /// Ciphertext (or plaintext before sealing) length — only meaningful when
    /// `length_present` is true; otherwise the record runs to end-of-datagram.
    record_len: u16,

    /// Number of bytes this header occupies on the wire.
    pub fn wireLen(h: Header) usize {
        var n: usize = 1; // B0
        n += if (h.seq_len == .long) @as(usize, 2) else @as(usize, 1);
        if (h.length_present) n += 2;
        return n;
    }

    /// Encode the header into `buf`.  Returns the sub-slice written.
    pub fn encode(h: Header, buf: []u8) EncodeError![]u8 {
        const wl = h.wireLen();
        if (buf.len < wl) return EncodeError.BufferTooSmall;

        // Validate seq fits in the chosen field width.
        if (h.seq_len == .short and h.seq > 0xFF) return EncodeError.SeqTooLarge;
        if (h.seq_len == .long and h.seq > 0xFFFF) return EncodeError.SeqTooLarge;

        // B0: fixed 0b001_0 prefix, C=0 (no CID), S, L, epoch_low[1:0]
        var b0: u8 = 0b0010_0000; // fixed bits [7:5] = 001, bit4 (C) = 0
        if (h.seq_len == .long) b0 |= 0b0000_1000; // S bit
        if (h.length_present) b0 |= 0b0000_0100; // L bit
        b0 |= @as(u8, h.epoch_low); // bits [1:0]

        buf[0] = b0;
        var off: usize = 1;

        // Sequence number (big-endian, truncated to 8 or 16 bits).
        switch (h.seq_len) {
            .short => {
                buf[off] = @truncate(h.seq);
                off += 1;
            },
            .long => {
                buf[off] = @truncate(h.seq >> 8);
                buf[off + 1] = @truncate(h.seq);
                off += 2;
            },
        }

        // Optional length field.
        if (h.length_present) {
            buf[off] = @truncate(h.record_len >> 8);
            buf[off + 1] = @truncate(h.record_len);
        }

        return buf[0..wl];
    }

    /// Decode a header from `buf`.  Returns the header and the number of
    /// bytes consumed.
    pub fn decode(buf: []const u8) DecodeError!struct { hdr: Header, consumed: usize } {
        if (buf.len < 1) return DecodeError.BufferTooShort;

        const b0 = buf[0];

        // Fixed bits [7:5] must be 0b001.
        if ((b0 & 0b1110_0000) != 0b0010_0000) return DecodeError.InvalidFixedBit;

        const seq_is_long = (b0 & 0b0000_1000) != 0;
        const length_present = (b0 & 0b0000_0100) != 0;
        const epoch_low: u2 = @truncate(b0 & 0b0000_0011);

        const seq_bytes: usize = if (seq_is_long) 2 else 1;
        const extra: usize = seq_bytes + (if (length_present) @as(usize, 2) else 0);
        if (buf.len < 1 + extra) return DecodeError.BufferTooShort;

        var off: usize = 1;
        const seq: u64 = blk: {
            if (seq_is_long) {
                const hi: u64 = buf[off];
                const lo: u64 = buf[off + 1];
                off += 2;
                break :blk (hi << 8) | lo;
            } else {
                const v: u64 = buf[off];
                off += 1;
                break :blk v;
            }
        };

        var record_len: u16 = 0;
        if (length_present) {
            record_len = (@as(u16, buf[off]) << 8) | @as(u16, buf[off + 1]);
            off += 2;
        }

        return .{
            .hdr = .{
                .epoch_low = epoch_low,
                .seq = seq,
                .seq_len = if (seq_is_long) .long else .short,
                .length_present = length_present,
                .record_len = record_len,
            },
            .consumed = off,
        };
    }
};

// ---------------------------------------------------------------------------
// Sequence-number mask (header protection, analogous to QUIC)
// ---------------------------------------------------------------------------

/// Apply or remove a header-protection mask in-place on a serialised header.
///
/// The mask is XORed into:
///   • The sequence-number byte(s) (always).
///   • Bits [1:0] of B0 (the encoded epoch_low bits).
///
/// Applying the same mask a second time removes it (XOR is its own inverse).
/// The caller is responsible for deriving the mask (e.g. from a ChaCha20
/// keystream over a sample of the ciphertext, as in QUIC).
///
/// `mask` must be at least as long as the header (1 + seq_bytes).
pub fn applyMask(header_buf: []u8, mask: []const u8) void {
    std.debug.assert(header_buf.len >= 2);
    std.debug.assert(mask.len >= header_buf.len);

    // B0: only epoch_low bits [1:0] are masked.
    header_buf[0] ^= mask[0] & 0b0000_0011;

    // Sequence number byte(s).
    var i: usize = 1;
    while (i < header_buf.len) : (i += 1) {
        header_buf[i] ^= mask[i];
    }
}

// ---------------------------------------------------------------------------
// Anti-replay filter
// ---------------------------------------------------------------------------

/// Sliding-window anti-replay filter (RFC 6479 / RFC 9147 §4.5.1).
///
/// Uses a 64-bit bitmap keyed on the sequence number modulo 64.  The highest
/// seen sequence number anchors the right edge of the window; anything more
/// than 63 below it is considered too old.
pub const AntiReplay = struct {
    /// Highest sequence number seen so far (inclusive).
    top: u64 = 0,
    /// Bit i is set when (top - (63 - i)) has been received.
    /// Bit 63 always corresponds to `top` itself.
    window: u64 = 0,
    /// True once the first packet has been recorded.
    initialised: bool = false,

    /// Check whether `seq` should be accepted.
    pub fn check(ar: *const AntiReplay, seq: u64) DecodeError!void {
        if (!ar.initialised) return; // first packet always ok

        if (seq > ar.top) return; // ahead of window — ok
        const diff = ar.top - seq;
        if (diff >= window_bits) return DecodeError.TooOld;

        // seq is within [top-63, top]: check the bit.
        const bit_pos: u6 = @truncate(window_bits - 1 - diff);
        if ((ar.window >> bit_pos) & 1 == 1) return DecodeError.Replay;
    }

    /// Record `seq` as received (call only after `check` succeeds).
    pub fn record(ar: *AntiReplay, seq: u64) void {
        if (!ar.initialised or seq > ar.top) {
            if (seq > ar.top) {
                const shift = seq - ar.top;
                if (shift >= window_bits) {
                    ar.window = 0;
                } else {
                    // Right-shift: bit63 (old top) becomes bit62 (top-1 in new frame),
                    // preserving the history of seen sequence numbers.
                    ar.window >>= @truncate(shift);
                }
            }
            ar.top = seq;
            ar.initialised = true;
        }
        // Mark the bit for seq.
        const diff = ar.top - seq;
        const bit_pos: u6 = @truncate(window_bits - 1 - diff);
        ar.window |= @as(u64, 1) << bit_pos;
    }
};

// ---------------------------------------------------------------------------
// Per-record nonce derivation
// ---------------------------------------------------------------------------

/// Build the 12-byte ChaCha20-Poly1305 nonce for a record.
///
/// RFC 9147 §4.2.3: nonce = write_iv XOR left-padded(seq).
///   The sequence number is placed in the rightmost bytes of a 12-byte field,
///   zero-padded on the left, then XORed with the 12-byte write IV.
pub fn buildNonce(write_iv: [12]u8, seq: u64) [12]u8 {
    var padded = @as([12]u8, @splat(0));
    // seq big-endian in the last 8 bytes.
    padded[4] = @truncate(seq >> 56);
    padded[5] = @truncate(seq >> 48);
    padded[6] = @truncate(seq >> 40);
    padded[7] = @truncate(seq >> 32);
    padded[8] = @truncate(seq >> 24);
    padded[9] = @truncate(seq >> 16);
    padded[10] = @truncate(seq >> 8);
    padded[11] = @truncate(seq);

    var nonce: [12]u8 = undefined;
    for (&nonce, write_iv, padded) |*n, iv, p| n.* = iv ^ p;
    return nonce;
}

// ---------------------------------------------------------------------------
// AEAD record seal / open
// ---------------------------------------------------------------------------

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// Seal (encrypt + authenticate) a DTLS 1.3 record payload.
///
/// Parameters
/// ----------
/// `key`        — 32-byte ChaCha20-Poly1305 key.
/// `write_iv`   — 12-byte write IV (from key schedule).
/// `seq`        — epoch-scoped sequence number (used in nonce derivation).
/// `header_aad` — serialised DTLSCiphertext header bytes (used as AAD).
/// `plaintext`  — application data to encrypt.
/// `ciphertext` — output buffer; must be at least `plaintext.len + tag_len` bytes.
///
/// Returns the sub-slice of `ciphertext` that was written.
pub fn sealRecord(
    key: [32]u8,
    write_iv: [12]u8,
    seq: u64,
    header_aad: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
) EncodeError![]u8 {
    const out_len = plaintext.len + tag_len;
    if (ciphertext.len < out_len) return EncodeError.BufferTooSmall;

    const nonce = buildNonce(write_iv, seq);
    const ct_slice = ciphertext[0..plaintext.len];
    const tag_slice = ciphertext[plaintext.len..][0..tag_len];

    ChaCha20Poly1305.encrypt(ct_slice, tag_slice, plaintext, header_aad, nonce, key);

    return ciphertext[0..out_len];
}

/// Open (authenticate + decrypt) a DTLS 1.3 record.
///
/// Parameters
/// ----------
/// `key`        — 32-byte ChaCha20-Poly1305 key.
/// `write_iv`   — 12-byte write IV used during sealing.
/// `seq`        — epoch-scoped sequence number.
/// `header_aad` — serialised DTLSCiphertext header bytes (as AAD).
/// `ciphertext` — ciphertext || tag (at least `tag_len` bytes).
/// `plaintext`  — output buffer; must be at least `ciphertext.len - tag_len` bytes.
///
/// Returns the sub-slice of `plaintext` that was written.
pub fn openRecord(
    key: [32]u8,
    write_iv: [12]u8,
    seq: u64,
    header_aad: []const u8,
    ciphertext: []const u8,
    plaintext: []u8,
) DecodeError![]u8 {
    if (ciphertext.len < tag_len) return DecodeError.PlaintextTooShort;

    const ct_len = ciphertext.len - tag_len;
    if (plaintext.len < ct_len) return DecodeError.BufferTooShort;

    const nonce = buildNonce(write_iv, seq);
    const ct_slice = ciphertext[0..ct_len];
    const tag_slice = ciphertext[ct_len..][0..tag_len];
    const pt_slice = plaintext[0..ct_len];

    ChaCha20Poly1305.decrypt(pt_slice, ct_slice, tag_slice.*, header_aad, nonce, key) catch
        return DecodeError.AuthenticationFailed;

    return pt_slice;
}

// ---------------------------------------------------------------------------
// AES-128-GCM record seal / open (TLS_AES_128_GCM_SHA256, RFC 9147 §4.2.2)
// ---------------------------------------------------------------------------

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = std.crypto.core.aes.Aes128;

/// AES-128 key length (and, for this suite, the sn-encryption key length).
pub const aes128_key_len: usize = 16;
/// AEAD write-IV length (shared by AES-128-GCM and ChaCha20-Poly1305).
pub const iv_len: usize = 12;

comptime {
    std.debug.assert(Aes128Gcm.key_length == aes128_key_len);
    std.debug.assert(Aes128Gcm.nonce_length == iv_len);
    std.debug.assert(Aes128Gcm.tag_length == tag_len);
}

/// Seal a DTLS 1.3 record payload with AES-128-GCM. Mirrors `sealRecord` but for
/// the TLS_AES_128_GCM_SHA256 suite. `header_aad` is the unified-header bytes
/// with the sequence number in the CLEAR (record-number encryption is applied to
/// the on-wire header AFTER sealing; see `recordNumberMaskAes128`).
pub fn sealRecordAes128Gcm(
    key: [aes128_key_len]u8,
    write_iv: [iv_len]u8,
    seq: u64,
    header_aad: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
) EncodeError![]u8 {
    const out_len = plaintext.len + tag_len;
    if (ciphertext.len < out_len) return EncodeError.BufferTooSmall;

    const nonce = buildNonce(write_iv, seq);
    const ct_slice = ciphertext[0..plaintext.len];
    const tag_slice = ciphertext[plaintext.len..][0..tag_len];

    Aes128Gcm.encrypt(ct_slice, tag_slice, plaintext, header_aad, nonce, key);
    return ciphertext[0..out_len];
}

/// Open (authenticate + decrypt) an AES-128-GCM DTLS 1.3 record. `header_aad`
/// must be the unified header with the sequence number in the clear (the peer's
/// sealing-time value, recovered by removing the record-number mask first).
pub fn openRecordAes128Gcm(
    key: [aes128_key_len]u8,
    write_iv: [iv_len]u8,
    seq: u64,
    header_aad: []const u8,
    ciphertext: []const u8,
    plaintext: []u8,
) DecodeError![]u8 {
    if (ciphertext.len < tag_len) return DecodeError.PlaintextTooShort;

    const ct_len = ciphertext.len - tag_len;
    if (plaintext.len < ct_len) return DecodeError.BufferTooShort;

    const nonce = buildNonce(write_iv, seq);
    const ct_slice = ciphertext[0..ct_len];
    const tag_slice = ciphertext[ct_len..][0..tag_len];
    const pt_slice = plaintext[0..ct_len];

    Aes128Gcm.decrypt(pt_slice, ct_slice, tag_slice.*, header_aad, nonce, key) catch
        return DecodeError.AuthenticationFailed;

    return pt_slice;
}

// ---------------------------------------------------------------------------
// Traffic-key + record-number-encryption key derivation (RFC 9147 §4.2.2/§4.2.3)
// ---------------------------------------------------------------------------

/// Per-epoch record-protection keys for the AES-128-GCM / SHA-256 suite:
/// the AEAD `key` + `iv`, plus the `sn_key` used for record-number encryption.
pub const Aes128GcmKeys = struct {
    key: [aes128_key_len]u8,
    iv: [iv_len]u8,
    sn_key: [aes128_key_len]u8,

    pub fn wipe(self: *Aes128GcmKeys) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, &self.sn_key);
    }
};

/// Derive {key, iv, sn_key} from a TLS 1.3 traffic secret via HKDF-Expand-Label
/// (RFC 8446 §7.3 for key/iv; RFC 9147 §4.2.3 for the "sn" label). The three
/// output lengths are fixed and well within the HKDF limits, so the expansions
/// are infallible for this suite (asserted by construction — no attacker input).
pub fn deriveAes128GcmKeys(traffic_secret: [hash.Hkdf(.sha256).prk_len]u8) Aes128GcmKeys {
    const Hkdf = hash.Hkdf(.sha256);
    var prk = Hkdf.Prk.init(traffic_secret);
    defer prk.wipe();

    var out: Aes128GcmKeys = undefined;
    Hkdf.expandLabel(&prk, "key", "", &out.key) catch unreachable;
    Hkdf.expandLabel(&prk, "iv", "", &out.iv) catch unreachable;
    Hkdf.expandLabel(&prk, "sn", "", &out.sn_key) catch unreachable;
    return out;
}

// ---------------------------------------------------------------------------
// Record-number encryption (RFC 9147 §4.2.3)
// ---------------------------------------------------------------------------

/// The RFC 9147 §4.2.3 sequence-number mask for AES-based suites:
/// `Mask = AES-ECB(sn_key, sample)`, where `sample` is the first 16 bytes of the
/// record's ciphertext (`encrypted_record`). Only the leading `seq_bytes` of the
/// returned mask are consumed.
pub fn recordNumberMaskAes128(sn_key: [aes128_key_len]u8, sample: [16]u8) [16]u8 {
    var mask: [16]u8 = undefined;
    const ctx = Aes128.initEnc(sn_key);
    ctx.encrypt(&mask, &sample);
    return mask;
}

/// Apply (or, being XOR, remove) the record-number mask over the on-wire
/// sequence-number bytes of a unified header (RFC 9147 §4.2.3). Per the RFC only
/// the sequence-number field is masked — never the first byte / epoch bits.
pub fn applyRecordNumberMask(seq_bytes: []u8, mask: []const u8) void {
    std.debug.assert(mask.len >= seq_bytes.len);
    for (seq_bytes, 0..) |*b, i| b.* ^= mask[i];
}

/// Reconstruct the full epoch-scoped sequence number from a truncated on-wire
/// value (RFC 9147 §4.2.2 / §5.2). `wire_low` is the decoded 8/16-bit value,
/// `bits` its width, and `highest_seen` the largest full sequence number already
/// accepted in this epoch. The reconstruction picks the value congruent to
/// `wire_low` closest to what is anticipated next.
pub fn reconstructSeq(wire_low: u64, bits: u6, highest_seen: u64) u64 {
    const window: u64 = @as(u64, 1) << bits;
    const low_mask = window - 1;
    var seq = (highest_seen & ~low_mask) | (wire_low & low_mask);
    // If the first guess lands far below what we've already accepted, the
    // low-bit counter must have wrapped; advance by one window.
    if (seq +| (window / 2) < highest_seen) seq +|= window;
    return seq;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "header encode/decode round-trip — 8-bit seq, no length" {
    const t = std.testing;

    const orig = Header{
        .epoch_low = 2,
        .seq = 0xAB,
        .seq_len = .short,
        .length_present = false,
        .record_len = 0,
    };

    var buf: [max_header_len]u8 = undefined;
    const encoded = try orig.encode(&buf);
    try t.expectEqual(@as(usize, 2), encoded.len);

    const result = try Header.decode(encoded);
    try t.expectEqual(@as(usize, 2), result.consumed);
    try t.expectEqual(orig.epoch_low, result.hdr.epoch_low);
    try t.expectEqual(orig.seq, result.hdr.seq);
    try t.expectEqual(orig.seq_len, result.hdr.seq_len);
    try t.expectEqual(orig.length_present, result.hdr.length_present);
}

test "header encode/decode round-trip — 16-bit seq, with length" {
    const t = std.testing;

    const orig = Header{
        .epoch_low = 3,
        .seq = 0x1234,
        .seq_len = .long,
        .length_present = true,
        .record_len = 512,
    };

    var buf: [max_header_len]u8 = undefined;
    const encoded = try orig.encode(&buf);
    try t.expectEqual(@as(usize, 5), encoded.len);

    const result = try Header.decode(encoded);
    try t.expectEqual(@as(usize, 5), result.consumed);
    try t.expectEqual(orig.epoch_low, result.hdr.epoch_low);
    try t.expectEqual(orig.seq, result.hdr.seq);
    try t.expectEqual(orig.seq_len, result.hdr.seq_len);
    try t.expectEqual(orig.length_present, result.hdr.length_present);
    try t.expectEqual(orig.record_len, result.hdr.record_len);
}

test "header decode — invalid fixed bits rejected" {
    const t = std.testing;
    // First byte 0xFF has bits [7:5] = 0b111, not 0b001.
    const buf = [_]u8{ 0xFF, 0x00, 0x00, 0x00, 0x00 };
    try t.expectError(DecodeError.InvalidFixedBit, Header.decode(&buf));
}

test "header decode — truncated buffer rejected" {
    const t = std.testing;
    // Valid B0 for long-seq + length-present, but no payload bytes.
    const buf = [_]u8{0b0010_1100}; // S=1, L=1
    try t.expectError(DecodeError.BufferTooShort, Header.decode(&buf));
}

test "header wireLen" {
    const t = std.testing;

    var h = Header{ .epoch_low = 0, .seq = 1, .seq_len = .short, .length_present = false, .record_len = 0 };
    try t.expectEqual(@as(usize, 2), h.wireLen());

    h.seq_len = .long;
    try t.expectEqual(@as(usize, 3), h.wireLen());

    h.length_present = true;
    try t.expectEqual(@as(usize, 5), h.wireLen());

    h.seq_len = .short;
    try t.expectEqual(@as(usize, 4), h.wireLen());
}

test "seq mask apply/remove reversible" {
    const t = std.testing;

    // Build a short-seq header.
    const orig = Header{ .epoch_low = 1, .seq = 0x7F, .seq_len = .short, .length_present = false, .record_len = 0 };
    var buf: [max_header_len]u8 = undefined;
    const encoded = try orig.encode(&buf);

    // Snapshot pre-mask bytes.
    const before: [2]u8 = encoded[0..2].*;

    const mask = [_]u8{ 0xAB, 0xCD };
    applyMask(encoded, &mask);

    // Must differ from original.
    try t.expect(!std.mem.eql(u8, &before, encoded[0..2]));

    // Apply again to remove.
    applyMask(encoded, &mask);
    try t.expectEqualSlices(u8, &before, encoded[0..2]);

    // Re-decode after double-apply yields original header.
    const result = try Header.decode(encoded);
    try t.expectEqual(orig.seq, result.hdr.seq);
    try t.expectEqual(orig.epoch_low, result.hdr.epoch_low);
}

test "seq mask — 16-bit seq apply/remove" {
    const t = std.testing;

    const orig = Header{ .epoch_low = 0, .seq = 0xBEEF, .seq_len = .long, .length_present = false, .record_len = 0 };
    var buf: [max_header_len]u8 = undefined;
    const encoded = try orig.encode(&buf);

    const before: [3]u8 = encoded[0..3].*;
    const mask = [_]u8{ 0x11, 0x22, 0x33 };

    applyMask(encoded[0..3], &mask);
    try t.expect(!std.mem.eql(u8, &before, encoded[0..3]));

    applyMask(encoded[0..3], &mask);
    try t.expectEqualSlices(u8, &before, encoded[0..3]);
}

test "anti-replay — first packet always accepted" {
    const t = std.testing;
    var ar = AntiReplay{};
    try ar.check(42);
    ar.record(42);
    try t.expectEqual(@as(u64, 42), ar.top);
}

test "anti-replay — duplicate rejected" {
    const t = std.testing;
    var ar = AntiReplay{};
    try ar.check(10);
    ar.record(10);
    try t.expectError(DecodeError.Replay, ar.check(10));
}

test "anti-replay — in-window new sequence accepted" {
    const t = std.testing;
    var ar = AntiReplay{};
    // Record packets 0..62 (skip 30).
    for (0..63) |i| {
        if (i == 30) continue;
        try ar.check(@intCast(i));
        ar.record(@intCast(i));
    }
    // Seq 30 is still in window and unseen — should be accepted.
    try ar.check(30);
    ar.record(30);
    // Now 30 is a replay.
    try t.expectError(DecodeError.Replay, ar.check(30));
}

test "anti-replay — too-old rejected" {
    const t = std.testing;
    var ar = AntiReplay{};
    ar.record(100);
    // 100 - 64 = 36 is exactly out of window.
    try t.expectError(DecodeError.TooOld, ar.check(36));
    // 99 - 63 = 37 is the oldest in-window slot.
    try ar.check(37);
}

test "anti-replay — window slides forward" {
    const t = std.testing;
    var ar = AntiReplay{};
    for (0..64) |i| {
        try ar.check(@intCast(i));
        ar.record(@intCast(i));
    }
    // Advance by 1: seq 0 falls off the back.
    try ar.check(64);
    ar.record(64);
    try t.expectError(DecodeError.TooOld, ar.check(0));
    // seq 1 is now the oldest in-window position (top=64, diff=63).
    try t.expectError(DecodeError.Replay, ar.check(1));
}

test "anti-replay — large jump clears window" {
    const t = std.testing;
    var ar = AntiReplay{};
    ar.record(5);
    // Jump far ahead — old window should be wiped.
    try ar.check(200);
    ar.record(200);
    // seq 5 is now too old.
    try t.expectError(DecodeError.TooOld, ar.check(5));
}

test "buildNonce — known vector" {
    const t = std.testing;
    const iv = @as([12]u8, @splat(0));
    // With all-zero IV the nonce should equal the padded seq.
    const nonce = buildNonce(iv, 0x0102030405060708);
    const expected = [_]u8{ 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    try t.expectEqualSlices(u8, &expected, &nonce);
}

test "buildNonce — XOR with IV" {
    const t = std.testing;
    var iv: [12]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @truncate(i);

    const nonce = buildNonce(iv, 0);
    // seq=0 → padded all zeros, so nonce == iv.
    try t.expectEqualSlices(u8, &iv, &nonce);
}

test "AEAD seal/open round-trip" {
    const t = std.testing;

    const key = @as([32]u8, @splat(0x42));
    const iv = @as([12]u8, @splat(0x00));
    const seq: u64 = 7;
    const aad = "dtls-header";
    const plaintext = "hello, dtls 1.3 record layer";

    var ct_buf: [plaintext.len + tag_len]u8 = undefined;
    const ct = try sealRecord(key, iv, seq, aad, plaintext, &ct_buf);

    var pt_buf: [plaintext.len]u8 = undefined;
    const pt = try openRecord(key, iv, seq, aad, ct, &pt_buf);

    try t.expectEqualStrings(plaintext, pt);
}

test "AEAD — tampered ciphertext rejected" {
    const t = std.testing;

    const key = @as([32]u8, @splat(0x11));
    const iv = @as([12]u8, @splat(0x22));
    const seq: u64 = 99;
    const aad = "aad";
    const plaintext = "secret message";

    var ct_buf: [plaintext.len + tag_len]u8 = undefined;
    var ct = try sealRecord(key, iv, seq, aad, plaintext, &ct_buf);

    // Flip a bit in the ciphertext body.
    ct[0] ^= 0x01;

    var pt_buf: [plaintext.len]u8 = undefined;
    try t.expectError(DecodeError.AuthenticationFailed, openRecord(key, iv, seq, aad, ct, &pt_buf));
}

test "AEAD — tampered tag rejected" {
    const t = std.testing;

    const key = @as([32]u8, @splat(0x33));
    const iv = @as([12]u8, @splat(0x44));
    const seq: u64 = 0;
    const aad = "hdr";
    const plaintext = "payload";

    var ct_buf: [plaintext.len + tag_len]u8 = undefined;
    var ct = try sealRecord(key, iv, seq, aad, plaintext, &ct_buf);

    // Flip a bit in the Poly1305 tag.
    ct[ct.len - 1] ^= 0xFF;

    var pt_buf: [plaintext.len]u8 = undefined;
    try t.expectError(DecodeError.AuthenticationFailed, openRecord(key, iv, seq, aad, ct, &pt_buf));
}

test "AEAD — wrong AAD rejected" {
    const t = std.testing;

    const key = @as([32]u8, @splat(0x55));
    const iv = @as([12]u8, @splat(0x66));
    const seq: u64 = 1;
    const plaintext = "data";

    var ct_buf: [plaintext.len + tag_len]u8 = undefined;
    const ct = try sealRecord(key, iv, seq, "aad-A", plaintext, &ct_buf);

    var pt_buf: [plaintext.len]u8 = undefined;
    try t.expectError(DecodeError.AuthenticationFailed, openRecord(key, iv, seq, "aad-B", ct, &pt_buf));
}

test "AEAD — wrong seq (nonce mismatch) rejected" {
    const t = std.testing;

    const key = @as([32]u8, @splat(0x77));
    const iv = @as([12]u8, @splat(0x88));
    const aad = "hdr";
    const plaintext = "nonce test";

    var ct_buf: [plaintext.len + tag_len]u8 = undefined;
    const ct = try sealRecord(key, iv, 10, aad, plaintext, &ct_buf);

    var pt_buf: [plaintext.len]u8 = undefined;
    try t.expectError(DecodeError.AuthenticationFailed, openRecord(key, iv, 11, aad, ct, &pt_buf));
}

test "AEAD — deterministic (same inputs, same output)" {
    const t = std.testing;

    const key = @as([32]u8, @splat(0x99));
    const iv = @as([12]u8, @splat(0xAA));
    const aad = "deterministic";
    const plaintext = "same every time";

    var ct1: [plaintext.len + tag_len]u8 = undefined;
    var ct2: [plaintext.len + tag_len]u8 = undefined;
    _ = try sealRecord(key, iv, 3, aad, plaintext, &ct1);
    _ = try sealRecord(key, iv, 3, aad, plaintext, &ct2);
    try t.expectEqualSlices(u8, &ct1, &ct2);
}

test "AES-128-GCM seal/open round-trip" {
    const t = std.testing;
    const key = @as([16]u8, @splat(0x42));
    const iv = @as([12]u8, @splat(0x00));
    const aad = "dtls13-header";
    const plaintext = "hello, dtls 1.3 aes-128-gcm record";

    var ct_buf: [plaintext.len + tag_len]u8 = undefined;
    const ct = try sealRecordAes128Gcm(key, iv, 9, aad, plaintext, &ct_buf);
    try t.expectEqual(@as(usize, plaintext.len + tag_len), ct.len);

    var pt_buf: [plaintext.len]u8 = undefined;
    const pt = try openRecordAes128Gcm(key, iv, 9, aad, ct, &pt_buf);
    try t.expectEqualStrings(plaintext, pt);
}

test "AES-128-GCM — tampered ciphertext / wrong AAD / wrong seq rejected" {
    const t = std.testing;
    const key = @as([16]u8, @splat(0x11));
    const iv = @as([12]u8, @splat(0x22));
    const plaintext = "seq-bound aead";

    var ct_buf: [plaintext.len + tag_len]u8 = undefined;
    var ct = try sealRecordAes128Gcm(key, iv, 5, "hdr", plaintext, &ct_buf);
    var pt_buf: [plaintext.len]u8 = undefined;

    // wrong AAD
    try t.expectError(DecodeError.AuthenticationFailed, openRecordAes128Gcm(key, iv, 5, "HDR", ct, &pt_buf));
    // wrong seq (nonce mismatch)
    try t.expectError(DecodeError.AuthenticationFailed, openRecordAes128Gcm(key, iv, 6, "hdr", ct, &pt_buf));
    // tampered ciphertext
    ct[0] ^= 0x01;
    try t.expectError(DecodeError.AuthenticationFailed, openRecordAes128Gcm(key, iv, 5, "hdr", ct, &pt_buf));
}

test "deriveAes128GcmKeys is deterministic and input-sensitive" {
    const t = std.testing;
    var secret: [32]u8 = undefined;
    for (&secret, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);

    var a = deriveAes128GcmKeys(secret);
    defer a.wipe();
    var b = deriveAes128GcmKeys(secret);
    defer b.wipe();
    try t.expectEqualSlices(u8, &a.key, &b.key);
    try t.expectEqualSlices(u8, &a.iv, &b.iv);
    try t.expectEqualSlices(u8, &a.sn_key, &b.sn_key);
    // key, iv and sn_key are independent derivations (must all differ).
    try t.expect(!std.mem.eql(u8, a.key[0..12], a.iv[0..12]));
    try t.expect(!std.mem.eql(u8, &a.key, &a.sn_key));

    secret[0] ^= 0xff;
    var c = deriveAes128GcmKeys(secret);
    defer c.wipe();
    try t.expect(!std.mem.eql(u8, &a.key, &c.key));
    try t.expect(!std.mem.eql(u8, &a.sn_key, &c.sn_key));
}

test "record-number encryption round-trips over the on-wire seq bytes" {
    const t = std.testing;
    const sn_key = @as([16]u8, @splat(0x5c));

    // Build a unified header with a 16-bit sequence number and a length field.
    const orig = Header{
        .epoch_low = 2,
        .seq = 0x0007,
        .seq_len = .long,
        .length_present = true,
        .record_len = 61,
    };
    var hdr_buf: [max_header_len]u8 = undefined;
    const wire = try orig.encode(&hdr_buf);

    // A 16-byte ciphertext sample (would be the record's first 16 bytes).
    var sample: [16]u8 = undefined;
    for (&sample, 0..) |*x, i| x.* = @truncate(0xA0 +% i);
    const mask = recordNumberMaskAes128(sn_key, sample);

    // The sequence-number field occupies bytes [1..3] for a 16-bit seq.
    const seq_before: [2]u8 = wire[1..3].*;
    applyRecordNumberMask(wire[1..3], mask[0..2]);
    try t.expect(!std.mem.eql(u8, &seq_before, wire[1..3])); // actually encrypted
    // B0 (epoch bits) must be untouched by record-number encryption.
    try t.expectEqual(hdr_buf[0], wire[0]);

    // Removing the mask (XOR is its own inverse) recovers the cleartext seq.
    applyRecordNumberMask(wire[1..3], mask[0..2]);
    try t.expectEqualSlices(u8, &seq_before, wire[1..3]);
    const dec = try Header.decode(wire);
    try t.expectEqual(@as(u64, 0x0007), dec.hdr.seq);
    try t.expectEqual(@as(u2, 2), dec.hdr.epoch_low);
}

test "reconstructSeq extends truncated wire values and handles wrap" {
    const t = std.testing;
    // Small handshake seqs: 16-bit wire value equals the full value.
    try t.expectEqual(@as(u64, 0), reconstructSeq(0, 16, 0));
    try t.expectEqual(@as(u64, 3), reconstructSeq(3, 16, 2));
    // 8-bit counter that wrapped past 255 relative to a high `highest_seen`.
    try t.expectEqual(@as(u64, 256), reconstructSeq(0, 8, 255));
    try t.expectEqual(@as(u64, 257), reconstructSeq(1, 8, 260));
}
