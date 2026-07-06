// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Delegated Credentials wire codec (RFC 9345).
//!
//! A pure, allocation-free codec for the `DelegatedCredential` structure a TLS
//! 1.3 server carries in the extensions of its end-entity `CertificateEntry`
//! (RFC 8446 §4.4.2), plus the reconstruction of the exact byte string the
//! delegation certificate's key signs (RFC 9345 §4.1.3).  The verification
//! itself — checking that signature under the leaf key, enforcing the
//! `DelegationUsage` X.509 extension, and the validity window — lives in the
//! TLS client, which owns the leaf certificate and the crypto verifiers; this
//! module only walks bytes.
//!
//! Wire layout (RFC 9345 §4):
//!
//!     struct {
//!         uint32 valid_time;
//!         SignatureScheme dc_cert_verify_algorithm;
//!         opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
//!     } Credential;
//!
//!     struct {
//!         Credential cred;
//!         SignatureScheme algorithm;
//!         opaque signature<0..2^16-1>;
//!     } DelegatedCredential;
//!
//! The leaf key signs, per RFC 9345 §4.1.3, the concatenation of:
//!   1. octet 0x20 repeated 64 times,
//!   2. the context string "TLS, server delegated credentials",
//!   3. a single 0x00 separator,
//!   4. the DER-encoded end-entity (delegation) certificate,
//!   5. `Credential.valid_time`,
//!   6. `Credential.dc_cert_verify_algorithm`,
//!   7. `Credential.ASN1_subjectPublicKeyInfo` (the opaque vector, length-prefix
//!      included, exactly as on the wire),
//!   8. `DelegatedCredential.algorithm`.
//!
//! Items 5–8 are precisely the contiguous wire bytes preceding the signature's
//! own length prefix, so the codec captures them as one slice
//! (`Parsed.signed_portion`) rather than re-serializing — the reconstruction is
//! byte-identical to what the peer signed, by construction.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  Callers own every
//! buffer.  Every length is bounds-checked; a truncated or malformed input
//! yields `error.Truncated` rather than reading past the slice.  Only `std` is
//! imported.
const std = @import("std");
const mem = std.mem;

/// The IANA `delegated_credential(34)` extension type (RFC 9345 §3).
pub const extension_type: u16 = 34;

/// The maximum validity period (RFC 9345 §4.1.3 check 2): seven days, in seconds.
/// This bounds the DC's *remaining* lifetime — a DC is rejected when its expiry
/// time (the delegation certificate's `notBefore` + `valid_time`) exceeds the
/// current time plus this value. It is NOT a cap on the raw `valid_time` field,
/// which is anchored to the certificate's `notBefore` and may legitimately be far
/// larger than seven days for a cert issued weeks ago.
pub const max_valid_time_seconds: u32 = 7 * 24 * 60 * 60;

/// The RFC 9345 §4.1.3 context string for a *server* delegated credential — the
/// only kind a TLS client validates.  A client-authentication DC would use
/// "TLS, client delegated credentials" instead.
pub const server_context = "TLS, server delegated credentials";

/// Length of the fixed prefix (64 spaces || context || 0x00 separator) the
/// signed message begins with, before the certificate and credential bytes.
pub const signed_prefix_len: usize = 64 + server_context.len + 1;

/// Errors produced while parsing, serializing, or reconstructing a DC.
pub const Error = error{
    /// The input ended mid-field or declared more bytes than it carried, an
    /// SPKI length of zero (the vector is `<1..2^24-1>`), or trailing bytes
    /// after the signature.
    Truncated,
    /// A caller-provided output buffer ran out of room.
    NoSpaceLeft,
};

/// The `Credential` half of a `DelegatedCredential` (everything the leaf key
/// binds except the outer `algorithm`).  `spki` is the raw
/// SubjectPublicKeyInfo DER of the delegated key.
pub const Credential = struct {
    valid_time: u32,
    dc_cert_verify_algorithm: u16,
    /// Raw ASN.1 SubjectPublicKeyInfo of the delegated public key (no wire
    /// length prefix; `<1..2^24-1>`).
    spki: []const u8,
};

/// A decoded `DelegatedCredential`.  `spki`, `signature`, and `signed_portion`
/// alias the caller's input buffer — nothing is copied.
pub const Parsed = struct {
    valid_time: u32,
    dc_cert_verify_algorithm: u16,
    /// Raw SubjectPublicKeyInfo DER of the delegated public key.
    spki: []const u8,
    /// The outer signature scheme: the leaf key signs the credential with this.
    algorithm: u16,
    /// The leaf-key signature over `writeSignedMessage(cert, signed_portion)`.
    signature: []const u8,
    /// The contiguous wire bytes the leaf signature covers *before* the
    /// context/certificate prefix is prepended — i.e. `Credential` (with the
    /// SPKI's 3-byte length prefix) followed by the 2-byte `algorithm`.  This is
    /// exactly RFC 9345 §4.1.3 items 5–8, captured verbatim.
    signed_portion: []const u8,

    /// The credential view of a parsed DC.
    pub fn credential(self: Parsed) Credential {
        return .{
            .valid_time = self.valid_time,
            .dc_cert_verify_algorithm = self.dc_cert_verify_algorithm,
            .spki = self.spki,
        };
    }
};

/// Parse a server-presented `DelegatedCredential` from the raw extension data.
/// Fails closed: every length is bounds-checked, a zero-length SPKI is rejected,
/// and trailing bytes after the signature are an error (the structure must span
/// the input exactly).  The returned slices alias `raw`.
pub fn parse(raw: []const u8) Error!Parsed {
    // valid_time(4) + dc_cert_verify_algorithm(2) + spki length(3) = 9.
    if (raw.len < 9) return error.Truncated;
    const valid_time = mem.readInt(u32, raw[0..4], .big);
    const dc_cert_verify_algorithm = mem.readInt(u16, raw[4..6], .big);
    const spki_len: usize = mem.readInt(u24, raw[6..9], .big);
    if (spki_len == 0) return error.Truncated; // ASN1_subjectPublicKeyInfo<1..>
    const spki_end = 9 + spki_len;
    // Need the SPKI plus the 2-byte outer algorithm.
    if (raw.len < spki_end + 2) return error.Truncated;
    const spki = raw[9..spki_end];
    const algorithm = mem.readInt(u16, raw[spki_end..][0..2], .big);
    const algo_end = spki_end + 2;
    // Then the 2-byte signature length.
    if (raw.len < algo_end + 2) return error.Truncated;
    const sig_len: usize = mem.readInt(u16, raw[algo_end..][0..2], .big);
    const sig_start = algo_end + 2;
    // The signature must consume the input exactly — no trailing bytes.
    if (raw.len != sig_start + sig_len) return error.Truncated;
    return .{
        .valid_time = valid_time,
        .dc_cert_verify_algorithm = dc_cert_verify_algorithm,
        .spki = spki,
        .algorithm = algorithm,
        .signature = raw[sig_start..],
        .signed_portion = raw[0..algo_end],
    };
}

/// Write the leaf-signed portion — `Credential` followed by the 2-byte
/// `algorithm` — into `out`, returning the used prefix.  This is the byte string
/// `Parsed.signed_portion` captures; a builder uses it to know what to sign.
pub fn writeSignedPortion(out: []u8, cred: Credential, algorithm: u16) Error![]const u8 {
    if (cred.spki.len > std.math.maxInt(u24)) return error.Truncated;
    const total = 9 + cred.spki.len + 2;
    if (out.len < total) return error.NoSpaceLeft;
    mem.writeInt(u32, out[0..4], cred.valid_time, .big);
    mem.writeInt(u16, out[4..6], cred.dc_cert_verify_algorithm, .big);
    mem.writeInt(u24, out[6..9], @intCast(cred.spki.len), .big);
    @memcpy(out[9..][0..cred.spki.len], cred.spki);
    mem.writeInt(u16, out[9 + cred.spki.len ..][0..2], algorithm, .big);
    return out[0..total];
}

/// Serialize a full `DelegatedCredential` (leaf-signed portion || 2-byte
/// signature length || signature) into `out`, returning the used prefix.
pub fn serialize(out: []u8, cred: Credential, algorithm: u16, signature: []const u8) Error![]const u8 {
    if (signature.len > std.math.maxInt(u16)) return error.NoSpaceLeft;
    const portion = try writeSignedPortion(out, cred, algorithm);
    const sig_off = portion.len;
    if (out.len < sig_off + 2 + signature.len) return error.NoSpaceLeft;
    mem.writeInt(u16, out[sig_off..][0..2], @intCast(signature.len), .big);
    @memcpy(out[sig_off + 2 ..][0..signature.len], signature);
    return out[0 .. sig_off + 2 + signature.len];
}

/// Bytes required by `writeSignedMessage` for the given certificate and
/// leaf-signed-portion lengths.
pub fn signedMessageLen(cert_der_len: usize, signed_portion_len: usize) usize {
    return signed_prefix_len + cert_der_len + signed_portion_len;
}

/// Reconstruct the exact RFC 9345 §4.1.3 message the leaf key signs, into `out`:
/// 64 `0x20` octets, the server context string, a `0x00` separator, the DER
/// end-entity certificate, then `signed_portion` (Credential || algorithm).
/// `signed_portion` is `Parsed.signed_portion` (or `writeSignedPortion`'s
/// output) — the very bytes the peer signed, so this is byte-identical to the
/// peer's input by construction.
pub fn writeSignedMessage(out: []u8, cert_der: []const u8, signed_portion: []const u8) Error![]const u8 {
    const total = signedMessageLen(cert_der.len, signed_portion.len);
    if (out.len < total) return error.NoSpaceLeft;
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..server_context.len], server_context);
    out[64 + server_context.len] = 0x00;
    var off: usize = signed_prefix_len;
    @memcpy(out[off..][0..cert_der.len], cert_der);
    off += cert_der.len;
    @memcpy(out[off..][0..signed_portion.len], signed_portion);
    off += signed_portion.len;
    return out[0..off];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "serialize then parse round-trips every field" {
    // Arrange: a plausible DC with a 4-byte stand-in SPKI and 6-byte signature.
    const spki = [_]u8{ 0x30, 0x03, 0xAA, 0xBB }; // opaque stand-in
    const sig = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const cred: Credential = .{
        .valid_time = 0x00015180, // 86400 = one day
        .dc_cert_verify_algorithm = 0x0403, // ecdsa_secp256r1_sha256
        .spki = &spki,
    };
    var buf: [64]u8 = undefined;

    // Act
    const wire = try serialize(&buf, cred, 0x0807, &sig); // algorithm = ed25519
    const dc = try parse(wire);

    // Assert
    try testing.expectEqual(@as(u32, 0x00015180), dc.valid_time);
    try testing.expectEqual(@as(u16, 0x0403), dc.dc_cert_verify_algorithm);
    try testing.expectEqualSlices(u8, &spki, dc.spki);
    try testing.expectEqual(@as(u16, 0x0807), dc.algorithm);
    try testing.expectEqualSlices(u8, &sig, dc.signature);

    // signed_portion is Credential || algorithm, sans the signature.
    var portion_buf: [32]u8 = undefined;
    const portion = try writeSignedPortion(&portion_buf, cred, 0x0807);
    try testing.expectEqualSlices(u8, portion, dc.signed_portion);
}

test "parse rejects a zero-length SPKI" {
    // valid_time(4) || alg(2) || spki_len=0(3) || algorithm(2) || sig_len=0(2)
    const raw = [_]u8{ 0, 0, 0, 1, 0x04, 0x03, 0, 0, 0, 0x08, 0x07, 0, 0 };
    try testing.expectError(error.Truncated, parse(&raw));
}

test "parse rejects truncation before the outer algorithm" {
    // spki_len declares 4 bytes but only 2 follow, with nothing after.
    const raw = [_]u8{ 0, 0, 0, 1, 0x04, 0x03, 0, 0, 4, 0xAA, 0xBB };
    try testing.expectError(error.Truncated, parse(&raw));
}

test "parse rejects a truncated signature vector" {
    // Well-formed through the sig length (declares 4) but carries only 1 byte.
    const spki = [_]u8{0xAA};
    const cred: Credential = .{ .valid_time = 1, .dc_cert_verify_algorithm = 0x0403, .spki = &spki };
    var buf: [32]u8 = undefined;
    const portion = try writeSignedPortion(&buf, cred, 0x0807);
    // Append a sig_len of 4 but only one signature byte.
    var raw: [40]u8 = undefined;
    @memcpy(raw[0..portion.len], portion);
    std.mem.writeInt(u16, raw[portion.len..][0..2], 4, .big);
    raw[portion.len + 2] = 0xFF;
    try testing.expectError(error.Truncated, parse(raw[0 .. portion.len + 3]));
}

test "parse rejects trailing bytes after the signature" {
    const spki = [_]u8{0xAA};
    const sig = [_]u8{ 0x11, 0x22 };
    const cred: Credential = .{ .valid_time = 1, .dc_cert_verify_algorithm = 0x0403, .spki = &spki };
    var buf: [40]u8 = undefined;
    const wire = try serialize(&buf, cred, 0x0807, &sig);
    // One extra byte past a valid DC must be rejected (structure spans exactly).
    var raw: [48]u8 = undefined;
    @memcpy(raw[0..wire.len], wire);
    raw[wire.len] = 0x00;
    try testing.expectError(error.Truncated, parse(raw[0 .. wire.len + 1]));
}

test "writeSignedMessage lays out the RFC 9345 prefix, cert, then signed portion" {
    // Arrange
    const cert = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const portion = [_]u8{ 0x01, 0x02, 0x03 };
    var out: [128]u8 = undefined;

    // Act
    const msg = try writeSignedMessage(&out, &cert, &portion);

    // Assert
    try testing.expectEqual(signedMessageLen(cert.len, portion.len), msg.len);
    for (msg[0..64]) |b| try testing.expectEqual(@as(u8, 0x20), b);
    try testing.expectEqualSlices(u8, server_context, msg[64 .. 64 + server_context.len]);
    try testing.expectEqual(@as(u8, 0x00), msg[64 + server_context.len]);
    try testing.expectEqualSlices(u8, &cert, msg[signed_prefix_len .. signed_prefix_len + cert.len]);
    try testing.expectEqualSlices(u8, &portion, msg[signed_prefix_len + cert.len ..]);
}

test "writeSignedPortion reports NoSpaceLeft on a short buffer" {
    const spki = [_]u8{ 0xAA, 0xBB };
    const cred: Credential = .{ .valid_time = 1, .dc_cert_verify_algorithm = 0x0403, .spki = &spki };
    var tiny: [8]u8 = undefined; // needs 9 + 2 + 2 = 13
    try testing.expectError(error.NoSpaceLeft, writeSignedPortion(&tiny, cred, 0x0807));
}

test "max_valid_time_seconds is seven days" {
    try testing.expectEqual(@as(u32, 604800), max_valid_time_seconds);
}
