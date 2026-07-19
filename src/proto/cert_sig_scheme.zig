// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Map an X.509 certificate's outer `signatureAlgorithm` OID to the TLS 1.3
//! `SignatureScheme` code point it corresponds to (RFC 8446 §4.2.3), for
//! `signature_algorithms_cert` enforcement.
//!
//! `signature_algorithms_cert` constrains the algorithms used to sign the
//! CERTIFICATES in a chain (as opposed to `signature_algorithms`, which
//! constrains the CertificateVerify signature). To decide whether a presented
//! chain conforms to a peer's advertised cert-scheme list, each chain
//! certificate's `signatureAlgorithm` OID must be classified as the TLS
//! `SignatureScheme` a peer would name for it.
//!
//! This module is deliberately fail-closed: an OID it does not model maps to
//! `null` ("unclassifiable"). A caller enforcing conformance must treat a
//! `null`-classified (non-exempt) certificate as NON-conforming rather than
//! guessing — better to refuse than to admit a chain signed with an algorithm
//! the verifier cannot even name. The classical OIDs Onyx Server's own certificates
//! use (Ed25519, ECDSA P-256/P-384, RSA PKCS#1) are all modeled.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation. Only `std` is imported.
const std = @import("std");

/// TLS 1.3 `SignatureScheme` wire code points (RFC 8446 §4.2.3 + IANA registry)
/// that a certificate can be signed with. The PKCS#1 `rsa_pkcs1_*` schemes are
/// legacy for CertificateVerify but remain valid inside certificate chains.
pub const rsa_pkcs1_sha256: u16 = 0x0401;
pub const rsa_pkcs1_sha384: u16 = 0x0501;
pub const rsa_pkcs1_sha512: u16 = 0x0601;
pub const ecdsa_secp256r1_sha256: u16 = 0x0403;
pub const ecdsa_secp384r1_sha384: u16 = 0x0503;
pub const ed25519: u16 = 0x0807;

// Certificate `signatureAlgorithm` OIDs (the outer AlgorithmIdentifier), as raw
// DER OID bytes (tag/length stripped) — matching `x509.Certificate.signature_algorithm_oid`.
const oid_rsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B }; // sha256WithRSAEncryption
const oid_rsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C }; // sha384WithRSAEncryption
const oid_rsa_sha512 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D }; // sha512WithRSAEncryption
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 }; // ecdsa-with-SHA256
const oid_ecdsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 }; // ecdsa-with-SHA384
const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 }; // id-Ed25519

/// Classify a certificate's outer `signatureAlgorithm` OID as the TLS
/// `SignatureScheme` code point a peer would advertise for it, or `null` if the
/// OID is not one this module models (RSASSA-PSS, PQ, and any unknown OID are
/// intentionally unclassified — callers must fail closed on `null`).
pub fn schemeForCertOid(oid: []const u8) ?u16 {
    if (std.mem.eql(u8, oid, &oid_ed25519)) return ed25519;
    if (std.mem.eql(u8, oid, &oid_ecdsa_sha256)) return ecdsa_secp256r1_sha256;
    if (std.mem.eql(u8, oid, &oid_ecdsa_sha384)) return ecdsa_secp384r1_sha384;
    if (std.mem.eql(u8, oid, &oid_rsa_sha256)) return rsa_pkcs1_sha256;
    if (std.mem.eql(u8, oid, &oid_rsa_sha384)) return rsa_pkcs1_sha384;
    if (std.mem.eql(u8, oid, &oid_rsa_sha512)) return rsa_pkcs1_sha512;
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const testing = std.testing;

test "tls signature_algorithms_cert: classifies the classical certificate signatureAlgorithm OIDs" {
    try testing.expectEqual(@as(?u16, ed25519), schemeForCertOid(&oid_ed25519));
    try testing.expectEqual(@as(?u16, ecdsa_secp256r1_sha256), schemeForCertOid(&oid_ecdsa_sha256));
    try testing.expectEqual(@as(?u16, ecdsa_secp384r1_sha384), schemeForCertOid(&oid_ecdsa_sha384));
    try testing.expectEqual(@as(?u16, rsa_pkcs1_sha256), schemeForCertOid(&oid_rsa_sha256));
    try testing.expectEqual(@as(?u16, rsa_pkcs1_sha384), schemeForCertOid(&oid_rsa_sha384));
    try testing.expectEqual(@as(?u16, rsa_pkcs1_sha512), schemeForCertOid(&oid_rsa_sha512));
}

test "tls signature_algorithms_cert: unmodeled OIDs (RSASSA-PSS, PQ, empty, garbage) classify as null" {
    // id-RSASSA-PSS (1.2.840.113549.1.1.10) — hash lives in params, not modeled.
    const pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
    try testing.expectEqual(@as(?u16, null), schemeForCertOid(&pss));
    // id-ML-DSA-65 (2.16.840.1.101.3.4.3.18).
    const mldsa = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
    try testing.expectEqual(@as(?u16, null), schemeForCertOid(&mldsa));
    try testing.expectEqual(@as(?u16, null), schemeForCertOid(&.{}));
    try testing.expectEqual(@as(?u16, null), schemeForCertOid(&[_]u8{ 0x00, 0x01, 0x02 }));
    // A prefix of a real OID must NOT match (exact-equality only).
    try testing.expectEqual(@as(?u16, null), schemeForCertOid(oid_ed25519[0..2]));
}
