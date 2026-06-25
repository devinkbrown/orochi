// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! EC P-256 private-key DER codec for daemon TLS certificate loading.
//!
//! Let's Encrypt (and most modern ACME issuance) hands operators an ECDSA
//! P-256 leaf with the private key in one of two encodings:
//!   * **SEC1** `ECPrivateKey` (`-----BEGIN EC PRIVATE KEY-----`).
//!   * **PKCS#8** `PrivateKeyInfo` wrapping that same SEC1 structure under the
//!     `id-ecPublicKey` + `prime256v1` algorithm identifier
//!     (`-----BEGIN PRIVATE KEY-----`).
//! Both decode to the 32-byte secret scalar consumed by
//! `crypto/ecdsa_p256.zig`. Only the NIST P-256 curve is supported (the curve
//! the daemon's TLS stack presents); any other curve is rejected.

const std = @import("std");

const x509 = @import("../crypto/x509.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("ec_pkcs requires a 64-bit target");
}

/// SEC1 / PKCS#8 EC private-key parse failures.
pub const ParseError = x509.Error || error{
    /// The structure is DER, but not a supported key version.
    UnsupportedVersion,
    /// The PKCS#8 AlgorithmIdentifier is not id-ecPublicKey.
    UnsupportedAlgorithm,
    /// The named curve is not prime256v1 (P-256).
    UnsupportedCurve,
    /// The decoded scalar is empty or too wide for P-256.
    InvalidKey,
};

/// Length of a P-256 private scalar.
pub const scalar_len = 32;

/// ASN.1 OID for id-ecPublicKey (1.2.840.10045.2.1).
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
/// ASN.1 OID for prime256v1 / secp256r1 (1.2.840.10045.3.1.7).
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

/// Context tag [0] (curve parameters) inside a SEC1 ECPrivateKey.
const tag_params: u8 = 0xa0;

/// Parse a SEC1 `ECPrivateKey` or a PKCS#8 `PrivateKeyInfo(EC P-256)` DER value
/// and return the 32-byte private scalar (left-padded with zeros if the DER
/// octet string was minimally encoded).
pub fn parseScalar(der: []const u8) ParseError![scalar_len]u8 {
    var top = x509.DerReader.init(der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(seq);
    const version = try body.readExpected(x509.Tag.integer);
    if (version.value.len != 1) return error.UnsupportedVersion;

    switch (version.value[0]) {
        // SEC1 ECPrivateKey: version == 1, then the private-key OCTET STRING.
        0x01 => {
            const private = try body.readExpected(x509.Tag.octet_string);
            // The optional [0] curve parameters follow; when present, enforce
            // P-256 so we never silently accept a key for an unsupported curve.
            if (body.hasRemaining()) {
                if ((try body.peekTag()) == tag_params) {
                    const params = try body.readExpected(tag_params);
                    var p = try body.child(params);
                    const oid = try p.readExpected(x509.Tag.oid);
                    if (!std.mem.eql(u8, oid.value, &oid_prime256v1)) return error.UnsupportedCurve;
                }
            }
            return scalarFromOctets(private.value);
        },
        // PKCS#8 PrivateKeyInfo: version == 0, AlgorithmIdentifier, OCTET STRING.
        0x00 => {
            const alg = try body.readExpected(x509.Tag.sequence);
            var algr = try body.child(alg);
            const alg_oid = try algr.readExpected(x509.Tag.oid);
            if (!std.mem.eql(u8, alg_oid.value, &oid_ec_public_key)) return error.UnsupportedAlgorithm;
            const curve_oid = try algr.readExpected(x509.Tag.oid);
            if (!std.mem.eql(u8, curve_oid.value, &oid_prime256v1)) return error.UnsupportedCurve;

            const inner = try body.readExpected(x509.Tag.octet_string);
            // The OCTET STRING wraps a full SEC1 ECPrivateKey; recurse into it.
            return parseScalar(inner.value);
        },
        else => return error.UnsupportedVersion,
    }
}

fn scalarFromOctets(value: []const u8) ParseError![scalar_len]u8 {
    if (value.len == 0 or value.len > scalar_len) return error.InvalidKey;
    var out: [scalar_len]u8 = [_]u8{0} ** scalar_len;
    @memcpy(out[scalar_len - value.len ..], value);
    return out;
}

const testing = std.testing;

test "parse SEC1 ECPrivateKey scalar" {
    // SEQUENCE { INTEGER 1, OCTET STRING <32 bytes>, [0] { OID prime256v1 } }
    var scalar: [32]u8 = undefined;
    for (&scalar, 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xff);
    var der: [128]u8 = undefined;
    var n: usize = 0;
    der[n] = 0x30;
    n += 1;
    const body_len_pos = n;
    n += 1; // sequence length, filled below
    const body_start = n;
    // version INTEGER 1
    der[n] = 0x02;
    der[n + 1] = 0x01;
    der[n + 2] = 0x01;
    n += 3;
    // privateKey OCTET STRING (32)
    der[n] = 0x04;
    der[n + 1] = 0x20;
    @memcpy(der[n + 2 .. n + 2 + 32], &scalar);
    n += 2 + 32;
    // [0] { OID prime256v1 }
    der[n] = 0xa0;
    der[n + 1] = @intCast(2 + oid_prime256v1.len);
    der[n + 2] = 0x06;
    der[n + 3] = @intCast(oid_prime256v1.len);
    @memcpy(der[n + 4 .. n + 4 + oid_prime256v1.len], &oid_prime256v1);
    n += 4 + oid_prime256v1.len;
    der[body_len_pos] = @intCast(n - body_start);

    const out = try parseScalar(der[0..n]);
    try testing.expectEqualSlices(u8, &scalar, &out);
}

test "rejects non-P256 and malformed" {
    try testing.expectError(error.Truncated, parseScalar(&.{0x30}));
    // version 1 + 33-byte scalar is too wide for P-256.
    var der: [64]u8 = undefined;
    der[0] = 0x30;
    der[1] = 0x05;
    der[2] = 0x02;
    der[3] = 0x01;
    der[4] = 0x01;
    der[5] = 0x04;
    der[6] = 0x21; // 33 bytes claimed but body is short -> Truncated
    try testing.expectError(error.Truncated, parseScalar(der[0..7]));
}
