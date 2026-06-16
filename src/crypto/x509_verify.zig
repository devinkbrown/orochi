//! X.509 verification helpers for TLS and CERTFP plumbing.
//!
//! This module consumes the local strict DER parser in x509.zig, computes
//! CERTFP values, checks parsed validity windows, and verifies certificate
//! chains. Chain verification is cryptographic, not merely structural: each
//! certificate's signature is checked against its issuer's public key using the
//! project's own signature primitives (RSA PKCS#1 v1.5, ECDSA P-256, Ed25519).
//!
//! ## Trust-anchor stance
//!
//! `verifySimpleChain` guarantees **cryptographic chain integrity to a
//! self-signed root**: every certificate `chain[i]` is signed by `chain[i+1]`,
//! the issuer/subject distinguished names link, and the final certificate is
//! self-issued with a signature that verifies under its own embedded key. It
//! does NOT by itself establish trust — a self-signed root verifying its own
//! signature proves only that the chain is internally consistent, not that the
//! root is one the caller chose to trust.
//!
//! The CALLER must still enforce:
//!   * **Anchoring** — that the self-signed root (or a pinned leaf) is actually
//!     trusted, e.g. by matching it against a configured CA set, or by
//!     CertFP/SPKI pinning. `tls_client.zig`'s `verifyChainToTrustAnchors`
//!     performs the configured-anchor form for the outbound/admin TLS client.
//!   * **Naming** — that a leaf's SAN matches the expected hostname.
//!
//! This module is used for OUTBOUND/admin CA-chain verification. It is
//! deliberately independent of CertFP-based SASL EXTERNAL, which authenticates a
//! client by its certificate fingerprint and does not consult chain validity.
const std = @import("std");
const hash = @import("hash.zig");
const x509 = @import("x509.zig");
const rsa_verify = @import("rsa_verify.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const ed25519 = @import("sign.zig");

pub const Digest = hash.Sha256.Digest;
pub const digest_len = hash.Sha256.digest_len;

pub const Error = x509.Error || error{
    NotYetValid,
    Expired,
    EmptyChain,
    IssuerMismatch,
    NotSelfSigned,
    MissingSignature,
    /// The signature algorithm OID is not one this verifier supports.
    UnsupportedSigAlg,
    /// A certificate's signature did not verify under its issuer's public key,
    /// or the signature/key encoding was malformed.
    BadSignature,
};

/// Signature-algorithm OIDs found in a certificate's outer AlgorithmIdentifier.
const SigOid = struct {
    /// sha256WithRSAEncryption (1.2.840.113549.1.1.11).
    const rsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
    /// sha384WithRSAEncryption (1.2.840.113549.1.1.12).
    const rsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
    /// sha512WithRSAEncryption (1.2.840.113549.1.1.13).
    const rsa_sha512 = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
    /// ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    const ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    /// id-Ed25519 (1.3.101.112).
    const ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };
};

pub const LinkInfo = struct {
    subject_der: []const u8,
    issuer_der: []const u8,
    signature_der: []const u8,
    /// The signed TBSCertificate bytes (the message the signature covers).
    tbs_der: []const u8,
    /// The outer signatureAlgorithm OID identifying the signature scheme.
    sig_alg_oid: []const u8,
    /// This certificate's own SubjectPublicKeyInfo (the full SEQUENCE).
    spki_der: []const u8,

    pub fn isSelfIssued(self: LinkInfo) bool {
        return std.mem.eql(u8, self.subject_der, self.issuer_der);
    }

    pub fn hasSignature(self: LinkInfo) bool {
        return self.signature_der.len != 0;
    }
};

pub fn certfp(der: []const u8) Error!Digest {
    const cert = try x509.parse(der);
    return cert.certSha256();
}

pub fn certfpHex(der: []const u8, out: []u8) Error![]const u8 {
    if (out.len < digest_len * 2) return error.OutputTooSmall;
    const digest = try certfp(der);
    return x509.writeHex(&digest, out);
}

pub fn certfpEqual(a: *const Digest, b: *const Digest) bool {
    var diff: u8 = 0;
    for (a.*, b.*) |left, right| {
        diff |= left ^ right;
    }
    return diff == 0;
}

pub fn certfpMatchesDer(der: []const u8, expected: *const Digest) Error!bool {
    const actual = try certfp(der);
    return certfpEqual(&actual, expected);
}

pub fn validateParsedAt(cert: x509.Certificate, now_epoch_seconds: i64) Error!void {
    if (now_epoch_seconds < cert.not_before.epoch_seconds) return error.NotYetValid;
    if (now_epoch_seconds > cert.not_after.epoch_seconds) return error.Expired;
}

pub fn validateDerAt(der: []const u8, now_epoch_seconds: i64) Error!void {
    const cert = try x509.parse(der);
    return validateParsedAt(cert, now_epoch_seconds);
}

pub fn linkInfo(der: []const u8) Error!LinkInfo {
    _ = try x509.parse(der);
    return extractLinkInfo(der);
}

pub fn verifySelfSigned(der: []const u8) Error!void {
    const info = try linkInfo(der);
    try requireSignature(info);
    if (!info.isSelfIssued()) return error.NotSelfSigned;
    // A self-signed certificate must verify under its own embedded key.
    try verifySignedBy(info, info);
}

/// Verify a leaf-first certificate chain.
///
/// In addition to the structural issuer/subject DN linkage, this verifies each
/// certificate's signature against the public key of its issuer:
///   * `chain[i]` is signed by `chain[i+1]` (the next certificate toward the
///     root), and
///   * the final certificate is self-issued and its signature verifies under
///     its OWN embedded key (a self-signed root).
///
/// A broken signature, a DN that does not link, or a missing/self-non-issued
/// tail rejects the whole chain. See the module header for what callers must
/// still enforce (anchoring and naming).
pub fn verifySimpleChain(chain_der: []const []const u8) Error!void {
    if (chain_der.len == 0) return error.EmptyChain;

    var previous = try linkInfo(chain_der[0]);
    try requireSignature(previous);

    if (chain_der.len == 1) {
        if (!previous.isSelfIssued()) return error.NotSelfSigned;
        // The lone certificate is a self-signed root; verify its self-signature.
        try verifySignedBy(previous, previous);
        return;
    }

    for (chain_der[1..]) |issuer_der| {
        const issuer = try linkInfo(issuer_der);
        try requireSignature(issuer);
        if (!std.mem.eql(u8, previous.issuer_der, issuer.subject_der)) {
            return error.IssuerMismatch;
        }
        // The child's signature must verify under the issuer's public key.
        try verifySignedBy(previous, issuer);
        previous = issuer;
    }

    // The chain tip must be a self-signed root with a verifying self-signature.
    if (!previous.isSelfIssued()) return error.NotSelfSigned;
    try verifySignedBy(previous, previous);
}

/// Verify that `child`'s TBS bytes were signed by the holder of `issuer`'s key.
fn verifySignedBy(child: LinkInfo, issuer: LinkInfo) Error!void {
    try verifyCertSignature(child.tbs_der, child.signature_der, child.sig_alg_oid, issuer.spki_der);
}

pub fn verifySimpleChainAt(chain_der: []const []const u8, now_epoch_seconds: i64) Error!void {
    for (chain_der) |der| {
        try validateDerAt(der, now_epoch_seconds);
    }
    return verifySimpleChain(chain_der);
}

/// Validate the daemon's OWN leaf-first server certificate chain at load.
///
/// A server presents `chain[0]` (its leaf) plus any issuing intermediates as
/// opaque DER for the *client* to anchor at a trusted root. It therefore must
/// NOT be held to `verifySimpleChain`'s client-anchoring rules: a real CA-issued
/// server chain never ships a self-signed root (`NotSelfSigned`), and its
/// issuing intermediate may use a key type/curve the server does not itself sign
/// with — e.g. a P-384 Let's Encrypt intermediate — which `verifySimpleChain`
/// would reject as `UnsupportedKey` while verifying the leaf→issuer signature.
///
/// So validate only what the server actually owns: the LEAF must parse and be
/// within its validity window. Intermediates are relayed verbatim and never
/// key-parsed here; the matching signing key is verified separately at load.
pub fn validateServerChainAt(chain_der: []const []const u8, now_epoch_seconds: i64) Error!void {
    if (chain_der.len == 0) return error.EmptyChain;
    try validateDerAt(chain_der[0], now_epoch_seconds);
}

fn requireSignature(info: LinkInfo) Error!void {
    if (!info.hasSignature()) return error.MissingSignature;
}

fn extractLinkInfo(der: []const u8) x509.Error!LinkInfo {
    var top = x509.DerReader.init(der);
    const cert_seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(x509.Tag.sequence);
    const sig_alg = try body.readExpected(x509.Tag.sequence);
    const signature = try body.readExpected(x509.Tag.bit_string);
    try body.expectEmpty();

    const sig_alg_oid = try algorithmOid(body, sig_alg);
    const signature_der = try signatureBytes(signature);
    var tbs_reader = try body.child(tbs);

    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == x509.Tag.context_0_constructed) {
        _ = try tbs_reader.readTlv();
    }

    _ = try tbs_reader.readExpected(x509.Tag.integer);
    _ = try tbs_reader.readExpected(x509.Tag.sequence);
    const issuer = try tbs_reader.readExpected(x509.Tag.sequence);
    _ = try tbs_reader.readExpected(x509.Tag.sequence);
    const subject = try tbs_reader.readExpected(x509.Tag.sequence);
    const spki = try tbs_reader.readExpected(x509.Tag.sequence);

    return .{
        .subject_der = subject.raw,
        .issuer_der = issuer.raw,
        .signature_der = signature_der,
        .tbs_der = tbs.raw,
        .sig_alg_oid = sig_alg_oid,
        .spki_der = spki.raw,
    };
}

/// Read the OID from an AlgorithmIdentifier SEQUENCE (ignoring any parameters).
fn algorithmOid(parent: x509.DerReader, seq_tlv: x509.Tlv) x509.Error![]const u8 {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    while (r.hasRemaining()) _ = try r.readTlv();
    return oid.value;
}

fn signatureBytes(tlv: x509.Tlv) x509.Error![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

/// Cryptographically verify that `signed.tbs_der` carries a valid signature made
/// by the holder of the key in `issuer_spki`, using the scheme named by
/// `signed.sig_alg_oid`.
///
/// Dispatches on the signature-algorithm OID:
///   * sha256/384/512WithRSAEncryption → RSASSA-PKCS1-v1_5 over the matching SHA
///   * ecdsa-with-SHA256 (P-256)       → ECDSA/P-256/SHA-256
///   * id-Ed25519                       → Ed25519 (signs the TBS directly)
///
/// The issuer's key family must be compatible with the signature scheme (an
/// RSA OID requires an RSA issuer key, etc.); a mismatch is `BadSignature`. Any
/// other algorithm is `UnsupportedSigAlg`.
pub fn verifyCertSignature(
    cert_tbs: []const u8,
    sig_value: []const u8,
    sig_alg_oid: []const u8,
    issuer_spki: []const u8,
) Error!void {
    const key = try x509.extractPublicKey(issuer_spki);

    if (std.mem.eql(u8, sig_alg_oid, &SigOid.rsa_sha256)) {
        return verifyRsaPkcs1(key, .sha256, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.rsa_sha384)) {
        return verifyRsaPkcs1(key, .sha384, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.rsa_sha512)) {
        return verifyRsaPkcs1(key, .sha512, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.ecdsa_sha256)) {
        return verifyEcdsaP256(key, cert_tbs, sig_value);
    } else if (std.mem.eql(u8, sig_alg_oid, &SigOid.ed25519)) {
        return verifyEd25519(key, cert_tbs, sig_value);
    }
    return error.UnsupportedSigAlg;
}

fn verifyRsaPkcs1(
    key: x509.SubjectPublicKey,
    alg: rsa_verify.HashAlg,
    tbs: []const u8,
    sig: []const u8,
) Error!void {
    const rsa = switch (key) {
        .rsa => |k| k,
        else => return error.BadSignature,
    };
    var digest: [64]u8 = undefined;
    const digest_slice = digest[0..alg.digestLen()];
    switch (alg) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(tbs, digest[0..32], .{}),
        .sha384 => std.crypto.hash.sha2.Sha384.hash(tbs, digest[0..48], .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(tbs, digest[0..64], .{}),
    }
    const pub_key = rsa_verify.PublicKey{ .n = rsa.modulus, .e = rsa.exponent };
    if (!rsa_verify.verifyPkcs1v15(pub_key, alg, digest_slice, sig)) return error.BadSignature;
}

fn verifyEcdsaP256(key: x509.SubjectPublicKey, tbs: []const u8, sig: []const u8) Error!void {
    const sec1 = switch (key) {
        .ecdsa_p256 => |k| k,
        else => return error.BadSignature,
    };
    const pub_key = ecdsa_p256.parsePublicKeySec1(sec1) catch return error.BadSignature;
    const signature = ecdsa_p256.signatureFromDer(sig) catch return error.BadSignature;
    if (!ecdsa_p256.verify(signature, tbs, pub_key)) return error.BadSignature;
}

fn verifyEd25519(key: x509.SubjectPublicKey, tbs: []const u8, sig: []const u8) Error!void {
    const raw = switch (key) {
        .ed25519 => |k| k,
        else => return error.BadSignature,
    };
    if (raw.len != ed25519.public_key_len) return error.BadSignature;
    if (sig.len != ed25519.signature_len) return error.BadSignature;
    var pk: ed25519.PublicKey = undefined;
    @memcpy(&pk, raw);
    var fixed_sig: ed25519.Signature = undefined;
    @memcpy(&fixed_sig, sig);
    const ok = ed25519.verify(tbs, fixed_sig, pk) catch return error.BadSignature;
    if (!ok) return error.BadSignature;
}

const TestPem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT
    \\BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz
    \\MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj
    \\GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp
    \\LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O
    \\BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf
    \\lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN
    \\Lw0=
    \\-----END CERTIFICATE-----
;

const TestFixture = struct {
    storage: []u8,
    der: []const u8,

    fn deinit(self: TestFixture) void {
        std.testing.allocator.free(self.storage);
    }
};

fn testDer() !TestFixture {
    const allocator = std.testing.allocator;
    const storage = try allocator.alloc(u8, 512);
    errdefer allocator.free(storage);
    const decoded = try x509.pemToDer(TestPem, storage);
    return .{ .storage = storage, .der = storage[0..decoded.len] };
}

test "certfp of known DER and constant-time compare" {
    const fixture = try testDer();
    defer fixture.deinit();
    const der = fixture.der;

    const fp = try certfp(der);
    var hex: [digest_len * 2]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        "231a5709f3e42db6130a35b75d56b45dedee32690a9e6f71bf6ad87e6707ba7a",
        try certfpHex(der, &hex),
    );

    var direct: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &direct, .{});
    try std.testing.expect(certfpEqual(&fp, &direct));
    try std.testing.expect(try certfpMatchesDer(der, &fp));

    var different = fp;
    different[digest_len - 1] ^= 1;
    try std.testing.expect(!certfpEqual(&fp, &different));
}

test "validity window pass and fail" {
    const fixture = try testDer();
    defer fixture.deinit();
    const der = fixture.der;
    const cert = try x509.parse(der);

    try validateParsedAt(cert, cert.not_before.epoch_seconds);
    try validateParsedAt(cert, cert.not_after.epoch_seconds);
    try validateDerAt(der, cert.not_before.epoch_seconds + 1);
    try std.testing.expectError(error.NotYetValid, validateParsedAt(cert, cert.not_before.epoch_seconds - 1));
    try std.testing.expectError(error.Expired, validateDerAt(der, cert.not_after.epoch_seconds + 1));
}

test "self-signed certificate is accepted structurally" {
    const fixture = try testDer();
    defer fixture.deinit();
    const der = fixture.der;

    const info = try linkInfo(der);
    try std.testing.expect(info.isSelfIssued());
    try std.testing.expect(info.hasSignature());
    try verifySelfSigned(der);

    const chain = [_][]const u8{der};
    try verifySimpleChain(&chain);
    const cert = try x509.parse(der);
    try verifySimpleChainAt(&chain, cert.not_before.epoch_seconds);
}

// ===========================================================================
// Real signature-verification tests.
//
// These mint live certificate chains with the project's own signing
// primitives, so the positive cases prove the verifier accepts a genuinely
// signed chain and the negative cases prove it rejects forgeries (a flipped
// signature byte, a leaf signed by the wrong key, an unsupported algorithm, and
// an expired cert). x509_selfsign mints self-signed roots; the helpers below
// mint a CA-signed leaf whose issuer DN differs from its subject DN.
// ===========================================================================

const x509_selfsign = @import("../proto/x509_selfsign.zig");
const StdEd25519 = std.crypto.sign.Ed25519;

const not_before: i64 = 1_704_067_200; // 2024-01-01
const not_after: i64 = 1_924_991_999; // 2030-12-31

// A small fixed-buffer DER writer mirroring x509_selfsign's, used to mint a
// CA-signed leaf (issuer DN != subject DN) signed by a separate issuer key.
const W = struct {
    buf: []u8,
    pos: usize = 0,
    fn init(buf: []u8) W {
        return .{ .buf = buf };
    }
    fn bytes(self: *const W) []const u8 {
        return self.buf[0..self.pos];
    }
    fn raw(self: *W, b: []const u8) void {
        @memcpy(self.buf[self.pos..][0..b.len], b);
        self.pos += b.len;
    }
    fn tlv(self: *W, tag: u8, val: []const u8) void {
        self.buf[self.pos] = tag;
        self.pos += 1;
        if (val.len < 128) {
            self.buf[self.pos] = @intCast(val.len);
            self.pos += 1;
        } else {
            // Single-byte long form (all test certs fit < 256, < 65536).
            var tmp: [8]u8 = undefined;
            var n = val.len;
            var c: usize = 0;
            while (n != 0) : (n >>= 8) {
                tmp[tmp.len - 1 - c] = @intCast(n & 0xff);
                c += 1;
            }
            self.buf[self.pos] = 0x80 | @as(u8, @intCast(c));
            self.pos += 1;
            @memcpy(self.buf[self.pos..][0..c], tmp[tmp.len - c ..]);
            self.pos += c;
        }
        self.raw(val);
    }
};

const oid_ed25519_bytes = [_]u8{ 0x2b, 0x65, 0x70 };

fn writeAlgEd25519(w: *W) void {
    var body: [8]u8 = undefined;
    var b = W.init(&body);
    b.tlv(0x06, &oid_ed25519_bytes);
    w.tlv(0x30, b.bytes());
}

fn writeNameCn(w: *W, cn: []const u8) void {
    var attr_body: [80]u8 = undefined;
    var ab = W.init(&attr_body);
    ab.tlv(0x06, &[_]u8{ 0x55, 0x04, 0x03 }); // commonName
    ab.tlv(0x0c, cn); // UTF8String
    var attr: [96]u8 = undefined;
    var a = W.init(&attr);
    a.tlv(0x30, ab.bytes());
    var rdn: [112]u8 = undefined;
    var r = W.init(&rdn);
    r.tlv(0x31, a.bytes()); // SET
    w.tlv(0x30, r.bytes());
}

fn writeValidity(w: *W, nb: i64, na: i64) void {
    var body: [40]u8 = undefined;
    var b = W.init(&body);
    var nbuf: [15]u8 = undefined;
    var abuf: [15]u8 = undefined;
    const before = x509_selfsign_formatTime(&nbuf, nb);
    const after = x509_selfsign_formatTime(&abuf, na);
    b.tlv(before.tag, nbuf[0..before.len]);
    b.tlv(after.tag, abuf[0..after.len]);
    w.tlv(0x30, b.bytes());
}

const TimeOut = struct { tag: u8, len: usize };

// Reuse the project epoch->ASN.1 time encoding by formatting via UTCTime for the
// in-range years the tests use (2024-2030 -> 1950..2049 => UTCTime).
fn x509_selfsign_formatTime(out: *[15]u8, unix_seconds: i64) TimeOut {
    const spd: i64 = 86_400;
    const days = @divFloor(unix_seconds, spd);
    const sod = @mod(unix_seconds, spd);
    const z = days + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097;
    const yoe = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36_524) - @divTrunc(doe, 146_096), 365);
    var year = yoe + era * 400;
    const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp = @divTrunc(5 * doy + 2, 153);
    const day = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const month = mp + if (mp < 10) @as(i64, 3) else -9;
    if (month <= 2) year += 1;
    const hour = @divTrunc(sod, 3600);
    const minute = @divTrunc(sod - hour * 3600, 60);
    const second = sod - hour * 3600 - minute * 60;
    const w2 = struct {
        fn f(o: []u8, v: i64) void {
            o[0] = '0' + @as(u8, @intCast(@divTrunc(v, 10)));
            o[1] = '0' + @as(u8, @intCast(@mod(v, 10)));
        }
    }.f;
    w2(out[0..2], @mod(year, 100));
    w2(out[2..4], month);
    w2(out[4..6], day);
    w2(out[6..8], hour);
    w2(out[8..10], minute);
    w2(out[10..12], second);
    out[12] = 'Z';
    return .{ .tag = 0x17, .len = 13 };
}

fn writeSpkiEd25519(w: *W, pub_key: [32]u8) void {
    var body: [64]u8 = undefined;
    var b = W.init(&body);
    writeAlgEd25519(&b);
    var bit: [33]u8 = undefined;
    bit[0] = 0;
    @memcpy(bit[1..], &pub_key);
    b.tlv(0x03, &bit);
    w.tlv(0x30, b.bytes());
}

/// Mint a leaf cert whose issuer DN is `issuer_cn`, subject DN is `subject_cn`,
/// embedding `subject_pub`, signed (Ed25519) with `issuer_kp`. Returns the DER
/// in `out`.
fn mintEd25519Leaf(
    out: []u8,
    issuer_cn: []const u8,
    subject_cn: []const u8,
    subject_pub: [32]u8,
    issuer_kp: StdEd25519.KeyPair,
    nb: i64,
    na: i64,
) ![]const u8 {
    var tbs_body: [512]u8 = undefined;
    var tb = W.init(&tbs_body);
    // version [0] EXPLICIT INTEGER 2
    var ver: [5]u8 = undefined;
    var vw = W.init(&ver);
    vw.tlv(0x02, &[_]u8{0x02});
    tb.tlv(0xa0, vw.bytes());
    tb.tlv(0x02, &[_]u8{ 0x12, 0x34 }); // serial
    writeAlgEd25519(&tb); // signature alg in TBS
    writeNameCn(&tb, issuer_cn);
    writeValidity(&tb, nb, na);
    writeNameCn(&tb, subject_cn);
    writeSpkiEd25519(&tb, subject_pub);

    var tbs: [560]u8 = undefined;
    var tw = W.init(&tbs);
    tw.tlv(0x30, tb.bytes());
    const tbs_der = tw.bytes();

    const sig = try StdEd25519.KeyPair.sign(issuer_kp, tbs_der, null);
    const sig_bytes = sig.toBytes();

    var body: [700]u8 = undefined;
    var bw = W.init(&body);
    bw.raw(tbs_der);
    writeAlgEd25519(&bw);
    var bit: [65]u8 = undefined;
    bit[0] = 0;
    @memcpy(bit[1..], &sig_bytes);
    bw.tlv(0x03, &bit);

    var cert = W.init(out);
    cert.tlv(0x30, bw.bytes());
    return cert.bytes();
}

fn ed25519KpFromSeed(seed_byte: u8) !StdEd25519.KeyPair {
    return StdEd25519.KeyPair.generateDeterministic([_]u8{seed_byte} ** 32);
}

test "valid Ed25519 two-cert chain (leaf signed by self-signed root) verifies" {
    const root_kp = try ed25519KpFromSeed(0x01);
    const leaf_kp = try ed25519KpFromSeed(0x02);

    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Orochi Test Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x10, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    var leaf_buf: [700]u8 = undefined;
    const leaf = try mintEd25519Leaf(
        &leaf_buf,
        "Orochi Test Root", // issuer DN == root subject DN
        "leaf.example.test",
        leaf_kp.public_key.toBytes(),
        root_kp,
        not_before,
        not_after,
    );

    const chain = [_][]const u8{ leaf, root };
    try verifySimpleChain(&chain);
    try verifySimpleChainAt(&chain, not_before + 1);
}

test "valid ECDSA-P256 self-signed root verifies and a flipped signature byte is rejected" {
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var root_buf: [1024]u8 = undefined;
    const root = try x509_selfsign.buildSelfSignedEcdsaP256(&root_buf, .{
        .common_name = "ecdsa.root.test",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x20, 0x01 },
        .key_pair = kp,
        .is_ca = true,
    });

    const chain = [_][]const u8{root};
    try verifySimpleChain(&chain);

    // Negative: corrupt the trailing signature byte and reject.
    var bad = try std.testing.allocator.alloc(u8, root.len);
    defer std.testing.allocator.free(bad);
    @memcpy(bad, root);
    bad[bad.len - 1] ^= 0x01;
    const bad_chain = [_][]const u8{bad};
    try std.testing.expectError(error.BadSignature, verifySimpleChain(&bad_chain));
}

test "valid RSA-SHA256 self-signed root verifies" {
    const rsa_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
    const rsa_e = hexToBytes("010001");
    const rsa_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
    const rsa_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
    const rsa_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
    const rsa_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
    const rsa_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
    const rsa_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");
    const priv = @import("rsa_sign.zig").PrivateKey{ .n = &rsa_n, .e = &rsa_e, .d = &rsa_d, .p = &rsa_p, .q = &rsa_q, .dp = &rsa_dp, .dq = &rsa_dq, .qinv = &rsa_qinv };

    var root_buf: [2048]u8 = undefined;
    const root = try x509_selfsign.buildSelfSignedRsa(&root_buf, .{
        .common_name = "rsa.root.test",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x30, 0x01 },
        .public_modulus = &rsa_n,
        .public_exponent = &rsa_e,
        .private_key = priv,
        .is_ca = true,
    });

    const chain = [_][]const u8{root};
    try verifySimpleChain(&chain);
    try verifySimpleChainAt(&chain, not_before + 1);
}

test "chain where leaf signature is corrupted is rejected" {
    const root_kp = try ed25519KpFromSeed(0x05);
    const leaf_kp = try ed25519KpFromSeed(0x06);

    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Corrupt Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x40, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    var leaf_buf: [700]u8 = undefined;
    const leaf = try mintEd25519Leaf(&leaf_buf, "Corrupt Root", "leaf.test", leaf_kp.public_key.toBytes(), root_kp, not_before, not_after);

    // Flip the last byte of the leaf (its Ed25519 signature tail).
    var corrupted = try std.testing.allocator.alloc(u8, leaf.len);
    defer std.testing.allocator.free(corrupted);
    @memcpy(corrupted, leaf);
    corrupted[corrupted.len - 1] ^= 0x01;

    const chain = [_][]const u8{ corrupted, root };
    try std.testing.expectError(error.BadSignature, verifySimpleChain(&chain));
}

test "chain where leaf was signed by a different key than the issuer SPKI is rejected" {
    const root_kp = try ed25519KpFromSeed(0x07); // root's published key
    const attacker_kp = try ed25519KpFromSeed(0x08); // actually signs the leaf
    const leaf_kp = try ed25519KpFromSeed(0x09);

    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Honest Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x50, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    // The leaf names "Honest Root" as issuer (DN links) but is signed by the
    // attacker's key, which is NOT the key in the root's SPKI.
    var leaf_buf: [700]u8 = undefined;
    const leaf = try mintEd25519Leaf(&leaf_buf, "Honest Root", "forged.test", leaf_kp.public_key.toBytes(), attacker_kp, not_before, not_after);

    const chain = [_][]const u8{ leaf, root };
    try std.testing.expectError(error.BadSignature, verifySimpleChain(&chain));
}

test "unsupported signature algorithm is rejected with UnsupportedSigAlg" {
    // Craft a minimal cert whose outer signatureAlgorithm OID is a supported-
    // looking-but-not OID (md5WithRSAEncryption, 1.2.840.113549.1.1.4), with a
    // valid RSA-shaped SPKI so dispatch reaches the OID switch and rejects it.
    // We build it by taking a valid Ed25519 self-signed cert and verifying the
    // dispatcher's unsupported branch directly via verifyCertSignature.
    const fixture = try testDer();
    defer fixture.deinit();
    const info = try linkInfo(fixture.der);

    const md5_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 };
    try std.testing.expectError(
        error.UnsupportedSigAlg,
        verifyCertSignature(info.tbs_der, info.signature_der, &md5_rsa, info.spki_der),
    );
}

test "expired certificate is rejected by verifySimpleChainAt" {
    const root_kp = try ed25519KpFromSeed(0x0a);
    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "Expiring Root",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x60, 0x01 },
        .key_pair = root_kp,
        .is_ca = true,
    });

    const chain = [_][]const u8{root};
    // Signature still verifies, but the clock is past not_after.
    try verifySimpleChain(&chain);
    try std.testing.expectError(error.Expired, verifySimpleChainAt(&chain, not_after + 1));
    try std.testing.expectError(error.NotYetValid, verifySimpleChainAt(&chain, not_before - 1));
}

test "bootstrapped Ed25519 self-signed leaf still validates with real signature checks" {
    const tls_certs = @import("../daemon/tls_certs.zig");
    var loaded = try tls_certs.loadOrBootstrap(std.testing.allocator, std.testing.io, .{
        .enabled = true,
        .dns_name = "bootstrap.test",
    });
    defer loaded.deinit(std.testing.allocator);

    // The daemon's own bootstrap chain must pass the upgraded, signature-checking
    // verifier (this is what main.zig's validateTlsChain runs at boot).
    try verifySimpleChain(loaded.cert_chain);
    const cert = try x509.parse(loaded.cert_chain[0]);
    try verifySimpleChainAt(loaded.cert_chain, cert.not_before.epoch_seconds + 1);
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
