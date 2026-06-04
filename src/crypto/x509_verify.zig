//! Small X.509 verification helpers for TLS and CERTFP plumbing.
//!
//! This module intentionally stays below full PKIX validation. It consumes the
//! local strict DER parser in x509.zig, computes CERTFP values, checks parsed
//! validity windows, and performs structural chain checks: issuer/subject DER
//! linkage plus non-empty signature fields. x509.zig does not currently expose
//! signature verification material, so public-key signature verification is not
//! attempted here.
const std = @import("std");
const hash = @import("hash.zig");
const x509 = @import("x509.zig");

pub const Digest = hash.Sha256.Digest;
pub const digest_len = hash.Sha256.digest_len;

pub const Error = x509.Error || error{
    NotYetValid,
    Expired,
    EmptyChain,
    IssuerMismatch,
    NotSelfSigned,
    MissingSignature,
};

pub const LinkInfo = struct {
    subject_der: []const u8,
    issuer_der: []const u8,
    signature_der: []const u8,

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
}

pub fn verifySimpleChain(chain_der: []const []const u8) Error!void {
    if (chain_der.len == 0) return error.EmptyChain;

    var previous = try linkInfo(chain_der[0]);
    try requireSignature(previous);

    if (chain_der.len == 1) {
        if (!previous.isSelfIssued()) return error.NotSelfSigned;
        return;
    }

    for (chain_der[1..]) |issuer_der| {
        const issuer = try linkInfo(issuer_der);
        try requireSignature(issuer);
        if (!std.mem.eql(u8, previous.issuer_der, issuer.subject_der)) {
            return error.IssuerMismatch;
        }
        previous = issuer;
    }

    if (!previous.isSelfIssued()) return error.NotSelfSigned;
}

pub fn verifySimpleChainAt(chain_der: []const []const u8, now_epoch_seconds: i64) Error!void {
    for (chain_der) |der| {
        try validateDerAt(der, now_epoch_seconds);
    }
    return verifySimpleChain(chain_der);
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
    _ = try body.readExpected(x509.Tag.sequence);
    const signature = try body.readExpected(x509.Tag.bit_string);
    try body.expectEmpty();

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

    return .{
        .subject_der = subject.raw,
        .issuer_der = issuer.raw,
        .signature_der = signature_der,
    };
}

fn signatureBytes(tlv: x509.Tlv) x509.Error![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
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
