// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal fail-closed OCSP response parser for TLS OCSP stapling.
//!
//! This module implements the DER structure checks needed to consume stapled
//! OCSP responses (RFC 6960) and extract each SingleResponse CertID/status. It
//! intentionally does not verify the BasicOCSPResponse responder signature or
//! validate responder authorization; callers must do that before trusting the
//! freshness or authenticity of the result.
const std = @import("std");
const x509 = @import("x509.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_verify = @import("rsa_verify.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

pub const DefaultMaxResponses = 8;

pub const Error = x509.Error || error{
    InvalidOcspResponse,
    InvalidResponseStatus,
    InvalidGeneralizedTime,
    MissingResponseBytes,
    UnexpectedResponseBytes,
    UnsupportedResponseType,
    TooManyResponses,
};

const Asn1Tag = struct {
    const enumerated = 0x0A;
    const context_0_primitive = 0x80;
    const context_1_primitive = 0x81;
    const context_2_primitive = 0x82;
    const context_2_constructed = 0xA2;
};

const Oid = struct {
    // id-pkix-ocsp-basic: 1.3.6.1.5.5.7.48.1.1
    const ocsp_basic = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
};

pub const ResponseStatus = enum(u8) {
    successful = 0,
    malformedRequest = 1,
    internalError = 2,
    tryLater = 3,
    sigRequired = 5,
    unauthorized = 6,
};

pub const CertStatus = enum {
    good,
    revoked,
    unknown,
};

pub const SingleResponse = struct {
    /// AlgorithmIdentifier.algorithm from CertID.hashAlgorithm.
    hash_algorithm_oid: []const u8,
    /// CertID.issuerNameHash; retained as a slice into the OCSP DER input.
    issuer_name_hash: []const u8,
    /// CertID.issuerKeyHash; retained as a slice into the OCSP DER input.
    issuer_key_hash: []const u8,
    /// DER INTEGER contents for CertID.serialNumber, including a leading sign
    /// zero when DER required one for a positive serial.
    serial: []const u8,
    cert_status: CertStatus,
    /// Validated GeneralizedTime bytes (`YYYYMMDDHHMMSSZ`).
    this_update: []const u8,
    /// Optional validated nextUpdate GeneralizedTime bytes.
    next_update: ?[]const u8,
};

pub fn ParsedResponse(comptime max_responses: usize) type {
    return struct {
        const Self = @This();

        der: []const u8,
        response_status: ResponseStatus,
        basic_response_der: ?[]const u8,
        /// DER TLV for BasicOCSPResponse.tbsResponseData; signed by
        /// BasicOCSPResponse.signature.
        tbs_response_data_der: []const u8,
        /// AlgorithmIdentifier.algorithm from BasicOCSPResponse.signatureAlgorithm.
        signature_algorithm_oid: []const u8,
        /// Raw bytes from BasicOCSPResponse.signature BIT STRING.
        signature_value: []const u8,
        responses: [max_responses]SingleResponse,
        response_count: usize,

        pub fn responseAt(self: *const Self, index: usize) ?SingleResponse {
            if (index >= self.response_count) return null;
            return self.responses[index];
        }
    };
}

pub const Parsed = ParsedResponse(DefaultMaxResponses);

pub fn parse(der: []const u8) Error!Parsed {
    return parseBounded(DefaultMaxResponses, der);
}

pub fn parseBounded(comptime max_responses: usize, der: []const u8) Error!ParsedResponse(max_responses) {
    if (der.len == 0) return error.EmptyInput;
    if (der.len > x509.MaxDerLen) return error.Oversize;

    var parsed = ParsedResponse(max_responses){
        .der = der,
        .response_status = .successful,
        .basic_response_der = null,
        .tbs_response_data_der = &.{},
        .signature_algorithm_oid = &.{},
        .signature_value = &.{},
        .responses = undefined,
        .response_count = 0,
    };

    var top = x509.DerReader.init(der);
    const ocsp_response = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(ocsp_response);
    parsed.response_status = try parseResponseStatus(try body.readExpected(Asn1Tag.enumerated));

    if (parsed.response_status != .successful) {
        if (body.hasRemaining()) return error.UnexpectedResponseBytes;
        return parsed;
    }

    if (!body.hasRemaining()) return error.MissingResponseBytes;
    const response_bytes_explicit = try body.readExpected(x509.Tag.context_0_constructed);
    try body.expectEmpty();
    const basic_der = try parseResponseBytes(body, response_bytes_explicit);
    parsed.basic_response_der = basic_der;
    try parseBasicOcspResponse(max_responses, &parsed, basic_der);
    return parsed;
}

pub fn statusForSerial(parsed: anytype, serial: []const u8) ?CertStatus {
    for (parsed.responses[0..parsed.response_count]) |single| {
        if (serialsEqual(single.serial, serial)) return single.cert_status;
    }
    return null;
}

/// Verify a BasicOCSPResponse signed directly by the issuing CA.
///
/// This covers the common stapling case where `signature` authenticates
/// `tbsResponseData` with the issuer certificate's SubjectPublicKeyInfo. OCSP
/// delegated responders are deliberately out of scope here: this function does
/// not validate responder certificates embedded in the BasicOCSPResponse, nor
/// does it enforce id-kp-OCSPSigning EKU. A caller that accepts delegated OCSP
/// responders must build and authorize that responder chain before trusting the
/// response.
pub fn verifyResponseSignature(parsed: anytype, issuer_spki_der: []const u8) bool {
    if (parsed.basic_response_der == null) return false;
    if (parsed.tbs_response_data_der.len == 0 or
        parsed.signature_algorithm_oid.len == 0 or
        parsed.signature_value.len == 0)
    {
        return false;
    }
    return verifyDerSignature(
        parsed.signature_algorithm_oid,
        issuer_spki_der,
        parsed.tbs_response_data_der,
        parsed.signature_value,
    );
}

/// Verify an X.509-style DER signature whose key is carried in SPKI form.
///
/// This helper is shared by OCSP and CRL parsing code. It intentionally
/// supports only the signature schemes used by the daemon's certificate path:
/// SHA256-RSA PKCS#1 v1.5, RSA-PSS with SHA-256 and 32-byte salt, ECDSA
/// P-256/SHA-256, ECDSA P-384/SHA-384, and Ed25519.
pub fn verifyDerSignature(
    signature_algorithm_oid: []const u8,
    signer_spki_der: []const u8,
    signed_data: []const u8,
    signature: []const u8,
) bool {
    const key = parsePublicKeyFromSpki(signer_spki_der) catch return false;
    verifyWithOid(key, signature_algorithm_oid, signed_data, signature) catch return false;
    return true;
}

fn parseResponseStatus(tlv: x509.Tlv) Error!ResponseStatus {
    if (tlv.value.len != 1) return error.InvalidResponseStatus;
    return switch (tlv.value[0]) {
        0 => .successful,
        1 => .malformedRequest,
        2 => .internalError,
        3 => .tryLater,
        5 => .sigRequired,
        6 => .unauthorized,
        else => error.InvalidResponseStatus,
    };
}

fn parseResponseBytes(parent: x509.DerReader, explicit_tlv: x509.Tlv) Error![]const u8 {
    var explicit = try parent.child(explicit_tlv);
    const seq_tlv = try explicit.readExpected(x509.Tag.sequence);
    try explicit.expectEmpty();

    var seq = try explicit.child(seq_tlv);
    const oid_tlv = try seq.readExpected(x509.Tag.oid);
    try validateOid(oid_tlv.value);
    if (!std.mem.eql(u8, oid_tlv.value, &Oid.ocsp_basic)) return error.UnsupportedResponseType;

    const response = try seq.readExpected(x509.Tag.octet_string);
    try seq.expectEmpty();
    return response.value;
}

fn parseBasicOcspResponse(
    comptime max_responses: usize,
    parsed: *ParsedResponse(max_responses),
    der: []const u8,
) Error!void {
    var top = x509.DerReader.init(der);
    const basic = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(basic);
    const tbs = try body.readExpected(x509.Tag.sequence);

    parsed.tbs_response_data_der = tbs.raw;
    parsed.signature_algorithm_oid = try parseAlgorithmIdentifier(body, try body.readExpected(x509.Tag.sequence));
    parsed.signature_value = try parseSignatureBitString(try body.readExpected(x509.Tag.bit_string));
    if (body.hasRemaining()) {
        _ = try body.readExpected(x509.Tag.context_0_constructed); // certs
    }
    try body.expectEmpty();

    try parseResponseData(max_responses, parsed, body, tbs);
}

fn parseResponseData(
    comptime max_responses: usize,
    parsed: *ParsedResponse(max_responses),
    parent: x509.DerReader,
    tbs_tlv: x509.Tlv,
) Error!void {
    var tbs = try parent.child(tbs_tlv);

    if (tbs.hasRemaining() and try tbs.peekTag() == x509.Tag.context_0_constructed) {
        try parseVersion(tbs, try tbs.readTlv());
    }

    const responder = try tbs.readTlv();
    switch (responder.tag) {
        x509.Tag.context_1_constructed,
        Asn1Tag.context_2_primitive,
        Asn1Tag.context_2_constructed,
        => {},
        else => return error.InvalidOcspResponse,
    }

    _ = try parseGeneralizedTime(try tbs.readExpected(x509.Tag.generalized_time));

    const responses_tlv = try tbs.readExpected(x509.Tag.sequence);
    var responses = try tbs.child(responses_tlv);
    while (responses.hasRemaining()) {
        if (parsed.response_count >= parsed.responses.len) return error.TooManyResponses;
        parsed.responses[parsed.response_count] = try parseSingleResponse(responses, try responses.readExpected(x509.Tag.sequence));
        parsed.response_count += 1;
    }

    if (tbs.hasRemaining()) {
        _ = try tbs.readExpected(x509.Tag.context_1_constructed); // responseExtensions
    }
    try tbs.expectEmpty();
}

fn parseVersion(parent: x509.DerReader, version_tlv: x509.Tlv) Error!void {
    var explicit = try parent.child(version_tlv);
    const version = try explicit.readExpected(x509.Tag.integer);
    try explicit.expectEmpty();
    try validateDerInteger(version.value);
    if (version.value.len != 1 or version.value[0] != 0) return error.InvalidOcspResponse;
}

fn parseSingleResponse(parent: x509.DerReader, single_tlv: x509.Tlv) Error!SingleResponse {
    var single = try parent.child(single_tlv);
    const cert_id = try parseCertId(single, try single.readExpected(x509.Tag.sequence));
    const status = try parseCertStatus(single, try single.readTlv());
    const this_update = try parseGeneralizedTime(try single.readExpected(x509.Tag.generalized_time));

    var next_update: ?[]const u8 = null;
    if (single.hasRemaining() and try single.peekTag() == x509.Tag.context_0_constructed) {
        var explicit = try single.child(try single.readTlv());
        next_update = try parseGeneralizedTime(try explicit.readExpected(x509.Tag.generalized_time));
        try explicit.expectEmpty();
    }

    if (single.hasRemaining()) {
        _ = try single.readExpected(x509.Tag.context_1_constructed); // singleExtensions
    }
    try single.expectEmpty();

    return .{
        .hash_algorithm_oid = cert_id.hash_algorithm_oid,
        .issuer_name_hash = cert_id.issuer_name_hash,
        .issuer_key_hash = cert_id.issuer_key_hash,
        .serial = cert_id.serial,
        .cert_status = status,
        .this_update = this_update,
        .next_update = next_update,
    };
}

const CertId = struct {
    hash_algorithm_oid: []const u8,
    issuer_name_hash: []const u8,
    issuer_key_hash: []const u8,
    serial: []const u8,
};

fn parseCertId(parent: x509.DerReader, cert_id_tlv: x509.Tlv) Error!CertId {
    var cert_id = try parent.child(cert_id_tlv);
    const hash_algorithm_oid = try parseAlgorithmIdentifier(cert_id, try cert_id.readExpected(x509.Tag.sequence));
    const issuer_name_hash = try cert_id.readExpected(x509.Tag.octet_string);
    const issuer_key_hash = try cert_id.readExpected(x509.Tag.octet_string);
    const serial = try cert_id.readExpected(x509.Tag.integer);
    try validatePositiveInteger(serial.value);
    try cert_id.expectEmpty();

    return .{
        .hash_algorithm_oid = hash_algorithm_oid,
        .issuer_name_hash = issuer_name_hash.value,
        .issuer_key_hash = issuer_key_hash.value,
        .serial = serial.value,
    };
}

fn parseAlgorithmIdentifier(parent: x509.DerReader, seq_tlv: x509.Tlv) Error![]const u8 {
    var alg = try parent.child(seq_tlv);
    const oid_tlv = try alg.readExpected(x509.Tag.oid);
    try validateOid(oid_tlv.value);
    if (alg.hasRemaining()) {
        _ = try alg.readTlv(); // optional parameters
    }
    try alg.expectEmpty();
    return oid_tlv.value;
}

fn parseCertStatus(parent: x509.DerReader, status_tlv: x509.Tlv) Error!CertStatus {
    return switch (status_tlv.tag) {
        Asn1Tag.context_0_primitive => blk: {
            if (status_tlv.value.len != 0) return error.InvalidOcspResponse;
            break :blk .good;
        },
        x509.Tag.context_1_constructed => blk: {
            var revoked = try parent.child(status_tlv);
            _ = try parseGeneralizedTime(try revoked.readExpected(x509.Tag.generalized_time));
            if (revoked.hasRemaining()) {
                _ = try revoked.readExpected(x509.Tag.context_0_constructed); // revocationReason
            }
            try revoked.expectEmpty();
            break :blk .revoked;
        },
        Asn1Tag.context_2_primitive => blk: {
            if (status_tlv.value.len != 0) return error.InvalidOcspResponse;
            break :blk .unknown;
        },
        else => error.InvalidOcspResponse,
    };
}

fn parseBitString(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

fn parseSignatureBitString(tlv: x509.Tlv) Error![]const u8 {
    const bytes = try parseBitString(tlv);
    if (tlv.value[0] != 0) return error.InvalidBitString;
    return bytes;
}

fn parseGeneralizedTime(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.value.len != 15 or tlv.value[14] != 'Z') return error.InvalidGeneralizedTime;
    _ = try digits(tlv.value[0..4]);
    const month = try digits(tlv.value[4..6]);
    const day = try digits(tlv.value[6..8]);
    const hour = try digits(tlv.value[8..10]);
    const minute = try digits(tlv.value[10..12]);
    const second = try digits(tlv.value[12..14]);
    if (month < 1 or month > 12) return error.InvalidGeneralizedTime;
    if (day < 1 or day > 31) return error.InvalidGeneralizedTime;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidGeneralizedTime;
    return tlv.value;
}

fn digits(bytes: []const u8) Error!u16 {
    var value: u16 = 0;
    for (bytes) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidGeneralizedTime;
        value = value * 10 + @as(u16, byte - '0');
    }
    return value;
}

fn validatePositiveInteger(value: []const u8) Error!void {
    try validateDerInteger(value);
    if ((value[0] & 0x80) != 0) return error.InvalidInteger;
}

fn validateDerInteger(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidInteger;
    if (value.len > 1) {
        if (value[0] == 0x00 and (value[1] & 0x80) == 0) return error.InvalidInteger;
        if (value[0] == 0xFF and (value[1] & 0x80) != 0) return error.InvalidInteger;
    }
}

fn validateOid(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidOid;
    var at_arc_start = true;
    var ended_arc = false;
    for (value) |byte| {
        if (at_arc_start and byte == 0x80) return error.InvalidOid;
        ended_arc = (byte & 0x80) == 0;
        at_arc_start = ended_arc;
    }
    if (!ended_arc) return error.InvalidOid;
}

fn serialsEqual(a_der: []const u8, b_der: []const u8) bool {
    if (std.mem.eql(u8, a_der, b_der)) return true;
    return std.mem.eql(u8, unsignedSerial(a_der), unsignedSerial(b_der));
}

fn unsignedSerial(serial: []const u8) []const u8 {
    if (serial.len > 1 and serial[0] == 0x00) return serial[1..];
    return serial;
}

const PublicKey = union(enum) {
    rsa: rsa_verify.PublicKey,
    ecdsa_p256: ecdsa_p256.PublicKey,
    ecdsa_p384: EcdsaP384.PublicKey,
    ed25519: Ed25519.PublicKey,
};

fn verifyWithOid(key: PublicKey, oid: []const u8, msg: []const u8, sig: []const u8) !void {
    if (oidEq(oid, &oid_ecdsa_sha256)) {
        const pk = switch (key) {
            .ecdsa_p256 => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        const decoded = try ecdsa_p256.signatureFromDer(sig);
        if (!ecdsa_p256.verify(decoded, msg, pk)) return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_ecdsa_sha384)) {
        const pk = switch (key) {
            .ecdsa_p384 => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        const decoded = EcdsaP384.Signature.fromDer(sig) catch return error.BadSignature;
        decoded.verify(msg, pk) catch return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_sha256_rsa)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
        if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, sig)) return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_rsassa_pss)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
        if (!rsa_verify.verifyPss(pk, .sha256, &digest, sig, 32)) return error.BadSignature;
        return;
    }
    if (oidEq(oid, &oid_ed25519)) {
        const pk = switch (key) {
            .ed25519 => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        if (sig.len != Ed25519.Signature.encoded_length) return error.BadSignature;
        const decoded = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
        decoded.verify(msg, pk) catch return error.BadSignature;
        return;
    }
    return error.UnsupportedSignatureScheme;
}

fn parsePublicKeyFromSpki(spki_der: []const u8) !PublicKey {
    var top = x509.DerReader.init(spki_der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(x509.Tag.sequence);
    const key_bits = try spki.readExpected(x509.Tag.bit_string);
    try spki.expectEmpty();
    const alg = try parseSpkiAlgorithm(spki, alg_seq);
    const key_bytes = try bitStringBytesZero(key_bits);
    if (oidEq(alg.oid, &oid_rsa_encryption)) {
        var r = x509.DerReader.init(key_bytes);
        const rsa_seq = try r.readExpected(x509.Tag.sequence);
        try r.expectEmpty();
        var body = try r.child(rsa_seq);
        const n = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        const e = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        try body.expectEmpty();
        return .{ .rsa = .{ .n = n, .e = e } };
    }
    if (oidEq(alg.oid, &oid_ec_public_key)) {
        const params = alg.params orelse return error.UnsupportedPublicKey;
        if (oidEq(params, &oid_prime256v1)) {
            return .{ .ecdsa_p256 = try ecdsa_p256.parsePublicKeySec1(key_bytes) };
        }
        if (oidEq(params, &oid_secp384r1)) {
            return .{ .ecdsa_p384 = EcdsaP384.PublicKey.fromSec1(key_bytes) catch return error.UnsupportedPublicKey };
        }
        return error.UnsupportedPublicKey;
    }
    if (oidEq(alg.oid, &oid_ed25519)) {
        if (key_bytes.len != Ed25519.PublicKey.encoded_length) return error.UnsupportedPublicKey;
        return .{ .ed25519 = Ed25519.PublicKey.fromBytes(key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return error.UnsupportedPublicKey };
    }
    return error.UnsupportedPublicKey;
}

const SpkiAlgorithm = struct {
    oid: []const u8,
    params: ?[]const u8,
};

fn parseSpkiAlgorithm(parent: x509.DerReader, seq_tlv: x509.Tlv) !SpkiAlgorithm {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    try validateOid(oid.value);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) {
        const p = try r.readTlv();
        if (p.tag == x509.Tag.oid) params = p.value;
    }
    try r.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

fn bitStringBytesZero(tlv: x509.Tlv) ![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    if (tlv.value[0] != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

fn positiveIntegerBytes(tlv: x509.Tlv) ![]const u8 {
    if (tlv.tag != x509.Tag.integer or tlv.value.len == 0) return error.InvalidInteger;
    if (tlv.value[0] & 0x80 != 0) return error.InvalidInteger;
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..];
    if (v.len == 0) return error.InvalidInteger;
    return v;
}

fn oidEq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const oid_rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
const oid_sha256_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
const oid_rsassa_pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_secp384r1 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_ecdsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };

const ocsp_good_one_response = [_]u8{
    0x30, 0x81, 0xBD,
    0x0A, 0x01, 0x00,
    0xA0, 0x81, 0xB7,
    0x30, 0x81, 0xB4,
    0x06, 0x09, 0x2B,
    0x06, 0x01, 0x05,
    0x05, 0x07, 0x30,
    0x01, 0x01, 0x04,
    0x81, 0xA6, 0x30,
    0x81, 0xA3, 0x30,
    0x81, 0x8D, 0x82,
    0x14, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA,
    0x18, 0x0F, '2',
    '0',  '2',  '6',
    '0',  '1',  '0',
    '2',  '0',  '3',
    '0',  '4',  '0',
    '5',  'Z',  0x30,
    0x64, 0x30, 0x62,
    0x30, 0x3A, 0x30,
    0x09, 0x06, 0x05,
    0x2B, 0x0E, 0x03,
    0x02, 0x1A, 0x05,
    0x00, 0x04, 0x14,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x11,
    0x11, 0x11, 0x04,
    0x14, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x22, 0x22, 0x22,
    0x02, 0x01, 0x01,
    0x80, 0x00, 0x18,
    0x0F, '2',  '0',
    '2',  '6',  '0',
    '1',  '0',  '2',
    '0',  '3',  '0',
    '4',  '0',  '5',
    'Z',  0xA0, 0x11,
    0x18, 0x0F, '2',
    '0',  '2',  '6',
    '0',  '2',  '0',
    '2',  '0',  '3',
    '0',  '4',  '0',
    '5',  'Z',  0x30,
    0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x0B,
    0x05, 0x00, 0x03,
    0x02, 0x00, 0x00,
};

test "ocsp parses successful basic response with one good single response" {
    const parsed = try parse(&ocsp_good_one_response);
    try std.testing.expectEqual(ResponseStatus.successful, parsed.response_status);
    try std.testing.expect(parsed.basic_response_der != null);
    try std.testing.expectEqual(@as(usize, 1), parsed.response_count);

    const single = parsed.responses[0];
    try std.testing.expectEqual(CertStatus.good, single.cert_status);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, single.serial);
    try std.testing.expectEqualSlices(u8, "20260102030405Z", single.this_update);
    try std.testing.expect(single.next_update != null);
    try std.testing.expectEqualSlices(u8, "20260202030405Z", single.next_update.?);
    try std.testing.expectEqual(CertStatus.good, statusForSerial(parsed, &[_]u8{0x01}).?);
    try std.testing.expect(statusForSerial(parsed, &[_]u8{0x02}) == null);
}

test "ocsp rejects malformed outer responses" {
    try std.testing.expectError(error.EmptyInput, parse(""));
    try std.testing.expectError(error.Truncated, parse(ocsp_good_one_response[0 .. ocsp_good_one_response.len - 1]));
    try std.testing.expectError(error.MissingResponseBytes, parse(&[_]u8{ 0x30, 0x03, 0x0A, 0x01, 0x00 }));
    try std.testing.expectError(error.InvalidResponseStatus, parse(&[_]u8{ 0x30, 0x03, 0x0A, 0x01, 0x04 }));
    try std.testing.expectError(
        error.UnexpectedResponseBytes,
        parse(&[_]u8{ 0x30, 0x08, 0x0A, 0x01, 0x01, 0xA0, 0x03, 0x30, 0x01, 0x00 }),
    );
}

test "ocsp covers cert status tag bytes" {
    var good_reader = x509.DerReader.init(&[_]u8{ 0x80, 0x00 });
    try std.testing.expectEqual(CertStatus.good, try parseCertStatus(good_reader, try good_reader.readTlv()));

    var revoked_reader = x509.DerReader.init(&[_]u8{
        0xA1, 0x11,
        0x18, 0x0F,
        '2',  '0',
        '2',  '6',
        '0',  '1',
        '0',  '2',
        '0',  '3',
        '0',  '4',
        '0',  '5',
        'Z',
    });
    try std.testing.expectEqual(CertStatus.revoked, try parseCertStatus(revoked_reader, try revoked_reader.readTlv()));

    var unknown_reader = x509.DerReader.init(&[_]u8{ 0x82, 0x00 });
    try std.testing.expectEqual(CertStatus.unknown, try parseCertStatus(unknown_reader, try unknown_reader.readTlv()));

    var malformed_reader = x509.DerReader.init(&[_]u8{ 0x80, 0x01, 0x00 });
    try std.testing.expectError(error.InvalidOcspResponse, parseCertStatus(malformed_reader, try malformed_reader.readTlv()));
}

test "ocsp verifyResponseSignature accepts direct issuer Ed25519 signature" {
    const allocator = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x5A} ** Ed25519.KeyPair.seed_length);
    const spki = try testEd25519Spki(allocator, kp.public_key.toBytes());
    defer allocator.free(spki);
    const response = try testSignedOcspResponse(allocator, kp, &[_]u8{0x44}, .good);
    defer allocator.free(response);

    const parsed = try parse(response);
    try std.testing.expect(verifyResponseSignature(parsed, spki));
    try std.testing.expectEqual(CertStatus.good, statusForSerial(parsed, &[_]u8{0x44}).?);

    var tampered = try allocator.dupe(u8, response);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    const bad = try parse(tampered);
    try std.testing.expect(!verifyResponseSignature(bad, spki));
}

test "buildRequest emits a well-formed single-CertID OCSP request" {
    const allocator = std.testing.allocator;
    const Sha1 = std.crypto.hash.Sha1;
    // Issuer Name = SEQUENCE{ SET{ SEQUENCE{ OID cn, UTF8String "CA" }}}.
    const issuer_name = "\x30\x0d\x31\x0b\x30\x09\x06\x03\x55\x04\x03\x0c\x02\x43\x41";
    const issuer_key = "\x04\x11\x22\x33\x44\x55"; // fake raw public-key bytes
    const serial = "\x12\x34\x56\x78";

    const req = try buildRequest(allocator, .{
        .issuer_name_der = issuer_name,
        .issuer_key_bytes = issuer_key,
        .serial_der = serial,
    });
    defer allocator.free(req);

    // Outer OCSPRequest is a DER SEQUENCE whose length covers the whole buffer.
    try std.testing.expectEqual(@as(u8, x509.Tag.sequence), req[0]);
    try std.testing.expectEqual(@as(usize, req[1] + 2), req.len); // short-form len (< 128)

    // The SHA-1 issuerNameHash, issuerKeyHash, the SHA-1 CertID OID, and the leaf
    // serial contents all appear verbatim in the request.
    var nh: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(issuer_name, &nh, .{});
    var kh: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(issuer_key, &kh, .{});
    try std.testing.expect(std.mem.indexOf(u8, req, &nh) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, &kh) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, &oid_sha1) != null);
    try std.testing.expect(std.mem.indexOf(u8, req, serial) != null);

    // Structurally re-parse the CertID nesting: SEQ{ SEQ{ SEQ{ SEQ{ CertID... }}}}.
    var r = x509.DerReader{ .input = req };
    const ocsp_req = try r.readExpected(x509.Tag.sequence);
    var tbs_r = try r.child(ocsp_req);
    const tbs = try tbs_r.readExpected(x509.Tag.sequence);
    var list_r = try tbs_r.child(tbs);
    const list = try list_r.readExpected(x509.Tag.sequence);
    var one_r = try list_r.child(list);
    const one = try one_r.readExpected(x509.Tag.sequence);
    var cid_r = try one_r.child(one);
    _ = try cid_r.readExpected(x509.Tag.sequence); // CertID SEQUENCE parses cleanly
}

fn testSignedOcspResponse(
    allocator: std.mem.Allocator,
    kp: Ed25519.KeyPair,
    serial: []const u8,
    status: CertStatus,
) ![]u8 {
    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(allocator);
    try appendDerTlv(allocator, &tbs_body, Asn1Tag.context_2_primitive, &([_]u8{0xA5} ** 20));
    try appendDerTlv(allocator, &tbs_body, x509.Tag.generalized_time, "20260102030405Z");

    var responses_body: std.ArrayList(u8) = .empty;
    defer responses_body.deinit(allocator);
    var single_body: std.ArrayList(u8) = .empty;
    defer single_body.deinit(allocator);
    var cert_id_body: std.ArrayList(u8) = .empty;
    defer cert_id_body.deinit(allocator);
    try appendAlgId(allocator, &cert_id_body, &oid_sha1, true);
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.octet_string, &([_]u8{0x11} ** 20));
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.octet_string, &([_]u8{0x22} ** 20));
    try appendDerTlv(allocator, &cert_id_body, x509.Tag.integer, serial);
    try appendDerSeq(allocator, &single_body, cert_id_body.items);
    switch (status) {
        .good => try appendDerTlv(allocator, &single_body, Asn1Tag.context_0_primitive, ""),
        .unknown => try appendDerTlv(allocator, &single_body, Asn1Tag.context_2_primitive, ""),
        .revoked => {
            var revoked_body: std.ArrayList(u8) = .empty;
            defer revoked_body.deinit(allocator);
            try appendDerTlv(allocator, &revoked_body, x509.Tag.generalized_time, "20260102030405Z");
            try appendDerTlv(allocator, &single_body, x509.Tag.context_1_constructed, revoked_body.items);
        },
    }
    try appendDerTlv(allocator, &single_body, x509.Tag.generalized_time, "20260102030405Z");
    try appendDerSeq(allocator, &responses_body, single_body.items);
    try appendDerSeq(allocator, &tbs_body, responses_body.items);

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(allocator);
    try appendDerSeq(allocator, &tbs, tbs_body.items);
    const sig = try kp.sign(tbs.items, null);
    const sig_bytes = sig.toBytes();

    var basic_body: std.ArrayList(u8) = .empty;
    defer basic_body.deinit(allocator);
    try basic_body.appendSlice(allocator, tbs.items);
    try appendAlgId(allocator, &basic_body, &oid_ed25519, false);
    try appendDerBitString(allocator, &basic_body, &sig_bytes);
    var basic: std.ArrayList(u8) = .empty;
    defer basic.deinit(allocator);
    try appendDerSeq(allocator, &basic, basic_body.items);

    var rb_body: std.ArrayList(u8) = .empty;
    defer rb_body.deinit(allocator);
    try appendDerTlv(allocator, &rb_body, x509.Tag.oid, &Oid.ocsp_basic);
    try appendDerTlv(allocator, &rb_body, x509.Tag.octet_string, basic.items);
    var rb: std.ArrayList(u8) = .empty;
    defer rb.deinit(allocator);
    try appendDerSeq(allocator, &rb, rb_body.items);

    var outer_body: std.ArrayList(u8) = .empty;
    defer outer_body.deinit(allocator);
    try appendDerTlv(allocator, &outer_body, Asn1Tag.enumerated, &[_]u8{0});
    try appendDerTlv(allocator, &outer_body, x509.Tag.context_0_constructed, rb.items);
    var outer: std.ArrayList(u8) = .empty;
    errdefer outer.deinit(allocator);
    try appendDerSeq(allocator, &outer, outer_body.items);
    return outer.toOwnedSlice(allocator);
}

fn testEd25519Spki(allocator: std.mem.Allocator, public_key: [Ed25519.PublicKey.encoded_length]u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendAlgId(allocator, &body, &oid_ed25519, false);
    try appendDerBitString(allocator, &body, &public_key);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
}

/// Inputs identifying the certificate an OCSP request asks about. All three are
/// DER byte views the caller extracts from the leaf + issuer certificates:
pub const CertIdInput = struct {
    /// The issuer's full Name TLV (the `SEQUENCE` of RDNs, tag+len+value).
    issuer_name_der: []const u8,
    /// The issuer's subjectPublicKey BIT STRING value WITHOUT the leading
    /// unused-bits octet (i.e. the raw public-key bytes).
    issuer_key_bytes: []const u8,
    /// The leaf certificate's serialNumber INTEGER contents (x509 `serial_der`).
    serial_der: []const u8,
};

/// Build a DER `OCSPRequest` (RFC 6960 §4.1) with a single SHA-1 `CertID` and no
/// optional signature or nonce. Caller owns the returned slice.
///
/// SHA-1 here is an *identifier* hash — the `CertID` responders key their
/// pre-produced responses on (Let's Encrypt and virtually all responders). It is
/// NOT a certificate or protocol signature, so it does not conflict with the
/// modern-only ban on SHA-1 cert signatures.
pub fn buildRequest(allocator: std.mem.Allocator, in: CertIdInput) std.mem.Allocator.Error![]u8 {
    const Sha1 = std.crypto.hash.Sha1;
    var name_hash: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(in.issuer_name_der, &name_hash, .{});
    var key_hash: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(in.issuer_key_bytes, &key_hash, .{});

    // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    var cert_id: std.ArrayList(u8) = .empty;
    defer cert_id.deinit(allocator);
    try appendAlgId(allocator, &cert_id, &oid_sha1, true);
    try appendDerTlv(allocator, &cert_id, x509.Tag.octet_string, &name_hash);
    try appendDerTlv(allocator, &cert_id, x509.Tag.octet_string, &key_hash);
    try appendDerTlv(allocator, &cert_id, x509.Tag.integer, in.serial_der);

    // Request ::= SEQUENCE { reqCert CertID } → requestList → TBSRequest → OCSPRequest.
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try appendDerSeq(allocator, &request, cert_id.items);
    var request_list: std.ArrayList(u8) = .empty;
    defer request_list.deinit(allocator);
    try appendDerSeq(allocator, &request_list, request.items);
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(allocator);
    try appendDerSeq(allocator, &tbs, request_list.items);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, tbs.items);
    return out.toOwnedSlice(allocator);
}

fn appendAlgId(allocator: std.mem.Allocator, out: *std.ArrayList(u8), oid: []const u8, with_null: bool) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendDerTlv(allocator, &body, x509.Tag.oid, oid);
    if (with_null) try appendDerTlv(allocator, &body, x509.Tag.null_value, "");
    try appendDerSeq(allocator, out, body.items);
}

fn appendDerSeq(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    try appendDerTlv(allocator, out, x509.Tag.sequence, value);
}

fn appendDerBitString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.append(allocator, 0);
    try body.appendSlice(allocator, value);
    try appendDerTlv(allocator, out, x509.Tag.bit_string, body.items);
}

fn appendDerTlv(allocator: std.mem.Allocator, out: *std.ArrayList(u8), tag: u8, value: []const u8) !void {
    try out.append(allocator, tag);
    try appendDerLen(allocator, out, value.len);
    try out.appendSlice(allocator, value);
}

fn appendDerLen(allocator: std.mem.Allocator, out: *std.ArrayList(u8), len: usize) !void {
    if (len < 128) {
        try out.append(allocator, @intCast(len));
        return;
    }
    var tmp: [@sizeOf(usize)]u8 = undefined;
    var n = len;
    var count: usize = 0;
    while (n != 0) : (n >>= 8) {
        tmp[tmp.len - 1 - count] = @intCast(n & 0xff);
        count += 1;
    }
    try out.append(allocator, 0x80 | @as(u8, @intCast(count)));
    try out.appendSlice(allocator, tmp[tmp.len - count ..]);
}

const oid_sha1 = [_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };
