//! Minimal fail-closed OCSP response parser for TLS OCSP stapling.
//!
//! This module implements the DER structure checks needed to consume stapled
//! OCSP responses (RFC 6960) and extract each SingleResponse CertID/status. It
//! intentionally does not verify the BasicOCSPResponse responder signature or
//! validate responder authorization; callers must do that before trusting the
//! freshness or authenticity of the result.
const std = @import("std");
const x509 = @import("x509.zig");

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

    // Signature verification is deliberately out of scope here, but the
    // signatureAlgorithm/signature fields must still be structurally DER-valid.
    _ = try body.readExpected(x509.Tag.sequence);
    _ = try parseBitString(try body.readExpected(x509.Tag.bit_string));
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
