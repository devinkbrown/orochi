//! Minimal DER parser for OCSP response status (RFC 6960).
//!
//! Pure parsing only: no sockets, filesystem, clock, RNG, heap allocation, or
//! ownership transfer. This is intentionally limited to the OCSPResponse outer
//! status and the certStatus CHOICE tag used by a SingleResponse.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("ocsp parser requires a 64-bit target");
}

pub const OcspResponseStatus = enum(u8) {
    successful = 0,
    malformed_request = 1,
    internal_error = 2,
    try_later = 3,
    sig_required = 5,
    unauthorized = 6,
};

pub const CertStatus = enum {
    good,
    revoked,
    unknown,
};

pub const ParseError = error{
    Truncated,
    InvalidDer,
    UnexpectedTag,
    UnsupportedStatus,
    TrailingData,
};

const tag_sequence: u8 = 0x30;
const tag_enumerated: u8 = 0x0a;
const tag_oid: u8 = 0x06;
const tag_octet_string: u8 = 0x04;
const tag_response_bytes_explicit: u8 = 0xa0;

const DerElement = struct {
    tag: u8,
    body: []const u8,
    consumed: usize,
};

const DerReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn readElement(self: *DerReader) ParseError!DerElement {
        const el = try readDerElement(self.bytes[self.pos..]);
        self.pos += el.consumed;
        return el;
    }

    fn eof(self: DerReader) bool {
        return self.pos == self.bytes.len;
    }
};

/// Parse RFC 6960 OCSPResponse far enough to return responseStatus.
///
/// OCSPResponse ::= SEQUENCE {
///   responseStatus OCSPResponseStatus,
///   responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
/// }
pub fn parseResponseStatus(der: []const u8) ParseError!OcspResponseStatus {
    const outer = try readDerElement(der);
    if (outer.tag != tag_sequence) return error.UnexpectedTag;
    if (outer.consumed != der.len) return error.TrailingData;

    var reader = DerReader{ .bytes = outer.body };

    const status_el = try reader.readElement();
    if (status_el.tag != tag_enumerated) return error.UnexpectedTag;
    const status = try decodeResponseStatus(status_el.body);

    if (!reader.eof()) {
        const response_bytes = try reader.readElement();
        if (response_bytes.tag != tag_response_bytes_explicit) return error.UnexpectedTag;
        try validateResponseBytes(response_bytes.body);
    }
    if (!reader.eof()) return error.TrailingData;

    return status;
}

/// Classify the context-specific CHOICE tag for SingleResponse.certStatus.
///
/// CertStatus ::= CHOICE {
///   good    [0] IMPLICIT NULL,        -- DER tag 0x80
///   revoked [1] IMPLICIT RevokedInfo, -- DER tag 0xa1
///   unknown [2] IMPLICIT UnknownInfo  -- DER tag 0x82
/// }
pub fn classifyCertStatusTag(tag: u8) ParseError!CertStatus {
    return switch (tag) {
        0x80 => .good,
        0xa1 => .revoked,
        0x82 => .unknown,
        else => error.UnexpectedTag,
    };
}

fn decodeResponseStatus(body: []const u8) ParseError!OcspResponseStatus {
    if (body.len != 1) return error.InvalidDer;

    return switch (body[0]) {
        0 => .successful,
        1 => .malformed_request,
        2 => .internal_error,
        3 => .try_later,
        5 => .sig_required,
        6 => .unauthorized,
        else => error.UnsupportedStatus,
    };
}

fn validateResponseBytes(body: []const u8) ParseError!void {
    const wrapped = try readDerElement(body);
    if (wrapped.tag != tag_sequence) return error.UnexpectedTag;
    if (wrapped.consumed != body.len) return error.TrailingData;

    var reader = DerReader{ .bytes = wrapped.body };

    const response_type = try reader.readElement();
    if (response_type.tag != tag_oid) return error.UnexpectedTag;
    if (response_type.body.len == 0) return error.InvalidDer;

    const response = try reader.readElement();
    if (response.tag != tag_octet_string) return error.UnexpectedTag;

    if (!reader.eof()) return error.TrailingData;
}

fn readDerElement(bytes: []const u8) ParseError!DerElement {
    if (bytes.len < 2) return error.Truncated;

    const tag = bytes[0];
    const len_info = try readDerLength(bytes[1..]);
    const header_len = 1 + len_info.consumed;
    const end = std.math.add(usize, header_len, len_info.len) catch return error.InvalidDer;
    if (end > bytes.len) return error.Truncated;

    return .{
        .tag = tag,
        .body = bytes[header_len..end],
        .consumed = end,
    };
}

fn readDerLength(bytes: []const u8) ParseError!struct { len: usize, consumed: usize } {
    if (bytes.len == 0) return error.Truncated;

    const first = bytes[0];
    if ((first & 0x80) == 0) {
        return .{ .len = first, .consumed = 1 };
    }

    const count: usize = first & 0x7f;
    if (count == 0) return error.InvalidDer; // indefinite length is BER, not DER
    if (count > @sizeOf(usize)) return error.InvalidDer;
    if (bytes.len < 1 + count) return error.Truncated;
    if (bytes[1] == 0) return error.InvalidDer; // non-minimal long form

    var len: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        len = (len << 8) | bytes[1 + i];
    }
    if (len < 128) return error.InvalidDer; // must have used short form

    return .{ .len = len, .consumed = 1 + count };
}

test "parseResponseStatus returns successful from OCSPResponse with responseBytes" {
    // Arrange
    const der = [_]u8{
        0x30, 0x14,
        0x0a, 0x01,
        0x00, 0xa0,
        0x0f, 0x30,
        0x0d, 0x06,
        0x09, 0x2b,
        0x06, 0x01,
        0x05, 0x05,
        0x07, 0x30,
        0x01, 0x01,
        0x04, 0x00,
    };

    // Act
    const status = try parseResponseStatus(&der);

    // Assert
    try std.testing.expectEqual(OcspResponseStatus.successful, status);
}

test "parseResponseStatus returns try_later from status-only OCSPResponse" {
    // Arrange
    const der = [_]u8{ 0x30, 0x03, 0x0a, 0x01, 0x03 };

    // Act
    const status = try parseResponseStatus(&der);

    // Assert
    try std.testing.expectEqual(OcspResponseStatus.try_later, status);
}

test "parseResponseStatus rejects malformed OCSPResponse status tag" {
    // Arrange
    const der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 };

    // Act
    const result = parseResponseStatus(&der);

    // Assert
    try std.testing.expectError(error.UnexpectedTag, result);
}

test "parseResponseStatus rejects truncated OCSPResponse length" {
    // Arrange
    const der = [_]u8{ 0x30, 0x03, 0x0a, 0x01 };

    // Act
    const result = parseResponseStatus(&der);

    // Assert
    try std.testing.expectError(error.Truncated, result);
}

test "classifyCertStatusTag maps good choice tag" {
    // Arrange
    const tag: u8 = 0x80;

    // Act
    const status = try classifyCertStatusTag(tag);

    // Assert
    try std.testing.expectEqual(CertStatus.good, status);
}

test "classifyCertStatusTag maps revoked choice tag" {
    // Arrange
    const tag: u8 = 0xa1;

    // Act
    const status = try classifyCertStatusTag(tag);

    // Assert
    try std.testing.expectEqual(CertStatus.revoked, status);
}

test "classifyCertStatusTag maps unknown choice tag" {
    // Arrange
    const tag: u8 = 0x82;

    // Act
    const status = try classifyCertStatusTag(tag);

    // Assert
    try std.testing.expectEqual(CertStatus.unknown, status);
}
