// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.2 extension inner-data codecs for small RFC 5746 / RFC 8422 bodies.
//!
//! This module deliberately handles only extension_data payloads.  The outer
//! TLS Extension envelope (type + length) is owned by the sibling generic
//! extension-list codec.
//!
//! Implemented payloads:
//!   * `ec_point_formats` (RFC 8422): `<1-byte list length><format bytes>`.
//!   * `renegotiation_info` (RFC 5746): `<1-byte length><verify bytes>`.
//!   * `SessionTicket` (RFC 5077, type 0x0023): the extension_data IS the
//!     opaque ticket with no inner length prefix.  An empty body in a
//!     ClientHello means "I support tickets, send me one"; a non-empty body
//!     is the ticket the client wishes to resume.  An empty body in a
//!     ServerHello means "I will issue a NewSessionTicket".
//!
//! Pure logic: no I/O, no clock, no RNG, and no allocation.  All output writes
//! go to caller-owned buffers and every length is checked before indexing.
const std = @import("std");

/// TLS extension type for the RFC 5077 SessionTicket extension.
pub const session_ticket_ext_type: u16 = 0x0023;

/// Wire value for the only EC point format TLS 1.2 clients and servers need
/// for the named curves in RFC 8422.
pub const ec_point_format_uncompressed: u8 = 0;

/// Maximum payload length carried by a one-octet vector length.
pub const max_u8_vector_len: usize = std.math.maxInt(u8);

/// Errors produced while parsing or building these extension inner bodies.
pub const Error = error{
    /// The input ended before the declared one-octet vector body.
    Truncated,
    /// The vector length is illegal for that extension, or leaves trailing
    /// bytes inside the inner extension_data block.
    InvalidLength,
    /// A caller-provided vector is too large for the one-octet length field.
    Oversize,
    /// The caller-provided output buffer is too small.
    NoSpaceLeft,
};

fn exactVectorBody(block: []const u8, allow_empty: bool) Error![]const u8 {
    if (block.len < 1) return error.Truncated;
    const declared: usize = block[0];
    const body = block[1..];
    if (!allow_empty and declared == 0) return error.InvalidLength;
    if (body.len < declared) return error.Truncated;
    if (body.len != declared) return error.InvalidLength;
    return body;
}

/// Forward iterator over an RFC 8422 ECPointFormatList body.  Yields raw
/// format octets in wire order.
pub const Iterator = struct {
    formats: []const u8,
    pos: usize = 0,

    /// Return the next format octet, or `null` once exhausted.
    pub fn next(self: *Iterator) ?u8 {
        if (self.pos >= self.formats.len) return null;
        const value = self.formats[self.pos];
        self.pos += 1;
        return value;
    }

    /// Number of format octets not yet yielded.
    pub fn remaining(self: Iterator) usize {
        return self.formats.len - self.pos;
    }
};

/// Parse an `ec_point_formats` extension_data block and return an iterator over
/// the advertised point formats.  RFC 8422 uses a non-empty one-byte vector.
pub fn parseEcPointFormats(block: []const u8) Error!Iterator {
    return .{ .formats = try exactVectorBody(block, false) };
}

/// Encode an `ec_point_formats` extension_data block into `out`, returning the
/// written prefix.  `formats` must contain at least one and at most 255 octets.
pub fn buildEcPointFormats(out: []u8, formats: []const u8) Error![]const u8 {
    if (formats.len == 0) return error.InvalidLength;
    if (formats.len > max_u8_vector_len) return error.Oversize;
    const total = 1 + formats.len;
    if (out.len < total) return error.NoSpaceLeft;

    out[0] = @intCast(formats.len);
    @memcpy(out[1..total], formats);
    return out[0..total];
}

/// Return true iff a well-formed `ec_point_formats` block includes the
/// uncompressed point format (wire value 0).
pub fn supportsUncompressed(block: []const u8) bool {
    var it = parseEcPointFormats(block) catch return false;
    while (it.next()) |format| {
        if (format == ec_point_format_uncompressed) return true;
    }
    return false;
}

/// Parse a `renegotiation_info` extension_data block and return the
/// `renegotiated_connection` verify bytes.  The returned slice aliases `block`.
/// Initial handshakes encode this as a single zero byte.
pub fn parseRenegotiationInfo(block: []const u8) Error![]const u8 {
    return exactVectorBody(block, true);
}

/// Encode a `renegotiation_info` extension_data block into `out`, returning the
/// written prefix.  `verify_bytes` may be empty for the initial handshake.
pub fn buildRenegotiationInfo(out: []u8, verify_bytes: []const u8) Error![]const u8 {
    if (verify_bytes.len > max_u8_vector_len) return error.Oversize;
    const total = 1 + verify_bytes.len;
    if (out.len < total) return error.NoSpaceLeft;

    out[0] = @intCast(verify_bytes.len);
    @memcpy(out[1..total], verify_bytes);
    return out[0..total];
}

/// Parse a `SessionTicket` (RFC 5077) extension_data block.  The whole body is
/// the opaque ticket; there is no inner length field.  The returned slice
/// aliases `block` and may be empty (the "send me a ticket" / "I will issue a
/// ticket" signalling form).
pub fn parseSessionTicket(block: []const u8) []const u8 {
    return block;
}

/// Encode a `SessionTicket` extension_data block into `out`, returning the
/// written prefix.  `ticket` may be empty: an empty ClientHello body asks the
/// server for a ticket, and an empty ServerHello body promises a
/// NewSessionTicket.  A non-empty body carries the ticket to resume.
pub fn buildSessionTicket(out: []u8, ticket: []const u8) Error![]const u8 {
    if (out.len < ticket.len) return error.NoSpaceLeft;
    @memcpy(out[0..ticket.len], ticket);
    return out[0..ticket.len];
}

const testing = std.testing;

test "ec_point_formats round-trips multiple format octets in order" {
    // Arrange
    var out: [8]u8 = undefined;
    const formats = [_]u8{ 0, 1, 2 };

    // Act
    const block = try buildEcPointFormats(&out, &formats);
    var it = try parseEcPointFormats(block);
    const first = it.next();
    const second = it.next();
    const third = it.next();
    const end = it.next();

    // Assert
    try testing.expectEqualSlices(u8, &[_]u8{ 3, 0, 1, 2 }, block);
    try testing.expectEqual(@as(?u8, 0), first);
    try testing.expectEqual(@as(?u8, 1), second);
    try testing.expectEqual(@as(?u8, 2), third);
    try testing.expectEqual(@as(?u8, null), end);
}

test "ec_point_formats known vector for uncompressed only" {
    // Arrange
    const block = [_]u8{ 1, ec_point_format_uncompressed };

    // Act
    var it = try parseEcPointFormats(&block);
    const format = it.next();
    const end = it.next();

    // Assert
    try testing.expectEqual(@as(?u8, ec_point_format_uncompressed), format);
    try testing.expectEqual(@as(?u8, null), end);
}

test "supportsUncompressed accepts only well-formed blocks containing format zero" {
    // Arrange
    const has_uncompressed = [_]u8{ 2, 1, 0 };
    const lacks_uncompressed = [_]u8{ 2, 1, 2 };
    const malformed = [_]u8{ 2, 0 };

    // Act
    const has = supportsUncompressed(&has_uncompressed);
    const lacks = supportsUncompressed(&lacks_uncompressed);
    const bad = supportsUncompressed(&malformed);

    // Assert
    try testing.expect(has);
    try testing.expect(!lacks);
    try testing.expect(!bad);
}

test "ec_point_formats rejects empty list, truncation, trailing data, and oversize build" {
    // Arrange
    const empty = [_]u8{0};
    const truncated = [_]u8{ 2, 0 };
    const trailing = [_]u8{ 1, 0, 2 };
    var small: [1]u8 = undefined;
    var too_many: [max_u8_vector_len + 1]u8 = undefined;
    @memset(&too_many, 0);

    // Act
    const empty_result = parseEcPointFormats(&empty);
    const truncated_result = parseEcPointFormats(&truncated);
    const trailing_result = parseEcPointFormats(&trailing);
    const no_space_result = buildEcPointFormats(&small, &[_]u8{ 0, 1 });
    const oversize_result = buildEcPointFormats(&small, &too_many);

    // Assert
    try testing.expectError(error.InvalidLength, empty_result);
    try testing.expectError(error.Truncated, truncated_result);
    try testing.expectError(error.InvalidLength, trailing_result);
    try testing.expectError(error.NoSpaceLeft, no_space_result);
    try testing.expectError(error.Oversize, oversize_result);
}

test "renegotiation_info initial handshake known vector parses as empty verify bytes" {
    // Arrange
    const block = [_]u8{0};

    // Act
    const verify_bytes = try parseRenegotiationInfo(&block);

    // Assert
    try testing.expectEqual(@as(usize, 0), verify_bytes.len);
}

test "renegotiation_info round-trips verify bytes" {
    // Arrange
    var out: [16]u8 = undefined;
    const verify = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    // Act
    const block = try buildRenegotiationInfo(&out, &verify);
    const parsed = try parseRenegotiationInfo(block);

    // Assert
    try testing.expectEqualSlices(u8, &[_]u8{ 4, 0xaa, 0xbb, 0xcc, 0xdd }, block);
    try testing.expectEqualSlices(u8, &verify, parsed);
}

test "renegotiation_info builds the empty initial-handshake vector" {
    // Arrange
    var out: [1]u8 = undefined;

    // Act
    const block = try buildRenegotiationInfo(&out, "");
    const parsed = try parseRenegotiationInfo(block);

    // Assert
    try testing.expectEqualSlices(u8, &[_]u8{0}, block);
    try testing.expectEqual(@as(usize, 0), parsed.len);
}

test "renegotiation_info rejects truncation, trailing data, oversize, and short output" {
    // Arrange
    const truncated = [_]u8{ 3, 0xaa };
    const trailing = [_]u8{ 1, 0xaa, 0xbb };
    var small: [2]u8 = undefined;
    var too_many: [max_u8_vector_len + 1]u8 = undefined;
    @memset(&too_many, 0);

    // Act
    const truncated_result = parseRenegotiationInfo(&truncated);
    const trailing_result = parseRenegotiationInfo(&trailing);
    const no_space_result = buildRenegotiationInfo(&small, &[_]u8{ 0, 1 });
    const oversize_result = buildRenegotiationInfo(&small, &too_many);

    // Assert
    try testing.expectError(error.Truncated, truncated_result);
    try testing.expectError(error.InvalidLength, trailing_result);
    try testing.expectError(error.NoSpaceLeft, no_space_result);
    try testing.expectError(error.Oversize, oversize_result);
}

test "SessionTicket round-trips an opaque ticket body" {
    // Arrange
    var out: [8]u8 = undefined;
    const ticket = [_]u8{ 0xde, 0xad, 0xbe, 0xef };

    // Act
    const block = try buildSessionTicket(&out, &ticket);
    const parsed = parseSessionTicket(block);

    // Assert
    try testing.expectEqualSlices(u8, &ticket, block);
    try testing.expectEqualSlices(u8, &ticket, parsed);
}

test "SessionTicket encodes and parses the empty signalling body" {
    // Arrange
    var out: [0]u8 = undefined;

    // Act: an empty ClientHello body asks for a ticket; an empty ServerHello
    // body promises one. Both encode to a zero-length extension_data block.
    const block = try buildSessionTicket(&out, "");
    const parsed = parseSessionTicket(block);

    // Assert
    try testing.expectEqual(@as(usize, 0), block.len);
    try testing.expectEqual(@as(usize, 0), parsed.len);
}

test "SessionTicket build reports NoSpaceLeft when the output is too small" {
    // Arrange
    var small: [2]u8 = undefined;

    // Act
    const result = buildSessionTicket(&small, &[_]u8{ 1, 2, 3 });

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}
