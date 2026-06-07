//! Standalone ASN.1 OBJECT IDENTIFIER (DER) codec plus a small table of
//! common X.509/TLS OID values.
//!
//! This module is pure: it performs no I/O and no allocation. Encoders write
//! the DER *content* octets (the value bytes that follow the tag and length in
//! a `06` TLV) into a caller-owned buffer; decoders read content octets from a
//! caller-owned slice and write the decoded numeric arcs into a caller-owned
//! `u32` slice. Both return a sub-slice of the caller's buffer.
//!
//! DER content encoding rules (X.690 8.19):
//!   * The first two arcs are packed into one base-128 value `40*arc0 + arc1`.
//!   * `arc0` is 0, 1, or 2; when `arc0` < 2, `arc1` is < 40.
//!   * Each remaining arc is encoded as a base-128 big-endian varint where
//!     every byte except the last has its high bit (0x80) set, and the value
//!     uses the minimum number of bytes (no leading 0x80 padding byte).

const std = @import("std");

/// Errors produced by the OID codec. `NoSpaceLeft` is returned when a caller
/// buffer is too small; the remaining errors flag malformed or out-of-range
/// input.
pub const Error = error{
    /// Output buffer (bytes or arcs) cannot hold the result.
    NoSpaceLeft,
    /// Fewer than two arcs supplied to `encode`, or empty content to `decode`.
    TooFewArcs,
    /// First arc is not 0, 1, or 2, or the second arc is out of range for it.
    InvalidArc,
    /// Encoded content ends in the middle of a multi-byte arc.
    TruncatedInput,
    /// A sub-identifier has a leading 0x80 continuation byte (non-minimal).
    NonMinimalEncoding,
    /// A decoded arc does not fit in a u32.
    ArcOverflow,
};

/// Number of base-128 bytes needed to encode `value`.
fn varintLen(value: u32) usize {
    var len: usize = 1;
    var v = value >> 7;
    while (v != 0) : (v >>= 7) len += 1;
    return len;
}

/// Write `value` as a base-128 big-endian varint into `out` starting at
/// `idx`. Returns the index just past the written bytes.
fn writeVarint(out: []u8, idx: usize, value: u32) Error!usize {
    const len = varintLen(value);
    if (idx + len > out.len) return error.NoSpaceLeft;
    var shift: u5 = @intCast((len - 1) * 7);
    var pos = idx;
    var remaining = len;
    while (remaining > 0) : (remaining -= 1) {
        const chunk: u8 = @intCast((value >> shift) & 0x7f);
        const cont: u8 = if (remaining == 1) 0 else 0x80;
        out[pos] = chunk | cont;
        pos += 1;
        if (shift >= 7) shift -= 7;
    }
    return pos;
}

/// Encode the dotted arc sequence `arcs` into DER OID content octets, writing
/// into `out` and returning the populated prefix of `out`.
pub fn encode(out: []u8, arcs: []const u32) Error![]const u8 {
    if (arcs.len < 2) return error.TooFewArcs;
    const arc0 = arcs[0];
    const arc1 = arcs[1];
    if (arc0 > 2) return error.InvalidArc;
    if (arc0 < 2 and arc1 >= 40) return error.InvalidArc;

    // 40*arc0 + arc1 cannot overflow u32 for valid inputs (arc0 <= 2).
    const first = 40 * arc0 + arc1;
    var idx: usize = try writeVarint(out, 0, first);
    for (arcs[2..]) |arc| {
        idx = try writeVarint(out, idx, arc);
    }
    return out[0..idx];
}

/// Decode DER OID content octets `content` into numeric arcs, writing into
/// `out_arcs` and returning the populated prefix of `out_arcs`.
pub fn decode(content: []const u8, out_arcs: []u32) Error![]const u32 {
    if (content.len == 0) return error.TooFewArcs;

    var arc_idx: usize = 0;
    var i: usize = 0;
    var first_done = false;

    while (i < content.len) {
        // A non-minimal sub-identifier begins with 0x80.
        if (content[i] == 0x80) return error.NonMinimalEncoding;

        var value: u32 = 0;
        var consumed = false;
        while (i < content.len) {
            const byte = content[i];
            i += 1;
            // Guard against overflow before the 7-bit shift.
            if (value > (std.math.maxInt(u32) >> 7)) return error.ArcOverflow;
            value = (value << 7) | (byte & 0x7f);
            if (byte & 0x80 == 0) {
                consumed = true;
                break;
            }
        }
        if (!consumed) return error.TruncatedInput;

        if (!first_done) {
            first_done = true;
            // Split packed value into arc0 and arc1.
            const arc0: u32 = if (value < 80) value / 40 else 2;
            const arc1: u32 = value - 40 * arc0;
            if (arc_idx + 2 > out_arcs.len) return error.NoSpaceLeft;
            out_arcs[arc_idx] = arc0;
            out_arcs[arc_idx + 1] = arc1;
            arc_idx += 2;
        } else {
            if (arc_idx + 1 > out_arcs.len) return error.NoSpaceLeft;
            out_arcs[arc_idx] = value;
            arc_idx += 1;
        }
    }

    return out_arcs[0..arc_idx];
}

/// Compare two OID content byte sequences for equality. Content octets are a
/// canonical DER representation, so a raw byte compare is the correct test.
pub fn eql(a_content: []const u8, b_content: []const u8) bool {
    return std.mem.eql(u8, a_content, b_content);
}

// -- Named OID content constants (DER value octets, no tag/length) -----------

/// 1.3.101.112 — Ed25519 signature algorithm / key.
pub const id_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

/// 1.2.840.10045.4.3.2 — ecdsa-with-SHA256.
pub const ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

/// 1.2.840.113549.1.1.1 — rsaEncryption.
pub const rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

/// 1.2.840.10045.3.1.7 — prime256v1 (secp256r1) named curve.
pub const prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

/// 2.5.4.3 — id-at-commonName (X.520 CN attribute).
pub const common_name = [_]u8{ 0x55, 0x04, 0x03 };

// -- Tests -------------------------------------------------------------------

test "encode 1.3.101.112 equals id_ed25519 constant" {
    // Arrange
    var buf: [16]u8 = undefined;
    const arcs = [_]u32{ 1, 3, 101, 112 };

    // Act
    const encoded = try encode(&buf, &arcs);

    // Assert
    try std.testing.expectEqualSlices(u8, &id_ed25519, encoded);
}

test "decode round-trips encoded content back to arcs" {
    // Arrange
    var buf: [16]u8 = undefined;
    const arcs = [_]u32{ 1, 3, 101, 112 };
    const encoded = try encode(&buf, &arcs);

    // Act
    var out_arcs: [8]u32 = undefined;
    const decoded = try decode(encoded, &out_arcs);

    // Assert
    try std.testing.expectEqualSlices(u32, &arcs, decoded);
}

test "base-128 multi-byte arc encodes and decodes (1.2.840.10045.4.3.2)" {
    // Arrange: 840 = 0x86 0x48 and 10045 = 0xce 0x3d are multi-byte arcs.
    var buf: [32]u8 = undefined;
    const arcs = [_]u32{ 1, 2, 840, 10045, 4, 3, 2 };

    // Act
    const encoded = try encode(&buf, &arcs);
    var out_arcs: [16]u32 = undefined;
    const decoded = try decode(encoded, &out_arcs);

    // Assert
    try std.testing.expectEqualSlices(u8, &ecdsa_with_sha256, encoded);
    try std.testing.expectEqualSlices(u32, &arcs, decoded);
}

test "eql matches identical content and rejects differing content" {
    // Arrange
    var buf: [16]u8 = undefined;
    const encoded = try encode(&buf, &[_]u32{ 1, 3, 101, 112 });

    // Act / Assert
    try std.testing.expect(eql(encoded, &id_ed25519));
    try std.testing.expect(!eql(&id_ed25519, &common_name));
}

test "named constants decode to their dotted arcs" {
    // Arrange
    const cases = [_]struct {
        content: []const u8,
        arcs: []const u32,
    }{
        .{ .content = &id_ed25519, .arcs = &[_]u32{ 1, 3, 101, 112 } },
        .{ .content = &ecdsa_with_sha256, .arcs = &[_]u32{ 1, 2, 840, 10045, 4, 3, 2 } },
        .{ .content = &rsa_encryption, .arcs = &[_]u32{ 1, 2, 840, 113549, 1, 1, 1 } },
        .{ .content = &prime256v1, .arcs = &[_]u32{ 1, 2, 840, 10045, 3, 1, 7 } },
        .{ .content = &common_name, .arcs = &[_]u32{ 2, 5, 4, 3 } },
    };

    // Act / Assert
    var out_arcs: [16]u32 = undefined;
    for (cases) |c| {
        const decoded = try decode(c.content, &out_arcs);
        try std.testing.expectEqualSlices(u32, c.arcs, decoded);
    }
}

test "encode rejects fewer than two arcs and bad first arc" {
    // Arrange
    var buf: [16]u8 = undefined;

    // Act / Assert
    try std.testing.expectError(error.TooFewArcs, encode(&buf, &[_]u32{1}));
    try std.testing.expectError(error.InvalidArc, encode(&buf, &[_]u32{ 3, 0 }));
    try std.testing.expectError(error.InvalidArc, encode(&buf, &[_]u32{ 1, 40 }));
}

test "encode reports NoSpaceLeft on undersized buffer" {
    // Arrange
    var buf: [1]u8 = undefined;

    // Act / Assert: encoding requires at least the 840 arc (2 bytes).
    try std.testing.expectError(error.NoSpaceLeft, encode(&buf, &[_]u32{ 1, 2, 840 }));
}

test "decode rejects non-minimal leading continuation byte" {
    // Arrange: 0x80 0x01 is a non-minimal encoding of value 1.
    const bad = [_]u8{ 0x2b, 0x80, 0x01 };

    // Act / Assert
    var out_arcs: [8]u32 = undefined;
    try std.testing.expectError(error.NonMinimalEncoding, decode(&bad, &out_arcs));
}

test "decode rejects truncated multi-byte arc" {
    // Arrange: trailing 0x86 sets the continuation bit with no following byte.
    const bad = [_]u8{ 0x2b, 0x86 };

    // Act / Assert
    var out_arcs: [8]u32 = undefined;
    try std.testing.expectError(error.TruncatedInput, decode(&bad, &out_arcs));
}

test "decode reports NoSpaceLeft when arc buffer is too small" {
    // Arrange
    var out_arcs: [1]u32 = undefined;

    // Act / Assert: first sub-identifier already yields two arcs.
    try std.testing.expectError(error.NoSpaceLeft, decode(&id_ed25519, &out_arcs));
}
