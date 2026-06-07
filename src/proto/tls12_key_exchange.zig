//! TLS 1.2 ECDHE key-exchange handshake message bodies (RFC 4492 / RFC 8422).
//!
//! Two handshake bodies live here; both are the *inner* message payload (the
//! 4-byte handshake header — msg_type + 24-bit length — is stripped by the
//! caller):
//!
//!   * ServerKeyExchange (ECDHE) — a `ServerECDHParams` followed by a
//!     `digitally-signed` struct:
//!         struct {
//!             ECParameters    curve_params;   // see below
//!             ECPoint         public;         // <1-byte-len> opaque point
//!             SignatureAndHashAlgorithm algorithm;  // u16 SignatureScheme
//!             opaque          signature<0..2^16-1>; // <2-byte-len>
//!         }
//!     where `ECParameters` for a named curve is:
//!         struct {
//!             ECCurveType curve_type = named_curve(3);  // 1 byte
//!             NamedCurve  namedcurve;                    // u16
//!         }
//!
//!   * ClientKeyExchange (ECDHE) — a bare `ClientECDiffieHellmanPublic` whose
//!     ecdh_Yc is an explicit `ECPoint`:  <1-byte-len> opaque point.
//!
//! `signedParams` rebuilds the exact byte string a peer signs/verifies, which
//! per RFC 4492 §5.4 is `client_random || server_random || ServerECDHParams`
//! (the params only — not the signature).
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  The caller owns every
//! buffer.  Parsers never copy — returned `point` / `signature` slices alias the
//! caller's input.  Every length is bounds-checked; malformed input yields an
//! error rather than reading past the slice.  Only `std` is imported.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;

/// `ECCurveType.named_curve` — the only curve form we encode or accept.
/// Explicit prime/char2 curve descriptions (deprecated by RFC 8422) are
/// rejected.
pub const curve_type_named_curve: u8 = 3;

/// Errors produced while parsing or building a key-exchange body.
pub const Error = error{
    /// Input ended mid-field, or a declared length disagrees with the bytes
    /// actually present / leaves unexpected trailing data.
    Truncated,
    /// A builder ran out of room in the caller-provided buffer.
    NoSpaceLeft,
    /// A point exceeds the 1-byte ECPoint length field (255 bytes), or a
    /// signature exceeds the 2-byte field (65535 bytes).
    DataTooLong,
    /// `curve_type` was not `named_curve(3)` (explicit curves are unsupported).
    UnsupportedCurveType,
};

/// A decoded or to-be-encoded ECDHE ServerKeyExchange.  `point` and `signature`
/// alias the caller's input when produced by `parseServerKeyExchange`.
pub const ServerKeyExchange = struct {
    /// IANA NamedCurve / "Supported Groups" code point (e.g. secp256r1 = 23).
    named_curve: u16,
    /// The server's ephemeral ECDH public key, in its on-wire point encoding.
    point: []const u8,
    /// TLS 1.2 SignatureScheme value (the `SignatureAndHashAlgorithm` u16).
    sig_scheme: u16,
    /// The signature over `signedParams(...)`.
    signature: []const u8,
};

/// Header bytes of `ServerECDHParams` for a named curve: curve_type(1) +
/// named_curve(2) + point length prefix(1).
const ecdh_params_header_len: usize = 4;

/// Builds the exact byte string that is signed for an ECDHE ServerKeyExchange:
/// `client_random || server_random || ServerECDHParams`, where ServerECDHParams
/// is `curve_type(3) || named_curve || <1-byte-len> point`.  Returns the written
/// prefix slice of `out`.  This is the signature *input* — it never includes the
/// algorithm or signature fields.
pub fn signedParams(
    out: []u8,
    client_random: [32]u8,
    server_random: [32]u8,
    named_curve: u16,
    point: []const u8,
) Error![]const u8 {
    if (point.len > std.math.maxInt(u8)) return Error.DataTooLong;
    const total = client_random.len + server_random.len +
        ecdh_params_header_len + point.len;
    if (out.len < total) return Error.NoSpaceLeft;

    var pos: usize = 0;
    @memcpy(out[pos .. pos + client_random.len], &client_random);
    pos += client_random.len;
    @memcpy(out[pos .. pos + server_random.len], &server_random);
    pos += server_random.len;

    out[pos] = curve_type_named_curve;
    pos += 1;
    mem.writeInt(u16, out[pos..][0..2], named_curve, .big);
    pos += 2;
    out[pos] = @intCast(point.len);
    pos += 1;
    @memcpy(out[pos .. pos + point.len], point);
    pos += point.len;

    return out[0..pos];
}

/// Encodes an ECDHE ServerKeyExchange body into `out`, returning the written
/// prefix slice of `out`.  Layout: ServerECDHParams || algorithm(u16) ||
/// signature<2-byte-len>.
pub fn encodeServerKeyExchange(out: []u8, ske: ServerKeyExchange) Error![]const u8 {
    if (ske.point.len > std.math.maxInt(u8)) return Error.DataTooLong;
    if (ske.signature.len > std.math.maxInt(u16)) return Error.DataTooLong;

    const total = ecdh_params_header_len + ske.point.len +
        2 + // algorithm
        2 + ske.signature.len; // signature length prefix + body
    if (out.len < total) return Error.NoSpaceLeft;

    var pos: usize = 0;
    out[pos] = curve_type_named_curve;
    pos += 1;
    mem.writeInt(u16, out[pos..][0..2], ske.named_curve, .big);
    pos += 2;
    out[pos] = @intCast(ske.point.len);
    pos += 1;
    @memcpy(out[pos .. pos + ske.point.len], ske.point);
    pos += ske.point.len;

    mem.writeInt(u16, out[pos..][0..2], ske.sig_scheme, .big);
    pos += 2;
    mem.writeInt(u16, out[pos..][0..2], @intCast(ske.signature.len), .big);
    pos += 2;
    @memcpy(out[pos .. pos + ske.signature.len], ske.signature);
    pos += ske.signature.len;

    return out[0..pos];
}

/// Parses an ECDHE ServerKeyExchange body.  Requires `body` to be consumed
/// exactly (no trailing bytes).  Returned `point` / `signature` alias `body`.
/// Rejects a `curve_type` other than `named_curve(3)`.
pub fn parseServerKeyExchange(body: []const u8) Error!ServerKeyExchange {
    if (body.len < ecdh_params_header_len) return Error.Truncated;
    if (body[0] != curve_type_named_curve) return Error.UnsupportedCurveType;

    const named_curve = mem.readInt(u16, body[1..3], .big);
    const point_len: usize = body[3];
    const point_start = ecdh_params_header_len;
    const point_end = point_start + point_len;
    if (body.len < point_end + 2) return Error.Truncated; // need algorithm too

    const sig_scheme = mem.readInt(u16, body[point_end..][0..2], .big);
    const sig_len_off = point_end + 2;
    if (body.len < sig_len_off + 2) return Error.Truncated;
    const sig_len = mem.readInt(u16, body[sig_len_off..][0..2], .big);
    const sig_start = sig_len_off + 2;
    const sig_end = sig_start + @as(usize, sig_len);
    if (body.len != sig_end) return Error.Truncated;

    return ServerKeyExchange{
        .named_curve = named_curve,
        .point = body[point_start..point_end],
        .sig_scheme = sig_scheme,
        .signature = body[sig_start..sig_end],
    };
}

/// Encodes an ECDHE ClientKeyExchange body (`ecdh_Yc` = <1-byte-len> point)
/// into `out`, returning the written prefix slice of `out`.
pub fn encodeClientKeyExchange(out: []u8, point: []const u8) Error![]const u8 {
    if (point.len > std.math.maxInt(u8)) return Error.DataTooLong;
    const total = 1 + point.len;
    if (out.len < total) return Error.NoSpaceLeft;

    out[0] = @intCast(point.len);
    @memcpy(out[1 .. 1 + point.len], point);
    return out[0..total];
}

/// Parses an ECDHE ClientKeyExchange body, returning the `ecdh_Yc` point.
/// Requires `body` to be consumed exactly.  The returned slice aliases `body`.
pub fn parseClientKeyExchange(body: []const u8) Error![]const u8 {
    if (body.len < 1) return Error.Truncated;
    const point_len: usize = body[0];
    const end = 1 + point_len;
    if (body.len != end) return Error.Truncated;
    return body[1..end];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// A representative uncompressed secp256r1 point: 0x04 || X(32) || Y(32) = 65 B.
fn sampleP256Point() [65]u8 {
    var p: [65]u8 = undefined;
    p[0] = 0x04;
    for (p[1..], 0..) |*b, i| b.* = @intCast((i * 7 + 1) & 0xff);
    return p;
}

test "ServerKeyExchange encode -> parse round-trip" {
    // Arrange
    const point = sampleP256Point();
    const signature = [_]u8{ 0x30, 0x44, 0x02, 0x20, 0xab, 0xcd, 0xef, 0x01 };
    const ske = ServerKeyExchange{
        .named_curve = 23, // secp256r1
        .point = &point,
        .sig_scheme = 0x0403, // ecdsa_secp256r1_sha256
        .signature = &signature,
    };
    var buf: [256]u8 = undefined;

    // Act
    const wire = try encodeServerKeyExchange(&buf, ske);
    const decoded = try parseServerKeyExchange(wire);

    // Assert
    try testing.expectEqual(@as(u16, 23), decoded.named_curve);
    try testing.expectEqualSlices(u8, &point, decoded.point);
    try testing.expectEqual(@as(u16, 0x0403), decoded.sig_scheme);
    try testing.expectEqualSlices(u8, &signature, decoded.signature);
    // Returned slices alias the wire buffer rather than copying.
    try testing.expectEqual(wire.ptr + ecdh_params_header_len, decoded.point.ptr);
}

test "ClientKeyExchange encode -> parse round-trip" {
    // Arrange
    const point = sampleP256Point();
    var buf: [128]u8 = undefined;

    // Act
    const wire = try encodeClientKeyExchange(&buf, &point);
    const decoded = try parseClientKeyExchange(wire);

    // Assert
    try testing.expectEqualSlices(u8, &point, decoded);
    try testing.expectEqual(@as(usize, point.len), wire[0]);
    try testing.expectEqual(wire.ptr + 1, decoded.ptr);
}

test "signedParams layout has client_random first then server_random" {
    // Arrange
    var client_random: [32]u8 = undefined;
    var server_random: [32]u8 = undefined;
    for (&client_random, 0..) |*b, i| b.* = @intCast(0xc0 + (i & 0x0f));
    for (&server_random, 0..) |*b, i| b.* = @intCast(0x50 + (i & 0x0f));
    const point = sampleP256Point();
    var buf: [256]u8 = undefined;

    // Act
    const out = try signedParams(&buf, client_random, server_random, 23, &point);

    // Assert: client_random occupies bytes [0,32), server_random [32,64).
    try testing.expectEqualSlices(u8, &client_random, out[0..32]);
    try testing.expectEqualSlices(u8, &server_random, out[32..64]);
    // ServerECDHParams follows: curve_type, named_curve, point length, point.
    try testing.expectEqual(curve_type_named_curve, out[64]);
    try testing.expectEqual(@as(u16, 23), mem.readInt(u16, out[65..67], .big));
    try testing.expectEqual(@as(u8, point.len), out[67]);
    try testing.expectEqualSlices(u8, &point, out[68 .. 68 + point.len]);
    try testing.expectEqual(@as(usize, 64 + ecdh_params_header_len + point.len), out.len);
}

test "truncated ServerKeyExchange yields error.Truncated" {
    // Arrange: a valid SKE, then feed progressively shorter prefixes.
    const point = sampleP256Point();
    const signature = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const ske = ServerKeyExchange{
        .named_curve = 23,
        .point = &point,
        .sig_scheme = 0x0403,
        .signature = &signature,
    };
    var buf: [256]u8 = undefined;
    const wire = try encodeServerKeyExchange(&buf, ske);

    // Act / Assert: chop the last byte (signature short by one) and a header.
    try testing.expectError(Error.Truncated, parseServerKeyExchange(wire[0 .. wire.len - 1]));
    try testing.expectError(Error.Truncated, parseServerKeyExchange(wire[0..3]));
    // Trailing garbage is also rejected (must consume body exactly).
    var longer: [257]u8 = undefined;
    @memcpy(longer[0..wire.len], wire);
    longer[wire.len] = 0x00;
    try testing.expectError(Error.Truncated, parseServerKeyExchange(longer[0 .. wire.len + 1]));
}

test "truncated ClientKeyExchange yields error.Truncated" {
    // Arrange
    const point = sampleP256Point();
    var buf: [128]u8 = undefined;
    const wire = try encodeClientKeyExchange(&buf, &point);

    // Act / Assert
    try testing.expectError(Error.Truncated, parseClientKeyExchange(wire[0 .. wire.len - 1]));
    try testing.expectError(Error.Truncated, parseClientKeyExchange(&.{}));
}

test "non-named curve_type is rejected" {
    // Arrange: a body that is structurally fine but declares explicit_prime(1).
    const point = sampleP256Point();
    const signature = [_]u8{ 0x01, 0x02 };
    const ske = ServerKeyExchange{
        .named_curve = 23,
        .point = &point,
        .sig_scheme = 0x0403,
        .signature = &signature,
    };
    var buf: [256]u8 = undefined;
    const wire = try encodeServerKeyExchange(&buf, ske);
    var mutated: [256]u8 = undefined;
    @memcpy(mutated[0..wire.len], wire);
    mutated[0] = 1; // explicit_prime, not named_curve

    // Act / Assert
    try testing.expectError(
        Error.UnsupportedCurveType,
        parseServerKeyExchange(mutated[0..wire.len]),
    );
}

test "builders report NoSpaceLeft when buffer is too small" {
    // Arrange
    const point = sampleP256Point();
    const signature = [_]u8{ 0x00, 0x00 };
    const ske = ServerKeyExchange{
        .named_curve = 23,
        .point = &point,
        .sig_scheme = 0x0403,
        .signature = &signature,
    };
    var tiny: [8]u8 = undefined;

    // Act / Assert
    try testing.expectError(Error.NoSpaceLeft, encodeServerKeyExchange(&tiny, ske));
    try testing.expectError(Error.NoSpaceLeft, encodeClientKeyExchange(&tiny, &point));
    var cr: [32]u8 = undefined;
    var sr: [32]u8 = undefined;
    @memset(&cr, 0);
    @memset(&sr, 0);
    try testing.expectError(Error.NoSpaceLeft, signedParams(&tiny, cr, sr, 23, &point));
}
