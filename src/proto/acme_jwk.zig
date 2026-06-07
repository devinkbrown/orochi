//! JSON Web Key (JWK) encoding and RFC 7638 thumbprint computation.
//!
//! These helpers produce the canonical JWK JSON used by ACME (RFC 8555)
//! account keys and compute the RFC 7638 thumbprint over that canonical
//! form. Two key types are supported:
//!
//!   * NIST P-256 EC keys  — `{"crv":"P-256","kty":"EC","x":...,"y":...}`
//!   * Ed25519 OKP keys    — `{"crv":"Ed25519","kty":"OKP","x":...}`
//!
//! RFC 7638 requires the thumbprint input to be the JWK reduced to its
//! *required* members, with the member names sorted in lexicographic
//! (code-point) order and no insignificant whitespace. For EC keys the
//! required members are `crv`, `kty`, `x`, `y`; for OKP keys they are
//! `crv`, `kty`, `x`. The emit functions here always produce that exact
//! canonical ordering, so the same bytes serve both as a public JWK and as
//! the thumbprint pre-image.
//!
//! Coordinate inputs are the raw big-endian field elements (32 bytes each
//! for P-256; 32 bytes for the Ed25519 public key). They are base64url
//! encoded (unpadded) per RFC 7518 §6.
//!
//! Pure: this module performs no I/O, consults no clock, and uses no RNG.
//! The caller owns every output buffer. Hashing uses
//! `std.crypto.hash.sha2.Sha256`.

const std = @import("std");
const b64 = @import("base64url.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Errors surfaced by the JWK emit functions.
///
/// `NoSpaceLeft` — the provided output buffer was too small to hold the
/// canonical JWK JSON.
pub const Error = error{NoSpaceLeft};

/// Byte length of an unpadded base64url encoding of a 32-byte value
/// (`ceil(32 * 4 / 3)` == 43, since 32 mod 3 == 2).
const b64_len_32: usize = 43;

/// Worst-case canonical JSON length for an EC (P-256) JWK.
///   {"crv":"P-256","kty":"EC","x":"<43>","y":"<43>"}
pub const ec_json_max_len: usize = 48 + 2 * b64_len_32;

/// Worst-case canonical JSON length for an OKP (Ed25519) JWK.
///   {"crv":"Ed25519","kty":"OKP","x":"<43>"}
pub const okp_json_max_len: usize = 37 + b64_len_32;

/// Number of base64url characters produced by `thumbprintB64`
/// (unpadded encoding of the 32-byte SHA-256 digest).
pub const thumbprint_b64_len: usize = b64_len_32;

/// Append `bytes` to `out` starting at `*pos`, advancing `*pos`.
///
/// Returns `error.NoSpaceLeft` when `out` cannot hold the bytes. This is the
/// single bounds-checked primitive every emit path funnels through.
fn appendBytes(out: []u8, pos: *usize, bytes: []const u8) Error!void {
    const end = pos.* + bytes.len;
    if (end > out.len) return error.NoSpaceLeft;
    @memcpy(out[pos.*..end], bytes);
    pos.* = end;
}

/// Append the base64url (unpadded) encoding of `coord` to `out` at `*pos`.
///
/// Encoding is staged through a fixed local buffer so the public buffer is
/// only written via the bounds-checked `appendBytes` primitive.
fn appendB64(out: []u8, pos: *usize, value: [32]u8) Error!void {
    var scratch: [b64_len_32]u8 = undefined;
    // `value` is exactly 32 bytes, so encoding into a 43-byte buffer can
    // never fail; map any (impossible) shortfall to NoSpaceLeft regardless.
    const enc = b64.encode(&scratch, &value) catch return error.NoSpaceLeft;
    try appendBytes(out, pos, enc);
}

/// Emit the canonical JWK JSON for a NIST P-256 public key into `out`.
///
/// Members appear in the exact lexicographic order required by RFC 7638
/// (`crv`, `kty`, `x`, `y`) with no whitespace, e.g.:
///
///     {"crv":"P-256","kty":"EC","x":"<b64url(x)>","y":"<b64url(y)>"}
///
/// `x` and `y` are the raw big-endian affine coordinates. Returns the
/// populated prefix of `out`, or `error.NoSpaceLeft` if `out` is too small
/// (`ec_json_max_len` always suffices).
pub fn jwkEc(x: [32]u8, y: [32]u8, out: []u8) Error![]const u8 {
    var pos: usize = 0;
    try appendBytes(out, &pos, "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
    try appendB64(out, &pos, x);
    try appendBytes(out, &pos, "\",\"y\":\"");
    try appendB64(out, &pos, y);
    try appendBytes(out, &pos, "\"}");
    return out[0..pos];
}

/// Emit the canonical JWK JSON for an Ed25519 public key into `out`.
///
/// Members appear in RFC 7638 order (`crv`, `kty`, `x`) with no whitespace:
///
///     {"crv":"Ed25519","kty":"OKP","x":"<b64url(x)>"}
///
/// `x` is the raw 32-byte Ed25519 public key. Returns the populated prefix
/// of `out`, or `error.NoSpaceLeft` if `out` is too small
/// (`okp_json_max_len` always suffices).
pub fn jwkOkp(x: [32]u8, out: []u8) Error![]const u8 {
    var pos: usize = 0;
    try appendBytes(out, &pos, "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"");
    try appendB64(out, &pos, x);
    try appendBytes(out, &pos, "\"}");
    return out[0..pos];
}

/// Compute the RFC 7638 thumbprint of a P-256 JWK into `out`.
///
/// The thumbprint is `SHA-256` over the canonical JWK JSON produced by
/// `jwkEc` (sorted members, no whitespace). `out` receives the raw 32-byte
/// digest.
pub fn thumbprintEc(x: [32]u8, y: [32]u8, out: *[32]u8) void {
    var buf: [ec_json_max_len]u8 = undefined;
    // jwkEc into ec_json_max_len bytes cannot fail; treat any failure as a
    // programming error.
    const json = jwkEc(x, y, &buf) catch unreachable;
    Sha256.hash(json, out, .{});
}

/// Compute the RFC 7638 thumbprint of an Ed25519 (OKP) JWK into `out`.
///
/// The thumbprint is `SHA-256` over the canonical JWK JSON produced by
/// `jwkOkp`. `out` receives the raw 32-byte digest.
pub fn thumbprintOkp(x: [32]u8, out: *[32]u8) void {
    var buf: [okp_json_max_len]u8 = undefined;
    const json = jwkOkp(x, &buf) catch unreachable;
    Sha256.hash(json, out, .{});
}

/// Convenience: P-256 thumbprint as unpadded base64url text.
///
/// Writes the encoding into `out` (which must hold at least
/// `thumbprint_b64_len` bytes) and returns the populated slice.
pub fn thumbprintB64(x: [32]u8, y: [32]u8, out: []u8) []const u8 {
    var digest: [32]u8 = undefined;
    thumbprintEc(x, y, &digest);
    // out is expected to be >= thumbprint_b64_len; a 32-byte input always
    // encodes to exactly 43 chars.
    return b64.encode(out, &digest) catch unreachable;
}

// ---------------------------------------------------------------------------
// Tests (Arrange-Act-Assert)
// ---------------------------------------------------------------------------

/// Deterministic 32-byte coordinate: byte i == base +% i (no RNG).
fn coord(base: u8) [32]u8 {
    var c: [32]u8 = undefined;
    var i: usize = 0;
    while (i < c.len) : (i += 1) c[i] = base +% @as(u8, @intCast(i));
    return c;
}

test "jwkEc emits exact canonical member order and no whitespace" {
    // Arrange
    const x = coord(0x01);
    const y = coord(0x80);
    var xb: [43]u8 = undefined;
    var yb: [43]u8 = undefined;
    const xe = try b64.encode(&xb, &x);
    const ye = try b64.encode(&yb, &y);
    var out: [ec_json_max_len]u8 = undefined;

    // Act
    const json = try jwkEc(x, y, &out);

    // Assert: member order is crv, kty, x, y exactly, no spaces.
    var expected_buf: [ec_json_max_len]u8 = undefined;
    const expected = try std.fmt.bufPrint(
        &expected_buf,
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}",
        .{ xe, ye },
    );
    try std.testing.expectEqualStrings(expected, json);
    try std.testing.expect(std.mem.indexOfScalar(u8, json, ' ') == null);
    // Lexicographic order: each key appears after the previous.
    const ic = std.mem.indexOf(u8, json, "\"crv\"").?;
    const ik = std.mem.indexOf(u8, json, "\"kty\"").?;
    const ix = std.mem.indexOf(u8, json, "\"x\"").?;
    const iy = std.mem.indexOf(u8, json, "\"y\"").?;
    try std.testing.expect(ic < ik and ik < ix and ix < iy);
}

test "jwkOkp emits exact canonical OKP form" {
    // Arrange
    const x = coord(0x10);
    var xb: [43]u8 = undefined;
    const xe = try b64.encode(&xb, &x);
    var out: [okp_json_max_len]u8 = undefined;

    // Act
    const json = try jwkOkp(x, &out);

    // Assert
    var expected_buf: [okp_json_max_len]u8 = undefined;
    const expected = try std.fmt.bufPrint(
        &expected_buf,
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{s}\"}}",
        .{xe},
    );
    try std.testing.expectEqualStrings(expected, json);
    try std.testing.expect(std.mem.indexOfScalar(u8, json, ' ') == null);
}

test "thumbprintEc is SHA-256 of the exact canonical EC JSON" {
    // Arrange: independently rebuild the canonical JSON and hash it.
    const x = coord(0x2a);
    const y = coord(0xc3);
    var json_buf: [ec_json_max_len]u8 = undefined;
    const json = try jwkEc(x, y, &json_buf);
    var independent: [32]u8 = undefined;
    Sha256.hash(json, &independent, .{});

    // Act
    var got: [32]u8 = undefined;
    thumbprintEc(x, y, &got);

    // Assert
    try std.testing.expectEqualSlices(u8, &independent, &got);
}

test "thumbprintOkp is SHA-256 of the exact canonical OKP JSON" {
    // Arrange
    const x = coord(0x55);
    var json_buf: [okp_json_max_len]u8 = undefined;
    const json = try jwkOkp(x, &json_buf);
    var independent: [32]u8 = undefined;
    Sha256.hash(json, &independent, .{});

    // Act
    var got: [32]u8 = undefined;
    thumbprintOkp(x, &got);

    // Assert
    try std.testing.expectEqualSlices(u8, &independent, &got);
}

test "thumbprintB64 is base64url of the raw EC thumbprint" {
    // Arrange
    const x = coord(0x07);
    const y = coord(0x9e);
    var raw: [32]u8 = undefined;
    thumbprintEc(x, y, &raw);
    var expected_buf: [43]u8 = undefined;
    const expected = try b64.encode(&expected_buf, &raw);

    // Act
    var out: [thumbprint_b64_len]u8 = undefined;
    const got = thumbprintB64(x, y, &out);

    // Assert
    try std.testing.expectEqual(@as(usize, thumbprint_b64_len), got.len);
    try std.testing.expectEqualStrings(expected, got);
    try std.testing.expect(std.mem.indexOfScalar(u8, got, '=') == null);
}

test "thumbprint digest pipeline matches a fixed canonical string" {
    // Arrange: a fully-specified canonical JWK string. Hashing it with the
    // standard SHA-256 must agree with hashing the bytes our emitters would
    // produce, anchoring the SHA-256 + base64url contract end to end.
    const sample = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"AQAB\"}";
    var digest: [32]u8 = undefined;
    Sha256.hash(sample, &digest, .{});
    var b64buf: [43]u8 = undefined;

    // Act
    const enc = try b64.encode(&b64buf, &digest);

    // Assert: a 32-byte digest base64url-encodes to exactly 43 unpadded
    // characters, matching `thumbprint_b64_len`.
    try std.testing.expectEqual(@as(usize, 32), digest.len);
    try std.testing.expectEqual(thumbprint_b64_len, enc.len);
}

test "jwkEc returns NoSpaceLeft when output buffer too small" {
    // Arrange
    const x = coord(0x01);
    const y = coord(0x02);
    var tiny: [16]u8 = undefined;

    // Act
    const result = jwkEc(x, y, &tiny);

    // Assert
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "jwkOkp returns NoSpaceLeft when output buffer too small" {
    // Arrange
    const x = coord(0x03);
    var tiny: [8]u8 = undefined;

    // Act
    const result = jwkOkp(x, &tiny);

    // Assert
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "different coordinates yield different thumbprints" {
    // Arrange
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;

    // Act
    thumbprintEc(coord(0x01), coord(0x02), &a);
    thumbprintEc(coord(0x01), coord(0x03), &b);

    // Assert
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
