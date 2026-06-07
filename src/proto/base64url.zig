//! URL-safe Base64 (RFC 4648 §5) encode/decode helpers.
//!
//! This module exposes a small, stable convenience API around the standard
//! library's URL-safe codecs (`std.base64.url_safe` / `url_safe_no_pad`).
//! It is used for token-style surfaces (JWT/JWK, opaque tokens) where the
//! URL-safe alphabet (`-`/`_` instead of `+`/`/`) and optional padding are
//! required.
//!
//! Pure: this module performs no I/O. The caller owns every output buffer.
//! `encode` is unpadded (JWT default); `encodePadded` adds `=`; `decode`
//! tolerates input with or without padding.

const std = @import("std");

/// Backing standard-library codecs. The alphabets are identical; only the
/// padding behavior differs.
const padded = std.base64.url_safe;
const no_pad = std.base64.url_safe_no_pad;

/// The pad character used by the padded variant.
const pad_char: u8 = '=';

/// Errors surfaced by this module.
///
/// `NoSpaceLeft`      — the provided output buffer was too small.
/// `InvalidCharacter` — input contained a byte outside the URL-safe alphabet.
/// `InvalidPadding`   — input length / padding is not a valid encoding.
pub const Error = error{
    NoSpaceLeft,
    InvalidCharacter,
    InvalidPadding,
};

/// Exact number of characters produced by `encode` (unpadded) for `n` bytes.
pub fn encodedLen(n: usize) usize {
    return no_pad.Encoder.calcSize(n);
}

/// Exact number of characters produced by `encodePadded` for `n` bytes.
pub fn encodedLenPadded(n: usize) usize {
    return padded.Encoder.calcSize(n);
}

/// Exact number of decoded bytes that `decode` will produce for `text`.
///
/// Accepts input with or without padding. Returns `InvalidPadding` when the
/// (unpadded) length is not a valid base64 encoding.
pub fn decodedLen(text: []const u8) Error!usize {
    const trimmed = stripPadding(text);
    return no_pad.Decoder.calcSizeForSlice(trimmed) catch |err| switch (err) {
        error.InvalidPadding => error.InvalidPadding,
        error.InvalidCharacter => error.InvalidCharacter,
        error.NoSpaceLeft => error.NoSpaceLeft,
    };
}

/// Encode `data` as unpadded URL-safe base64 into `out`.
///
/// Returns the populated slice of `out` (its first `encodedLen(data.len)`
/// bytes). Returns `error.NoSpaceLeft` if `out` is too small. The result
/// never contains a `=` padding character.
pub fn encode(out: []u8, data: []const u8) Error![]const u8 {
    const need = no_pad.Encoder.calcSize(data.len);
    if (out.len < need) return error.NoSpaceLeft;
    return no_pad.Encoder.encode(out[0..need], data);
}

/// Encode `data` as padded URL-safe base64 into `out`.
///
/// Returns the populated slice of `out`. Returns `error.NoSpaceLeft` if `out`
/// is too small. Output is padded with `=` to a multiple of four characters.
pub fn encodePadded(out: []u8, data: []const u8) Error![]const u8 {
    const need = padded.Encoder.calcSize(data.len);
    if (out.len < need) return error.NoSpaceLeft;
    return padded.Encoder.encode(out[0..need], data);
}

/// Decode URL-safe base64 `text` into `out`, tolerating missing padding.
///
/// Both padded and unpadded inputs are accepted; trailing `=` characters are
/// stripped before decoding. Returns the populated slice of `out`. Returns
/// `error.NoSpaceLeft` if `out` is too small, `error.InvalidCharacter` for
/// out-of-alphabet bytes, and `error.InvalidPadding` for malformed lengths.
pub fn decode(out: []u8, text: []const u8) Error![]const u8 {
    const trimmed = stripPadding(text);
    const need = no_pad.Decoder.calcSizeForSlice(trimmed) catch |err| switch (err) {
        error.InvalidPadding => return error.InvalidPadding,
        error.InvalidCharacter => return error.InvalidCharacter,
        error.NoSpaceLeft => return error.NoSpaceLeft,
    };
    if (out.len < need) return error.NoSpaceLeft;
    no_pad.Decoder.decode(out[0..need], trimmed) catch |err| switch (err) {
        error.InvalidCharacter => return error.InvalidCharacter,
        error.InvalidPadding => return error.InvalidPadding,
        error.NoSpaceLeft => return error.NoSpaceLeft,
    };
    return out[0..need];
}

/// Return `text` with any trailing `=` padding removed.
fn stripPadding(text: []const u8) []const u8 {
    var end = text.len;
    while (end > 0 and text[end - 1] == pad_char) : (end -= 1) {}
    return text[0..end];
}

// ---------------------------------------------------------------------------
// Tests (Arrange-Act-Assert)
// ---------------------------------------------------------------------------

test "encode/decode round-trip across lengths" {
    // Arrange
    var enc_buf: [64]u8 = undefined;
    var dec_buf: [64]u8 = undefined;
    const samples = [_][]const u8{
        "",
        "f",
        "fo",
        "foo",
        "foob",
        "fooba",
        "foobar",
        &[_]u8{ 0x00, 0xff, 0x10, 0x80, 0x7f, 0xab },
    };

    // Act / Assert
    for (samples) |s| {
        const e = try encode(&enc_buf, s);
        const d = try decode(&dec_buf, e);
        try std.testing.expectEqualSlices(u8, s, d);
    }
}

test "unpadded encode never contains padding character" {
    // Arrange: lengths 1 and 2 mod 3 would normally require padding.
    var buf: [16]u8 = undefined;

    // Act
    const a = try encode(&buf, "f"); // would be "Zg==" padded
    const b = try encode(&buf, "fo"); // would be "Zm8=" padded

    // Assert
    try std.testing.expect(std.mem.indexOfScalar(u8, a, '=') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, b, '=') == null);
}

test "url-safe alphabet uses '-' and '_' not '+' and '/'" {
    // Arrange: bytes chosen to force index 62 ('-') and 63 ('_').
    var buf: [16]u8 = undefined;
    const data = [_]u8{ 0xfb, 0xff, 0xbf }; // standard base64 -> "+/+/"-ish

    // Act
    const e = try encode(&buf, &data);

    // Assert
    try std.testing.expect(std.mem.indexOfScalar(u8, e, '+') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, e, '/') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, e, '-') != null or
        std.mem.indexOfScalar(u8, e, '_') != null);
}

test "decode tolerates both padded and unpadded input" {
    // Arrange: "fo" -> "Zm8" unpadded / "Zm8=" padded.
    var buf: [16]u8 = undefined;
    var buf2: [16]u8 = undefined;

    // Act
    const from_unpadded = try decode(&buf, "Zm8");
    const from_padded = try decode(&buf2, "Zm8=");

    // Assert
    try std.testing.expectEqualSlices(u8, "fo", from_unpadded);
    try std.testing.expectEqualSlices(u8, "fo", from_padded);
}

test "encodePadded matches RFC padded form and decodes back" {
    // Arrange
    var enc_buf: [16]u8 = undefined;
    var dec_buf: [16]u8 = undefined;

    // Act
    const e = try encodePadded(&enc_buf, "fo");
    const d = try decode(&dec_buf, e);

    // Assert
    try std.testing.expectEqualStrings("Zm8=", e);
    try std.testing.expectEqualSlices(u8, "fo", d);
}

test "encode returns NoSpaceLeft when output buffer too small" {
    // Arrange: "foobar" needs encodedLen(6) == 8 unpadded chars.
    var tiny: [4]u8 = undefined;

    // Act
    const result = encode(&tiny, "foobar");

    // Assert
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "decode returns NoSpaceLeft when output buffer too small" {
    // Arrange: "Zm9vYmFy" decodes to 6 bytes ("foobar").
    var tiny: [2]u8 = undefined;

    // Act
    const result = decode(&tiny, "Zm9vYmFy");

    // Assert
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "decode rejects out-of-alphabet characters" {
    // Arrange: '+' and '/' are NOT valid in the URL-safe alphabet.
    var buf: [16]u8 = undefined;

    // Act / Assert
    try std.testing.expectError(error.InvalidCharacter, decode(&buf, "Zm+v"));
    try std.testing.expectError(error.InvalidCharacter, decode(&buf, "Zm/v"));
}

test "known-answer vector (JWT-style)" {
    // Arrange: JWT header {"alg":"none"} encodes to a well-known token.
    const header = "{\"alg\":\"none\"}";
    const expected = "eyJhbGciOiJub25lIn0";
    var enc_buf: [64]u8 = undefined;
    var dec_buf: [64]u8 = undefined;

    // Act
    const e = try encode(&enc_buf, header);
    const d = try decode(&dec_buf, expected);

    // Assert
    try std.testing.expectEqualStrings(expected, e);
    try std.testing.expectEqualSlices(u8, header, d);
}

test "length helpers are exact" {
    // Arrange / Act / Assert
    try std.testing.expectEqual(@as(usize, 0), encodedLen(0));
    try std.testing.expectEqual(@as(usize, 2), encodedLen(1));
    try std.testing.expectEqual(@as(usize, 3), encodedLen(2));
    try std.testing.expectEqual(@as(usize, 4), encodedLen(3));
    try std.testing.expectEqual(@as(usize, 4), encodedLenPadded(1));
    try std.testing.expectEqual(@as(usize, 6), try decodedLen("Zm9vYmFy")); // "foobar"
    try std.testing.expectEqual(@as(usize, 2), try decodedLen("Zm8")); // "fo"
    try std.testing.expectEqual(@as(usize, 2), try decodedLen("Zm8=")); // padded "fo"
}
