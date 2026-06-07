//! ACME (RFC 8555 §6.2) flattened JWS framing.
//!
//! This module assembles the on-the-wire JSON Web Signature objects that an
//! ACME client exchanges with a CA directory. It does **not** sign anything:
//! the caller computes the signature over `signingInput` using their own key
//! (ES256 → raw r||s, EdDSA → raw 64-byte sig) and hands the raw signature
//! bytes back to `flattened`, which base64url-encodes them.
//!
//! Two protected-header shapes are supported:
//!   - JWK header  (`protectedHeaderJwk`)  — for the `newAccount` request,
//!     which embeds the public key as a JWK.
//!   - KID header  (`protectedHeaderKid`)  — for every request after the
//!     account exists, which references the account URL via `kid`.
//!
//! The signing input is `base64url(protected) "." base64url(payload)`, exactly
//! per RFC 7515 §5.1. For POST-as-GET the payload is the empty string, which
//! base64url-encodes to an empty segment, yielding `"<b64url(protected)>."`.
//!
//! Pure: std + the sibling `base64url` module only. No I/O, clock, RNG, or
//! crypto. Every output buffer is owned by the caller. Errors surface as
//! `error.NoSpaceLeft` when a buffer is too small.

const std = @import("std");
const b64 = @import("base64url.zig");

/// Errors surfaced by this module. `NoSpaceLeft` is the only failure mode:
/// every entry point writes into a caller-provided buffer.
pub const Error = error{NoSpaceLeft};

/// Append `bytes` to `out` starting at `*pos`, advancing `*pos`.
/// Returns `error.NoSpaceLeft` if it would overflow `out`.
fn append(out: []u8, pos: *usize, bytes: []const u8) Error!void {
    const end = pos.* + bytes.len;
    if (end > out.len) return error.NoSpaceLeft;
    @memcpy(out[pos.*..end], bytes);
    pos.* = end;
}

/// Append a JSON string member `"name":"value"` (value is assumed to need no
/// escaping — ACME alg/nonce/url/kid tokens are base64url/URL safe).
fn appendStrMember(out: []u8, pos: *usize, name: []const u8, value: []const u8) Error!void {
    try append(out, pos, "\"");
    try append(out, pos, name);
    try append(out, pos, "\":\"");
    try append(out, pos, value);
    try append(out, pos, "\"");
}

/// Append a JSON member whose value is raw JSON (no quoting): `"name":<json>`.
fn appendRawMember(out: []u8, pos: *usize, name: []const u8, json: []const u8) Error!void {
    try append(out, pos, "\"");
    try append(out, pos, name);
    try append(out, pos, "\":");
    try append(out, pos, json);
}

/// Build the protected header JSON embedding a JWK, used for `newAccount`:
///
///   {"alg":"<alg>","jwk":<jwk_json>,"nonce":"<nonce>","url":"<url>"}
///
/// `jwk_json` is inserted verbatim as a JSON object. Member order is fixed
/// (alg, jwk, nonce, url). Returns the populated slice of `out`.
pub fn protectedHeaderJwk(
    alg: []const u8,
    nonce: []const u8,
    url: []const u8,
    jwk_json: []const u8,
    out: []u8,
) Error![]const u8 {
    var pos: usize = 0;
    try append(out, &pos, "{");
    try appendStrMember(out, &pos, "alg", alg);
    try append(out, &pos, ",");
    try appendRawMember(out, &pos, "jwk", jwk_json);
    try append(out, &pos, ",");
    try appendStrMember(out, &pos, "nonce", nonce);
    try append(out, &pos, ",");
    try appendStrMember(out, &pos, "url", url);
    try append(out, &pos, "}");
    return out[0..pos];
}

/// Build the protected header JSON referencing an account by URL, used for
/// every request after `newAccount`:
///
///   {"alg":"<alg>","kid":"<kid>","nonce":"<nonce>","url":"<url>"}
///
/// Member order is fixed (alg, kid, nonce, url). Returns the populated slice
/// of `out`.
pub fn protectedHeaderKid(
    alg: []const u8,
    nonce: []const u8,
    url: []const u8,
    kid: []const u8,
    out: []u8,
) Error![]const u8 {
    var pos: usize = 0;
    try append(out, &pos, "{");
    try appendStrMember(out, &pos, "alg", alg);
    try append(out, &pos, ",");
    try appendStrMember(out, &pos, "kid", kid);
    try append(out, &pos, ",");
    try appendStrMember(out, &pos, "nonce", nonce);
    try append(out, &pos, ",");
    try appendStrMember(out, &pos, "url", url);
    try append(out, &pos, "}");
    return out[0..pos];
}

/// Build the JWS signing input (RFC 7515 §5.1):
///
///   base64url(protected_json) "." base64url(payload_json)
///
/// These are the exact bytes the caller signs. For POST-as-GET, pass
/// `payload_json == ""`; base64url("") is empty, so the result is
/// `"<b64url(protected)>."` with an empty second segment. Returns the
/// populated slice of `out`.
pub fn signingInput(
    protected_json: []const u8,
    payload_json: []const u8,
    out: []u8,
) Error![]const u8 {
    var pos: usize = 0;

    const p_enc = b64.encode(out[pos..], protected_json) catch return error.NoSpaceLeft;
    pos += p_enc.len;

    try append(out, &pos, ".");

    const pay_enc = b64.encode(out[pos..], payload_json) catch return error.NoSpaceLeft;
    pos += pay_enc.len;

    return out[0..pos];
}

/// Build the final flattened JWS JSON (RFC 7515 §7.2.2):
///
///   {"protected":"<b64url(protected)>",
///    "payload":"<b64url(payload)>",
///    "signature":"<b64url(signature)>"}
///
/// `signature` is the raw signature bytes (ES256: r||s, EdDSA: 64-byte sig);
/// this module only base64url-encodes them. Member order is fixed (protected,
/// payload, signature). Returns the populated slice of `out`.
pub fn flattened(
    protected_json: []const u8,
    payload_json: []const u8,
    signature: []const u8,
    out: []u8,
) Error![]const u8 {
    var pos: usize = 0;

    try append(out, &pos, "{\"protected\":\"");
    const p_enc = b64.encode(out[pos..], protected_json) catch return error.NoSpaceLeft;
    pos += p_enc.len;

    try append(out, &pos, "\",\"payload\":\"");
    const pay_enc = b64.encode(out[pos..], payload_json) catch return error.NoSpaceLeft;
    pos += pay_enc.len;

    try append(out, &pos, "\",\"signature\":\"");
    const sig_enc = b64.encode(out[pos..], signature) catch return error.NoSpaceLeft;
    pos += sig_enc.len;

    try append(out, &pos, "\"}");
    return out[0..pos];
}

// ---------------------------------------------------------------------------
// Tests (AAA: Arrange / Act / Assert)
// ---------------------------------------------------------------------------

test "protectedHeaderJwk: fixed member order alg,jwk,nonce,url" {
    // Arrange
    var buf: [256]u8 = undefined;
    const jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"abc\"}";

    // Act
    const hdr = try protectedHeaderJwk("EdDSA", "n0nce", "https://ca/acct", jwk, &buf);

    // Assert
    const expected =
        "{\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"abc\"}," ++
        "\"nonce\":\"n0nce\",\"url\":\"https://ca/acct\"}";
    try std.testing.expectEqualStrings(expected, hdr);
}

test "protectedHeaderKid: fixed member order alg,kid,nonce,url" {
    // Arrange
    var buf: [256]u8 = undefined;

    // Act
    const hdr = try protectedHeaderKid("ES256", "n0nce", "https://ca/order", "https://ca/acct/1", &buf);

    // Assert
    const expected =
        "{\"alg\":\"ES256\",\"kid\":\"https://ca/acct/1\"," ++
        "\"nonce\":\"n0nce\",\"url\":\"https://ca/order\"}";
    try std.testing.expectEqualStrings(expected, hdr);
}

test "signingInput: b64url(protected) DOT b64url(payload)" {
    // Arrange
    var buf: [256]u8 = undefined;
    const protected = "{\"a\":1}";
    const payload = "{\"b\":2}";
    var pbuf: [64]u8 = undefined;
    var paybuf: [64]u8 = undefined;
    const p_enc = try b64.encode(&pbuf, protected);
    const pay_enc = try b64.encode(&paybuf, payload);

    // Act
    const si = try signingInput(protected, payload, &buf);

    // Assert: exactly "<b64url(protected)>.<b64url(payload)>"
    const dot = std.mem.indexOfScalar(u8, si, '.').?;
    try std.testing.expectEqualStrings(p_enc, si[0..dot]);
    try std.testing.expectEqualStrings(pay_enc, si[dot + 1 ..]);
    // Exactly one separator.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, si, "."));
}

test "signingInput: empty payload yields trailing empty segment" {
    // Arrange
    var buf: [256]u8 = undefined;
    const protected = "{\"x\":true}";
    var pbuf: [64]u8 = undefined;
    const p_enc = try b64.encode(&pbuf, protected);

    // Act
    const si = try signingInput(protected, "", &buf);

    // Assert: "<b64url(protected)>." with nothing after the dot
    try std.testing.expect(si.len == p_enc.len + 1);
    try std.testing.expectEqual(@as(u8, '.'), si[si.len - 1]);
    try std.testing.expectEqualStrings(p_enc, si[0 .. si.len - 1]);
}

test "flattened: JSON shape with three b64url fields in order" {
    // Arrange
    var buf: [512]u8 = undefined;
    const protected = "{\"alg\":\"ES256\"}";
    const payload = "{\"p\":1}";
    const signature = [_]u8{0xAA} ** 64; // raw r||s placeholder
    var pbuf: [64]u8 = undefined;
    var paybuf: [64]u8 = undefined;
    var sbuf: [128]u8 = undefined;
    const p_enc = try b64.encode(&pbuf, protected);
    const pay_enc = try b64.encode(&paybuf, payload);
    const sig_enc = try b64.encode(&sbuf, &signature);

    // Act
    const jws = try flattened(protected, payload, &signature, &buf);

    // Assert: exact wire JSON, member order protected/payload/signature.
    var exp_buf: [512]u8 = undefined;
    var pos: usize = 0;
    inline for (.{
        "{\"protected\":\"",   p_enc,
        "\",\"payload\":\"",   pay_enc,
        "\",\"signature\":\"", sig_enc,
        "\"}",
    }) |seg| {
        @memcpy(exp_buf[pos .. pos + seg.len], seg);
        pos += seg.len;
    }
    try std.testing.expectEqualStrings(exp_buf[0..pos], jws);
}

test "flattened: empty payload (POST-as-GET) has empty payload field" {
    // Arrange
    var buf: [512]u8 = undefined;
    const protected = "{\"kid\":\"u\"}";
    const signature = [_]u8{0x01} ** 64;

    // Act
    const jws = try flattened(protected, "", &signature, &buf);

    // Assert: payload field is the empty string.
    try std.testing.expect(std.mem.indexOf(u8, jws, "\"payload\":\"\"") != null);
    try std.testing.expectEqual(@as(u8, '}'), jws[jws.len - 1]);
}

test "NoSpaceLeft surfaces when output buffer too small" {
    // Arrange
    var tiny: [4]u8 = undefined;

    // Act / Assert
    try std.testing.expectError(error.NoSpaceLeft, protectedHeaderKid("ES256", "n", "u", "k", &tiny));
    try std.testing.expectError(error.NoSpaceLeft, signingInput("{\"a\":1}", "{\"b\":2}", &tiny));
    const sig = [_]u8{0} ** 64;
    try std.testing.expectError(error.NoSpaceLeft, flattened("{}", "{}", &sig, &tiny));
}
