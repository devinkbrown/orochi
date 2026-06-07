//! ACME (RFC 8555 §8) challenge key authorization helpers.
//!
//! This module computes the small, deterministic strings an ACME client needs
//! to answer the two common challenge types defined by RFC 8555:
//!
//!   * HTTP-01 (§8.3) — the client serves the *key authorization* as a file at
//!     `/.well-known/acme-challenge/<token>`.
//!   * DNS-01  (§8.4) — the client publishes `base64url(SHA-256(keyAuth))` as a
//!     TXT record at `_acme-challenge.<domain>`.
//!
//! The *key authorization* (§8.1) is the challenge `token`, a `.` separator,
//! and the base64url-encoded SHA-256 thumbprint of the account key's JWK
//! (RFC 7638). This module does NOT compute the thumbprint — the caller
//! supplies it (e.g. from the sibling JWK module) so this file stays free of
//! key-material handling.
//!
//! Pure: no I/O, no clock, no RNG. Hashing uses `std.crypto.hash.sha2.Sha256`
//! and base64url encoding is delegated to the sibling `base64url.zig`. The
//! caller owns every output buffer; functions return the populated sub-slice.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64url = @import("base64url.zig");
const toml = @import("toml.zig");

/// The fixed URL path prefix every HTTP-01 challenge is served under (§8.3).
pub const well_known_prefix = "/.well-known/acme-challenge/";

/// The byte that joins the token and the thumbprint in a key authorization.
const join_byte: u8 = '.';

/// Defensive upper bound on ACME token length. Tokens are server-chosen opaque
/// base64url strings; RFC 8555 §8.1 requires "at least 128 bits of entropy"
/// but sets no maximum. We accept a generous range and reject absurd inputs.
pub const default_max_token_len: usize = 256;

/// Operationally tunable wire-parse cap on challenge token length. Overridable
/// via `[acme].wire_max_token_len`; defaults to the historic 256-byte bound so
/// behavior is unchanged when unset.
pub var max_token_len: usize = default_max_token_len;

/// Overlay `[acme].wire_max_token_len` onto the module-level token cap. Absent
/// or zero values leave the current cap unchanged (behavior preserved).
pub fn applyToml(doc: *const toml.Document) void {
    if (doc.getUint("acme.wire_max_token_len")) |v| {
        if (v != 0) max_token_len = @intCast(v);
    }
}

/// Errors surfaced by this module.
///
/// `NoSpaceLeft` — a provided output buffer was too small for the result.
pub const Error = error{NoSpaceLeft};

/// Length, in bytes, of a key authorization for the given parts.
///
/// Equal to `token.len + 1 + thumbprint_b64.len` (the `1` is the `.`).
pub fn keyAuthorizationLen(token: []const u8, thumbprint_b64: []const u8) usize {
    return token.len + 1 + thumbprint_b64.len;
}

/// Build the key authorization `token "." thumbprint_b64` into `out` (§8.1).
///
/// `thumbprint_b64` is the base64url SHA-256 thumbprint of the account-key JWK
/// (RFC 7638), supplied by the caller. Returns the populated slice of `out`,
/// or `error.NoSpaceLeft` if `out` cannot hold the full result.
pub fn keyAuthorization(
    token: []const u8,
    thumbprint_b64: []const u8,
    out: []u8,
) Error![]const u8 {
    const need = keyAuthorizationLen(token, thumbprint_b64);
    if (out.len < need) return error.NoSpaceLeft;

    @memcpy(out[0..token.len], token);
    out[token.len] = join_byte;
    @memcpy(out[token.len + 1 ..][0..thumbprint_b64.len], thumbprint_b64);
    return out[0..need];
}

/// Length, in bytes, of the HTTP-01 path for `token`.
pub fn http01PathLen(token: []const u8) usize {
    return well_known_prefix.len + token.len;
}

/// Build the HTTP-01 challenge path `/.well-known/acme-challenge/<token>` into
/// `out` (§8.3). This is the URL path at which the server must serve the key
/// authorization. Returns the populated slice, or `error.NoSpaceLeft`.
pub fn http01Path(token: []const u8, out: []u8) Error![]const u8 {
    const need = http01PathLen(token);
    if (out.len < need) return error.NoSpaceLeft;

    @memcpy(out[0..well_known_prefix.len], well_known_prefix);
    @memcpy(out[well_known_prefix.len..][0..token.len], token);
    return out[0..need];
}

/// Exact number of base64url characters produced for a DNS-01 TXT value.
///
/// The value is the base64url (unpadded) encoding of a 32-byte SHA-256 digest.
pub fn dns01TxtValueLen() usize {
    return base64url.encodedLen(Sha256.digest_length);
}

/// Compute the DNS-01 TXT record value for `key_auth` (§8.4).
///
/// Returns `base64url(SHA-256(key_authorization))` — the value published at
/// `_acme-challenge.<domain>` — into `out`. Returns the populated slice, or
/// `error.NoSpaceLeft` if `out` is too small (need `dns01TxtValueLen()`).
pub fn dns01TxtValue(key_auth: []const u8, out: []u8) Error![]const u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(key_auth, &digest, .{});

    return base64url.encode(out, &digest) catch |err| switch (err) {
        error.NoSpaceLeft => error.NoSpaceLeft,
        // `encode` only ever fails with NoSpaceLeft; map any other variant
        // (none expected) conservatively to the same buffer-size error.
        else => error.NoSpaceLeft,
    };
}

/// Return true if `c` is a member of the URL-safe base64 alphabet (RFC 4648 §5):
/// `A-Z`, `a-z`, `0-9`, `-`, `_`. ACME tokens never contain padding.
fn isBase64UrlChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => true,
        else => false,
    };
}

/// Validate an ACME challenge `token` (§8.1).
///
/// A token must be non-empty, within a reasonable length bound, and contain
/// only URL-safe base64 characters (no padding). Returns false otherwise.
pub fn validateToken(token: []const u8) bool {
    if (token.len == 0) return false;
    if (token.len > max_token_len) return false;
    for (token) |c| {
        if (!isBase64UrlChar(c)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "keyAuthorization concatenates token, dot, and thumbprint" {
    // Arrange
    const token = "DGyRejmCefe7v4NfDGDKfA";
    const thumbprint = "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";
    var buf: [128]u8 = undefined;

    // Act
    const key_auth = try keyAuthorization(token, thumbprint, &buf);

    // Assert
    try testing.expectEqualStrings(token ++ "." ++ thumbprint, key_auth);
    try testing.expectEqual(keyAuthorizationLen(token, thumbprint), key_auth.len);
}

test "keyAuthorization returns NoSpaceLeft when buffer too small" {
    // Arrange
    const token = "abc";
    const thumbprint = "xyz";
    var buf: [3]u8 = undefined; // need 7 ("abc.xyz")

    // Act
    const result = keyAuthorization(token, thumbprint, &buf);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "http01Path produces well-known acme-challenge prefix" {
    // Arrange
    const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    var buf: [128]u8 = undefined;

    // Act
    const path = try http01Path(token, &buf);

    // Assert
    try testing.expectEqualStrings("/.well-known/acme-challenge/" ++ token, path);
    try testing.expect(std.mem.startsWith(u8, path, well_known_prefix));
    try testing.expect(std.mem.endsWith(u8, path, token));
}

test "http01Path returns NoSpaceLeft for tiny buffer" {
    // Arrange
    const token = "tok";
    var buf: [4]u8 = undefined; // prefix alone is far longer

    // Act
    const result = http01Path(token, &buf);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "dns01TxtValue equals base64url(sha256(keyAuth)) recomputed independently" {
    // Arrange
    const key_auth = "DGyRejmCefe7v4NfDGDKfA.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";
    var out: [64]u8 = undefined;

    // Act
    const txt = try dns01TxtValue(key_auth, &out);

    // Assert — independently recompute the expected value.
    var expected_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(key_auth, &expected_digest, .{});
    var expected_buf: [64]u8 = undefined;
    const expected = try base64url.encode(&expected_buf, &expected_digest);
    try testing.expectEqualStrings(expected, txt);
    try testing.expectEqual(dns01TxtValueLen(), txt.len);
    // base64url of a 32-byte digest is 43 unpadded characters.
    try testing.expectEqual(@as(usize, 43), txt.len);
}

test "dns01TxtValue returns NoSpaceLeft when buffer too small" {
    // Arrange
    const key_auth = "token.thumb";
    var out: [10]u8 = undefined; // need 43

    // Act
    const result = dns01TxtValue(key_auth, &out);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "validateToken accepts a well-formed base64url token" {
    // Arrange
    const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";

    // Act
    const ok = validateToken(token);

    // Assert
    try testing.expect(ok);
}

test "validateToken rejects an empty token" {
    // Arrange
    const token = "";

    // Act / Assert
    try testing.expect(!validateToken(token));
}

test "validateToken rejects illegal characters" {
    // Arrange — padding, plus/slash, dot, and whitespace are all invalid.
    const bad = [_][]const u8{
        "abc=def", // padding char
        "abc+def", // standard-alphabet '+'
        "abc/def", // standard-alphabet '/'
        "abc.def", // the key-auth separator is not a token char
        "abc def", // whitespace
        "abc\ndef", // control char
    };

    // Act / Assert
    for (bad) |t| {
        try testing.expect(!validateToken(t));
    }
}

test "validateToken rejects an over-long token" {
    // Arrange
    const token = "a" ** (default_max_token_len + 1);

    // Act / Assert
    try testing.expect(!validateToken(token));
}

test "validateToken accepts all alphabet boundary characters" {
    // Arrange — every distinct class plus the two special chars.
    const token = "AZaz09-_";

    // Act / Assert
    try testing.expect(validateToken(token));
}

test "applyToml overrides the wire token cap and restores cleanly" {
    // Arrange
    const saved = max_token_len;
    defer max_token_len = saved; // never leak the override into other tests
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[acme]\nwire_max_token_len = 8\n");
    defer doc.deinit(allocator);

    // Act
    applyToml(&doc);

    // Assert — a 9-char token now fails, an 8-char token passes.
    try testing.expectEqual(@as(usize, 8), max_token_len);
    try testing.expect(!validateToken("AAAAAAAAA"));
    try testing.expect(validateToken("AAAAAAAA"));
}

test "applyToml leaves the cap unchanged when key absent or zero" {
    const saved = max_token_len;
    defer max_token_len = saved;
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator, "[acme]\nwire_max_token_len = 0\n");
    defer doc.deinit(allocator);

    applyToml(&doc);
    try testing.expectEqual(default_max_token_len, max_token_len);
}
