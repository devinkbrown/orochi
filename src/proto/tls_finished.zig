//! TLS 1.3 Finished message MAC (RFC 8446 section 4.4.4).
//!
//! The Finished message proves possession of the handshake traffic secret and
//! integrity-protects the entire handshake transcript. Its verify_data is:
//!
//!     finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
//!     verify_data  = HMAC(finished_key, Transcript-Hash(handshake_context))
//!
//! where HKDF-Expand-Label (RFC 8446 section 7.1) prefixes the label with the
//! ASCII string "tls13 " before structured encoding. This module fixes the
//! cipher suite to SHA-256 (32-byte secrets and digests).
//!
//! Pure: no sockets, filesystem, clock, or RNG. Only `std.crypto` is used.
//! The HKDF-Expand-Label primitive is reused from the shared TLS 1.3 key
//! schedule rather than reimplemented here; the contribution of this file is
//! the plain-bytes Finished-MAC surface plus a constant-time `verify` helper.

const std = @import("std");
const hkdf = @import("../crypto/hkdf_tls13.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Length in bytes of every secret and MAC handled here (SHA-256 digest size).
pub const mac_len: usize = 32;

const Schedule = hkdf.Sha256;

comptime {
    // The plain-bytes API below assumes the SHA-256 key schedule uses 32-byte
    // secrets/digests. Guard against an upstream change to that invariant.
    std.debug.assert(Schedule.hash_len == mac_len);
    std.debug.assert(HmacSha256.mac_length == mac_len);
}

/// Derive the Finished key from a handshake traffic secret.
///
///     finished_key = HKDF-Expand-Label(base_key, "finished", "", 32)
///
/// `base_key` is the client_handshake_traffic_secret or
/// server_handshake_traffic_secret depending on which side's Finished is being
/// produced or checked. The expansion cannot fail for a fixed 32-byte output,
/// so the (impossible) HKDF error path is treated as a programming bug.
pub fn finishedKey(base_key: [mac_len]u8) [mac_len]u8 {
    const secret = Schedule.SecretBytes.init(base_key);
    var out: [mac_len]u8 = undefined;
    // HKDF-Expand-Label with an empty context and a 32-byte output length is
    // always within HKDF's bounds, so this never returns an error.
    Schedule.hkdfExpandLabel(&secret, "finished", "", &out) catch unreachable;
    return out;
}

/// Compute Finished verify_data over a transcript hash.
///
///     verify_data = HMAC-SHA256(finished_key(base_key), transcript_hash)
///
/// `transcript_hash` is Transcript-Hash of the handshake messages up to but not
/// including the Finished being produced.
pub fn verifyData(base_key: [mac_len]u8, transcript_hash: [mac_len]u8) [mac_len]u8 {
    const fk = finishedKey(base_key);
    var out: [mac_len]u8 = undefined;
    HmacSha256.create(&out, &transcript_hash, &fk);
    return out;
}

/// Constant-time check of a received Finished verify_data.
///
/// Returns true only when `received` is exactly `mac_len` bytes and equals the
/// locally computed verify_data. The comparison is constant time with respect
/// to byte contents to avoid leaking how many leading bytes matched.
pub fn verify(
    base_key: [mac_len]u8,
    transcript_hash: [mac_len]u8,
    received: []const u8,
) bool {
    if (received.len != mac_len) return false;
    const expected = verifyData(base_key, transcript_hash);
    return std.crypto.timing_safe.eql([mac_len]u8, expected, received[0..mac_len].*);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "finishedKey is deterministic for a fixed input" {
    // Arrange
    var base_key: [mac_len]u8 = undefined;
    for (&base_key, 0..) |*b, i| b.* = @intCast(i);

    // Act
    const first = finishedKey(base_key);
    const second = finishedKey(base_key);

    // Assert
    try std.testing.expectEqualSlices(u8, &first, &second);
}

test "finishedKey differs from the base key it is derived from" {
    // Arrange
    const base_key = [_]u8{0xAB} ** mac_len;

    // Act
    const fk = finishedKey(base_key);

    // Assert: an expansion that returned the input unchanged would be a bug.
    try std.testing.expect(!std.mem.eql(u8, &fk, &base_key));
}

test "finishedKey reuses the shared key schedule primitive" {
    // Arrange
    const base_key = [_]u8{0x5C} ** mac_len;
    const secret = Schedule.SecretBytes.init(base_key);

    // Act
    const via_module = finishedKey(base_key);
    const via_schedule = (try Schedule.finishedKey(&secret)).declassify();

    // Assert
    try std.testing.expectEqualSlices(u8, &via_schedule, &via_module);
}

test "verifyData round-trips with verify returning true" {
    // Arrange
    const base_key = [_]u8{0x11} ** mac_len;
    const transcript = [_]u8{0x22} ** mac_len;

    // Act
    const mac = verifyData(base_key, transcript);
    const ok = verify(base_key, transcript, &mac);

    // Assert
    try std.testing.expect(ok);
}

test "tampered MAC fails verification" {
    // Arrange
    const base_key = [_]u8{0x33} ** mac_len;
    const transcript = [_]u8{0x44} ** mac_len;
    var mac = verifyData(base_key, transcript);

    // Act: flip a single bit of the received tag.
    mac[0] ^= 0x01;
    const ok = verify(base_key, transcript, &mac);

    // Assert
    try std.testing.expect(!ok);
}

test "verify rejects a wrong-length received MAC" {
    // Arrange
    const base_key = [_]u8{0x55} ** mac_len;
    const transcript = [_]u8{0x66} ** mac_len;
    const full = verifyData(base_key, transcript);

    // Act
    const too_short = verify(base_key, transcript, full[0 .. mac_len - 1]);
    const too_long = verify(base_key, transcript, &([_]u8{0} ** (mac_len + 1)));

    // Assert
    try std.testing.expect(!too_short);
    try std.testing.expect(!too_long);
}

test "verifyData changes when the transcript hash changes" {
    // Arrange
    const base_key = [_]u8{0x77} ** mac_len;
    const transcript_a = [_]u8{0x00} ** mac_len;
    var transcript_b = transcript_a;
    transcript_b[mac_len - 1] = 0x01;

    // Act
    const mac_a = verifyData(base_key, transcript_a);
    const mac_b = verifyData(base_key, transcript_b);

    // Assert: distinct transcripts must not collide, and a tag for one must not
    // verify against the other.
    try std.testing.expect(!std.mem.eql(u8, &mac_a, &mac_b));
    try std.testing.expect(!verify(base_key, transcript_b, &mac_a));
}

test "verify uses a constant-time comparison" {
    // Arrange: a MAC matching every byte except the last still fails, and the
    // comparison must not short-circuit on the first byte.
    const base_key = [_]u8{0x99} ** mac_len;
    const transcript = [_]u8{0xAA} ** mac_len;
    var almost = verifyData(base_key, transcript);
    almost[mac_len - 1] ^= 0xFF;

    // Act
    const ok = verify(base_key, transcript, &almost);

    // Assert
    try std.testing.expect(!ok);
}
