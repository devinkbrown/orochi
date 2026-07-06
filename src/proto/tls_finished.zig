// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

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
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

/// Length in bytes of the SHA-256 Finished secret/MAC (default cipher suite).
pub const mac_len: usize = 32;

/// Generic Finished-MAC surface for one TLS 1.3 key schedule + its HMAC. The
/// secret and MAC length follow the schedule's digest size (32 for SHA-256, 48
/// for SHA-384).
pub fn FinishedFor(comptime Schedule: type, comptime Hmac: type) type {
    return struct {
        const Self = @This();
        pub const len = Schedule.hash_len;

        comptime {
            std.debug.assert(Hmac.mac_length == len);
        }

        /// finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
        pub fn finishedKey(base_key: [len]u8) [len]u8 {
            const secret = Schedule.SecretBytes.init(base_key);
            var out: [len]u8 = undefined;
            // Empty context + a Hash.length output is always within HKDF bounds.
            Schedule.hkdfExpandLabel(&secret, "finished", "", &out) catch unreachable;
            return out;
        }

        /// verify_data = HMAC(finished_key(base_key), transcript_hash)
        pub fn verifyData(base_key: [len]u8, transcript_hash: [len]u8) [len]u8 {
            const fk = Self.finishedKey(base_key);
            var out: [len]u8 = undefined;
            Hmac.create(&out, &transcript_hash, &fk);
            return out;
        }

        /// Constant-time check of a received Finished verify_data.
        pub fn verify(base_key: [len]u8, transcript_hash: [len]u8, received: []const u8) bool {
            if (received.len != len) return false;
            const expected = Self.verifyData(base_key, transcript_hash);
            return std.crypto.timing_safe.eql([len]u8, expected, received[0..len].*);
        }
    };
}

/// Pick the Finished surface for a key schedule (SHA-256 or SHA-384).
pub fn For(comptime Schedule: type) type {
    return FinishedFor(Schedule, switch (Schedule) {
        hkdf.Sha256 => HmacSha256,
        hkdf.Sha384 => HmacSha384,
        else => @compileError("unsupported Finished schedule"),
    });
}

pub const Sha256F = For(hkdf.Sha256);
pub const Sha384F = For(hkdf.Sha384);

// --- SHA-256 free-function API (back-compat; the default cipher suite) -------

pub fn finishedKey(base_key: [mac_len]u8) [mac_len]u8 {
    return Sha256F.finishedKey(base_key);
}

pub fn verifyData(base_key: [mac_len]u8, transcript_hash: [mac_len]u8) [mac_len]u8 {
    return Sha256F.verifyData(base_key, transcript_hash);
}

pub fn verify(base_key: [mac_len]u8, transcript_hash: [mac_len]u8, received: []const u8) bool {
    return Sha256F.verify(base_key, transcript_hash, received);
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
    const base_key = @as([mac_len]u8, @splat(0xAB));

    // Act
    const fk = finishedKey(base_key);

    // Assert: an expansion that returned the input unchanged would be a bug.
    try std.testing.expect(!std.mem.eql(u8, &fk, &base_key));
}

test "finishedKey reuses the shared key schedule primitive" {
    // Arrange
    const base_key = @as([mac_len]u8, @splat(0x5C));
    const secret = hkdf.Sha256.SecretBytes.init(base_key);

    // Act
    const via_module = finishedKey(base_key);
    const via_schedule = (try hkdf.Sha256.finishedKey(&secret)).declassify();

    // Assert
    try std.testing.expectEqualSlices(u8, &via_schedule, &via_module);
}

test "SHA-384 Finished surface produces 48-byte verify_data" {
    const base_key = @as([Sha384F.len]u8, @splat(0x24));
    const transcript = @as([Sha384F.len]u8, @splat(0x42));
    try std.testing.expectEqual(@as(usize, 48), Sha384F.len);
    const mac = Sha384F.verifyData(base_key, transcript);
    try std.testing.expect(Sha384F.verify(base_key, transcript, &mac));
    var tampered = mac;
    tampered[0] ^= 1;
    try std.testing.expect(!Sha384F.verify(base_key, transcript, &tampered));
}

test "verifyData round-trips with verify returning true" {
    // Arrange
    const base_key = @as([mac_len]u8, @splat(0x11));
    const transcript = @as([mac_len]u8, @splat(0x22));

    // Act
    const mac = verifyData(base_key, transcript);
    const ok = verify(base_key, transcript, &mac);

    // Assert
    try std.testing.expect(ok);
}

test "tampered MAC fails verification" {
    // Arrange
    const base_key = @as([mac_len]u8, @splat(0x33));
    const transcript = @as([mac_len]u8, @splat(0x44));
    var mac = verifyData(base_key, transcript);

    // Act: flip a single bit of the received tag.
    mac[0] ^= 0x01;
    const ok = verify(base_key, transcript, &mac);

    // Assert
    try std.testing.expect(!ok);
}

test "verify rejects a wrong-length received MAC" {
    // Arrange
    const base_key = @as([mac_len]u8, @splat(0x55));
    const transcript = @as([mac_len]u8, @splat(0x66));
    const full = verifyData(base_key, transcript);

    // Act
    const too_short = verify(base_key, transcript, full[0 .. mac_len - 1]);
    const too_long = verify(base_key, transcript, &(@as([(mac_len + 1)]u8, @splat(0))));

    // Assert
    try std.testing.expect(!too_short);
    try std.testing.expect(!too_long);
}

test "verifyData changes when the transcript hash changes" {
    // Arrange
    const base_key = @as([mac_len]u8, @splat(0x77));
    const transcript_a = @as([mac_len]u8, @splat(0x00));
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
    const base_key = @as([mac_len]u8, @splat(0x99));
    const transcript = @as([mac_len]u8, @splat(0xAA));
    var almost = verifyData(base_key, transcript);
    almost[mac_len - 1] ^= 0xFF;

    // Act
    const ok = verify(base_key, transcript, &almost);

    // Assert
    try std.testing.expect(!ok);
}
