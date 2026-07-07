// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 8122 DTLS-SRTP peer-certificate fingerprint verification for the media
//! plane's DTLS terminators.
//!
//! WebRTC binds the SDP-signaled `a=fingerprint` to the certificate a peer
//! presents in the DTLS handshake. orochi is the DTLS *server* (`setup:passive`),
//! so the browser is the DTLS client: the daemon must verify the browser's
//! presented certificate against the fingerprint the browser signaled in its
//! MEDIA OFFER. This module owns that binding (per remote transport address) and
//! the constant-time comparison, so the handshake-completion path can FAIL
//! CLOSED on a mismatch — withholding the exported SRTP keys entirely.
//!
//! Scope note (Increment 3): the DTLS 1.2/1.3 terminators are today
//! server-authenticated only — they do not yet emit a CertificateRequest nor
//! capture/possession-verify the browser's client certificate (that is a
//! companion terminator-increment change, since it touches the handshake
//! signature crypto). `recordPeerCert` is the seam the terminator calls the
//! moment client-certificate capture lands. Until then, when an expected
//! fingerprint is bound but no peer certificate has been recorded, the peer is
//! UNVERIFIED and the terminator's `exportedKeys`/`srtpProfile` return null
//! (fail closed): a fingerprint that cannot be verified yields no media.

const std = @import("std");
const TransportAddress = @import("ice.zig").TransportAddress;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Length of a SHA-256 certificate fingerprint (RFC 8122 sha-256), in bytes.
pub const digest_len = Sha256.digest_length; // 32

/// SHA-256 over a certificate's DER encoding — the raw bytes an RFC 8122
/// `a=fingerprint:sha-256 <colon-hex>` attribute renders.
pub fn certDigest(cert_der: []const u8) [digest_len]u8 {
    var d: [digest_len]u8 = undefined;
    Sha256.hash(cert_der, &d, .{});
    return d;
}

/// Equality of two 32-byte fingerprints. Both operands are public data; the
/// timing-safe compare is defensive hygiene (the code path is a security gate),
/// not the protection of a secret.
pub fn digestEql(a: [digest_len]u8, b: [digest_len]u8) bool {
    return std.crypto.timing_safe.eql([digest_len]u8, a, b);
}

/// Fixed-capacity table of expected peer fingerprints keyed by remote transport
/// address, sized to the terminator's session table so every in-flight peer can
/// hold one binding. No allocation; a terminator embeds it by value. Lifetime is
/// decoupled from the session slots (a binding is set the moment the signaling
/// layer learns the peer address, before the ClientHello creates a session).
pub fn Bindings(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const Slot = struct {
            addr: TransportAddress = .{},
            digest: [digest_len]u8 = @splat(0),
            active: bool = false,
        };
        slots: [capacity]Slot = @splat(.{}),

        /// Bind (or update) the expected fingerprint for `addr`. Idempotent for a
        /// repeated address. Returns false only when the table is full and `addr`
        /// is new — the caller then treats that peer as UNVERIFIED (fail closed),
        /// never evicting a live peer's binding.
        pub fn bind(self: *Self, addr: TransportAddress, digest: [digest_len]u8) bool {
            var free: ?*Slot = null;
            for (&self.slots) |*s| {
                if (s.active and s.addr.eql(addr)) {
                    s.digest = digest;
                    return true;
                }
                if (!s.active and free == null) free = s;
            }
            if (free) |s| {
                s.* = .{ .addr = addr, .digest = digest, .active = true };
                return true;
            }
            return false;
        }

        /// The expected fingerprint bound for `addr`, or null if none.
        pub fn expectedFor(self: *const Self, addr: TransportAddress) ?[digest_len]u8 {
            for (&self.slots) |*s| {
                if (s.active and s.addr.eql(addr)) return s.digest;
            }
            return null;
        }

        /// Release the binding for `addr` (peer gone / session slot reused for a
        /// new address). Secure-zeros the stored digest.
        pub fn clear(self: *Self, addr: TransportAddress) void {
            for (&self.slots) |*s| {
                if (s.active and s.addr.eql(addr)) {
                    s.active = false;
                    std.crypto.secureZero(u8, &s.digest);
                    return;
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testAddr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

test "certDigest matches std SHA-256" {
    const der = "orochi dtls peer certificate DER";
    var expected: [digest_len]u8 = undefined;
    Sha256.hash(der, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &certDigest(der));
}

test "digestEql distinguishes match from a single-bit flip" {
    const a = certDigest("cert-a");
    var b = a;
    try testing.expect(digestEql(a, b));
    b[0] ^= 0x01;
    try testing.expect(!digestEql(a, b));
}

test "Bindings: bind, lookup, idempotent update, and clear" {
    var b: Bindings(4) = .{};
    const a1 = testAddr(1, 5000);
    const a2 = testAddr(2, 5000);
    const d1 = certDigest("one");
    const d2 = certDigest("two");

    try testing.expect(b.expectedFor(a1) == null);
    try testing.expect(b.bind(a1, d1));
    try testing.expect(b.bind(a2, d2));
    try testing.expectEqualSlices(u8, &d1, &(b.expectedFor(a1).?));
    try testing.expectEqualSlices(u8, &d2, &(b.expectedFor(a2).?));

    // Re-binding the same address updates in place (no new slot consumed).
    const d1b = certDigest("one-prime");
    try testing.expect(b.bind(a1, d1b));
    try testing.expectEqualSlices(u8, &d1b, &(b.expectedFor(a1).?));

    b.clear(a1);
    try testing.expect(b.expectedFor(a1) == null);
    // a2 is unaffected.
    try testing.expectEqualSlices(u8, &d2, &(b.expectedFor(a2).?));
}

test "Bindings: full table refuses a new address (fail closed) but still updates known ones" {
    var b: Bindings(2) = .{};
    const a1 = testAddr(1, 6000);
    const a2 = testAddr(2, 6000);
    const a3 = testAddr(3, 6000);
    try testing.expect(b.bind(a1, certDigest("1")));
    try testing.expect(b.bind(a2, certDigest("2")));
    // Table full: a brand-new address cannot be bound (never evicts a1/a2).
    try testing.expect(!b.bind(a3, certDigest("3")));
    try testing.expect(b.expectedFor(a3) == null);
    // A known address can still be updated even when full.
    const d1b = certDigest("1-prime");
    try testing.expect(b.bind(a1, d1b));
    try testing.expectEqualSlices(u8, &d1b, &(b.expectedFor(a1).?));
}
