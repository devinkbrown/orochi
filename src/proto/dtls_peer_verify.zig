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
            /// Monotonic bind order, for stalest-first eviction on a full table.
            stamp: u64 = 0,
        };
        slots: [capacity]Slot = @splat(.{}),
        /// Monotonic tick incremented on every bind; the per-slot `stamp` snapshot
        /// records recency so a full table evicts its oldest binding.
        tick: u64 = 0,

        /// Bind (or update) the expected fingerprint for `addr`. Idempotent for a
        /// repeated address. ALWAYS records the expectation — a signaled
        /// fingerprint must never silently vanish (which would let a peer read as
        /// "verification not required" and export keys UNVERIFIED). On a full
        /// table with a new address it evicts the STALEST binding; the terminator
        /// backstops any peer whose binding is evicted after its flight via a
        /// per-session "mutual auth required" flag, so eviction can never open a
        /// fail-open hole. Returns true on success (always, barring a zero-capacity
        /// table), false only when `capacity == 0`.
        pub fn bind(self: *Self, addr: TransportAddress, digest: [digest_len]u8) bool {
            if (self.slots.len == 0) return false;
            self.tick += 1;
            var free: ?*Slot = null;
            var stalest: *Slot = &self.slots[0];
            for (&self.slots) |*s| {
                if (s.active and s.addr.eql(addr)) {
                    s.digest = digest;
                    s.stamp = self.tick;
                    return true;
                }
                if (!s.active) {
                    if (free == null) free = s;
                } else if (s.stamp < stalest.stamp) {
                    stalest = s;
                }
            }
            const slot = free orelse stalest;
            // Evicting another peer's live binding: secure-zero the stale digest.
            if (slot.active and !slot.addr.eql(addr)) std.crypto.secureZero(u8, &slot.digest);
            slot.* = .{ .addr = addr, .digest = digest, .active = true, .stamp = self.tick };
            return true;
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

test "Bindings: a full table evicts the stalest binding rather than dropping a new one" {
    var b: Bindings(2) = .{};
    const a1 = testAddr(1, 6000);
    const a2 = testAddr(2, 6000);
    const a3 = testAddr(3, 6000);
    try testing.expect(b.bind(a1, certDigest("1"))); // stamp 1 (stalest)
    try testing.expect(b.bind(a2, certDigest("2"))); // stamp 2
    // Table full + new address: the expectation is ALWAYS recorded (a signaled
    // fingerprint must never silently vanish). The STALEST binding (a1) is
    // evicted; the terminator's per-session mutual-auth flag keeps any peer whose
    // binding is evicted after its flight fail-closed.
    try testing.expect(b.bind(a3, certDigest("3")));
    try testing.expectEqualSlices(u8, &certDigest("3"), &(b.expectedFor(a3).?));
    try testing.expect(b.expectedFor(a1) == null); // evicted (stalest)
    try testing.expectEqualSlices(u8, &certDigest("2"), &(b.expectedFor(a2).?)); // untouched

    // A known address is still updated in place (no eviction, no new slot).
    const d2b = certDigest("2-prime");
    try testing.expect(b.bind(a2, d2b));
    try testing.expectEqualSlices(u8, &d2b, &(b.expectedFor(a2).?));
    try testing.expectEqualSlices(u8, &certDigest("3"), &(b.expectedFor(a3).?));
}
