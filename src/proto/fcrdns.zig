//! Forward-Confirmed reverse DNS (FCrDNS) verification.
//!
//! Pure host-validation logic an IRC daemon applies before trusting a hostname
//! derived from a client connection. The flow an ircd performs is:
//!
//!   1. Take the client's connecting IP.
//!   2. Resolve its PTR record to obtain a hostname.
//!   3. Resolve that hostname forward (A / AAAA) to a set of addresses.
//!   4. Confirm the original IP appears in that forward set.
//!
//! Only step 4 (the decision) lives here. All network resolution happens behind
//! the reactor I/O seam; this module reads no sockets, files, or clocks and
//! performs no allocation. Callers feed in the already-resolved facts and
//! receive a verdict.

const std = @import("std");
const dns = @import("dns.zig");

/// Re-export so callers depend on a single canonical address type.
pub const Address = dns.Address;

/// Outcome of an FCrDNS check.
pub const Verdict = enum {
    /// PTR produced a hostname and the original IP is in the forward set.
    confirmed,
    /// PTR produced a hostname but the original IP is absent from the forward
    /// set (possible spoof or stale/incorrect records). Hostname must not be
    /// trusted; fall back to the textual IP.
    mismatch,
    /// No PTR hostname was available for the original IP.
    no_ptr,
    /// A PTR hostname existed but it resolved to no forward addresses.
    no_forward,
};

/// Byte-exact equality between two addresses. Addresses of differing families
/// are never equal, so an IPv4 address can never falsely confirm against an
/// IPv6 forward record (or vice versa).
pub fn addressEql(a: Address, b: Address) bool {
    return switch (a) {
        .ipv4 => |a_bytes| switch (b) {
            .ipv4 => |b_bytes| std.mem.eql(u8, &a_bytes, &b_bytes),
            .ipv6 => false,
        },
        .ipv6 => |a_bytes| switch (b) {
            .ipv4 => false,
            .ipv6 => |b_bytes| std.mem.eql(u8, &a_bytes, &b_bytes),
        },
    };
}

/// Decide the FCrDNS verdict.
///
/// - `original`: the IP the client actually connected from.
/// - `ptr_hostname`: the hostname obtained from the PTR lookup. An empty slice
///   means no PTR record was found.
/// - `forward`: the A/AAAA addresses the PTR hostname resolved to.
///
/// Precedence: a missing hostname short-circuits to `.no_ptr` regardless of the
/// forward set; an empty forward set yields `.no_forward`; otherwise membership
/// of `original` decides between `.confirmed` and `.mismatch`.
pub fn verify(
    original: Address,
    ptr_hostname: []const u8,
    forward: []const Address,
) Verdict {
    if (ptr_hostname.len == 0) return .no_ptr;
    if (forward.len == 0) return .no_forward;

    for (forward) |candidate| {
        if (addressEql(original, candidate)) return .confirmed;
    }
    return .mismatch;
}

const testing = std.testing;

test "verify returns confirmed when original ipv4 is in forward set" {
    // Arrange
    const original = Address{ .ipv4 = .{ 203, 0, 113, 7 } };
    const forward = [_]Address{.{ .ipv4 = .{ 203, 0, 113, 7 } }};

    // Act
    const verdict = verify(original, "host.example.net", &forward);

    // Assert
    try testing.expectEqual(Verdict.confirmed, verdict);
}

test "verify returns confirmed when original ipv6 is in forward set" {
    // Arrange
    const v6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const original = Address{ .ipv6 = v6 };
    const forward = [_]Address{.{ .ipv6 = v6 }};

    // Act
    const verdict = verify(original, "v6.example.net", &forward);

    // Assert
    try testing.expectEqual(Verdict.confirmed, verdict);
}

test "verify returns mismatch when original ip absent from forward set" {
    // Arrange
    const original = Address{ .ipv4 = .{ 198, 51, 100, 9 } };
    const forward = [_]Address{
        .{ .ipv4 = .{ 203, 0, 113, 1 } },
        .{ .ipv4 = .{ 203, 0, 113, 2 } },
    };

    // Act
    const verdict = verify(original, "liar.example.net", &forward);

    // Assert
    try testing.expectEqual(Verdict.mismatch, verdict);
}

test "verify returns no_ptr when hostname is empty" {
    // Arrange
    const original = Address{ .ipv4 = .{ 192, 0, 2, 5 } };
    const forward = [_]Address{.{ .ipv4 = .{ 192, 0, 2, 5 } }};

    // Act: even a matching forward set cannot rescue a missing PTR.
    const verdict = verify(original, "", &forward);

    // Assert
    try testing.expectEqual(Verdict.no_ptr, verdict);
}

test "verify returns no_forward when forward set is empty" {
    // Arrange
    const original = Address{ .ipv4 = .{ 192, 0, 2, 5 } };
    const forward = [_]Address{};

    // Act
    const verdict = verify(original, "host.example.net", &forward);

    // Assert
    try testing.expectEqual(Verdict.no_forward, verdict);
}

test "verify confirms when original is the second of several forward addresses" {
    // Arrange
    const original = Address{ .ipv4 = .{ 203, 0, 113, 22 } };
    const forward = [_]Address{
        .{ .ipv4 = .{ 203, 0, 113, 21 } },
        .{ .ipv4 = .{ 203, 0, 113, 22 } },
        .{ .ipv4 = .{ 203, 0, 113, 23 } },
    };

    // Act
    const verdict = verify(original, "multi.example.net", &forward);

    // Assert
    try testing.expectEqual(Verdict.confirmed, verdict);
}

test "verify does not falsely confirm on family mismatch with equal byte prefix" {
    // Arrange: an IPv4 address whose bytes match the leading bytes of an IPv6
    // forward record must not confirm — families differ.
    const original = Address{ .ipv4 = .{ 0x20, 0x01, 0x0d, 0xb8 } };
    const forward = [_]Address{.{ .ipv6 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    } }};

    // Act
    const verdict = verify(original, "v6host.example.net", &forward);

    // Assert
    try testing.expectEqual(Verdict.mismatch, verdict);
}

test "addressEql is true for identical ipv4 addresses" {
    // Arrange
    const a = Address{ .ipv4 = .{ 10, 0, 0, 1 } };
    const b = Address{ .ipv4 = .{ 10, 0, 0, 1 } };

    // Act / Assert
    try testing.expect(addressEql(a, b));
}

test "addressEql is false across families" {
    // Arrange
    const v4 = Address{ .ipv4 = .{ 0, 0, 0, 0 } };
    const v6 = Address{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } };

    // Act / Assert
    try testing.expect(!addressEql(v4, v6));
    try testing.expect(!addressEql(v6, v4));
}
