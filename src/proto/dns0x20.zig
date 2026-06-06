//! DNS-0x20 query-name case randomization (draft-vixie-dnsext-dns0x20).
//!
//! An anti-cache-poisoning technique: before sending a DNS query, the resolver
//! randomizes the case of each ASCII letter in the question name. A compliant
//! authoritative server echoes the question section verbatim, preserving that
//! case. A blind off-path spoofer can match the name case-insensitively but
//! cannot reproduce the exact random case pattern, so its forged reply is
//! rejected. This adds entropy on top of the query ID and source port without
//! changing the resolved answer (DNS names are case-insensitive for matching).
//!
//! This module is pure and deterministic: the randomness is supplied by the
//! caller as `rand_bits` (drawn from a CSPRNG in production), which keeps the
//! logic testable and free of any I/O, clock, or RNG dependency. Zero-alloc:
//! all output goes into a caller-owned buffer.

const std = @import("std");

/// Errors returned by the DNS-0x20 codec.
pub const Error = error{
    /// The caller-provided output buffer is smaller than the input name.
    NoSpaceLeft,
};

/// Returns true if `c` is an ASCII letter (the only bytes whose case varies).
fn isAsciiLetter(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z');
}

/// Folds a single ASCII byte to lowercase; non-letters are returned unchanged.
fn toLowerAscii(c: u8) u8 {
    return switch (c) {
        'A'...'Z' => c | 0x20,
        else => c,
    };
}

/// Forces a single ASCII letter to a given case. Non-letters are unchanged.
fn applyCase(c: u8, upper: bool) u8 {
    return switch (c) {
        'A'...'Z', 'a'...'z' => if (upper) (c & ~@as(u8, 0x20)) else (c | 0x20),
        else => c,
    };
}

/// Copies `name` into `out`, randomizing the case of each ASCII letter using
/// successive bits of `rand_bits` (LSB first): a 1-bit forces uppercase, a
/// 0-bit forces lowercase. Non-letter bytes (digits, dots, hyphens, etc.) are
/// copied unchanged and do NOT consume a randomness bit. Returns the populated
/// slice of `out`.
///
/// At most 64 letters draw fresh entropy; beyond that the bit index saturates
/// and reuses the high bit, which is acceptable for the rare case of very long
/// names (the query ID and port still contribute independent entropy).
pub fn encode(name: []const u8, out: []u8, rand_bits: u64) Error![]const u8 {
    if (out.len < name.len) return error.NoSpaceLeft;

    var bit_index: u6 = 0;
    for (name, 0..) |c, i| {
        if (isAsciiLetter(c)) {
            const upper = (rand_bits >> bit_index) & 1 == 1;
            out[i] = applyCase(c, upper);
            // Saturate at bit 63 instead of wrapping back to bit 0, so a long
            // name does not periodically repeat the low-order bit pattern.
            if (bit_index != 63) bit_index += 1;
        } else {
            out[i] = c;
        }
    }

    return out[0..name.len];
}

/// Verifies that `echoed` is byte-for-byte identical to `sent`, including the
/// exact randomized case. This is the security check: a reply that only matched
/// the name case-insensitively (a spoofer) will differ in case and fail here.
/// A length mismatch always fails.
pub fn verify(sent: []const u8, echoed: []const u8) bool {
    if (sent.len != echoed.len) return false;
    for (sent, echoed) |a, b| {
        if (a != b) return false;
    }
    return true;
}

/// Case-insensitive ASCII equality, for the looser name comparisons DNS allows
/// (e.g. matching an answer's owner name against the question regardless of the
/// 0x20 randomization). A length mismatch returns false.
pub fn equalFold(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (toLowerAscii(x) != toLowerAscii(y)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "encode with all-ones bits uppercases every letter" {
    // Arrange
    const name = "example.com";
    var buf: [32]u8 = undefined;

    // Act
    const got = try encode(name, &buf, ~@as(u64, 0));

    // Assert
    try testing.expectEqualStrings("EXAMPLE.COM", got);
}

test "encode with all-zero bits lowercases every letter" {
    // Arrange
    const name = "EXAMPLE.COM";
    var buf: [32]u8 = undefined;

    // Act
    const got = try encode(name, &buf, 0);

    // Assert
    try testing.expectEqualStrings("example.com", got);
}

test "encode leaves digits dots and hyphens unchanged" {
    // Arrange
    const name = "a1-b2.host-9.net";
    var buf: [32]u8 = undefined;

    // Act: all-ones so letters uppercase, separators must survive verbatim.
    const got = try encode(name, &buf, ~@as(u64, 0));

    // Assert
    try testing.expectEqualStrings("A1-B2.HOST-9.NET", got);
}

test "encode applies per-letter bits LSB first skipping non-letters" {
    // Arrange: bits 0,1,2,3 = 1,0,1,0 -> upper,lower,upper,lower for letters.
    const name = "ab.cd";
    var buf: [8]u8 = undefined;
    const bits: u64 = 0b0101; // bit0=1,bit1=0,bit2=1,bit3=0

    // Act
    const got = try encode(name, &buf, bits);

    // Assert: '.' consumes no bit, so c,d use bits 2,3.
    try testing.expectEqualStrings("Ab.Cd", got);
}

test "encode returns NoSpaceLeft when buffer too small" {
    // Arrange
    const name = "toolong";
    var buf: [3]u8 = undefined;

    // Act
    const result = encode(name, &buf, 0);

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "encode handles empty name" {
    // Arrange
    var buf: [4]u8 = undefined;

    // Act
    const got = try encode("", &buf, ~@as(u64, 0));

    // Assert
    try testing.expectEqual(@as(usize, 0), got.len);
}

test "verify returns true for an exact echo" {
    // Arrange
    const sent = "ExAmPle.CoM";

    // Act
    const ok = verify(sent, "ExAmPle.CoM");

    // Assert
    try testing.expect(ok);
}

test "verify returns false for a case-flipped echo" {
    // Arrange: spoofer matched the name but not the exact 0x20 case pattern.
    const sent = "ExAmPle.CoM";

    // Act
    const ok = verify(sent, "eXaMpLE.coM");

    // Assert
    try testing.expect(!ok);
}

test "verify returns false on length mismatch" {
    // Arrange
    const sent = "example.com";

    // Act
    const ok = verify(sent, "example.co");

    // Assert
    try testing.expect(!ok);
}

test "verify round-trips with encode output" {
    // Arrange
    const name = "resolver.test.example";
    var buf: [40]u8 = undefined;
    const bits: u64 = 0xA5A5_A5A5_A5A5_A5A5;

    // Act
    const sent = try encode(name, &buf, bits);

    // Assert: a verbatim echo verifies; the case-insensitive original does not.
    try testing.expect(verify(sent, sent));
    try testing.expect(!verify(sent, name));
}

test "equalFold is true across differing case" {
    // Arrange / Act / Assert
    try testing.expect(equalFold("Example.COM", "eXaMpLe.com"));
}

test "equalFold is false across differing content" {
    // Arrange / Act / Assert
    try testing.expect(!equalFold("example.com", "example.net"));
}

test "equalFold is false on length mismatch" {
    // Arrange / Act / Assert
    try testing.expect(!equalFold("abc", "abcd"));
}

test "equalFold leaves non-letters compared literally" {
    // Arrange: digits and separators must match exactly even when folding.
    try testing.expect(equalFold("a-1.b", "A-1.B"));
    try testing.expect(!equalFold("a-1.b", "a_1.b"));
}
