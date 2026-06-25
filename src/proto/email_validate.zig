// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure, allocation-free email-address **syntax** validator.
//!
//! This module checks the lexical shape of an email address using a pragmatic,
//! RFC 5321-ish ruleset. It is intentionally *not* a full RFC 5322 parser: no
//! quoted local-parts, no comments, no folding whitespace, no IP-literal
//! domains, and no internationalized (IDN/UTF-8) labels. The goal is a strict,
//! predictable gate suitable for account-registration contact fields where the
//! address must look like an ordinary `local@domain` mailbox.
//!
//! Design constraints:
//!  * Pure functions over `[]const u8`; no allocation, no I/O, no globals.
//!  * Deterministic, exhaustive byte classification.
//!  * Typed errors so callers can map each rejection class to a user message.
//!
//! Accepted grammar (informal):
//!  * Exactly one unescaped `@` separating local and domain.
//!  * `local`  = dot-atom: 1..64 bytes of atom chars, dot-separated, no
//!    leading/trailing/consecutive dots.
//!  * `domain` = 1..255 bytes; one or more LDH labels separated by `.`; each
//!    label 1..63 bytes of letters/digits/hyphen, no leading/trailing hyphen;
//!    at least one dot (i.e. a TLD must be present).
//!  * Total length <= 254 bytes.

const std = @import("std");

/// Maximum length of the local-part in bytes (RFC 5321 §4.5.3.1.1).
pub const MAX_LOCAL_LEN: usize = 64;

/// Maximum length of the domain in bytes (RFC 5321 §4.5.3.1.2).
pub const MAX_DOMAIN_LEN: usize = 255;

/// Maximum length of a single DNS label in bytes (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum length of the entire address in bytes. RFC 5321 caps a forward-path
/// at 256 octets including angle brackets, leaving 254 for the bare address.
pub const MAX_TOTAL_LEN: usize = 254;

/// Typed rejection reasons returned by `validate`.
///
/// Each variant names exactly one failure class so callers can produce a
/// specific, user-facing message instead of a generic "invalid email".
pub const ValidateError = error{
    /// The address does not contain a `@`, so it has no domain separator.
    NoAt,
    /// More than one `@` is present; this validator forbids quoting.
    MultipleAt,
    /// The local-part (text before `@`) is empty.
    EmptyLocal,
    /// The domain (text after `@`) is empty.
    EmptyDomain,
    /// The local-part exceeds `MAX_LOCAL_LEN` bytes.
    LocalTooLong,
    /// The domain exceeds `MAX_DOMAIN_LEN` bytes.
    DomainTooLong,
    /// The whole address exceeds `MAX_TOTAL_LEN` bytes.
    TooLong,
    /// A byte outside the permitted set appeared in the local-part or domain.
    BadChar,
    /// A domain label is empty, too long, or has a leading/trailing hyphen.
    BadDomainLabel,
    /// Two dots appear back-to-back in the local-part or domain.
    ConsecutiveDots,
    /// A dot appears at the start or end of the local-part or domain.
    LeadingTrailingDot,
};

/// The two halves of an address, as borrowed slices into the original input.
pub const Parts = struct {
    /// Text before the `@` separator.
    local: []const u8,
    /// Text after the `@` separator.
    domain: []const u8,
};

/// Split `addr` at its single `@` separator without validating either half.
///
/// Returns `null` when there is not exactly one `@`. The returned slices borrow
/// from `addr`; no allocation is performed. Use `validate` for full checking;
/// this helper is for callers that only need the structural split.
pub fn splitParts(addr: []const u8) ?Parts {
    const at = std.mem.indexOfScalar(u8, addr, '@') orelse return null;
    // Reject a second '@' so the split is unambiguous.
    if (std.mem.indexOfScalarPos(u8, addr, at + 1, '@') != null) return null;
    return Parts{
        .local = addr[0..at],
        .domain = addr[at + 1 ..],
    };
}

/// Return `true` when `addr` is a syntactically valid email address.
///
/// Convenience wrapper over `validate` that discards the specific error.
pub fn isValid(addr: []const u8) bool {
    validate(addr) catch return false;
    return true;
}

/// Validate the syntax of `addr`, returning a specific `ValidateError` on the
/// first rule that fails. Returns normally (`void`) when the address is valid.
pub fn validate(addr: []const u8) ValidateError!void {
    if (addr.len > MAX_TOTAL_LEN) return error.TooLong;

    const at = std.mem.indexOfScalar(u8, addr, '@') orelse return error.NoAt;
    // A quoted-string local-part could legally contain '@', but this validator
    // does not support quoting, so any second '@' is an error.
    if (std.mem.indexOfScalarPos(u8, addr, at + 1, '@') != null) return error.MultipleAt;

    const local = addr[0..at];
    const domain = addr[at + 1 ..];

    try validateLocal(local);
    try validateDomain(domain);
}

/// Validate the local-part: a dot-atom of permitted bytes with no empty atoms.
fn validateLocal(local: []const u8) ValidateError!void {
    if (local.len == 0) return error.EmptyLocal;
    if (local.len > MAX_LOCAL_LEN) return error.LocalTooLong;
    if (local[0] == '.' or local[local.len - 1] == '.') return error.LeadingTrailingDot;

    var prev_dot = false;
    for (local) |byte| {
        if (byte == '.') {
            if (prev_dot) return error.ConsecutiveDots;
            prev_dot = true;
            continue;
        }
        prev_dot = false;
        if (!isLocalByte(byte)) return error.BadChar;
    }
}

/// Validate the domain: dot-separated LDH labels with at least one dot.
fn validateDomain(domain: []const u8) ValidateError!void {
    if (domain.len == 0) return error.EmptyDomain;
    if (domain.len > MAX_DOMAIN_LEN) return error.DomainTooLong;
    if (domain[0] == '.' or domain[domain.len - 1] == '.') return error.LeadingTrailingDot;

    var has_dot = false;
    var label_start: usize = 0;
    var i: usize = 0;
    while (i < domain.len) : (i += 1) {
        if (domain[i] == '.') {
            has_dot = true;
            // An empty label between two dots is a consecutive-dot error.
            if (i == label_start) return error.ConsecutiveDots;
            try validateLabel(domain[label_start..i]);
            label_start = i + 1;
        }
    }
    // The final label after the last dot (or the whole domain if dot-free).
    try validateLabel(domain[label_start..]);

    // A bare hostname with no dot (e.g. "localhost") is rejected: a real
    // deliverable mailbox domain must include at least one dot.
    if (!has_dot) return error.BadDomainLabel;
}

/// Validate a single domain label as an LDH (letter/digit/hyphen) token.
fn validateLabel(label: []const u8) ValidateError!void {
    if (label.len == 0 or label.len > MAX_LABEL_LEN) return error.BadDomainLabel;
    if (label[0] == '-' or label[label.len - 1] == '-') return error.BadDomainLabel;
    for (label) |byte| {
        if (!isLdhByte(byte)) {
            // A '.' here is impossible (the caller splits on dots); any other
            // non-LDH byte is a hard character error.
            return error.BadChar;
        }
    }
}

/// Return `true` for ASCII letters `A-Z`/`a-z`.
fn isAlpha(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

/// Return `true` for ASCII digits `0-9`.
fn isDigit(byte: u8) bool {
    return byte >= '0' and byte <= '9';
}

/// Return `true` for bytes permitted in an LDH domain label
/// (letters, digits, hyphen). The dot separator is handled by the caller.
fn isLdhByte(byte: u8) bool {
    return isAlpha(byte) or isDigit(byte) or byte == '-';
}

/// Return `true` for bytes permitted in a dot-atom local-part.
///
/// This is the RFC 5322 `atext` set (minus the dot, which is handled as the
/// atom separator by `validateLocal`).
fn isLocalByte(byte: u8) bool {
    if (isAlpha(byte) or isDigit(byte)) return true;
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "isValid accepts ordinary addresses" {
    const cases = [_][]const u8{
        "user@example.com",
        "a@b.co",
        "first.last@sub.domain.example.org",
        "tester@example.org",
        "x+tag@gmail.com",
        "name_123@a-b.example",
        "weird!#$%&'*+-/=?^_`{|}~@example.com",
        "1@2.com",
        "UPPER@Example.COM",
    };
    for (cases) |addr| {
        try testing.expect(isValid(addr));
        try validate(addr);
    }
}

test "validate rejects missing at sign" {
    try testing.expectError(error.NoAt, validate("plainaddress"));
    try testing.expect(!isValid("plainaddress"));
}

test "validate rejects multiple at signs" {
    try testing.expectError(error.MultipleAt, validate("a@b@example.com"));
    try testing.expectError(error.MultipleAt, validate("user@@example.com"));
}

test "validate rejects empty local part" {
    try testing.expectError(error.EmptyLocal, validate("@example.com"));
}

test "validate rejects empty domain" {
    try testing.expectError(error.EmptyDomain, validate("user@"));
}

test "validate rejects overlong local part" {
    // Build a local-part one byte over the limit; allocation-free fixed buffer.
    var buf: [MAX_LOCAL_LEN + 1 + 12]u8 = undefined;
    var i: usize = 0;
    while (i < MAX_LOCAL_LEN + 1) : (i += 1) buf[i] = 'a';
    const tail = "@a.com";
    @memcpy(buf[i .. i + tail.len], tail);
    const addr = buf[0 .. i + tail.len];
    try testing.expectError(error.LocalTooLong, validate(addr));
}

test "validate accepts local part at exactly the limit" {
    var buf: [MAX_LOCAL_LEN + 12]u8 = undefined;
    var i: usize = 0;
    while (i < MAX_LOCAL_LEN) : (i += 1) buf[i] = 'a';
    const tail = "@a.com";
    @memcpy(buf[i .. i + tail.len], tail);
    const addr = buf[0 .. i + tail.len];
    try validate(addr);
}

test "validate rejects overlong total length" {
    // Construct an address that fits per-part limits but blows the total cap.
    var buf: [MAX_TOTAL_LEN + 8]u8 = undefined;
    // 64-char local, then '@', then a chain of labels to exceed 254 total.
    var n: usize = 0;
    while (n < MAX_LOCAL_LEN) : (n += 1) buf[n] = 'a';
    buf[n] = '@';
    n += 1;
    // Fill labels "bbbbbbbbb." (9 + dot) until we surpass the total cap.
    while (n < MAX_TOTAL_LEN) {
        var k: usize = 0;
        while (k < 9 and n < buf.len) : (k += 1) {
            buf[n] = 'b';
            n += 1;
        }
        if (n < buf.len) {
            buf[n] = '.';
            n += 1;
        }
    }
    // Append a final TLD to keep the last label non-empty/valid in shape.
    const tld = "co";
    @memcpy(buf[n .. n + tld.len], tld);
    n += tld.len;
    const addr = buf[0..n];
    try testing.expect(addr.len > MAX_TOTAL_LEN);
    try testing.expectError(error.TooLong, validate(addr));
}

test "validate rejects overlong domain" {
    // Domain over 255 bytes but total under cap is impossible (local>=1, @=1),
    // so DomainTooLong is reachable only via the domain check when total<=254.
    // Use a 1-byte local so domain can be up to 252 bytes; push to 253+ via a
    // dedicated under-total construction by checking the helper directly.
    var buf: [MAX_DOMAIN_LEN + 4]u8 = undefined;
    var n: usize = 0;
    while (n < MAX_DOMAIN_LEN + 1) : (n += 1) buf[n] = 'a';
    try testing.expectError(error.DomainTooLong, validateDomain(buf[0..n]));
}

test "validate rejects bad characters in local part" {
    try testing.expectError(error.BadChar, validate("us er@example.com"));
    try testing.expectError(error.BadChar, validate("us(er@example.com"));
    try testing.expectError(error.BadChar, validate("a\"b@example.com"));
}

test "validate rejects bad characters in domain" {
    try testing.expectError(error.BadChar, validate("user@exa_mple.com"));
    try testing.expectError(error.BadChar, validate("user@exa mple.com"));
}

test "validate rejects bad domain labels" {
    try testing.expectError(error.BadDomainLabel, validate("user@-example.com"));
    try testing.expectError(error.BadDomainLabel, validate("user@example-.com"));
    try testing.expectError(error.BadDomainLabel, validate("user@example.-com"));
    // No dot at all: not a deliverable domain.
    try testing.expectError(error.BadDomainLabel, validate("user@localhost"));
}

test "validate rejects label over 63 bytes" {
    var buf: [MAX_LABEL_LEN + 1 + 16]u8 = undefined;
    const head = "user@";
    @memcpy(buf[0..head.len], head);
    var i: usize = head.len;
    var c: usize = 0;
    while (c < MAX_LABEL_LEN + 1) : (c += 1) {
        buf[i] = 'a';
        i += 1;
    }
    const tail = ".com";
    @memcpy(buf[i .. i + tail.len], tail);
    i += tail.len;
    try testing.expectError(error.BadDomainLabel, validate(buf[0..i]));
}

test "validate accepts label at exactly 63 bytes" {
    var buf: [MAX_LABEL_LEN + 16]u8 = undefined;
    const head = "user@";
    @memcpy(buf[0..head.len], head);
    var i: usize = head.len;
    var c: usize = 0;
    while (c < MAX_LABEL_LEN) : (c += 1) {
        buf[i] = 'a';
        i += 1;
    }
    const tail = ".com";
    @memcpy(buf[i .. i + tail.len], tail);
    i += tail.len;
    try validate(buf[0..i]);
}

test "validate rejects consecutive dots" {
    try testing.expectError(error.ConsecutiveDots, validate("a..b@example.com"));
    try testing.expectError(error.ConsecutiveDots, validate("user@example..com"));
}

test "validate rejects leading and trailing dots" {
    try testing.expectError(error.LeadingTrailingDot, validate(".user@example.com"));
    try testing.expectError(error.LeadingTrailingDot, validate("user.@example.com"));
    try testing.expectError(error.LeadingTrailingDot, validate("user@.example.com"));
    try testing.expectError(error.LeadingTrailingDot, validate("user@example.com."));
}

test "splitParts returns halves for a single at sign" {
    const parts = splitParts("user@example.com").?;
    try testing.expectEqualStrings("user", parts.local);
    try testing.expectEqualStrings("example.com", parts.domain);
}

test "splitParts returns null without exactly one at sign" {
    try testing.expectEqual(@as(?Parts, null), splitParts("noatsign"));
    try testing.expectEqual(@as(?Parts, null), splitParts("a@b@c"));
}

test "splitParts handles empty halves" {
    const lead = splitParts("@domain.com").?;
    try testing.expectEqualStrings("", lead.local);
    try testing.expectEqualStrings("domain.com", lead.domain);

    const trail = splitParts("local@").?;
    try testing.expectEqualStrings("local", trail.local);
    try testing.expectEqualStrings("", trail.domain);
}

test "boundary: minimal valid address" {
    try validate("a@b.co");
    try testing.expect(isValid("a@b.co"));
}

test "byte classifiers behave" {
    try testing.expect(isAlpha('A'));
    try testing.expect(isAlpha('z'));
    try testing.expect(!isAlpha('0'));
    try testing.expect(isDigit('5'));
    try testing.expect(!isDigit('a'));
    try testing.expect(isLdhByte('-'));
    try testing.expect(!isLdhByte('_'));
    try testing.expect(isLocalByte('_'));
    try testing.expect(!isLocalByte('@'));
    try testing.expect(!isLocalByte('.'));
}

test "validate uses a leak-free allocator-style harness" {
    // No allocations occur here, but exercise std.testing.allocator to assert
    // the module never leaks when driven from an allocator-bearing test.
    const alloc = std.testing.allocator;
    const dup = try alloc.dupe(u8, "user@example.com");
    defer alloc.free(dup);
    try validate(dup);
    try testing.expect(isValid(dup));
}
