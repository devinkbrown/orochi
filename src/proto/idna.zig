// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host-name normalization and validation for IRC use.
//!
//! This module owns a single, self-contained concern: turning a host string
//! into a canonical, case-folded, LDH-validated form, and rejecting hosts that
//! cannot be a well-formed DNS name. It performs no network I/O, no DNS
//! resolution, and no allocation in its public entry points (callers provide
//! the output buffer).
//!
//! Scope and intent:
//!   * ASCII case folding: `A`..`Z` are lowered to `a`..`z`.
//!   * LDH validation: every label is made of letters, digits, and hyphens,
//!     is 1..=63 octets long, and has no leading or trailing hyphen.
//!   * Length limits: the total host is at most 255 octets; a single optional
//!     trailing root dot is tolerated and stripped.
//!   * ACE awareness: labels carrying the `xn--` IDNA ACE prefix are validated
//!     for structural well-formedness (a non-empty Punycode tail using only the
//!     Punycode basic-code-point alphabet) without performing Unicode decoding.
//!
//! This module deliberately does NOT decode Punycode to Unicode nor encode
//! Unicode to Punycode. IRC hostmasks operate on the ASCII-compatible
//! encoding, so the daemon only needs to canonicalize and validate ACE form.
//! Keeping the scope here avoids a dependency on any separate Punycode module.

const std = @import("std");

/// Maximum total length, in octets, of a canonical host name.
///
/// This is the classic DNS presentation-form ceiling. The optional trailing
/// root dot is not counted against this budget.
pub const MAX_HOST_LEN: usize = 255;

/// Maximum length, in octets, of a single DNS label.
pub const MAX_LABEL_LEN: usize = 63;

/// Minimum length, in octets, of a single DNS label.
pub const MIN_LABEL_LEN: usize = 1;

/// The IDNA ACE (ASCII-Compatible Encoding) prefix marking a Punycode label.
pub const ACE_PREFIX = "xn--";

/// Errors returned by host-name normalization and validation.
pub const NormalizeError = error{
    /// The host (or a label) was empty where content was required.
    EmptyHost,
    /// A label was longer than `MAX_LABEL_LEN` octets.
    LabelTooLong,
    /// A label was shorter than `MIN_LABEL_LEN` octets (an empty label).
    LabelTooShort,
    /// The total host length exceeded `MAX_HOST_LEN` octets.
    HostTooLong,
    /// A label began or ended with a hyphen.
    HyphenAtLabelEdge,
    /// A byte outside the LDH (letter/digit/hyphen) set appeared in a label.
    InvalidCharacter,
    /// An `xn--` label was structurally malformed (e.g. empty Punycode tail
    /// or non-basic code points in the encoded body).
    InvalidAceLabel,
    /// The caller-provided output buffer was too small to hold the result.
    OutputTooSmall,
};

/// Normalize `host` into `out`, returning a slice of `out` holding the result.
///
/// The returned slice is the canonical form: ASCII-lowercased, with any single
/// trailing root dot removed, after validating every label. `out` must be at
/// least `host.len` octets; when in doubt size it to `MAX_HOST_LEN`.
///
/// The input is never mutated and no allocation occurs.
pub fn normalize(host: []const u8, out: []u8) NormalizeError![]const u8 {
    const trimmed = stripTrailingRootDot(host);
    if (trimmed.len == 0) return NormalizeError.EmptyHost;
    if (trimmed.len > MAX_HOST_LEN) return NormalizeError.HostTooLong;
    if (out.len < trimmed.len) return NormalizeError.OutputTooSmall;

    var written: usize = 0;
    var label_start: usize = 0;
    var i: usize = 0;
    while (i < trimmed.len) : (i += 1) {
        const c = trimmed[i];
        if (c == '.') {
            try validateLabel(trimmed[label_start..i]);
            out[written] = '.';
            written += 1;
            label_start = i + 1;
        } else {
            out[written] = asciiLower(c);
            written += 1;
        }
    }
    // Validate the final label (the segment after the last dot).
    try validateLabel(trimmed[label_start..trimmed.len]);

    return out[0..written];
}

/// Report whether `host` is a valid host name without producing output.
///
/// This is exactly `normalize` with the result discarded; it allocates a
/// fixed stack buffer sized to `MAX_HOST_LEN` and never touches the heap.
pub fn isValidHost(host: []const u8) bool {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    _ = normalize(host, &buf) catch return false;
    return true;
}

/// Validate a single label in place (no case folding, no output).
///
/// Exposed for callers that already split a host into labels and only need the
/// per-label rules.
pub fn validateLabel(label: []const u8) NormalizeError!void {
    if (label.len < MIN_LABEL_LEN) return NormalizeError.LabelTooShort;
    if (label.len > MAX_LABEL_LEN) return NormalizeError.LabelTooLong;
    if (label[0] == '-' or label[label.len - 1] == '-') {
        return NormalizeError.HyphenAtLabelEdge;
    }
    for (label) |c| {
        if (!isLdhByte(c)) return NormalizeError.InvalidCharacter;
    }
    if (hasAcePrefix(label)) {
        try validateAceLabel(label);
    }
}

/// Report whether `label` carries the `xn--` ACE prefix (case-insensitive).
pub fn hasAcePrefix(label: []const u8) bool {
    if (label.len < ACE_PREFIX.len) return false;
    return asciiEqlIgnoreCase(label[0..ACE_PREFIX.len], ACE_PREFIX);
}

// --- internal helpers -------------------------------------------------------

/// Validate the structure of an `xn--` ACE label.
///
/// The full LDH check (post case-folding) has already run by the time this is
/// called, and every LDH byte is also a Punycode basic code point, so the only
/// ACE-specific concern left is that the encoded tail after the prefix is
/// non-empty. An empty tail is normally caught earlier by the trailing-hyphen
/// rule, but this check makes the requirement explicit and prefix-position
/// independent.
fn validateAceLabel(label: []const u8) NormalizeError!void {
    const tail = label[ACE_PREFIX.len..];
    if (tail.len == 0) return NormalizeError.InvalidAceLabel;
    // Every remaining byte is guaranteed LDH (⊆ Punycode basic alphabet) by the
    // caller's prior validation, so no further per-byte scan is required here.
    std.debug.assert(blk: {
        for (tail) |c| {
            if (!isPunycodeBasic(c)) break :blk false;
        }
        break :blk true;
    });
}

/// Strip at most one trailing `.` (the DNS root label) from `host`.
fn stripTrailingRootDot(host: []const u8) []const u8 {
    if (host.len > 0 and host[host.len - 1] == '.') {
        return host[0 .. host.len - 1];
    }
    return host;
}

/// Lowercase an ASCII byte; non-letters pass through unchanged.
fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
}

/// Report whether `c` is in the LDH set: letter, digit, or hyphen.
fn isLdhByte(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
        (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == '-';
}

/// Report whether `c` is a Punycode basic code point in canonical (lower) form.
///
/// Punycode emits only `a`..`z`, `0`..`9`, and uses `-` as the delimiter
/// between the literal basic prefix and the encoded suffix. Uppercase is
/// already folded away before this check runs.
fn isPunycodeBasic(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-';
}

/// Case-insensitive ASCII equality for two equal-length-or-not slices.
fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (asciiLower(x) != asciiLower(y)) return false;
    }
    return true;
}

// --- tests ------------------------------------------------------------------

const testing = std.testing;

test "normalize: simple ascii host is unchanged" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize("example.com", &buf);
    try testing.expectEqualStrings("example.com", got);
}

test "normalize: folds mixed case to lowercase" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize("ExAmPle.COM", &buf);
    try testing.expectEqualStrings("example.com", got);
}

test "normalize: digits and hyphens in interior are allowed" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize("a1-b2.host-3.net", &buf);
    try testing.expectEqualStrings("a1-b2.host-3.net", got);
}

test "normalize: single-label host" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize("Localhost", &buf);
    try testing.expectEqualStrings("localhost", got);
}

test "normalize: trailing root dot is stripped" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize("Example.Com.", &buf);
    try testing.expectEqualStrings("example.com", got);
}

test "normalize: only-root-dot host is empty" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.EmptyHost, normalize(".", &buf));
}

test "normalize: empty host rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.EmptyHost, normalize("", &buf));
}

test "normalize: empty interior label rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.LabelTooShort, normalize("a..b", &buf));
}

test "normalize: leading dot rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.LabelTooShort, normalize(".example.com", &buf));
}

test "normalize: trailing empty label (double trailing dot) rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    // One trailing dot is stripped; the second leaves an empty final label.
    try testing.expectError(NormalizeError.LabelTooShort, normalize("example.com..", &buf));
}

test "normalize: leading hyphen in label rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.HyphenAtLabelEdge, normalize("-bad.com", &buf));
}

test "normalize: trailing hyphen in label rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.HyphenAtLabelEdge, normalize("bad-.com", &buf));
}

test "normalize: underscore is not LDH" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.InvalidCharacter, normalize("under_score.com", &buf));
}

test "normalize: non-ascii byte rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.InvalidCharacter, normalize("caf\xc3\xa9.com", &buf));
}

test "normalize: space rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.InvalidCharacter, normalize("bad host.com", &buf));
}

test "normalize: label of exactly 63 octets accepted" {
    const label = &@as([MAX_LABEL_LEN]u8, @splat('a'));
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize(label ++ ".com", &buf);
    try testing.expectEqualStrings(label ++ ".com", got);
}

test "normalize: label of 64 octets rejected" {
    const label = &@as([(MAX_LABEL_LEN + 1)]u8, @splat('a'));
    var buf: [MAX_HOST_LEN]u8 = undefined;
    try testing.expectError(NormalizeError.LabelTooLong, normalize(label ++ ".com", &buf));
}

test "normalize: host of exactly 255 octets accepted" {
    // Build "aaaa....a" repeated as 63-octet labels separated by dots to hit 255.
    // 63 + 1 + 63 + 1 + 63 + 1 + 62 = 254, add a 1-char label -> shape to 255.
    const seg = &@as([MAX_LABEL_LEN]u8, @splat('a'));
    // 63*4 = 252, plus 3 dots = 255 exactly.
    const host = seg ++ "." ++ seg ++ "." ++ seg ++ "." ++ seg;
    try testing.expectEqual(@as(usize, MAX_HOST_LEN), host.len);
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize(host, &buf);
    try testing.expectEqual(@as(usize, MAX_HOST_LEN), got.len);
}

test "normalize: host over 255 octets rejected" {
    const seg = &@as([MAX_LABEL_LEN]u8, @splat('a'));
    // 63*4 + 3 dots = 255; append ".a" to exceed.
    const host = seg ++ "." ++ seg ++ "." ++ seg ++ "." ++ seg ++ ".a";
    var buf: [MAX_HOST_LEN + 8]u8 = undefined;
    try testing.expectError(NormalizeError.HostTooLong, normalize(host, &buf));
}

test "normalize: output buffer too small rejected" {
    var small: [3]u8 = undefined;
    try testing.expectError(NormalizeError.OutputTooSmall, normalize("example.com", &small));
}

test "normalize: well-formed xn-- label accepted and folded" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    // "xn--nxasmq6b" is a real ACE label (Bulgarian "бг"-style sample form).
    const got = try normalize("XN--nxasmq6b.example", &buf);
    try testing.expectEqualStrings("xn--nxasmq6b.example", got);
}

test "normalize: xn-- with empty tail rejected" {
    var buf: [MAX_HOST_LEN]u8 = undefined;
    // An empty Punycode tail leaves the label ending in the prefix hyphen, so
    // the LDH trailing-hyphen rule fires first. Either way the label is invalid.
    try testing.expectError(NormalizeError.HyphenAtLabelEdge, normalize("xn--.com", &buf));
}

test "validateLabel: well-formed xn-- label with digits passes" {
    try validateLabel("xn--abc123");
    try validateLabel("xn--nxasmq6b");
}

test "normalize: xn-- tail with hyphen-only is structurally allowed" {
    // A bare delimiter is a valid basic code point; structural check passes.
    // (Punycode semantic decoding is intentionally out of scope.)
    var buf: [MAX_HOST_LEN]u8 = undefined;
    const got = try normalize("xn---a.com", &buf);
    try testing.expectEqualStrings("xn---a.com", got);
}

test "validateLabel: rejects empty and oversized" {
    try testing.expectError(NormalizeError.LabelTooShort, validateLabel(""));
    const big = &@as([(MAX_LABEL_LEN + 1)]u8, @splat('a'));
    try testing.expectError(NormalizeError.LabelTooLong, validateLabel(big));
}

test "hasAcePrefix: case-insensitive detection" {
    try testing.expect(hasAcePrefix("xn--abc"));
    try testing.expect(hasAcePrefix("XN--abc"));
    try testing.expect(hasAcePrefix("Xn--abc"));
    try testing.expect(!hasAcePrefix("xn-abc"));
    try testing.expect(!hasAcePrefix("xnn--abc"));
    try testing.expect(!hasAcePrefix("xn"));
}

test "isValidHost: accepts good hosts" {
    try testing.expect(isValidHost("example.com"));
    try testing.expect(isValidHost("a.b.c.d"));
    try testing.expect(isValidHost("xn--nxasmq6b.example"));
    try testing.expect(isValidHost("Host-1.Example.COM."));
}

test "isValidHost: rejects bad hosts" {
    try testing.expect(!isValidHost(""));
    try testing.expect(!isValidHost("."));
    try testing.expect(!isValidHost("-leading.com"));
    try testing.expect(!isValidHost("trailing-.com"));
    try testing.expect(!isValidHost("a..b"));
    try testing.expect(!isValidHost("under_score.net"));
    try testing.expect(!isValidHost("xn--.com"));
}

test "normalize: result fits in a heap-allocated buffer via testing allocator" {
    // Exercises the documented sizing contract with the testing allocator so
    // any leak in this path is caught by std.testing.allocator.
    const host = "MixedCase.Example.ORG";
    const out = try testing.allocator.alloc(u8, host.len);
    defer testing.allocator.free(out);

    const got = try normalize(host, out);
    try testing.expectEqualStrings("mixedcase.example.org", got);
}

test "isValidHost via allocator-backed copies of inputs" {
    const cases = [_]struct { in: []const u8, ok: bool }{
        .{ .in = "valid.example", .ok = true },
        .{ .in = "BAD_.example", .ok = false },
        .{ .in = "xn--nxasmq6b.io", .ok = true },
    };
    for (cases) |c| {
        const copy = try testing.allocator.dupe(u8, c.in);
        defer testing.allocator.free(copy);
        try testing.expectEqual(c.ok, isValidHost(copy));
    }
}
