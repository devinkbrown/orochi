// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict DNS response validation against cache-poisoning attacks.
//!
//! A forged or off-path DNS response can inject records the resolver never
//! asked for. To resist Kaminsky-style cache poisoning we validate a parsed
//! response against the exact question that was sent before trusting any of
//! its data. This module is pure logic: it inspects already-parsed
//! `dns.Message` values and answers a single yes/no-with-reason question.
//!
//! No sockets, no filesystem, no clock, no RNG, zero allocation.

const std = @import("std");
const dns = @import("dns.zig");

/// The question the resolver actually asked, expressed as plain slices so the
/// caller does not need to round-trip through `dns.Name`.
pub const Question = struct {
    /// Presentation-form domain name without a trailing dot (e.g. "example.com").
    name: []const u8,
    qtype: dns.RecordType,
};

/// Result of validating a response. `.ok` means every check passed and the
/// answer records are safe to consume; any other value names the first failed
/// check, in evaluation order.
pub const Verdict = enum {
    /// Header id, response flag, echoed question, and all owner names matched.
    ok,
    /// The transaction id did not match the one we generated.
    id_mismatch,
    /// The message has the QR bit clear (it is a query, not a response).
    not_response,
    /// The echoed question section did not exactly match what we asked.
    question_mismatch,
    /// An answer record's owner name fell outside the queried zone.
    out_of_bailiwick,
};

/// Validate a parsed DNS response against the question that produced it.
///
/// Checks run in this fixed order, returning the first failure:
///   1. `header.id == expected_id`            -> `.id_mismatch`
///   2. response (QR) bit is set              -> `.not_response`
///   3. exactly one question, echoed verbatim -> `.question_mismatch`
///      (name compared ASCII case-insensitively, qtype compared for equality)
///   4. every answer owner name is in-bailiwick for the queried name
///                                            -> `.out_of_bailiwick`
///
/// Bailiwick rule: an answer owner is accepted when it equals the question
/// name or is a label-boundary subdomain of it (see `inBailiwick`). For the
/// CNAME-less record types this module understands (A / AAAA / PTR) a direct
/// answer's owner should equal the qname; subdomains are tolerated because a
/// well-formed delegated zone may legitimately return deeper owners, but
/// sibling or parent zones are always rejected.
pub fn validate(
    msg: anytype,
    expected_id: u16,
    q: Question,
) Verdict {
    if (msg.header.id != expected_id) return .id_mismatch;
    if (!msg.header.isResponse()) return .not_response;

    const questions = msg.questionSlice();
    if (questions.len != 1) return .question_mismatch;

    const echoed = &questions[0];
    if (echoed.qtype != q.qtype) return .question_mismatch;
    if (!equalNameCI(echoed.name.slice(), q.name)) return .question_mismatch;

    for (msg.answerSlice()) |*rr| {
        if (!inBailiwick(rr.name.slice(), q.name)) return .out_of_bailiwick;
    }

    return .ok;
}

/// True when `owner` is within the zone rooted at `zone`: either an exact,
/// case-insensitive match, or a subdomain whose suffix aligns on a label
/// boundary.
///
/// Examples:
///   inBailiwick("example.com",       "example.com") == true   // exact
///   inBailiwick("a.example.com",     "example.com") == true   // subdomain
///   inBailiwick("EXAMPLE.com",       "example.com") == true   // case-insensitive
///   inBailiwick("evilexample.com",   "example.com") == false  // no '.' boundary
///   inBailiwick("com",               "example.com") == false  // parent zone
///   inBailiwick("example.org",       "example.com") == false  // sibling
///
/// A trailing dot on either argument is ignored so the root-relative and
/// presentation forms compare equal.
pub fn inBailiwick(owner: []const u8, zone: []const u8) bool {
    const o = stripTrailingDot(owner);
    const z = stripTrailingDot(zone);

    if (z.len == 0) return true; // root zone contains everything
    if (o.len < z.len) return false;

    // Compare the trailing `z.len` bytes of `o` against `z`, case-insensitively.
    const suffix = o[o.len - z.len ..];
    if (!equalNameCI(suffix, z)) return false;

    if (o.len == z.len) return true; // exact match

    // The byte immediately before the matched suffix must be a label
    // separator, otherwise "evilexample.com" would falsely match "example.com".
    return o[o.len - z.len - 1] == '.';
}

/// ASCII case-insensitive equality for two domain-name slices. Trailing dots
/// are NOT stripped here; callers normalize beforehand where needed.
fn equalNameCI(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLowerAscii(ca) != toLowerAscii(cb)) return false;
    }
    return true;
}

fn toLowerAscii(ch: u8) u8 {
    return switch (ch) {
        'A'...'Z' => ch + ('a' - 'A'),
        else => ch,
    };
}

fn stripTrailingDot(name: []const u8) []const u8 {
    if (name.len > 0 and name[name.len - 1] == '.') return name[0 .. name.len - 1];
    return name;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Build a response packet, parse it, and hand the message to `body`.
fn buildAndParse(
    comptime max_q: usize,
    comptime max_a: usize,
    build: dns.BuildMessage,
) !dns.Message(max_q, max_a) {
    var buf: [dns.max_message_len]u8 = undefined;
    const wire = try dns.encodeMessage(&buf, build);
    return try dns.parseMessage(max_q, max_a, wire);
}

test "validate accepts a well-formed in-bailiwick response" {
    // Arrange
    const q = dns.Query{ .name = "example.com", .qtype = .a };
    const answer = dns.Answer{
        .name = "example.com",
        .rr_type = .a,
        .ttl = 60,
        .data = .{ .a = .{ 93, 184, 216, 34 } },
    };
    const msg = try buildAndParse(1, 1, .{
        .id = 0x1234,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });

    // Act
    const verdict = validate(msg, 0x1234, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.ok, verdict);
}

test "validate accepts case-insensitive question name match" {
    // Arrange
    const q = dns.Query{ .name = "Example.COM", .qtype = .a };
    const answer = dns.Answer{
        .name = "Example.COM",
        .rr_type = .a,
        .ttl = 60,
        .data = .{ .a = .{ 1, 2, 3, 4 } },
    };
    const msg = try buildAndParse(1, 1, .{
        .id = 42,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });

    // Act
    const verdict = validate(msg, 42, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.ok, verdict);
}

test "validate accepts subdomain answer owner within zone" {
    // Arrange: question for the zone, answer owned by a deeper label.
    const q = dns.Query{ .name = "example.com", .qtype = .a };
    const answer = dns.Answer{
        .name = "www.example.com",
        .rr_type = .a,
        .ttl = 60,
        .data = .{ .a = .{ 10, 0, 0, 1 } },
    };
    const msg = try buildAndParse(1, 1, .{
        .id = 9,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });

    // Act
    const verdict = validate(msg, 9, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.ok, verdict);
}

test "validate rejects wrong transaction id" {
    // Arrange
    const q = dns.Query{ .name = "example.com", .qtype = .a };
    const msg = try buildAndParse(1, 0, .{
        .id = 0x1111,
        .response = true,
        .questions = (&q)[0..1],
    });

    // Act
    const verdict = validate(msg, 0x2222, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.id_mismatch, verdict);
}

test "validate rejects a query masquerading as a response" {
    // Arrange: response flag deliberately left clear.
    const q = dns.Query{ .name = "example.com", .qtype = .a };
    const msg = try buildAndParse(1, 0, .{
        .id = 5,
        .response = false,
        .questions = (&q)[0..1],
    });

    // Act
    const verdict = validate(msg, 5, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.not_response, verdict);
}

test "validate rejects mismatched question name" {
    // Arrange
    const q = dns.Query{ .name = "attacker.test", .qtype = .a };
    const msg = try buildAndParse(1, 0, .{
        .id = 7,
        .response = true,
        .questions = (&q)[0..1],
    });

    // Act
    const verdict = validate(msg, 7, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.question_mismatch, verdict);
}

test "validate rejects mismatched question type" {
    // Arrange: asked for A, response echoes an AAAA question.
    const q = dns.Query{ .name = "example.com", .qtype = .aaaa };
    const msg = try buildAndParse(1, 0, .{
        .id = 7,
        .response = true,
        .questions = (&q)[0..1],
    });

    // Act
    const verdict = validate(msg, 7, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.question_mismatch, verdict);
}

test "validate rejects an out-of-bailiwick answer owner" {
    // Arrange: echoed question is correct but an answer is owned by a
    // sibling zone, the classic poisoning payload.
    const q = dns.Query{ .name = "example.com", .qtype = .a };
    const answers = [_]dns.Answer{
        .{
            .name = "example.com",
            .rr_type = .a,
            .ttl = 60,
            .data = .{ .a = .{ 93, 184, 216, 34 } },
        },
        .{
            .name = "evil.test",
            .rr_type = .a,
            .ttl = 60,
            .data = .{ .a = .{ 6, 6, 6, 6 } },
        },
    };
    const msg = try buildAndParse(1, 2, .{
        .id = 3,
        .response = true,
        .questions = (&q)[0..1],
        .answers = &answers,
    });

    // Act
    const verdict = validate(msg, 3, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.out_of_bailiwick, verdict);
}

test "validate rejects a near-miss prefix sibling as out of bailiwick" {
    // Arrange: "evilexample.com" must NOT be treated as inside "example.com".
    const q = dns.Query{ .name = "example.com", .qtype = .a };
    const answer = dns.Answer{
        .name = "evilexample.com",
        .rr_type = .a,
        .ttl = 60,
        .data = .{ .a = .{ 1, 1, 1, 1 } },
    };
    const msg = try buildAndParse(1, 1, .{
        .id = 8,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });

    // Act
    const verdict = validate(msg, 8, .{ .name = "example.com", .qtype = .a });

    // Assert
    try testing.expectEqual(Verdict.out_of_bailiwick, verdict);
}

test "inBailiwick treats exact match as in-zone" {
    try testing.expect(inBailiwick("example.com", "example.com"));
}

test "inBailiwick treats label-boundary subdomain as in-zone" {
    try testing.expect(inBailiwick("a.example.com", "example.com"));
    try testing.expect(inBailiwick("deep.sub.example.com", "example.com"));
}

test "inBailiwick rejects prefix sibling that lacks a label boundary" {
    try testing.expect(!inBailiwick("evilexample.com", "example.com"));
}

test "inBailiwick rejects parent and sibling zones" {
    try testing.expect(!inBailiwick("com", "example.com"));
    try testing.expect(!inBailiwick("example.org", "example.com"));
}

test "inBailiwick is ASCII case-insensitive" {
    try testing.expect(inBailiwick("WWW.Example.COM", "example.com"));
    try testing.expect(inBailiwick("example.com", "EXAMPLE.COM"));
}

test "inBailiwick ignores trailing dots and accepts the root zone" {
    try testing.expect(inBailiwick("a.example.com.", "example.com"));
    try testing.expect(inBailiwick("a.example.com", "example.com."));
    try testing.expect(inBailiwick("anything.test", "."));
}
