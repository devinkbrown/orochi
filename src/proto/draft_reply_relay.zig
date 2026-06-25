// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 `+draft/reply` client-only message-tag validator and relay gate.
//!
//! The `+draft/reply=<msgid>` client-only tag carries a threaded-reply target:
//! the `msgid` of the message being replied to. As a client-only tag (the `+`
//! prefix) its value is opaque to the server *transport*, but a conforming
//! relay still benefits from rejecting values that cannot be a valid IRCv3
//! `msgid` before propagating them, and from gating passthrough on each
//! recipient's negotiated `message-tags` capability.
//!
//! This module is intentionally narrow and complementary:
//!   * `msgtags.zig`            — generates and composes outbound server tags
//!                                (including fresh `msgid` values).
//!   * `message_tags_relay.zig` — generic client-tag relay/allow-list builder.
//!   * `draft_reply_relay.zig`  — *semantic* validation of a single
//!                                `+draft/reply` value as a `msgid`, plus a
//!                                per-recipient relay decision.
//!
//! Nothing here allocates: every routine validates borrowed slices or returns
//! a slice that aliases its input. There is therefore nothing to free.
const std = @import("std");

/// The client-only tag key this module governs, including the `+` prefix.
pub const TAG_KEY: []const u8 = "+draft/reply";

/// Maximum accepted length of a `+draft/reply` msgid value.
///
/// IRCv3 `msgid` values are server-defined opaque tokens; the specification
/// caps their length at 64 octets. Values longer than this cannot have been
/// minted by a conforming server and are rejected to bound work and memory.
pub const MAX_MSGID_LEN: usize = 64;

/// Errors produced when validating a `+draft/reply` value.
pub const ReplyTagError = error{
    /// The value was empty (`+draft/reply=` with no msgid).
    EmptyMsgid,
    /// The value exceeded `MAX_MSGID_LEN`.
    MsgidTooLong,
    /// The value contained a byte that is illegal in an IRCv3 tag value
    /// (NUL, CR, LF, space, semicolon) or outside the msgid character set.
    InvalidMsgidChar,
};

/// Decision describing whether a validated `+draft/reply` tag should be
/// forwarded to a particular recipient.
pub const RelayDecision = enum {
    /// Forward the `+draft/reply` tag to this recipient.
    relay,
    /// Drop the tag for this recipient (no negotiated capability).
    drop,

    /// Returns `true` when the tag should be written to the recipient.
    pub fn shouldRelay(self: RelayDecision) bool {
        return self == .relay;
    }
};

/// Return whether a single byte is permitted inside a `+draft/reply` msgid.
///
/// IRCv3 message-tag values forbid NUL, CR, LF, space, and semicolon. A
/// `msgid` is additionally an opaque printable token: this accepts the
/// printable ASCII range minus the structural tag separators. The escape
/// backslash is rejected here because a validated `msgid` is the *decoded*
/// value, never an escaped wire fragment.
pub fn isValidMsgidByte(ch: u8) bool {
    return switch (ch) {
        // Printable ASCII (0x21..0x7e) split to exclude the structural tag
        // separator ';' (0x3b) and the escape lead '\\' (0x5c).
        0x21...0x3a, 0x3c...0x5b, 0x5d...0x7e => true,
        // NUL, CR, LF, space, ';', '\\', DEL, and any non-ASCII byte.
        else => false,
    };
}

/// Report whether `value` is a well-formed IRCv3 `msgid` for relay purposes.
///
/// This is the boolean companion to `parse`; it never allocates and performs
/// no side effects. An empty value is *not* a valid msgid.
pub fn isValidMsgid(value: []const u8) bool {
    if (value.len == 0 or value.len > MAX_MSGID_LEN) return false;
    for (value) |ch| {
        if (!isValidMsgidByte(ch)) return false;
    }
    return true;
}

/// Validate a raw `+draft/reply` tag value and return it unchanged on success.
///
/// The returned slice aliases `value`; callers retain ownership of the backing
/// memory. On failure a specific `ReplyTagError` is returned so callers can log
/// or surface a precise diagnostic instead of a generic parse failure.
pub fn parse(value: []const u8) ReplyTagError![]const u8 {
    if (value.len == 0) return error.EmptyMsgid;
    if (value.len > MAX_MSGID_LEN) return error.MsgidTooLong;
    for (value) |ch| {
        if (!isValidMsgidByte(ch)) return error.InvalidMsgidChar;
    }
    return value;
}

/// Decide whether a validated `+draft/reply` tag is relayed to one recipient.
///
/// Client-only tags are passthrough only to recipients that negotiated the
/// `message-tags` capability (here surfaced as `recipient_has_cap`). This is
/// the single gate every send path should consult per recipient.
pub fn relayDecision(recipient_has_cap: bool) RelayDecision {
    return if (recipient_has_cap) .relay else .drop;
}

/// Convenience: validate `value` and, if valid, decide relay for one recipient.
///
/// Returns `.drop` for any value that fails validation, so an invalid tag is
/// never propagated regardless of recipient capability. Use `parse` directly
/// when the distinction between "invalid" and "dropped" matters to the caller.
pub fn validateAndDecide(value: []const u8, recipient_has_cap: bool) RelayDecision {
    if (!isValidMsgid(value)) return .drop;
    return relayDecision(recipient_has_cap);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parse accepts a typical server-minted msgid" {
    // Arrange
    const value = "00000000003tlV7OC5p74x";

    // Act
    const parsed = try parse(value);

    // Assert: slice aliases input, content preserved.
    try std.testing.expectEqualStrings(value, parsed);
    try std.testing.expectEqual(value.ptr, parsed.ptr);
}

test "parse accepts msgid with hyphen and dot punctuation" {
    const value = "msg-Alpha_123.v2";
    try std.testing.expectEqualStrings(value, try parse(value));
}

test "parse accepts maximum-length msgid" {
    const value = "a" ** MAX_MSGID_LEN;
    try std.testing.expectEqualStrings(value, try parse(value));
}

test "parse rejects empty value" {
    try std.testing.expectError(error.EmptyMsgid, parse(""));
}

test "parse rejects over-length value" {
    const value = "a" ** (MAX_MSGID_LEN + 1);
    try std.testing.expectError(error.MsgidTooLong, parse(value));
}

test "parse rejects structural and control characters" {
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg id")); // space
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg;id")); // semicolon
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg\x00id")); // NUL
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg\rid")); // CR
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg\nid")); // LF
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg\\id")); // backslash
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg\x7fid")); // DEL
    try std.testing.expectError(error.InvalidMsgidChar, parse("msg\xffid")); // non-ASCII
}

test "isValidMsgid mirrors parse success and failure" {
    try std.testing.expect(isValidMsgid("abc123"));
    try std.testing.expect(!isValidMsgid(""));
    try std.testing.expect(!isValidMsgid("a" ** (MAX_MSGID_LEN + 1)));
    try std.testing.expect(!isValidMsgid("a b"));
    try std.testing.expect(!isValidMsgid("a;b"));
}

test "isValidMsgidByte accepts printable set and rejects separators" {
    try std.testing.expect(isValidMsgidByte('A'));
    try std.testing.expect(isValidMsgidByte('z'));
    try std.testing.expect(isValidMsgidByte('0'));
    try std.testing.expect(isValidMsgidByte('-'));
    try std.testing.expect(isValidMsgidByte('~'));
    try std.testing.expect(!isValidMsgidByte(' '));
    try std.testing.expect(!isValidMsgidByte(';'));
    try std.testing.expect(!isValidMsgidByte('\\'));
    try std.testing.expect(!isValidMsgidByte(0));
}

test "relayDecision gates on negotiated capability" {
    try std.testing.expectEqual(RelayDecision.relay, relayDecision(true));
    try std.testing.expectEqual(RelayDecision.drop, relayDecision(false));

    try std.testing.expect(relayDecision(true).shouldRelay());
    try std.testing.expect(!relayDecision(false).shouldRelay());
}

test "validateAndDecide drops invalid values regardless of capability" {
    // Valid msgid relays only to cap-enabled recipients.
    try std.testing.expectEqual(RelayDecision.relay, validateAndDecide("good-msgid", true));
    try std.testing.expectEqual(RelayDecision.drop, validateAndDecide("good-msgid", false));

    // Invalid msgid is dropped even when the recipient negotiated the cap.
    try std.testing.expectEqual(RelayDecision.drop, validateAndDecide("bad id", true));
    try std.testing.expectEqual(RelayDecision.drop, validateAndDecide("", true));
}

test "TAG_KEY identifies the governed client-only tag" {
    try std.testing.expectEqualStrings("+draft/reply", TAG_KEY);
    try std.testing.expectEqual(@as(u8, '+'), TAG_KEY[0]);
}
