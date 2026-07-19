// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Named conversations ("topics") within a channel — the Zulip-style projection
//! of channel chat into browsable, named threads. This module is the pure,
//! allocation-free core: it validates a topic label, extracts/strips the
//! `+onyx/topic` IRCv3 client-only message tag, and maintains the per-channel
//! topic registry stored as a bounded, comma-delimited IRCX channel PROP value.
//!
//! Wire surface (all backward-compatible — absent means "no change"):
//!   * message tag  `+onyx/topic=<label>` on a channel PRIVMSG/NOTICE stamps a
//!     conversation label onto that message. It rides the ordinary client-only
//!     tag path (members with `message-tags`, echo-message, mesh relay, history).
//!   * channel PROP `onyx_server.topics` — a comma-separated bounded set of the labels
//!     seen on a channel; auto-added on first use and op-manageable.
//!   * CHATHISTORY filter — an optional `+onyx/topic=<label>` tag on the
//!     CHATHISTORY command restricts replay to one conversation.
//!
//! Labels are hostile user input: bounded length, no control/CRLF bytes, and no
//! comma (the registry delimiter). Validation is fail-closed — an invalid label
//! is never stamped, stored, or registered.
//!
//! Segment contract: the `*Tags`/`rawValue`/`present`/`stripTag` helpers take
//! a client-tag segment that is ALREADY `@`-stripped and `+`-preserving — the
//! form the daemon's inline line parser exposes as `LineView.tags_raw` and the
//! form `clientOnlyTags` emits. Do NOT feed them `proto/irc_line`'s `tags_raw`,
//! which keeps the leading `@`.
const std = @import("std");
const irc_line = @import("irc_line.zig");

/// The IRCv3 client-only message-tag key that carries a conversation label.
pub const tag_key = "+onyx/topic";

/// The IRCX channel PROP key holding the per-channel topic registry (a bounded,
/// comma-delimited set of known labels). A generic channel prop (like PINS /
/// EPHEMERAL) so it persists and mesh-propagates through the signed CRDT store.
pub const registry_key = "onyx_server.topics";

/// Maximum decoded topic-label length, in bytes. Conversation names are short;
/// this bound keeps the registry small enough to mesh-propagate and render.
pub const max_label_len: usize = 50;

/// Registry bounds: at most this many labels, and at most this many bytes in the
/// serialized comma-delimited value. Both stay well under `MAX_PROP_VALUE` (512)
/// so the registry always fits the generic channel-prop store.
pub const registry_max_labels: usize = 64;
pub const registry_max_bytes: usize = 400;

pub const Error = error{
    Empty,
    TooLong,
    InvalidChar,
};

/// Validate a *decoded* topic label. Fail-closed: empty, over-long, control,
/// DEL, CRLF, or comma bytes are rejected. Spaces and non-ASCII (UTF-8) bytes are
/// allowed so labels can read naturally; the comma is reserved as the registry
/// delimiter, and control/CRLF bytes are refused so a label can never inject into
/// the wire, the registry value, or a PROP reply.
pub fn validateLabel(label: []const u8) Error!void {
    if (label.len == 0) return error.Empty;
    if (label.len > max_label_len) return error.TooLong;
    for (label) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == ',') return error.InvalidChar;
    }
}

/// The escaped, on-the-wire value of the `+onyx/topic` tag within a raw
/// client-only tag segment (`+a=1;+onyx/topic=general;+b`), or null if absent.
/// A bare `+onyx/topic` with no `=` yields an empty slice (which decodes to an
/// empty, and therefore invalid, label).
pub fn rawValue(client_tags_raw: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, client_tags_raw, ';');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse {
            if (std.mem.eql(u8, pair, tag_key)) return pair[0..0];
            continue;
        };
        if (std.mem.eql(u8, pair[0..eq], tag_key)) return pair[eq + 1 ..];
    }
    return null;
}

/// True when the `+onyx/topic` tag key is present in the raw tag segment.
pub fn present(client_tags_raw: []const u8) bool {
    return rawValue(client_tags_raw) != null;
}

/// Decode and validate the `+onyx/topic` label carried in a raw client-only tag
/// segment, writing the decoded label into `out`. Returns the decoded slice, or
/// null when the tag is absent, decodes larger than `out`/`max_label_len`, or
/// fails validation. `out` must be at least `max_label_len` bytes.
pub fn labelFromTags(client_tags_raw: []const u8, out: []u8) ?[]const u8 {
    const raw = rawValue(client_tags_raw) orelse return null;
    const cap = @min(out.len, max_label_len);
    const decoded = irc_line.unescapeTagValue(raw, out[0..cap]) catch return null;
    validateLabel(decoded) catch return null;
    return decoded;
}

/// Rebuild a raw client-only tag segment with the `+onyx/topic` tag removed,
/// preserving the order of all other tags. Used to fail-closed strip an invalid
/// label so it never reaches the wire, mesh, or history. `out` must be at least
/// `client_tags_raw.len` bytes (removing a tag only ever shrinks the segment).
pub fn stripTag(client_tags_raw: []const u8, out: []u8) []const u8 {
    var len: usize = 0;
    var it = std.mem.splitScalar(u8, client_tags_raw, ';');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        if (std.mem.eql(u8, pair[0..eq], tag_key)) continue;
        const sep: usize = if (len == 0) 0 else 1;
        if (len + sep + pair.len > out.len) break; // cannot grow; never reached for a sized buffer
        if (sep == 1) {
            out[len] = ';';
            len += 1;
        }
        @memcpy(out[len .. len + pair.len], pair);
        len += pair.len;
    }
    return out[0..len];
}

/// True when `label` (exact, case-sensitive) is one of the comma-delimited
/// entries in a registry value.
pub fn inRegistry(registry_value: []const u8, label: []const u8) bool {
    if (registry_value.len == 0) return false;
    var it = std.mem.splitScalar(u8, registry_value, ',');
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry, label)) return true;
    }
    return false;
}

/// Count the comma-delimited entries in a registry value (0 for empty).
pub fn registryCount(registry_value: []const u8) usize {
    if (registry_value.len == 0) return 0;
    var count: usize = 1;
    for (registry_value) |byte| {
        if (byte == ',') count += 1;
    }
    return count;
}

/// Append `label` to a registry value, writing the new comma-delimited value into
/// `out`. Returns the new value, or null when no change is warranted: the label is
/// already present, the registry is at its label cap, or appending would exceed
/// the byte bound (or `out`). The caller keeps the old value on null. The label
/// MUST already be validated (see `validateLabel`).
pub fn addToRegistry(registry_value: []const u8, label: []const u8, out: []u8) ?[]const u8 {
    if (label.len == 0 or label.len > max_label_len) return null;
    if (inRegistry(registry_value, label)) return null;
    if (registryCount(registry_value) >= registry_max_labels) return null;

    const sep: usize = if (registry_value.len == 0) 0 else 1;
    const new_len = registry_value.len + sep + label.len;
    if (new_len > registry_max_bytes or new_len > out.len) return null;

    @memcpy(out[0..registry_value.len], registry_value);
    var len = registry_value.len;
    if (sep == 1) {
        out[len] = ',';
        len += 1;
    }
    @memcpy(out[len .. len + label.len], label);
    len += label.len;
    return out[0..len];
}

/// Validate a whole registry value (as an operator might SET it directly): a
/// comma-delimited list of valid labels, within the label-count and byte bounds.
/// An empty value is valid (it clears the registry).
pub fn validRegistryValue(value: []const u8) bool {
    if (value.len == 0) return true;
    if (value.len > registry_max_bytes) return false;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |entry| {
        count += 1;
        if (count > registry_max_labels) return false;
        validateLabel(entry) catch return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "validateLabel accepts sane labels and rejects hostile ones" {
    try validateLabel("general");
    try validateLabel("release planning"); // spaces allowed
    try validateLabel("café"); // UTF-8 allowed

    try std.testing.expectError(error.Empty, validateLabel(""));

    const too_long: [max_label_len + 1]u8 = @splat('x');
    try std.testing.expectError(error.TooLong, validateLabel(&too_long));

    try std.testing.expectError(error.InvalidChar, validateLabel("a,b")); // comma = delimiter
    try std.testing.expectError(error.InvalidChar, validateLabel("a\rb")); // CR
    try std.testing.expectError(error.InvalidChar, validateLabel("a\nb")); // LF
    try std.testing.expectError(error.InvalidChar, validateLabel("a\x01b")); // control
    try std.testing.expectError(error.InvalidChar, validateLabel("a\x7fb")); // DEL
}

test "rawValue / present find the topic tag in a client-only segment" {
    try std.testing.expect(present("+typing=active;+onyx/topic=general;+draft/reply=m0"));
    try std.testing.expectEqualStrings("general", rawValue("+typing=active;+onyx/topic=general").?);
    // Bare key, no value → empty slice (decodes to an invalid empty label).
    try std.testing.expectEqualStrings("", rawValue("+onyx/topic;+typing=active").?);
    try std.testing.expect(!present("+typing=active;+draft/react=ok"));
    try std.testing.expect(rawValue("") == null);
    // A key that merely contains the tag_key as a prefix must not match.
    try std.testing.expect(!present("+onyx/topics=x"));
}

test "labelFromTags decodes escapes, validates, and bounds length" {
    var buf: [max_label_len]u8 = undefined;
    // `\s` decodes to a space per IRCv3 tag-value escaping.
    try std.testing.expectEqualStrings("release plan", labelFromTags("+onyx/topic=release\\splan", &buf).?);
    try std.testing.expectEqualStrings("general", labelFromTags("+a=1;+onyx/topic=general;+b", &buf).?);

    // Absent tag → null.
    try std.testing.expect(labelFromTags("+typing=active", &buf) == null);
    // Empty value → invalid (Empty) → null.
    try std.testing.expect(labelFromTags("+onyx/topic=", &buf) == null);
    // A decoded label longer than the cap → null (never truncated into a match).
    const long_val: [max_label_len + 10]u8 = @splat('y');
    var line_buf: [max_label_len + 40]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "+onyx/topic={s}", .{long_val[0..]}) catch unreachable;
    try std.testing.expect(labelFromTags(line, &buf) == null);
    // A literal comma in the decoded value is invalid (comma is the delimiter).
    try std.testing.expect(labelFromTags("+onyx/topic=a,b", &buf) == null);
}

test "stripTag removes only the topic tag and preserves order" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "+typing=active;+draft/reply=m0",
        stripTag("+typing=active;+onyx/topic=bad;+draft/reply=m0", &buf),
    );
    // Topic tag first.
    try std.testing.expectEqualStrings(
        "+typing=active",
        stripTag("+onyx/topic=x;+typing=active", &buf),
    );
    // Only the topic tag → empty.
    try std.testing.expectEqualStrings("", stripTag("+onyx/topic=x", &buf));
    // No topic tag → unchanged.
    try std.testing.expectEqualStrings("+typing=active", stripTag("+typing=active", &buf));
}

test "registry add/list is bounded and idempotent" {
    var buf: [registry_max_bytes]u8 = undefined;

    // First add into an empty registry.
    const r1 = addToRegistry("", "general", &buf).?;
    try std.testing.expectEqualStrings("general", r1);
    try std.testing.expect(inRegistry(r1, "general"));

    // Second distinct add appends with a comma.
    var buf2: [registry_max_bytes]u8 = undefined;
    const r2 = addToRegistry(r1, "random", &buf2).?;
    try std.testing.expectEqualStrings("general,random", r2);
    try std.testing.expectEqual(@as(usize, 2), registryCount(r2));

    // Re-adding an existing label is a no-op (null).
    try std.testing.expect(addToRegistry(r2, "general", &buf) == null);

    // Byte bound: a value already near the cap rejects a further large add.
    var big_buf: [registry_max_bytes]u8 = undefined;
    var w = std.Io.Writer.fixed(&big_buf);
    var i: usize = 0;
    while (w.buffered().len + 8 < registry_max_bytes) : (i += 1) {
        if (i != 0) w.writeAll(",") catch break;
        w.print("t{d:0>4}", .{i}) catch break;
    }
    const near_full = w.buffered();
    var out_buf: [registry_max_bytes]u8 = undefined;
    try std.testing.expect(addToRegistry(near_full, "wontfit-because-way-too-long-xxxxxxxxxxxxxxxxxxxx", &out_buf) == null);
}

test "registry label-count cap rejects overflow" {
    // Build a value at exactly the label cap using distinct two-char labels.
    var buf: [registry_max_bytes]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var i: usize = 0;
    while (i < registry_max_labels) : (i += 1) {
        if (i != 0) w.writeAll(",") catch unreachable;
        w.print("{c}{c}", .{ @as(u8, 'a' + @as(u8, @intCast(i / 26))), @as(u8, 'a' + @as(u8, @intCast(i % 26))) }) catch unreachable;
    }
    const full = w.buffered();
    try std.testing.expectEqual(registry_max_labels, registryCount(full));
    var out_buf: [registry_max_bytes]u8 = undefined;
    try std.testing.expect(addToRegistry(full, "zz", &out_buf) == null);
}

test "validRegistryValue mirrors label validation and bounds" {
    try std.testing.expect(validRegistryValue("")); // empty clears
    try std.testing.expect(validRegistryValue("general,random,release plan"));
    try std.testing.expect(!validRegistryValue("general,,random")); // empty entry
    try std.testing.expect(!validRegistryValue("general,bad\rlabel")); // control byte

    const over: [registry_max_bytes + 1]u8 = @splat('a');
    try std.testing.expect(!validRegistryValue(&over));
}
