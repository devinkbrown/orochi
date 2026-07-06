// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OPER_EVENT frame payload codec (network-wide Event-Spine propagation).
//!
//! Carries one operator event between mesh peers: "on `origin_server`, a
//! `category`/`severity` event happened, with this `message`". Unlike the
//! convergent facts (membership, props), an oper event is a one-shot
//! NOTIFICATION — peers do not store it; each delivers it to its own subscribed
//! operators rendered with `origin_server` as the source, so an alert raised on
//! one node is seen by opers everywhere with the originating server named.
//!
//! Compact fixed binary layout (little-endian):
//!
//!   category:u8 | severity:u8 | origin_len:u16 | origin… | msg_len:u16 | msg…
//!
//! Bounded per-field so a hostile peer cannot pin large buffers; decode borrows
//! the input (no allocation).
const std = @import("std");

pub const max_origin_len = 128;
pub const max_message_len = 400;
const fixed_prefix = 1 + 1; // category, severity

/// Upper bound on one encoded event (all fields at their limits).
pub const max_encoded_len = fixed_prefix + 2 + max_origin_len + 2 + max_message_len;

pub const Error = error{
    Truncated,
    NameTooLong,
    TrailingBytes,
};

pub const OperEvent = struct {
    /// Event Spine category as its raw `enum(u6)` value (server maps to/from
    /// `event_spine.EventCategory`). Kept as a plain `u6` so this codec stays
    /// daemon-independent.
    category: u6,
    /// Event Spine severity as a raw `u8` value (`event_spine.EventSeverity`).
    severity: u8,
    /// The server name where the event was raised (rendered as the source).
    origin_server: []const u8,
    /// The displayed event message body.
    message: []const u8,
};

pub fn encodedLen(ev: OperEvent) Error!usize {
    if (ev.origin_server.len > max_origin_len) return error.NameTooLong;
    if (ev.message.len > max_message_len) return error.NameTooLong;
    return fixed_prefix + 2 + ev.origin_server.len + 2 + ev.message.len;
}

fn putBytes16(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: OperEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = @as(u8, ev.category);
    i += 1;
    out[i] = ev.severity;
    i += 1;
    putBytes16(out, &i, ev.origin_server);
    putBytes16(out, &i, ev.message);
    return out[0..i];
}

fn takeBytes16(bytes: []const u8, i: *usize, max_len: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max_len) return error.NameTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const out = bytes[i.* .. i.* + len];
    i.* += len;
    return out;
}

/// Reject control bytes so a hostile peer can never smuggle a CR/LF (and thus an
/// injected line) into the rendered `:<origin> EVENT …` output.
fn validateLineField(bytes: []const u8) Error!void {
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.NameTooLong;
    }
}

/// Decode from `bytes`; the returned string fields borrow `bytes`.
pub fn decode(bytes: []const u8) Error!OperEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;
    var i: usize = 0;
    const category_raw = bytes[i];
    i += 1;
    if (category_raw > 0x3f) return error.NameTooLong; // category is a u6
    const severity = bytes[i];
    i += 1;

    const origin = try takeBytes16(bytes, &i, max_origin_len);
    const message = try takeBytes16(bytes, &i, max_message_len);

    if (i != bytes.len) return error.TrailingBytes;
    if (origin.len == 0) return error.NameTooLong;
    // Origin must be a clean server-name token (no spaces); the message may carry
    // spaces but never control bytes.
    for (origin) |b| {
        if (b <= 0x20 or b == 0x7f) return error.NameTooLong;
    }
    try validateLineField(message);
    return .{
        .category = @intCast(category_raw),
        .severity = severity,
        .origin_server = origin,
        .message = message,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "oper event round-trips" {
    const ev = OperEvent{
        .category = 13,
        .severity = 2,
        .origin_server = "eshmaki.me",
        .message = "FLOOD possible raid on #root: join rate exceeded",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(@as(u6, 13), got.category);
    try testing.expectEqual(@as(u8, 2), got.severity);
    try testing.expectEqualStrings("eshmaki.me", got.origin_server);
    try testing.expectEqualStrings("FLOOD possible raid on #root: join rate exceeded", got.message);
}

test "truncated input is rejected at every prefix" {
    const ev = OperEvent{ .category = 1, .severity = 0, .origin_server = "ircx.us", .message = "OPER_ACTION WARD ADD" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var cut: usize = 0;
    while (cut < wire.len) : (cut += 1) {
        try testing.expectError(error.Truncated, decode(wire[0..cut]));
    }
}

test "trailing bytes rejected" {
    const ev = OperEvent{ .category = 1, .severity = 0, .origin_server = "n", .message = "m" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var padded: [max_encoded_len + 1]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "over-long fields rejected by encode" {
    const big_origin = &@as([(max_origin_len + 1)]u8, @splat('x'));
    try testing.expectError(error.NameTooLong, encodedLen(.{ .category = 0, .severity = 0, .origin_server = big_origin, .message = "m" }));
    const big_msg = &@as([(max_message_len + 1)]u8, @splat('y'));
    try testing.expectError(error.NameTooLong, encodedLen(.{ .category = 0, .severity = 0, .origin_server = "n", .message = big_msg }));
}

test "control bytes / empty origin rejected by decode" {
    // Empty origin.
    const empty = OperEvent{ .category = 0, .severity = 0, .origin_server = "x", .message = "ok" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(empty, &buf);
    var corrupt: [max_encoded_len]u8 = undefined;
    @memcpy(corrupt[0..wire.len], wire);
    // Zero the origin length -> empty origin -> rejected.
    std.mem.writeInt(u16, corrupt[fixed_prefix..][0..2], 0, .little);
    // The message length now sits where origin bytes were; rebuild a minimal
    // empty-origin frame instead for a clean assert.
    var mini: [fixed_prefix + 2 + 2]u8 = undefined;
    mini[0] = 0;
    mini[1] = 0;
    std.mem.writeInt(u16, mini[2..4], 0, .little); // origin_len = 0
    std.mem.writeInt(u16, mini[4..6], 0, .little); // msg_len = 0
    try testing.expectError(error.NameTooLong, decode(&mini));

    // Newline smuggled into the message is rejected.
    const inj = OperEvent{ .category = 0, .severity = 0, .origin_server = "n", .message = "a\nb" };
    var ibuf: [max_encoded_len]u8 = undefined;
    const iwire = try encode(inj, &ibuf);
    try testing.expectError(error.NameTooLong, decode(iwire));
}
