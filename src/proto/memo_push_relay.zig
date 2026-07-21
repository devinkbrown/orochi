// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded S2S hint that asks a peer to run its local Web Push worker for an
//! account-scoped offline Memo/DM notification. It intentionally carries only
//! the push preview data, never browser push subscriptions or VAPID material.
const std = @import("std");

pub const max_account_len: usize = 32;
pub const max_from_len: usize = 64;
pub const max_text_len: usize = 240;
pub const max_encoded_len: usize = 1 + 1 + 2 + max_account_len + max_from_len + max_text_len;

pub const Error = error{ InvalidField, BufferTooSmall, Malformed };

pub const MemoPush = struct {
    account: []const u8,
    from: []const u8,
    text: []const u8,
};

pub fn encode(ev: MemoPush, out: []u8) Error![]const u8 {
    if (ev.account.len == 0 or ev.account.len > max_account_len) return error.InvalidField;
    if (ev.from.len == 0 or ev.from.len > max_from_len) return error.InvalidField;
    if (ev.text.len == 0) return error.InvalidField;

    const text = if (ev.text.len > max_text_len) ev.text[0..max_text_len] else ev.text;
    const total = 1 + 1 + 2 + ev.account.len + ev.from.len + text.len;
    if (out.len < total) return error.BufferTooSmall;

    out[0] = @intCast(ev.account.len);
    out[1] = @intCast(ev.from.len);
    std.mem.writeInt(u16, out[2..][0..2], @intCast(text.len), .little);
    var pos: usize = 4;
    @memcpy(out[pos..][0..ev.account.len], ev.account);
    pos += ev.account.len;
    @memcpy(out[pos..][0..ev.from.len], ev.from);
    pos += ev.from.len;
    @memcpy(out[pos..][0..text.len], text);
    return out[0..total];
}

pub fn decode(bytes: []const u8) Error!MemoPush {
    if (bytes.len < 4) return error.Malformed;
    const account_len: usize = bytes[0];
    const from_len: usize = bytes[1];
    const text_len: usize = std.mem.readInt(u16, bytes[2..][0..2], .little);
    if (account_len == 0 or account_len > max_account_len) return error.Malformed;
    if (from_len == 0 or from_len > max_from_len) return error.Malformed;
    if (text_len == 0 or text_len > max_text_len) return error.Malformed;
    const total = 4 + account_len + from_len + text_len;
    if (bytes.len != total) return error.Malformed;

    var pos: usize = 4;
    const account = bytes[pos..][0..account_len];
    pos += account_len;
    const from = bytes[pos..][0..from_len];
    pos += from_len;
    const text = bytes[pos..][0..text_len];
    return .{ .account = account, .from = from, .text = text };
}

test "memo push relay encode decode round-trip" {
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(.{ .account = "alice", .from = "bob", .text = "hello" }, &buf);
    const got = try decode(wire);
    try std.testing.expectEqualStrings("alice", got.account);
    try std.testing.expectEqualStrings("bob", got.from);
    try std.testing.expectEqualStrings("hello", got.text);
}

test "memo push relay truncates text preview and rejects malformed input" {
    const long_text = &@as([max_text_len + 16]u8, @splat('x'));
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(.{ .account = "alice", .from = "bob", .text = long_text }, &buf);
    const got = try decode(wire);
    try std.testing.expectEqual(max_text_len, got.text.len);

    try std.testing.expectError(error.Malformed, decode(&.{ 0, 1, 1, 0, 'x' }));
    try std.testing.expectError(error.InvalidField, encode(.{ .account = "", .from = "bob", .text = "hello" }, &buf));
}
