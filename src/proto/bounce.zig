// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client redirect / bounce line formatting for S2S session migration.
//!
//! This module is intentionally self-contained and allocation-free. Callers
//! provide the output buffer, and every formatter either returns a slice of the
//! formatted IRC line or `error.BufferTooSmall`.

const std = @import("std");

pub const Error = error{
    BufferTooSmall,
};

pub const token_len = 16;
pub const token_b64_len = std.base64.standard.Encoder.calcSize(token_len);

/// Format RFC2812 RPL_BOUNCE numeric 010:
/// `:<server> 010 * <host> <port> :<info>\r\n`
pub fn formatBounceNumeric(
    buf: []u8,
    server_name: []const u8,
    target_host: []const u8,
    target_port: u16,
    info: []const u8,
) Error![]const u8 {
    return printLine(
        buf,
        ":{s} 010 * {s} {} :{s}\r\n",
        .{ server_name, target_host, target_port, info },
    );
}

/// Format a non-numeric migration hint:
/// `:<server> NOTE MIGRATE <nick> reconnect token=<token_b64>\r\n`
pub fn formatResumeHint(
    buf: []u8,
    server_name: []const u8,
    nick: []const u8,
    token_b64: []const u8,
) Error![]const u8 {
    return printLine(
        buf,
        ":{s} NOTE MIGRATE {s} reconnect token={s}\r\n",
        .{ server_name, nick, token_b64 },
    );
}

/// Encode a 16-byte migration token as RFC4648 standard base64 with padding.
pub fn encodeTokenBase64(buf: []u8, token: *const [token_len]u8) Error![]const u8 {
    if (buf.len < token_b64_len) return error.BufferTooSmall;
    return std.base64.standard.Encoder.encode(buf[0..token_b64_len], token[0..]);
}

fn printLine(buf: []u8, comptime fmt: []const u8, args: anytype) Error![]const u8 {
    return std.fmt.bufPrint(buf, fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => error.BufferTooSmall,
    };
}

test "formatBounceNumeric formats exact RFC2812 bounce line" {
    var buf: [128]u8 = undefined;

    const line = try formatBounceNumeric(
        &buf,
        "mesh-a.example",
        "mesh-b.example",
        6697,
        "session migrating",
    );

    try std.testing.expectEqualStrings(
        ":mesh-a.example 010 * mesh-b.example 6697 :session migrating\r\n",
        line,
    );
}

test "formatBounceNumeric accepts boundary port values" {
    var low_buf: [64]u8 = undefined;
    const low = try formatBounceNumeric(&low_buf, "s", "h", 0, "");
    try std.testing.expectEqualStrings(":s 010 * h 0 :\r\n", low);

    var high_buf: [70]u8 = undefined;
    const high = try formatBounceNumeric(&high_buf, "s", "h", 65535, "max");
    try std.testing.expectEqualStrings(":s 010 * h 65535 :max\r\n", high);
}

test "formatBounceNumeric rejects undersized output buffer without truncation" {
    const expected = ":s 010 * h 6697 :go\r\n";
    var buf: [expected.len - 1]u8 = undefined;

    try std.testing.expectError(
        error.BufferTooSmall,
        formatBounceNumeric(&buf, "s", "h", 6697, "go"),
    );
}

test "formatResumeHint formats exact migrate note line" {
    var buf: [128]u8 = undefined;

    const line = try formatResumeHint(
        &buf,
        "mesh-a.example",
        "nick",
        "AAECAwQFBgcICQoLDA0ODw==",
    );

    try std.testing.expectEqualStrings(
        ":mesh-a.example NOTE MIGRATE nick reconnect token=AAECAwQFBgcICQoLDA0ODw==\r\n",
        line,
    );
}

test "formatResumeHint rejects undersized output buffer without truncation" {
    const expected = ":s NOTE MIGRATE n reconnect token=t\r\n";
    var buf: [expected.len - 1]u8 = undefined;

    try std.testing.expectError(
        error.BufferTooSmall,
        formatResumeHint(&buf, "s", "n", "t"),
    );
}

test "encodeTokenBase64 encodes 16 byte token with standard padding" {
    var buf: [token_b64_len]u8 = undefined;
    const token = [token_len]u8{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };

    const encoded = try encodeTokenBase64(&buf, &token);

    try std.testing.expectEqual(@as(usize, 24), token_b64_len);
    try std.testing.expectEqualStrings("AAECAwQFBgcICQoLDA0ODw==", encoded);
}

test "encodeTokenBase64 rejects short buffer" {
    var buf: [token_b64_len - 1]u8 = undefined;
    const token = @as([token_len]u8, @splat(0xaa));

    try std.testing.expectError(error.BufferTooSmall, encodeTokenBase64(&buf, &token));
}
