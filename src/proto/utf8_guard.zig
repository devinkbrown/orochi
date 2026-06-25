// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 utf8only guard helpers.
//!
//! This module is intentionally small and pure: it validates message bodies
//! through the substrate UTF-8 validator, exposes the valueless `UTF8ONLY`
//! ISUPPORT token, and builds the standard-replies INVALID_UTF8 failure line
//! body into caller-provided storage.
const std = @import("std");
const utf8 = @import("../substrate/utf8.zig");

pub const ISUPPORT_TOKEN: []const u8 = "UTF8ONLY";
pub const INVALID_UTF8_CODE: []const u8 = "INVALID_UTF8";
pub const DEFAULT_INVALID_UTF8_DESCRIPTION: []const u8 = "Invalid UTF-8";

pub const Utf8GuardError = error{
    InvalidCommand,
    InvalidDescription,
    OutputTooSmall,
};

/// Return true when an IRC message body is well-formed UTF-8.
pub fn isValidMessageBody(body: []const u8) bool {
    return utf8.validateUtf8(body);
}

/// Validate an IRC message body as well-formed UTF-8.
pub fn validateMessageBody(body: []const u8) utf8.Utf8Error!void {
    return utf8.validateUtf8Error(body);
}

/// Build the valueless ISUPPORT `UTF8ONLY` token into caller-owned storage.
pub fn buildIsupportToken(out: []u8) Utf8GuardError![]const u8 {
    if (out.len < ISUPPORT_TOKEN.len) return error.OutputTooSmall;
    @memcpy(out[0..ISUPPORT_TOKEN.len], ISUPPORT_TOKEN);
    return out[0..ISUPPORT_TOKEN.len];
}

/// Build `FAIL <cmd> INVALID_UTF8 :<default description>`.
pub fn buildInvalidUtf8Fail(out: []u8, cmd: []const u8) Utf8GuardError![]const u8 {
    return buildInvalidUtf8FailWith(out, cmd, DEFAULT_INVALID_UTF8_DESCRIPTION);
}

/// Build `FAIL <cmd> INVALID_UTF8 :<description>`.
pub fn buildInvalidUtf8FailWith(
    out: []u8,
    cmd: []const u8,
    description: []const u8,
) Utf8GuardError![]const u8 {
    try validateCommand(cmd);
    try validateDescription(description);

    var len: usize = 0;
    try append(out, &len, "FAIL ");
    try append(out, &len, cmd);
    try append(out, &len, " ");
    try append(out, &len, INVALID_UTF8_CODE);
    try append(out, &len, " :");
    try append(out, &len, description);
    return out[0..len];
}

fn validateCommand(cmd: []const u8) Utf8GuardError!void {
    if (cmd.len == 0) return error.InvalidCommand;
    if (std.mem.eql(u8, cmd, "*")) return;

    for (cmd) |byte| {
        if (!isCommandByte(byte)) return error.InvalidCommand;
    }
}

fn validateDescription(description: []const u8) Utf8GuardError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (!utf8.validateUtf8(description)) return error.InvalidDescription;

    for (description) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidDescription;
    }
}

fn isCommandByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        else => false,
    };
}

fn append(out: []u8, len: *usize, bytes: []const u8) Utf8GuardError!void {
    if (out.len - len.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[len.*..][0..bytes.len], bytes);
    len.* += bytes.len;
}

test "valid utf8 message bodies pass" {
    try std.testing.expect(isValidMessageBody(""));
    try std.testing.expect(isValidMessageBody("PRIVMSG #orochi :hello"));

    const euro = [_]u8{ 0xE2, 0x82, 0xAC };
    try std.testing.expect(isValidMessageBody(&euro));
    try validateMessageBody("NOTICE * :valid");
}

test "invalid bytes are rejected and fail bytes are built" {
    const invalid = [_]u8{ 'P', 'R', 'I', 'V', 'M', 'S', 'G', ' ', 0xC0, 0xAF };
    try std.testing.expect(!isValidMessageBody(&invalid));
    try std.testing.expectError(error.InvalidUtf8, validateMessageBody(&invalid));

    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    const fail = try buildInvalidUtf8FailWith(out, "PRIVMSG", "Invalid UTF-8 bytes");
    try std.testing.expectEqualStrings("FAIL PRIVMSG INVALID_UTF8 :Invalid UTF-8 bytes", fail);
}

test "isupport token" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, ISUPPORT_TOKEN.len);
    defer allocator.free(out);

    const token = try buildIsupportToken(out);
    try std.testing.expectEqualStrings("UTF8ONLY", token);
}
