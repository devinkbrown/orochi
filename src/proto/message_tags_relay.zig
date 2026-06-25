// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 message-tags client tag relay builder.
//!
//! The input tag segment is the sender-provided IRCv3 tag segment, with or
//! without its leading `@`. Only valid client-only tags (`+...`) are relayed.
//! Server tags are written first so callers can attach the returned prefix
//! directly before a rendered PRIVMSG or NOTICE line.
const std = @import("std");

pub const MAX_TAGS: usize = 64;
pub const MAX_TAG_SEGMENT: usize = 8191;
pub const MAX_TAG_PREFIX: usize = 8191;

pub const RelayError = error{
    OutputTooSmall,
    OversizeTags,
    TooManyTags,
    MalformedTags,
    InvalidTagKey,
    InvalidTagValue,
};

pub const ServerTags = struct {
    time: ?[]const u8 = null,
    account: ?[]const u8 = null,
};

/// Build a relayed tag prefix with all valid client-only tags preserved.
///
/// Returns either an empty slice, or a complete `@... ` prefix ending in one
/// space. The returned slice always points into `out`.
pub fn buildRelayPrefix(
    raw_client_tags: ?[]const u8,
    server_tags: ServerTags,
    out: []u8,
) RelayError![]const u8 {
    return buildRelayPrefixInternal(raw_client_tags, server_tags, null, out);
}

/// Build a relayed tag prefix with client tags narrowed to `allowed_client_tags`.
///
/// An empty allow-list drops every client tag. Non-client tags are validated
/// but never relayed.
pub fn buildRelayPrefixWithAllowed(
    raw_client_tags: ?[]const u8,
    server_tags: ServerTags,
    allowed_client_tags: []const []const u8,
    out: []u8,
) RelayError![]const u8 {
    return buildRelayPrefixInternal(raw_client_tags, server_tags, allowed_client_tags, out);
}

fn buildRelayPrefixInternal(
    raw_client_tags: ?[]const u8,
    server_tags: ServerTags,
    allowed_client_tags: ?[]const []const u8,
    out: []u8,
) RelayError![]const u8 {
    var writer = TagWriter{ .buf = out };

    if (server_tags.time) |time| try writer.writeEscapedValue("time", time);
    if (server_tags.account) |account| try writer.writeEscapedValue("account", account);

    if (raw_client_tags) |raw| {
        const segment = try normalizeTagSegment(raw);
        try appendAllowedClientTags(segment, allowed_client_tags, &writer);
    }

    try writer.finish();
    return writer.slice();
}

fn normalizeTagSegment(raw: []const u8) RelayError![]const u8 {
    if (raw.len == 0) return raw;
    if (raw.len > MAX_TAG_SEGMENT) return error.OversizeTags;

    for (raw) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ' => return error.MalformedTags,
            else => {},
        }
    }

    if (raw[0] == '@') {
        if (raw.len == 1) return error.MalformedTags;
        return raw[1..];
    }
    return raw;
}

fn appendAllowedClientTags(
    segment: []const u8,
    allowed_client_tags: ?[]const []const u8,
    writer: *TagWriter,
) RelayError!void {
    if (segment.len == 0) return;

    var tag_count: usize = 0;
    var cursor: usize = 0;
    while (cursor <= segment.len) {
        const next = findByte(segment, cursor, ';') orelse segment.len;
        if (next == cursor) return error.MalformedTags;
        if (tag_count >= MAX_TAGS) return error.TooManyTags;
        tag_count += 1;

        const item = segment[cursor..next];
        const eq = findByte(item, 0, '=');
        const key = if (eq) |pos| item[0..pos] else item;
        const value = if (eq) |pos| item[pos + 1 ..] else null;

        if (!validTagKey(key)) return error.InvalidTagKey;
        if (value) |raw_value| try validateRawTagValue(raw_value);

        if (isClientTag(key) and isAllowedClientTag(key, allowed_client_tags)) {
            try writer.writeRaw(item);
        }

        if (next == segment.len) break;
        cursor = next + 1;
    }
}

fn isAllowedClientTag(key: []const u8, allowed_client_tags: ?[]const []const u8) bool {
    const allowed = allowed_client_tags orelse return true;
    for (allowed) |candidate| {
        if (std.mem.eql(u8, key, candidate)) return true;
    }
    return false;
}

fn isClientTag(key: []const u8) bool {
    return key.len > 1 and key[0] == '+';
}

fn validTagKey(key: []const u8) bool {
    if (key.len == 0) return false;
    const start: usize = if (key[0] == '+') 1 else 0;
    if (start == key.len) return false;

    for (key[start..]) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn validateRawTagValue(value: []const u8) RelayError!void {
    for (value) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ' => return error.InvalidTagValue,
            else => {},
        }
    }
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

const TagWriter = struct {
    buf: []u8,
    len: usize = 0,
    count: usize = 0,

    fn writeRaw(self: *TagWriter, item: []const u8) RelayError!void {
        try self.begin();
        try self.append(item);
    }

    fn writeEscapedValue(self: *TagWriter, key: []const u8, value: []const u8) RelayError!void {
        try self.begin();
        try self.append(key);
        try self.byte('=');
        for (value) |ch| {
            switch (ch) {
                0 => return error.InvalidTagValue,
                ';' => try self.append("\\:"),
                ' ' => try self.append("\\s"),
                '\r' => try self.append("\\r"),
                '\n' => try self.append("\\n"),
                '\\' => try self.append("\\\\"),
                else => try self.byte(ch),
            }
        }
    }

    fn begin(self: *TagWriter) RelayError!void {
        if (self.count == 0) {
            try self.byte('@');
        } else {
            try self.byte(';');
        }
        self.count += 1;
    }

    fn finish(self: *TagWriter) RelayError!void {
        if (self.count != 0) try self.byte(' ');
    }

    fn append(self: *TagWriter, bytes: []const u8) RelayError!void {
        if (bytes.len > MAX_TAG_PREFIX - self.len) return error.OversizeTags;
        if (bytes.len > self.buf.len - self.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn byte(self: *TagWriter, value: u8) RelayError!void {
        if (self.len == MAX_TAG_PREFIX) return error.OversizeTags;
        if (self.len == self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = value;
        self.len += 1;
    }

    fn slice(self: *const TagWriter) []const u8 {
        return self.buf[0..self.len];
    }
};

test "filters and preserves client-only tags" {
    _ = std.testing.allocator;
    var out: [160]u8 = undefined;

    const rendered = try buildRelayPrefix(
        "@+typing=active;+draft/reply=msg-1",
        .{},
        &out,
    );

    try std.testing.expectEqualStrings("@+typing=active;+draft/reply=msg-1 ", rendered);
}

test "drops valid non-client tags" {
    _ = std.testing.allocator;
    var out: [160]u8 = undefined;

    const rendered = try buildRelayPrefix(
        "time=bad;+typing=active;account=bob",
        .{},
        &out,
    );

    try std.testing.expectEqualStrings("@+typing=active ", rendered);

    const empty = try buildRelayPrefix("time=bad;account=bob", .{}, &out);
    try std.testing.expectEqualStrings("", empty);
}

test "merges server time account and client tags into one segment" {
    _ = std.testing.allocator;
    var out: [192]u8 = undefined;

    const rendered = try buildRelayPrefix(
        "@+typing=active",
        .{
            .time = "2026-06-04T12:00:00.000Z",
            .account = "alice",
        },
        &out,
    );

    try std.testing.expectEqualStrings(
        "@time=2026-06-04T12:00:00.000Z;account=alice;+typing=active ",
        rendered,
    );
}

test "explicit allow list narrows client tags" {
    _ = std.testing.allocator;
    var out: [160]u8 = undefined;
    const allowed = [_][]const u8{"+typing"};

    const rendered = try buildRelayPrefixWithAllowed(
        "+typing=active;+draft/reply=msg-1;+draft/react=ok",
        .{},
        &allowed,
        &out,
    );

    try std.testing.expectEqualStrings("@+typing=active ", rendered);
}

test "rejects malformed client tag segments" {
    _ = std.testing.allocator;
    var out: [160]u8 = undefined;

    try std.testing.expectError(error.MalformedTags, buildRelayPrefix("@", .{}, &out));
    try std.testing.expectError(error.MalformedTags, buildRelayPrefix("+typing=active;", .{}, &out));
    try std.testing.expectError(error.InvalidTagKey, buildRelayPrefix("++bad=x", .{}, &out));
    try std.testing.expectError(error.MalformedTags, buildRelayPrefix("+typing=active now", .{}, &out));
    try std.testing.expectError(
        error.InvalidTagValue,
        buildRelayPrefix(null, .{ .account = "bad\x00account" }, &out),
    );
}

test "oversize input is rejected" {
    const allocator = std.testing.allocator;
    var raw = try allocator.alloc(u8, MAX_TAG_SEGMENT + 1);
    defer allocator.free(raw);
    raw[0] = '+';
    @memset(raw[1..], 'a');

    var out: [MAX_TAG_PREFIX]u8 = undefined;
    try std.testing.expectError(error.OversizeTags, buildRelayPrefix(raw, .{}, &out));
}
