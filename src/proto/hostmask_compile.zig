// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compiled nick!user@host mask matching.
//!
//! Callers compile one full hostmask glob once, then reuse it against many
//! candidate hostmasks without allocating on the match path.
const std = @import("std");

/// Which segment of a full nick!user@host mask is being handled.
pub const SegmentKind = enum(u2) {
    nick,
    user,
    host,
};

/// Tunable bounds used while compiling hostmask globs.
pub const Params = struct {
    max_mask_bytes: usize = 512,
    max_nick_bytes: usize = 64,
    max_user_bytes: usize = 64,
    max_host_bytes: usize = 255,
    max_tokens_per_segment: usize = 128,
};

/// Errors returned while compiling a reusable hostmask matcher.
pub const CompileError = std.mem.Allocator.Error || error{
    EmptyMask,
    MaskTooLong,
    MissingBang,
    MissingAt,
    EmptySegment,
    SegmentTooLong,
    TooManyTokens,
    InvalidByte,
};

/// Borrowed split view of a nick!user@host mask.
pub const HostmaskParts = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

const Token = union(enum) {
    literal: u8,
    any_one,
    any_many,
};

/// Compiled case-insensitive ASCII glob for one hostmask segment.
pub const CompiledGlob = struct {
    tokens: std.ArrayListUnmanaged(Token) = .empty,

    /// Compile one segment glob using default limits.
    pub fn compile(allocator: std.mem.Allocator, pattern: []const u8) CompileError!CompiledGlob {
        return CompiledGlob.compileWith(.{}, allocator, .host, pattern);
    }

    /// Compile one segment glob using caller-selected limits.
    pub fn compileWith(
        comptime params: Params,
        allocator: std.mem.Allocator,
        kind: SegmentKind,
        pattern: []const u8,
    ) CompileError!CompiledGlob {
        comptime {
            if (params.max_tokens_per_segment == 0) @compileError("hostmask glob needs token storage");
        }

        try validateSegmentWith(params, kind, pattern);

        var glob = CompiledGlob{};
        errdefer glob.deinit(allocator);

        for (pattern) |byte| {
            const token: Token = switch (byte) {
                '*' => .any_many,
                '?' => .any_one,
                else => .{ .literal = std.ascii.toLower(byte) },
            };

            if (token == .any_many and glob.tokens.items.len > 0 and glob.tokens.items[glob.tokens.items.len - 1] == .any_many) {
                continue;
            }
            if (glob.tokens.items.len >= params.max_tokens_per_segment) return error.TooManyTokens;
            try glob.tokens.append(allocator, token);
        }

        return glob;
    }

    /// Free all storage owned by this compiled glob.
    pub fn deinit(self: *CompiledGlob, allocator: std.mem.Allocator) void {
        self.tokens.deinit(allocator);
        self.* = undefined;
    }

    /// Match `text` against this compiled glob without allocating.
    pub fn matches(self: *const CompiledGlob, text: []const u8) bool {
        var pattern_index: usize = 0;
        var text_index: usize = 0;
        var star_index: ?usize = null;
        var retry_text_index: usize = 0;

        while (text_index < text.len) {
            if (pattern_index < self.tokens.items.len) {
                switch (self.tokens.items[pattern_index]) {
                    .literal => |literal| {
                        if (literal == std.ascii.toLower(text[text_index])) {
                            pattern_index += 1;
                            text_index += 1;
                            continue;
                        }
                    },
                    .any_one => {
                        pattern_index += 1;
                        text_index += 1;
                        continue;
                    },
                    .any_many => {
                        star_index = pattern_index;
                        pattern_index += 1;
                        retry_text_index = text_index;
                        continue;
                    },
                }
            }

            if (star_index) |star| {
                pattern_index = star + 1;
                retry_text_index += 1;
                text_index = retry_text_index;
            } else {
                return false;
            }
        }

        while (pattern_index < self.tokens.items.len and self.tokens.items[pattern_index] == .any_many) {
            pattern_index += 1;
        }
        return pattern_index == self.tokens.items.len;
    }
};

/// Reusable compiled matcher for a full nick!user@host mask.
pub const CompiledHostmask = struct {
    nick: CompiledGlob,
    user: CompiledGlob,
    host: CompiledGlob,

    /// Free all storage owned by this compiled hostmask matcher.
    pub fn deinit(self: *CompiledHostmask, allocator: std.mem.Allocator) void {
        self.nick.deinit(allocator);
        self.user.deinit(allocator);
        self.host.deinit(allocator);
        self.* = undefined;
    }

    /// Match a full nick!user@host candidate without allocating.
    pub fn matches(self: *const CompiledHostmask, candidate: []const u8) bool {
        const parts = splitHostmask(candidate) catch return false;
        return self.matchesParts(parts);
    }

    /// Match already split hostmask parts without allocating.
    pub fn matchesParts(self: *const CompiledHostmask, parts: HostmaskParts) bool {
        return self.nick.matches(parts.nick) and
            self.user.matches(parts.user) and
            self.host.matches(parts.host);
    }
};

/// Compile a full nick!user@host glob using default limits.
pub fn compile(allocator: std.mem.Allocator, mask: []const u8) CompileError!CompiledHostmask {
    return compileWith(.{}, allocator, mask);
}

/// Compile a full nick!user@host glob using caller-selected limits.
pub fn compileWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    mask: []const u8,
) CompileError!CompiledHostmask {
    const parts = try splitHostmaskWith(params, mask);

    var nick = try CompiledGlob.compileWith(params, allocator, .nick, parts.nick);
    errdefer nick.deinit(allocator);
    var user = try CompiledGlob.compileWith(params, allocator, .user, parts.user);
    errdefer user.deinit(allocator);
    var host = try CompiledGlob.compileWith(params, allocator, .host, parts.host);
    errdefer host.deinit(allocator);

    return .{
        .nick = nick,
        .user = user,
        .host = host,
    };
}

/// Split a full nick!user@host mask using default limits.
pub fn splitHostmask(mask: []const u8) CompileError!HostmaskParts {
    return splitHostmaskWith(.{}, mask);
}

/// Split a full nick!user@host mask using caller-selected limits.
pub fn splitHostmaskWith(comptime params: Params, mask: []const u8) CompileError!HostmaskParts {
    comptime {
        if (params.max_mask_bytes == 0) @compileError("hostmask parser needs mask storage");
        if (params.max_nick_bytes == 0) @compileError("hostmask parser needs nick storage");
        if (params.max_user_bytes == 0) @compileError("hostmask parser needs user storage");
        if (params.max_host_bytes == 0) @compileError("hostmask parser needs host storage");
    }

    if (mask.len == 0) return error.EmptyMask;
    if (mask.len > params.max_mask_bytes) return error.MaskTooLong;

    const bang = std.mem.indexOfScalar(u8, mask, '!') orelse return error.MissingBang;
    const after_bang = mask[bang + 1 ..];
    const at_relative = std.mem.indexOfScalar(u8, after_bang, '@') orelse return error.MissingAt;
    const at = bang + 1 + at_relative;

    if (std.mem.indexOfScalar(u8, mask[bang + 1 ..], '!') != null) return error.InvalidByte;
    if (std.mem.indexOfScalar(u8, mask[at + 1 ..], '@') != null) return error.InvalidByte;

    const parts = HostmaskParts{
        .nick = mask[0..bang],
        .user = mask[bang + 1 .. at],
        .host = mask[at + 1 ..],
    };

    try validateSegmentWith(params, .nick, parts.nick);
    try validateSegmentWith(params, .user, parts.user);
    try validateSegmentWith(params, .host, parts.host);
    return parts;
}

fn validateSegmentWith(comptime params: Params, kind: SegmentKind, segment: []const u8) CompileError!void {
    if (segment.len == 0) return error.EmptySegment;

    const max_len = switch (kind) {
        .nick => params.max_nick_bytes,
        .user => params.max_user_bytes,
        .host => params.max_host_bytes,
    };
    if (segment.len > max_len) return error.SegmentTooLong;

    for (segment) |byte| {
        switch (byte) {
            0...0x20, 0x7f, '!', '@' => return error.InvalidByte,
            else => {},
        }
    }
}

test "compile and match hostmask hits and misses" {
    // Arrange.
    const allocator = std.testing.allocator;
    var matcher = try compile(allocator, "Alice!ident@*.Example.NET");
    defer matcher.deinit(allocator);

    // Act.
    const host_hit = matcher.matches("alice!ident@client.example.net");
    const case_hit = matcher.matches("ALICE!IDENT@CLIENT.EXAMPLE.NET");
    const host_miss = matcher.matches("alice!ident@client.example.org");
    const user_miss = matcher.matches("alice!root@client.example.net");
    const nick_miss = matcher.matches("bob!ident@client.example.net");

    // Assert.
    try std.testing.expect(host_hit);
    try std.testing.expect(case_hit);
    try std.testing.expect(!host_miss);
    try std.testing.expect(!user_miss);
    try std.testing.expect(!nick_miss);
}

test "case insensitive matching applies to all three segments" {
    // Arrange.
    const allocator = std.testing.allocator;
    var matcher = try compile(allocator, "NICK!USER@HOST.EXAMPLE");
    defer matcher.deinit(allocator);

    // Act.
    const lower = matcher.matches("nick!user@host.example");
    const mixed = matcher.matches("NiCk!UsEr@HoSt.ExAmPlE");
    const wrong = matcher.matches("nick!user@other.example");

    // Assert.
    try std.testing.expect(lower);
    try std.testing.expect(mixed);
    try std.testing.expect(!wrong);
}

test "wildcard segments support star question mark and catch all masks" {
    // Arrange.
    const allocator = std.testing.allocator;
    var matcher = try compile(allocator, "*!u?er@host*");
    defer matcher.deinit(allocator);
    var catch_all = try compile(allocator, "*!*@*");
    defer catch_all.deinit(allocator);

    // Act.
    const segment_hit = matcher.matches("Nick!user@Host123");
    const short_hit = matcher.matches("n!uXer@host");
    const user_miss = matcher.matches("n!uer@host");
    const any_hit = catch_all.matches("any!thing@anywhere");
    const malformed_miss = catch_all.matches("not-a-hostmask");

    // Assert.
    try std.testing.expect(segment_hit);
    try std.testing.expect(short_hit);
    try std.testing.expect(!user_miss);
    try std.testing.expect(any_hit);
    try std.testing.expect(!malformed_miss);
}

test "precompiled matcher accepts already split parts" {
    // Arrange.
    const allocator = std.testing.allocator;
    var matcher = try compile(allocator, "a*!~u*@*.example");
    defer matcher.deinit(allocator);
    const hit = HostmaskParts{ .nick = "Alice", .user = "~user", .host = "edge.example" };
    const miss = HostmaskParts{ .nick = "Alice", .user = "ident", .host = "edge.example" };

    // Act.
    const split_hit = matcher.matchesParts(hit);
    const split_miss = matcher.matchesParts(miss);

    // Assert.
    try std.testing.expect(split_hit);
    try std.testing.expect(!split_miss);
}

test "compile rejects malformed masks and invalid bytes" {
    // Arrange.
    const allocator = std.testing.allocator;

    // Act and assert.
    try std.testing.expectError(error.EmptyMask, compile(allocator, ""));
    try std.testing.expectError(error.MissingBang, compile(allocator, "nickuser@host"));
    try std.testing.expectError(error.MissingAt, compile(allocator, "nick!userhost"));
    try std.testing.expectError(error.EmptySegment, compile(allocator, "!user@host"));
    try std.testing.expectError(error.EmptySegment, compile(allocator, "nick!@host"));
    try std.testing.expectError(error.EmptySegment, compile(allocator, "nick!user@"));
    try std.testing.expectError(error.InvalidByte, compile(allocator, "nick!user@bad host"));
    try std.testing.expectError(error.InvalidByte, compile(allocator, "nick!u@ser@host"));
}

test "caller selected limits are enforced during compile" {
    // Arrange.
    const allocator = std.testing.allocator;
    const limits = Params{
        .max_mask_bytes = 16,
        .max_nick_bytes = 4,
        .max_user_bytes = 4,
        .max_host_bytes = 8,
        .max_tokens_per_segment = 3,
    };

    // Act and assert.
    try std.testing.expectError(error.MaskTooLong, compileWith(limits, allocator, "nick!user@long.example"));
    try std.testing.expectError(error.SegmentTooLong, compileWith(limits, allocator, "alice!u@host"));
    try std.testing.expectError(error.TooManyTokens, compileWith(limits, allocator, "n?ck!u@host"));
}
