// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Convenience emitters for IRCv3 standard-replies.
//!
//! The lower-level `standard_replies.zig` module owns the canonical catalog
//! and fixed-buffer composer. This module is for callers that already maintain
//! an appendable byte sink and want to emit complete IRC lines.
const std = @import("std");
const standard_replies = @import("standard_replies.zig");

pub const MAX_LINE_BODY = standard_replies.MAX_LINE_BODY;
pub const MAX_LEGACY_BODY = standard_replies.MAX_LEGACY_BODY;
pub const ReplyType = standard_replies.ReplyType;
pub const BuildOptions = standard_replies.BuildOptions;
pub const BuildError = standard_replies.BuildError;

/// Common catalog codes used for FAIL replies.
pub const FailCode = standard_replies.Code;

pub const EmitError = BuildError || std.mem.Allocator.Error;

pub const Builder = struct {
    kind: ReplyType,
    command: []const u8,
    code: []const u8,
    context_params: []const []const u8 = &.{},
    description: []const u8,
    options: BuildOptions = .{},

    /// Attach IRC middle parameters between code and description.
    pub fn withContext(self: Builder, context_params: []const []const u8) Builder {
        var next = self;
        next.context_params = context_params;
        return next;
    }

    /// Use a custom maximum line-body length for this build.
    pub fn withMaxBodyLen(self: Builder, max_body_len: usize) Builder {
        var next = self;
        next.options.max_body_len = max_body_len;
        return next;
    }

    /// Reject CR/LF/NUL in descriptions instead of rendering visible escapes.
    pub fn withStrictDescription(self: Builder) Builder {
        var next = self;
        next.options.escape_description_controls = false;
        return next;
    }

    /// Return the exact body size before CRLF.
    pub fn requiredBodyLen(self: Builder) BuildError!usize {
        try validateBuilder(self);

        var total: usize = 0;
        try addLen(&total, self.kind.token().len);
        try addLen(&total, 1 + self.command.len);
        try addLen(&total, 1 + self.code.len);
        for (self.context_params) |param| {
            try addLen(&total, 1 + param.len);
        }
        try addLen(&total, 2);
        try addLen(&total, try escapedDescriptionLen(self.description, self.options));

        if (total > self.options.max_body_len) return error.MessageTooLong;
        return total;
    }

    /// Return the exact complete IRC line size including CRLF.
    pub fn requiredLineLen(self: Builder) BuildError!usize {
        var total = try self.requiredBodyLen();
        try addLen(&total, 2);
        return total;
    }

    /// Append `<TYPE> <command> <code> [context...] :description`.
    pub fn appendBody(
        self: Builder,
        allocator: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) EmitError!void {
        const needed = try self.requiredBodyLen();
        try sink.ensureUnusedCapacity(allocator, needed);
        self.appendBodyAssumeCapacity(sink);
    }

    /// Append a complete IRC line, adding CRLF after the standard-reply body.
    pub fn appendLine(
        self: Builder,
        allocator: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) EmitError!void {
        const needed = try self.requiredLineLen();
        try sink.ensureUnusedCapacity(allocator, needed);
        self.appendBodyAssumeCapacity(sink);
        sink.appendSliceAssumeCapacity("\r\n");
    }

    /// Alias for `appendLine`.
    pub fn emit(
        self: Builder,
        allocator: std.mem.Allocator,
        sink: *std.ArrayList(u8),
    ) EmitError!void {
        try self.appendLine(allocator, sink);
    }

    fn appendBodyAssumeCapacity(self: Builder, sink: *std.ArrayList(u8)) void {
        sink.appendSliceAssumeCapacity(self.kind.token());
        sink.appendSliceAssumeCapacity(" ");
        sink.appendSliceAssumeCapacity(self.command);
        sink.appendSliceAssumeCapacity(" ");
        sink.appendSliceAssumeCapacity(self.code);
        for (self.context_params) |param| {
            sink.appendSliceAssumeCapacity(" ");
            sink.appendSliceAssumeCapacity(param);
        }
        sink.appendSliceAssumeCapacity(" :");
        appendDescriptionAssumeCapacity(sink, self.description, self.options);
    }
};

/// Start a typed FAIL reply.
pub fn fail(command: []const u8, code: FailCode, description: []const u8) Builder {
    return build(.fail, command, @tagName(code), description);
}

/// Start a FAIL reply with an extension code token.
pub fn failCustom(command: []const u8, code: []const u8, description: []const u8) Builder {
    return build(.fail, command, code, description);
}

/// Start a WARN reply with a caller-provided code token.
pub fn warn(command: []const u8, code: []const u8, description: []const u8) Builder {
    return build(.warn, command, code, description);
}

/// Start any standard reply with a caller-provided code token.
pub fn custom(kind: ReplyType, command: []const u8, code: []const u8, description: []const u8) Builder {
    return build(kind, command, code, description);
}

/// Emit a typed FAIL line directly into `sink`.
pub fn emitFail(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    command: []const u8,
    code: FailCode,
    context_params: []const []const u8,
    description: []const u8,
) EmitError!void {
    try fail(command, code, description).withContext(context_params).emit(allocator, sink);
}

/// Emit a WARN line directly into `sink`.
pub fn emitWarn(
    allocator: std.mem.Allocator,
    sink: *std.ArrayList(u8),
    command: []const u8,
    code: []const u8,
    context_params: []const []const u8,
    description: []const u8,
) EmitError!void {
    try warn(command, code, description).withContext(context_params).emit(allocator, sink);
}

pub fn validCodeToken(token: []const u8) bool {
    return standard_replies.validMiddleParam(token);
}

fn build(kind: ReplyType, command: []const u8, code: []const u8, description: []const u8) Builder {
    return .{
        .kind = kind,
        .command = command,
        .code = code,
        .description = description,
    };
}

fn validateBuilder(builder: Builder) BuildError!void {
    if (!standard_replies.validMiddleParam(builder.command)) return error.InvalidCommand;
    if (!validCodeToken(builder.code)) return error.InvalidCode;
    for (builder.context_params) |param| {
        if (!standard_replies.validMiddleParam(param)) return error.InvalidContext;
    }
    if (!builder.options.escape_description_controls) {
        for (builder.description) |ch| {
            if (unsafeDescriptionByte(ch)) return error.InvalidDescription;
        }
    }
}

fn escapedDescriptionLen(description: []const u8, options: BuildOptions) BuildError!usize {
    var total: usize = 0;
    for (description) |ch| {
        try addLen(&total, try escapedDescriptionByteLen(ch, options));
    }
    return total;
}

fn escapedDescriptionByteLen(ch: u8, options: BuildOptions) BuildError!usize {
    if (options.escape_description_controls) {
        return switch (ch) {
            0, '\r', '\n', '\t', '\\' => 2,
            0x01...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => 4,
            else => 1,
        };
    }
    if (unsafeDescriptionByte(ch)) return error.InvalidDescription;
    return 1;
}

fn unsafeDescriptionByte(ch: u8) bool {
    return ch < ' ' or ch == 0x7f;
}

fn addLen(total: *usize, add: usize) BuildError!void {
    if (add > std.math.maxInt(usize) - total.*) return error.MessageTooLong;
    total.* += add;
}

fn appendDescriptionAssumeCapacity(sink: *std.ArrayList(u8), description: []const u8, options: BuildOptions) void {
    for (description) |ch| {
        if (options.escape_description_controls) {
            switch (ch) {
                0 => sink.appendSliceAssumeCapacity("\\0"),
                '\r' => sink.appendSliceAssumeCapacity("\\r"),
                '\n' => sink.appendSliceAssumeCapacity("\\n"),
                '\t' => sink.appendSliceAssumeCapacity("\\t"),
                '\\' => sink.appendSliceAssumeCapacity("\\\\"),
                0x01...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => appendHexEscapeAssumeCapacity(sink, ch),
                else => sink.appendAssumeCapacity(ch),
            }
        } else {
            sink.appendAssumeCapacity(ch);
        }
    }
}

fn appendHexEscapeAssumeCapacity(sink: *std.ArrayList(u8), byte: u8) void {
    const HEX = "0123456789ABCDEF";
    sink.appendSliceAssumeCapacity("\\x");
    sink.appendAssumeCapacity(HEX[byte >> 4]);
    sink.appendAssumeCapacity(HEX[byte & 0x0f]);
}

test "emit typed FAIL line with context params" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try emitFail(
        allocator,
        &sink,
        "REGISTER",
        .ACCOUNT_REQUIRED,
        &.{ "sasl", "plain" },
        "Authentication is required",
    );

    try std.testing.expectEqualStrings(
        "FAIL REGISTER ACCOUNT_REQUIRED sasl plain :Authentication is required\r\n",
        sink.items,
    );
}

test "emit WARN exact bytes" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try warn("CHATHISTORY", "MESSAGE_RATE_LIMITED", "History query was throttled")
        .withContext(&.{"#orochi"})
        .appendLine(allocator, &sink);

    try std.testing.expectEqualStrings(
        "WARN CHATHISTORY MESSAGE_RATE_LIMITED #orochi :History query was throttled\r\n",
        sink.items,
    );
}

test "append body omits CRLF for caller-framed sinks" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try fail("PROP", .INVALID_PROPERTY, "Property cannot be set")
        .withContext(&.{ "#orochi", "topic.locked" })
        .appendBody(allocator, &sink);

    try std.testing.expectEqualStrings(
        "FAIL PROP INVALID_PROPERTY #orochi topic.locked :Property cannot be set",
        sink.items,
    );
}

test "enforce body length bound" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    const builder = fail("CMD", .INVALID_PARAMS, "too long");
    const exact = try builder.requiredBodyLen();
    try builder.withMaxBodyLen(exact).emit(allocator, &sink);
    try std.testing.expectEqual(exact + 2, sink.items.len);

    try std.testing.expectError(
        error.MessageTooLong,
        builder.withMaxBodyLen(exact - 1).emit(allocator, &sink),
    );
}

test "validate code tokens without requiring catalog spelling" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try failCustom("CMD", "orochi-policy.denied", "Denied").emit(allocator, &sink);
    try std.testing.expectEqualStrings(
        "FAIL CMD orochi-policy.denied :Denied\r\n",
        sink.items,
    );

    try std.testing.expectError(
        error.InvalidCode,
        failCustom("CMD", "BAD CODE", "Denied").emit(allocator, &sink),
    );
}

test "validate command context and strict description" {
    const allocator = std.testing.allocator;
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(allocator);

    try std.testing.expectError(
        error.InvalidCommand,
        fail("BAD COMMAND", .INVALID_PARAMS, "bad command").emit(allocator, &sink),
    );
    try std.testing.expectError(
        error.InvalidContext,
        warn("ACCESS", "INVALID_TARGET", "bad context")
            .withContext(&.{"bad\tcontext"})
            .emit(allocator, &sink),
    );
    try std.testing.expectError(
        error.InvalidDescription,
        warn("MEMO", "UNKNOWN_ERROR", "bad\nline")
            .withMaxBodyLen(MAX_LEGACY_BODY)
            .withStrictDescription()
            .emit(allocator, &sink),
    );
}
