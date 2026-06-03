//! IRC MOTD numeric reply builder.
//!
//! This module is allocator-free: callers provide the output byte storage and
//! the line sink. Long MOTD text records are folded into multiple complete
//! RPL_MOTD lines without exceeding the configured IRC line byte limit.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = 510;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_REQUESTER: []const u8 = "*";

const motd_start_text_suffix = " Message of the Day -";
const end_of_motd_text = "End of /MOTD command.";
const no_motd_text = "MOTD File is missing";

pub const MotdError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidRequester,
    RequesterTooLong,
    InvalidMotdLine,
    MotdLineTooLong,
    OutputTooSmall,
    TooManyLines,
};

/// Compile-time limits for MOTD reply builders and validators.
pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
};

/// One complete numeric reply line stored in caller-owned output bytes.
pub const MotdLine = struct {
    bytes: []const u8,
};

/// Caller-provided storage for complete MOTD numeric reply lines.
pub const MotdLineSink = struct {
    lines: []MotdLine,
    count: usize = 0,

    pub fn append(self: *MotdLineSink, bytes: []const u8) MotdError!void {
        if (self.count >= self.lines.len) return error.TooManyLines;
        self.lines[self.count] = .{ .bytes = bytes };
        self.count += 1;
    }

    pub fn slice(self: *const MotdLineSink) []const MotdLine {
        return self.lines[0..self.count];
    }

    pub fn reset(self: *MotdLineSink) void {
        self.count = 0;
    }
};

/// Write a full MOTD reply sequence for an unknown requester (`*`).
pub fn writeMotdReplies(
    out: []u8,
    server_name: []const u8,
    motd_lines: []const []const u8,
    sink: *MotdLineSink,
) MotdError!void {
    return writeMotdRepliesForRequester(out, server_name, DEFAULT_REQUESTER, motd_lines, sink);
}

/// Write a full MOTD reply sequence for `requester`.
pub fn writeMotdRepliesForRequester(
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
    motd_lines: []const []const u8,
    sink: *MotdLineSink,
) MotdError!void {
    return writeMotdRepliesWith(.{}, out, server_name, requester, motd_lines, sink);
}

/// Write a full MOTD reply sequence using caller-selected compile-time limits.
///
/// Empty `motd_lines` emits only ERR_NOMOTD (422). A present empty text line is
/// a real MOTD line and emits `:- `.
pub fn writeMotdRepliesWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
    motd_lines: []const []const u8,
    sink: *MotdLineSink,
) MotdError!void {
    try validateServerNameWith(params, server_name);
    try validateRequesterWith(params, requester);

    var used: usize = 0;
    if (motd_lines.len == 0) {
        try appendBuiltLine(out, &used, sink, try buildNoMotdLineWith(params, out[used..], server_name, requester));
        return;
    }

    try appendBuiltLine(out, &used, sink, try buildMotdStartLineWith(params, out[used..], server_name, requester));

    for (motd_lines) |line| {
        try writeFoldedMotdLineWith(params, out, &used, server_name, requester, line, sink);
    }

    try appendBuiltLine(out, &used, sink, try buildEndOfMotdLineWith(params, out[used..], server_name, requester));
}

/// Build `:<server> 375 <requester> :- <server> Message of the Day -`.
pub fn buildMotdStartLine(
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
) MotdError![]const u8 {
    return buildMotdStartLineWith(.{}, out, server_name, requester);
}

/// Build a MOTDSTART line using caller-selected compile-time limits.
pub fn buildMotdStartLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
) MotdError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateRequesterWith(params, requester);

    var builder = LineBuilder.init(out, params.max_line_bytes);
    try builder.numericPrefix(.RPL_MOTDSTART, server_name, requester);
    try builder.appendBytes(" :- ");
    try builder.appendBytes(server_name);
    try builder.appendBytes(motd_start_text_suffix);
    return builder.slice();
}

/// Build one unfolded `:<server> 372 <requester> :- <line>` reply.
pub fn buildMotdLine(
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
    line: []const u8,
) MotdError![]const u8 {
    return buildMotdLineWith(.{}, out, server_name, requester, line);
}

/// Build one unfolded MOTD line using caller-selected compile-time limits.
pub fn buildMotdLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
    line: []const u8,
) MotdError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateRequesterWith(params, requester);
    try validateMotdLine(line);

    var builder = LineBuilder.init(out, params.max_line_bytes);
    try appendMotdLinePrefix(&builder, server_name, requester);
    if (line.len > builder.remainingLineBytes()) return error.MotdLineTooLong;
    try builder.appendBytes(line);
    return builder.slice();
}

/// Build `:<server> 376 <requester> :End of /MOTD command.`.
pub fn buildEndOfMotdLine(
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
) MotdError![]const u8 {
    return buildEndOfMotdLineWith(.{}, out, server_name, requester);
}

/// Build an ENDOFMOTD line using caller-selected compile-time limits.
pub fn buildEndOfMotdLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
) MotdError![]const u8 {
    return buildFixedTrailingLine(params, out, .RPL_ENDOFMOTD, server_name, requester, end_of_motd_text);
}

/// Build `:<server> 422 <requester> :MOTD File is missing`.
pub fn buildNoMotdLine(
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
) MotdError![]const u8 {
    return buildNoMotdLineWith(.{}, out, server_name, requester);
}

/// Build a NOMOTD line using caller-selected compile-time limits.
pub fn buildNoMotdLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
) MotdError![]const u8 {
    return buildFixedTrailingLine(params, out, .ERR_NOMOTD, server_name, requester, no_motd_text);
}

pub fn validateServerName(server_name: []const u8) MotdError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) MotdError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validServerNameByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateRequester(requester: []const u8) MotdError!void {
    return validateRequesterWith(.{}, requester);
}

pub fn validateRequesterWith(comptime params: Params, requester: []const u8) MotdError!void {
    if (requester.len == 0) return error.InvalidRequester;
    if (requester.len > params.max_requester_bytes) return error.RequesterTooLong;
    for (requester) |ch| {
        if (!validParamByte(ch)) return error.InvalidRequester;
    }
}

pub fn validateMotdLine(line: []const u8) MotdError!void {
    for (line) |ch| {
        if (!validMotdTextByte(ch)) return error.InvalidMotdLine;
    }
}

fn writeFoldedMotdLineWith(
    comptime params: Params,
    out: []u8,
    used: *usize,
    server_name: []const u8,
    requester: []const u8,
    line: []const u8,
    sink: *MotdLineSink,
) MotdError!void {
    try validateMotdLine(line);

    const prefix_len = motdLinePrefixLen(server_name, requester);
    if (prefix_len >= params.max_line_bytes) return error.MotdLineTooLong;
    const chunk_capacity = params.max_line_bytes - prefix_len;

    if (line.len == 0) {
        try appendBuiltLine(out, used, sink, try buildMotdLineWith(params, out[used.*..], server_name, requester, line));
        return;
    }

    var cursor: usize = 0;
    while (cursor < line.len) {
        const remaining = line.len - cursor;
        const chunk_len = @min(remaining, chunk_capacity);
        const chunk = line[cursor .. cursor + chunk_len];
        try appendBuiltLine(out, used, sink, try buildMotdLineWith(params, out[used.*..], server_name, requester, chunk));
        cursor += chunk_len;
    }
}

fn appendBuiltLine(out: []u8, used: *usize, sink: *MotdLineSink, line: []const u8) MotdError!void {
    const start = used.*;
    const end = start + line.len;
    try sink.append(out[start..end]);
    used.* = end;
}

fn buildFixedTrailingLine(
    comptime params: Params,
    out: []u8,
    code: numeric.Numeric,
    server_name: []const u8,
    requester: []const u8,
    text: []const u8,
) MotdError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateRequesterWith(params, requester);

    var builder = LineBuilder.init(out, params.max_line_bytes);
    try builder.numericPrefix(code, server_name, requester);
    try builder.appendBytes(" :");
    try builder.appendBytes(text);
    return builder.slice();
}

fn appendMotdLinePrefix(
    builder: *LineBuilder,
    server_name: []const u8,
    requester: []const u8,
) MotdError!void {
    try builder.numericPrefix(.RPL_MOTD, server_name, requester);
    try builder.appendBytes(" :- ");
}

fn motdLinePrefixLen(server_name: []const u8, requester: []const u8) usize {
    return 1 + server_name.len + 1 + 3 + 1 + requester.len + " :- ".len;
}

fn validServerNameByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn validParamByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return ch != ':';
}

fn validMotdTextByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn remainingLineBytes(self: *const LineBuilder) usize {
        return self.max_line_bytes - self.len;
    }

    fn numericPrefix(
        self: *LineBuilder,
        code: numeric.Numeric,
        server_name: []const u8,
        requester: []const u8,
    ) MotdError!void {
        try validateServerName(server_name);
        try validateRequester(requester);

        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) MotdError!void {
        if (bytes.len > self.remainingLineBytes()) return error.MotdLineTooLong;
        if (self.out.len - self.len < bytes.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) MotdError!void {
        if (self.remainingLineBytes() == 0) return error.MotdLineTooLong;
        if (self.out.len - self.len < 1) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "multi-line MOTD emits start body lines and end" {
    var out: [256]u8 = undefined;
    var line_storage: [4]MotdLine = undefined;
    var sink = MotdLineSink{ .lines = &line_storage };

    try writeMotdRepliesForRequester(&out, "irc.example", "alice", &.{ "first", "second" }, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 4), lines.len);
    try std.testing.expectEqualStrings(":irc.example 375 alice :- irc.example Message of the Day -", lines[0].bytes);
    try std.testing.expectEqualStrings(":irc.example 372 alice :- first", lines[1].bytes);
    try std.testing.expectEqualStrings(":irc.example 372 alice :- second", lines[2].bytes);
    try std.testing.expectEqualStrings(":irc.example 376 alice :End of /MOTD command.", lines[3].bytes);
}

test "empty MOTD emits ERR_NOMOTD only" {
    var out: [96]u8 = undefined;
    var line_storage: [1]MotdLine = undefined;
    var sink = MotdLineSink{ .lines = &line_storage };

    try writeMotdRepliesForRequester(&out, "irc.example", "alice", &.{}, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), lines.len);
    try std.testing.expectEqualStrings(":irc.example 422 alice :MOTD File is missing", lines[0].bytes);
}

test "single-line builders use exact numeric formats" {
    var out: [96]u8 = undefined;

    try std.testing.expectEqualStrings(
        ":irc.example 375 bob :- irc.example Message of the Day -",
        try buildMotdStartLine(&out, "irc.example", "bob"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example 372 bob :- hello there",
        try buildMotdLine(&out, "irc.example", "bob", "hello there"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example 376 bob :End of /MOTD command.",
        try buildEndOfMotdLine(&out, "irc.example", "bob"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example 422 bob :MOTD File is missing",
        try buildNoMotdLine(&out, "irc.example", "bob"),
    );
}

test "long MOTD text is folded to configured line limit" {
    var out: [256]u8 = undefined;
    var line_storage: [6]MotdLine = undefined;
    var sink = MotdLineSink{ .lines = &line_storage };

    try writeMotdRepliesWith(
        .{ .max_line_bytes = 34 },
        &out,
        "s",
        "n",
        &.{"abcdefghijklmnopqrstuvwxyz"},
        &sink,
    );

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 4), lines.len);
    try std.testing.expectEqualStrings(":s 375 n :- s Message of the Day -", lines[0].bytes);
    try std.testing.expectEqualStrings(":s 372 n :- abcdefghijklmnopqrstuv", lines[1].bytes);
    try std.testing.expectEqualStrings(":s 372 n :- wxyz", lines[2].bytes);
    try std.testing.expectEqualStrings(":s 376 n :End of /MOTD command.", lines[3].bytes);
}

test "present empty text line is not absent MOTD" {
    var out: [192]u8 = undefined;
    var line_storage: [3]MotdLine = undefined;
    var sink = MotdLineSink{ .lines = &line_storage };

    try writeMotdRepliesForRequester(&out, "irc.example", "alice", &.{""}, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings(":irc.example 372 alice :- ", lines[1].bytes);
}

test "invalid bytes and capacity failures are explicit" {
    var out: [96]u8 = undefined;
    var line_storage: [3]MotdLine = undefined;
    var sink = MotdLineSink{ .lines = &line_storage };

    try std.testing.expectError(
        error.InvalidMotdLine,
        writeMotdRepliesForRequester(&out, "irc.example", "alice", &.{"bad\nline"}, &sink),
    );

    sink.reset();
    try std.testing.expectError(
        error.InvalidServerName,
        writeMotdRepliesForRequester(&out, "irc example", "alice", &.{"ok"}, &sink),
    );

    var short_out: [8]u8 = undefined;
    sink.reset();
    try std.testing.expectError(
        error.OutputTooSmall,
        writeMotdRepliesForRequester(&short_out, "irc.example", "alice", &.{}, &sink),
    );

    var one_line_storage: [1]MotdLine = undefined;
    var one_line_sink = MotdLineSink{ .lines = &one_line_storage };
    try std.testing.expectError(
        error.TooManyLines,
        writeMotdRepliesForRequester(&out, "irc.example", "alice", &.{"one"}, &one_line_sink),
    );
}
