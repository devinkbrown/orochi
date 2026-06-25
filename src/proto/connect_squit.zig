// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CONNECT/SQUIT protocol parsing and reply builders.
//!
//! This module deliberately stops at typed requests and wire-line builders.
//! Opening or closing a server link remains the daemon caller's job.
const std = @import("std");
const irc_line = @import("irc_line.zig");
const numeric = @import("numeric.zig");

pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_REASON_BYTES: usize = 256;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;

pub const Params = struct {
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_reason_bytes: usize = DEFAULT_MAX_REASON_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
};

pub const Error = error{
    InvalidCommand,
    MissingServer,
    TooManyParameters,
    InvalidServerName,
    ServerNameTooLong,
    InvalidPort,
    InvalidRemote,
    RemoteTooLong,
    InvalidReason,
    ReasonTooLong,
    InvalidNick,
    NickTooLong,
    OutputTooSmall,
    LineTooLong,
} || irc_line.ParseError;

pub const ConnectRequest = struct {
    server: []const u8,
    port: ?u16 = null,
    remote: ?[]const u8 = null,
};

pub const SquitRequest = struct {
    server: []const u8,
    reason: ?[]const u8 = null,
};

pub const Request = union(enum) {
    connect: ConnectRequest,
    squit: SquitRequest,
};

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

pub const OperNoticeContext = struct {
    server_name: []const u8,
    operator: []const u8,
    timestamp_ms: u64,
};

pub fn parseLine(line: []const u8) Error!Request {
    return parseLineWith(.{}, line);
}

pub fn parseLineWith(comptime params: Params, line: []const u8) Error!Request {
    const parsed = try irc_line.parseLine(line);
    if (std.ascii.eqlIgnoreCase(parsed.command, "CONNECT")) {
        return .{ .connect = try parseConnectParamsWith(params, parsed.paramSlice()) };
    }
    if (std.ascii.eqlIgnoreCase(parsed.command, "SQUIT")) {
        return .{ .squit = try parseSquitParamsWith(params, parsed.paramSlice()) };
    }
    return error.InvalidCommand;
}

pub fn parseConnectParams(params: []const []const u8) Error!ConnectRequest {
    return parseConnectParamsWith(.{}, params);
}

pub fn parseConnectParamsWith(comptime bounds: Params, params: []const []const u8) Error!ConnectRequest {
    if (params.len == 0) return error.MissingServer;
    if (params.len > 3) return error.TooManyParameters;

    var request = ConnectRequest{ .server = params[0] };
    if (params.len >= 2) request.port = try parsePort(params[1]);
    if (params.len == 3) request.remote = params[2];

    try validateConnectWith(bounds, request);
    return request;
}

pub fn parseSquitParams(params: []const []const u8) Error!SquitRequest {
    return parseSquitParamsWith(.{}, params);
}

pub fn parseSquitParamsWith(comptime bounds: Params, params: []const []const u8) Error!SquitRequest {
    if (params.len == 0) return error.MissingServer;
    if (params.len > 2) return error.TooManyParameters;

    const request = SquitRequest{
        .server = params[0],
        .reason = if (params.len == 2) params[1] else null,
    };
    try validateSquitWith(bounds, request);
    return request;
}

pub fn validateRequest(request: Request) Error!void {
    return validateRequestWith(.{}, request);
}

pub fn validateRequestWith(comptime params: Params, request: Request) Error!void {
    switch (request) {
        .connect => |connect| try validateConnectWith(params, connect),
        .squit => |squit| try validateSquitWith(params, squit),
    }
}

pub fn validateConnect(request: ConnectRequest) Error!void {
    return validateConnectWith(.{}, request);
}

pub fn validateConnectWith(comptime params: Params, request: ConnectRequest) Error!void {
    try validateServerNameWith(params, request.server);
    if (request.port) |port| {
        if (port == 0) return error.InvalidPort;
    }
    if (request.remote) |remote| try validateRemoteWith(params, remote);
}

pub fn validateSquit(request: SquitRequest) Error!void {
    return validateSquitWith(.{}, request);
}

pub fn validateSquitWith(comptime params: Params, request: SquitRequest) Error!void {
    try validateServerNameWith(params, request.server);
    if (request.reason) |reason| try validateReasonWith(params, reason);
}

/// Build `ERR_NOSUCHSERVER` (402).
pub fn writeNoSuchServer(out: []u8, ctx: ReplyContext, target_server: []const u8) Error![]const u8 {
    return writeNoSuchServerWith(.{}, out, ctx, target_server);
}

pub fn writeNoSuchServerWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    target_server: []const u8,
) Error![]const u8 {
    try validateReplyContextWith(params, ctx);
    try validateServerNameWith(params, target_server);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.ERR_NOSUCHSERVER, ctx.server_name, ctx.requester);
    try b.spaceBytes(target_server);
    try b.spaceTrailing("No such server");
    try b.crlf();
    return b.slice();
}

/// Build an Event Spine oper-action note for a parsed CONNECT or SQUIT request.
pub fn writeOperActionNotice(out: []u8, ctx: OperNoticeContext, request: Request) Error![]const u8 {
    return writeOperActionNoticeWith(.{}, out, ctx, request);
}

pub fn writeOperActionNoticeWith(
    comptime params: Params,
    out: []u8,
    ctx: OperNoticeContext,
    request: Request,
) Error![]const u8 {
    try validateServerNameWith(params, ctx.server_name);
    try validateNickWith(params, ctx.operator);
    try validateRequestWith(params, request);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.appendBytes("@event-category=oper_action;event-severity=notice;event-timestamp-ms=");
    try b.appendUnsigned(ctx.timestamp_ms);
    try b.appendBytes(" :");
    try b.appendBytes(ctx.server_name);
    try b.appendBytes(" NOTE EVENT OPER_ACTION :");
    try b.appendBytes(ctx.operator);
    try b.appendBytes(" requested ");
    switch (request) {
        .connect => |connect| {
            try b.appendBytes("CONNECT ");
            try b.appendBytes(connect.server);
            if (connect.port) |port| {
                try b.appendByte(' ');
                try b.appendUnsigned(port);
            }
            if (connect.remote) |remote| {
                try b.appendByte(' ');
                try b.appendBytes(remote);
            }
        },
        .squit => |squit| {
            try b.appendBytes("SQUIT ");
            try b.appendBytes(squit.server);
            if (squit.reason) |reason| {
                try b.appendBytes(" (");
                try b.appendBytes(reason);
                try b.appendByte(')');
            }
        },
    }
    try b.crlf();
    return b.slice();
}

pub fn validateServerName(name: []const u8) Error!void {
    return validateServerNameWith(.{}, name);
}

pub fn validateReason(reason: []const u8) Error!void {
    return validateReasonWith(.{}, reason);
}

fn parsePort(bytes: []const u8) Error!u16 {
    if (bytes.len == 0) return error.InvalidPort;
    for (bytes) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidPort;
    }
    const port = std.fmt.parseUnsigned(u16, bytes, 10) catch return error.InvalidPort;
    if (port == 0) return error.InvalidPort;
    return port;
}

fn validateReplyContextWith(comptime params: Params, ctx: ReplyContext) Error!void {
    try validateServerNameWith(params, ctx.server_name);
    try validateNickWith(params, ctx.requester);
}

fn validateServerNameWith(comptime params: Params, name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidServerName;
    if (name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (name) |ch| {
        if (!validServerNameByte(ch)) return error.InvalidServerName;
    }
}

fn validateRemoteWith(comptime params: Params, remote: []const u8) Error!void {
    if (remote.len == 0) return error.InvalidRemote;
    if (remote.len > params.max_server_bytes) return error.RemoteTooLong;
    for (remote) |ch| {
        if (!validServerNameByte(ch)) return error.InvalidRemote;
    }
}

fn validateNickWith(comptime params: Params, nick: []const u8) Error!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validMiddleParamByte(ch)) return error.InvalidNick;
    }
}

fn validateReasonWith(comptime params: Params, reason: []const u8) Error!void {
    if (reason.len > params.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |ch| {
        if (ch == 0 or ch == '\r' or ch == '\n' or ch == 0x7f) return error.InvalidReason;
        if (ch < 0x20 and ch != '\t') return error.InvalidReason;
    }
}

fn validServerNameByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn validMiddleParamByte(ch: u8) bool {
    return ch >= 0x21 and ch != 0x7f and ch != ' ';
}

const LineBuilder = struct {
    out: []u8,
    len: usize = 0,
    max: usize,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max = @min(out.len, max_line_bytes) };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code: numeric.Numeric, server_name: []const u8, requester: []const u8) Error!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceBytes(self: *LineBuilder, bytes: []const u8) Error!void {
        try self.appendByte(' ');
        try self.appendBytes(bytes);
    }

    fn spaceTrailing(self: *LineBuilder, bytes: []const u8) Error!void {
        try self.appendBytes(" :");
        try self.appendBytes(bytes);
    }

    fn appendUnsigned(self: *LineBuilder, value: anytype) Error!void {
        var buf: [20]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return error.LineTooLong;
        try self.appendBytes(text);
    }

    fn crlf(self: *LineBuilder) Error!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) Error!void {
        if (self.out.len - self.len < bytes.len) return error.OutputTooSmall;
        if (self.max - self.len < bytes.len) return error.LineTooLong;
        @memcpy(self.out[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) Error!void {
        if (self.out.len - self.len < 1) return error.OutputTooSmall;
        if (self.max - self.len < 1) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

fn expectConnect(line: []const u8) !ConnectRequest {
    return switch (try parseLine(line)) {
        .connect => |request| request,
        .squit => error.InvalidCommand,
    };
}

fn expectSquit(line: []const u8) !SquitRequest {
    return switch (try parseLine(line)) {
        .connect => error.InvalidCommand,
        .squit => |request| request,
    };
}

test "parses CONNECT forms" {
    const allocator = std.testing.allocator;
    const owned = try allocator.dupe(u8, "CONNECT irc.remote 6697 hub.remote\r\n");
    defer allocator.free(owned);

    const full = try expectConnect(owned);
    try std.testing.expectEqualStrings("irc.remote", full.server);
    try std.testing.expectEqual(@as(?u16, 6697), full.port);
    try std.testing.expectEqualStrings("hub.remote", full.remote.?);

    const target_only = try expectConnect("connect irc.remote");
    try std.testing.expectEqualStrings("irc.remote", target_only.server);
    try std.testing.expectEqual(@as(?u16, null), target_only.port);
    try std.testing.expectEqual(@as(?[]const u8, null), target_only.remote);
}

test "parses SQUIT forms" {
    const allocator = std.testing.allocator;
    const owned = try allocator.dupe(u8, "SQUIT irc.remote :routing maintenance\r\n");
    defer allocator.free(owned);

    const with_reason = try expectSquit(owned);
    try std.testing.expectEqualStrings("irc.remote", with_reason.server);
    try std.testing.expectEqualStrings("routing maintenance", with_reason.reason.?);

    const without_reason = try expectSquit("squit irc.remote");
    try std.testing.expectEqualStrings("irc.remote", without_reason.server);
    try std.testing.expectEqual(@as(?[]const u8, null), without_reason.reason);
}

test "validates malformed requests" {
    try std.testing.expectError(error.MissingServer, parseLine("CONNECT"));
    try std.testing.expectError(error.InvalidPort, parseLine("CONNECT irc.remote 0"));
    try std.testing.expectError(error.InvalidPort, parseLine("CONNECT irc.remote nope"));
    try std.testing.expectError(error.TooManyParameters, parseLine("CONNECT a 1 b c"));
    try std.testing.expectError(error.InvalidServerName, parseLine("SQUIT bad@server :reason"));
    try std.testing.expectError(error.EmbeddedLineBreak, parseLine("SQUIT a :bad\nreason"));
    try std.testing.expectError(
        error.InvalidReason,
        validateSquit(.{ .server = "irc.remote", .reason = "bad\x00reason" }),
    );
}

test "builds reply bytes" {
    var out: [256]u8 = undefined;
    const no_such = try writeNoSuchServer(&out, .{
        .server_name = "irc.local",
        .requester = "alice",
    }, "missing.example");
    try std.testing.expectEqualStrings(
        ":irc.local 402 alice missing.example :No such server\r\n",
        no_such,
    );

    const notice = try writeOperActionNotice(&out, .{
        .server_name = "irc.local",
        .operator = "alice",
        .timestamp_ms = 17000042,
    }, .{ .connect = .{
        .server = "irc.remote",
        .port = 6697,
        .remote = "hub.remote",
    } });
    try std.testing.expectEqualStrings(
        "@event-category=oper_action;event-severity=notice;event-timestamp-ms=17000042 :irc.local NOTE EVENT OPER_ACTION :alice requested CONNECT irc.remote 6697 hub.remote\r\n",
        notice,
    );
}

test "builder validation and bounds failures are reported" {
    var tiny: [16]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        writeNoSuchServer(&tiny, .{ .server_name = "irc.local", .requester = "alice" }, "missing"),
    );
    try std.testing.expectError(
        error.InvalidNick,
        writeNoSuchServer(&tiny, .{ .server_name = "irc.local", .requester = "bad nick" }, "missing"),
    );

    var out: [128]u8 = undefined;
    try std.testing.expectError(
        error.LineTooLong,
        writeOperActionNoticeWith(
            .{ .max_line_bytes = 40 },
            &out,
            .{ .server_name = "irc.local", .operator = "alice", .timestamp_ms = 1 },
            .{ .squit = .{ .server = "irc.remote", .reason = "maintenance" } },
        ),
    );
}
