//! TRACE and ETRACE numeric reply builders.
//!
//! This module is allocator-free for production callers: each builder writes a
//! complete CRLF-terminated IRC line into caller storage, and emit helpers pass
//! that line to `sink.send(line)`.
const std = @import("std");

pub const MAX_LINE_BYTES: usize = 512;

pub const TraceError = error{
    InvalidParam,
    InvalidTrailing,
    OutputTooSmall,
};

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

pub const TraceLink = struct {
    version: []const u8,
    destination: []const u8,
    next_server: []const u8,
};

pub const TracePeer = struct {
    class: []const u8,
    name: []const u8,
};

pub const TraceUnknown = struct {
    class: []const u8,
    name: []const u8,
    ip: []const u8,
    age_seconds: u64,
};

pub const TraceClient = struct {
    class: []const u8,
    nick: []const u8,
    ip: []const u8,
    connected_seconds: u64,
    idle_seconds: u64,
};

pub const TraceServer = struct {
    class: []const u8,
    server_count: u64,
    user_count: u64,
    name: []const u8,
    by_nick: []const u8,
    by_user: []const u8 = "*",
    by_host: []const u8,
    link_seconds: u64,
};

pub const TraceClass = struct {
    name: []const u8,
    count: u64,
};

pub const EtraceEntry = struct {
    oper: bool = false,
    class: []const u8,
    nick: []const u8,
    username: []const u8,
    host: []const u8,
    ip: []const u8,
    realname: []const u8,
};

pub const TraceEntry = union(enum) {
    link: TraceLink,
    connecting: TracePeer,
    handshake: TracePeer,
    unknown: TraceUnknown,
    operator: TraceClient,
    user: TraceClient,
    server: TraceServer,
    class: TraceClass,
    end: []const u8,
};

pub fn emitTrace(
    ctx: ReplyContext,
    entries: []const TraceEntry,
    scratch: []u8,
    sink: anytype,
) anyerror!void {
    for (entries) |entry| {
        try sink.send(try writeTraceEntry(scratch, ctx, entry));
    }
}

pub fn emitEtrace(
    ctx: ReplyContext,
    entries: []const EtraceEntry,
    scratch: []u8,
    sink: anytype,
) anyerror!void {
    for (entries) |entry| {
        try sink.send(try writeEtrace(scratch, ctx, entry));
    }
}

pub fn writeTraceEntry(out: []u8, ctx: ReplyContext, entry: TraceEntry) TraceError![]const u8 {
    return switch (entry) {
        .link => |value| writeTraceLink(out, ctx, value),
        .connecting => |value| writeTraceConnecting(out, ctx, value),
        .handshake => |value| writeTraceHandshake(out, ctx, value),
        .unknown => |value| writeTraceUnknown(out, ctx, value),
        .operator => |value| writeTraceOperator(out, ctx, value),
        .user => |value| writeTraceUser(out, ctx, value),
        .server => |value| writeTraceServer(out, ctx, value),
        .class => |value| writeTraceClass(out, ctx, value),
        .end => |target| writeTraceEnd(out, ctx, target),
    };
}

/// Build RPL_TRACELINK (200): `Link <version> <destination> <next server>`.
pub fn writeTraceLink(out: []u8, ctx: ReplyContext, entry: TraceLink) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(200, ctx);
    try b.appendBytes(" Link ");
    try b.appendParam(entry.version);
    try b.spaceParam(entry.destination);
    try b.spaceParam(entry.next_server);
    try b.crlf();
    return b.slice();
}

/// Build RPL_TRACECONNECTING (201): `Try. <class> <name>`.
pub fn writeTraceConnecting(out: []u8, ctx: ReplyContext, entry: TracePeer) TraceError![]const u8 {
    return writeTracePeer(out, ctx, 201, "Try.", entry);
}

/// Build RPL_TRACEHANDSHAKE (202): `H.S. <class> <name>`.
pub fn writeTraceHandshake(out: []u8, ctx: ReplyContext, entry: TracePeer) TraceError![]const u8 {
    return writeTracePeer(out, ctx, 202, "H.S.", entry);
}

/// Build RPL_TRACEUNKNOWN (203): `???? <class> <name> (<ip>) <age>`.
pub fn writeTraceUnknown(out: []u8, ctx: ReplyContext, entry: TraceUnknown) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(203, ctx);
    try b.appendBytes(" ???? ");
    try b.appendParam(entry.class);
    try b.spaceParam(entry.name);
    try b.appendBytes(" (");
    try b.appendParam(entry.ip);
    try b.appendBytes(") ");
    try b.appendUnsigned(entry.age_seconds);
    try b.crlf();
    return b.slice();
}

/// Build RPL_TRACEOPERATOR (204): `Oper <class> <nick> (<ip>) <connected> <idle>`.
pub fn writeTraceOperator(out: []u8, ctx: ReplyContext, entry: TraceClient) TraceError![]const u8 {
    return writeTraceClient(out, ctx, 204, "Oper", entry);
}

/// Build RPL_TRACEUSER (205): `User <class> <nick> (<ip>) <connected> <idle>`.
pub fn writeTraceUser(out: []u8, ctx: ReplyContext, entry: TraceClient) TraceError![]const u8 {
    return writeTraceClient(out, ctx, 205, "User", entry);
}

/// Build RPL_TRACESERVER (206): `Serv <class> <n>S <n>C <name> <by>!<user>@<host> <seconds>`.
pub fn writeTraceServer(out: []u8, ctx: ReplyContext, entry: TraceServer) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(206, ctx);
    try b.appendBytes(" Serv ");
    try b.appendParam(entry.class);
    try b.appendByte(' ');
    try b.appendUnsigned(entry.server_count);
    try b.appendByte('S');
    try b.appendByte(' ');
    try b.appendUnsigned(entry.user_count);
    try b.appendByte('C');
    try b.spaceParam(entry.name);
    try b.appendByte(' ');
    try b.appendParam(entry.by_nick);
    try b.appendByte('!');
    try b.appendParam(entry.by_user);
    try b.appendByte('@');
    try b.appendParam(entry.by_host);
    try b.appendByte(' ');
    try b.appendUnsigned(entry.link_seconds);
    try b.crlf();
    return b.slice();
}

/// Build RPL_TRACECLASS (209): `Class <class> <count>`.
pub fn writeTraceClass(out: []u8, ctx: ReplyContext, entry: TraceClass) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(209, ctx);
    try b.appendBytes(" Class ");
    try b.appendParam(entry.name);
    try b.appendByte(' ');
    try b.appendUnsigned(entry.count);
    try b.crlf();
    return b.slice();
}

/// Build RPL_TRACEEND/RPL_ENDOFTRACE (262): `<target> :End of TRACE`.
pub fn writeTraceEnd(out: []u8, ctx: ReplyContext, target: []const u8) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(262, ctx);
    try b.appendByte(' ');
    try b.appendParam(target);
    try b.appendBytes(" :End of TRACE");
    try b.crlf();
    return b.slice();
}

/// Build charybdis/ratbox RPL_ETRACE (709): `<Oper|User> <class> <nick> <user> <host> <ip> :<realname>`.
pub fn writeEtrace(out: []u8, ctx: ReplyContext, entry: EtraceEntry) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(709, ctx);
    try b.appendByte(' ');
    try b.appendParam(if (entry.oper) "Oper" else "User");
    try b.spaceParam(entry.class);
    try b.spaceParam(entry.nick);
    try b.spaceParam(entry.username);
    try b.spaceParam(entry.host);
    try b.spaceParam(entry.ip);
    try b.appendBytes(" :");
    try b.appendTrailing(entry.realname);
    try b.crlf();
    return b.slice();
}

fn writeTracePeer(
    out: []u8,
    ctx: ReplyContext,
    code: u16,
    tag: []const u8,
    entry: TracePeer,
) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(code, ctx);
    try b.appendByte(' ');
    try b.appendParam(tag);
    try b.spaceParam(entry.class);
    try b.spaceParam(entry.name);
    try b.crlf();
    return b.slice();
}

fn writeTraceClient(
    out: []u8,
    ctx: ReplyContext,
    code: u16,
    tag: []const u8,
    entry: TraceClient,
) TraceError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(code, ctx);
    try b.appendByte(' ');
    try b.appendParam(tag);
    try b.spaceParam(entry.class);
    try b.spaceParam(entry.nick);
    try b.appendBytes(" (");
    try b.appendParam(entry.ip);
    try b.appendBytes(") ");
    try b.appendUnsigned(entry.connected_seconds);
    try b.appendByte(' ');
    try b.appendUnsigned(entry.idle_seconds);
    try b.crlf();
    return b.slice();
}

fn validateParam(param: []const u8) TraceError!void {
    if (param.len == 0) return error.InvalidParam;
    for (param) |ch| {
        switch (ch) {
            0, ' ', '\t', '\r', '\n' => return error.InvalidParam,
            else => {},
        }
    }
}

fn validateTrailing(param: []const u8) TraceError!void {
    for (param) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidTrailing,
            else => {},
        }
    }
}

const LineBuilder = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) LineBuilder {
        return .{ .out = out };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code: u16, ctx: ReplyContext) TraceError!void {
        try self.appendByte(':');
        try self.appendParam(ctx.server_name);
        try self.appendByte(' ');
        try self.appendCode(code);
        try self.appendByte(' ');
        try self.appendParam(ctx.requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) TraceError!void {
        try self.appendByte(' ');
        try self.appendParam(param);
    }

    fn appendParam(self: *LineBuilder, param: []const u8) TraceError!void {
        try validateParam(param);
        try self.appendBytes(param);
    }

    fn appendTrailing(self: *LineBuilder, param: []const u8) TraceError!void {
        try validateTrailing(param);
        try self.appendBytes(param);
    }

    fn appendCode(self: *LineBuilder, code: u16) TraceError!void {
        if (code > 999) return error.InvalidParam;
        try self.appendByte(@as(u8, '0') + @as(u8, @intCast(code / 100)));
        try self.appendByte(@as(u8, '0') + @as(u8, @intCast((code / 10) % 10)));
        try self.appendByte(@as(u8, '0') + @as(u8, @intCast(code % 10)));
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) TraceError!void {
        var buf: [20]u8 = undefined;
        var n: usize = buf.len;
        var current = value;

        while (true) {
            n -= 1;
            buf[n] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[n..]);
    }

    fn crlf(self: *LineBuilder) TraceError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) TraceError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) TraceError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

const TestSink = struct {
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),

    fn send(self: TestSink, line: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, line);
    }
};

fn sampleContext() ReplyContext {
    return .{ .server_name = "irc.example.test", .requester = "dan" };
}

test "TRACE class lines and end" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);

    var scratch: [MAX_LINE_BYTES]u8 = undefined;
    const entries = [_]TraceEntry{
        .{ .class = .{ .name = "users", .count = 42 } },
        .{ .class = .{ .name = "servers", .count = 3 } },
        .{ .end = "irc.example.test" },
    };

    try emitTrace(sampleContext(), &entries, &scratch, TestSink{
        .allocator = std.testing.allocator,
        .bytes = &bytes,
    });

    try std.testing.expectEqualStrings(
        ":irc.example.test 209 dan Class users 42\r\n" ++
            ":irc.example.test 209 dan Class servers 3\r\n" ++
            ":irc.example.test 262 dan irc.example.test :End of TRACE\r\n",
        bytes.items,
    );
}

test "ETRACE line" {
    var out: [MAX_LINE_BYTES]u8 = undefined;
    const line = try writeEtrace(&out, sampleContext(), .{
        .oper = true,
        .class = "opers",
        .nick = "alice",
        .username = "aliceu",
        .host = "cloak.example",
        .ip = "203.0.113.7",
        .realname = "Alice Example",
    });

    try std.testing.expectEqualStrings(
        ":irc.example.test 709 dan Oper opers alice aliceu cloak.example 203.0.113.7 :Alice Example\r\n",
        line,
    );
}

test "TRACE client and server lines" {
    var out: [MAX_LINE_BYTES]u8 = undefined;
    const user = try writeTraceUser(&out, sampleContext(), .{
        .class = "users",
        .nick = "bob",
        .ip = "255.255.255.255",
        .connected_seconds = 120,
        .idle_seconds = 9,
    });
    try std.testing.expectEqualStrings(
        ":irc.example.test 205 dan User users bob (255.255.255.255) 120 9\r\n",
        user,
    );

    const server = try writeTraceServer(&out, sampleContext(), .{
        .class = "servers",
        .server_count = 2,
        .user_count = 50,
        .name = "irc2.example.test",
        .by_nick = "hub",
        .by_host = "irc.example.test",
        .link_seconds = 3600,
    });
    try std.testing.expectEqualStrings(
        ":irc.example.test 206 dan Serv servers 2S 50C irc2.example.test hub!*@irc.example.test 3600\r\n",
        server,
    );
}

test "TRACE rejects unsafe params" {
    var out: [MAX_LINE_BYTES]u8 = undefined;
    try std.testing.expectError(error.InvalidParam, writeTraceEnd(&out, sampleContext(), "bad target"));
    try std.testing.expectError(error.InvalidTrailing, writeEtrace(&out, sampleContext(), .{
        .class = "users",
        .nick = "bob",
        .username = "bobu",
        .host = "host.example",
        .ip = "192.0.2.1",
        .realname = "Bad\rName",
    }));
}
