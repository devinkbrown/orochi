//! IRC LUSERS numeric reply builder.
//!
//! LUSERS reports network-visible population counters as the traditional
//! RFC1459/RFC2812 numeric sequence, with RFC-compatible reply text. The
//! caller owns output storage: this module formats one line at a time into a
//! scratch buffer and immediately hands it to `sink.send(line)`.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;

pub const LusersError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidRequester,
    RequesterTooLong,
    LineTooLong,
    OutputTooSmall,
};

/// Validation limits for LUSERS reply context and formatted IRC lines.
pub const Params = struct {
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
};

/// Prefix context for server-origin numeric replies.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

/// Precomputed LUSERS counters.
pub const Counts = struct {
    users: u64,
    invisible: u64,
    servers: u64,
    opers: u64,
    unknown: u64,
    channels: u64,
    local_clients: u64,
    local_max: u64,
    global_clients: u64,
    global_max: u64,
};

/// Emit the complete LUSERS numeric sequence to `sink.send(line)`.
pub fn emit(
    ctx: ReplyContext,
    counts: Counts,
    scratch: []u8,
    sink: anytype,
) LusersError!void {
    return emitWith(.{}, ctx, counts, scratch, sink);
}

/// Emit the complete LUSERS sequence using caller-selected validation limits.
pub fn emitWith(
    comptime params: Params,
    ctx: ReplyContext,
    counts: Counts,
    scratch: []u8,
    sink: anytype,
) LusersError!void {
    try validateContextWith(params, ctx);

    try sink.send(try writeLuserClientWith(params, scratch, ctx, counts));
    try sink.send(try writeLuserOpWith(params, scratch, ctx, counts));
    try sink.send(try writeLuserUnknownWith(params, scratch, ctx, counts));
    try sink.send(try writeLuserChannelsWith(params, scratch, ctx, counts));
    try sink.send(try writeLuserMeWith(params, scratch, ctx, counts));
    try sink.send(try writeLocalUsersWith(params, scratch, ctx, counts));
    try sink.send(try writeGlobalUsersWith(params, scratch, ctx, counts));
}

/// Build RPL_LUSERCLIENT (251).
pub fn writeLuserClient(out: []u8, ctx: ReplyContext, counts: Counts) LusersError![]const u8 {
    return writeLuserClientWith(.{}, out, ctx, counts);
}

/// Build RPL_LUSERCLIENT (251) using caller-selected validation limits.
pub fn writeLuserClientWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    counts: Counts,
) LusersError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_LUSERCLIENT, ctx);
    try b.appendBytes(" :There are ");
    try b.appendUnsigned(counts.users);
    try b.appendBytes(" users and ");
    try b.appendUnsigned(counts.invisible);
    try b.appendBytes(" invisible on ");
    try b.appendUnsigned(counts.servers);
    try b.appendBytes(" servers");
    try b.crlf();
    return b.slice();
}

/// Build RPL_LUSEROP (252).
pub fn writeLuserOp(out: []u8, ctx: ReplyContext, counts: Counts) LusersError![]const u8 {
    return writeLuserOpWith(.{}, out, ctx, counts);
}

/// Build RPL_LUSEROP (252) using caller-selected validation limits.
pub fn writeLuserOpWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    counts: Counts,
) LusersError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_LUSEROP, ctx);
    try b.appendByte(' ');
    try b.appendUnsigned(counts.opers);
    try b.appendBytes(" :IRC Operators online");
    try b.crlf();
    return b.slice();
}

/// Build RPL_LUSERUNKNOWN (253).
pub fn writeLuserUnknown(out: []u8, ctx: ReplyContext, counts: Counts) LusersError![]const u8 {
    return writeLuserUnknownWith(.{}, out, ctx, counts);
}

/// Build RPL_LUSERUNKNOWN (253) using caller-selected validation limits.
pub fn writeLuserUnknownWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    counts: Counts,
) LusersError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_LUSERUNKNOWN, ctx);
    try b.appendByte(' ');
    try b.appendUnsigned(counts.unknown);
    try b.appendBytes(" :unknown connection(s)");
    try b.crlf();
    return b.slice();
}

/// Build RPL_LUSERCHANNELS (254).
pub fn writeLuserChannels(out: []u8, ctx: ReplyContext, counts: Counts) LusersError![]const u8 {
    return writeLuserChannelsWith(.{}, out, ctx, counts);
}

/// Build RPL_LUSERCHANNELS (254) using caller-selected validation limits.
pub fn writeLuserChannelsWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    counts: Counts,
) LusersError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_LUSERCHANNELS, ctx);
    try b.appendByte(' ');
    try b.appendUnsigned(counts.channels);
    try b.appendBytes(" :channels formed");
    try b.crlf();
    return b.slice();
}

/// Build RPL_LUSERME (255).
pub fn writeLuserMe(out: []u8, ctx: ReplyContext, counts: Counts) LusersError![]const u8 {
    return writeLuserMeWith(.{}, out, ctx, counts);
}

/// Build RPL_LUSERME (255) using caller-selected validation limits.
pub fn writeLuserMeWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    counts: Counts,
) LusersError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_LUSERME, ctx);
    try b.appendBytes(" :I have ");
    try b.appendUnsigned(counts.local_clients);
    try b.appendBytes(" clients and ");
    try b.appendUnsigned(counts.servers);
    try b.appendBytes(" servers");
    try b.crlf();
    return b.slice();
}

/// Build RPL_LOCALUSERS (265).
pub fn writeLocalUsers(out: []u8, ctx: ReplyContext, counts: Counts) LusersError![]const u8 {
    return writeLocalUsersWith(.{}, out, ctx, counts);
}

/// Build RPL_LOCALUSERS (265) using caller-selected validation limits.
pub fn writeLocalUsersWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    counts: Counts,
) LusersError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_LOCALUSERS, ctx);
    // The optional leading `<u> <m>` params are deliberately omitted: clients
    // (e.g. WeeChat) render them verbatim before the human text, producing an
    // ugly "6 6 Current local users 6, max 6". The trailing message already
    // carries both numbers; this keeps the spec-allowed compact form.
    try b.appendBytes(" :Current local users ");
    try b.appendUnsigned(counts.local_clients);
    try b.appendBytes(", max ");
    try b.appendUnsigned(counts.local_max);
    try b.crlf();
    return b.slice();
}

/// Build RPL_GLOBALUSERS (266).
pub fn writeGlobalUsers(out: []u8, ctx: ReplyContext, counts: Counts) LusersError![]const u8 {
    return writeGlobalUsersWith(.{}, out, ctx, counts);
}

/// Build RPL_GLOBALUSERS (266) using caller-selected validation limits.
pub fn writeGlobalUsersWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    counts: Counts,
) LusersError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_GLOBALUSERS, ctx);
    // Omit the optional leading `<u> <m>` params (see writeLocalUsersWith).
    try b.appendBytes(" :Current global users ");
    try b.appendUnsigned(counts.global_clients);
    try b.appendBytes(", max ");
    try b.appendUnsigned(counts.global_max);
    try b.crlf();
    return b.slice();
}

pub fn validateContext(ctx: ReplyContext) LusersError!void {
    return validateContextWith(.{}, ctx);
}

pub fn validateContextWith(comptime params: Params, ctx: ReplyContext) LusersError!void {
    try validateServerNameWith(params, ctx.server_name);
    try validateRequesterWith(params, ctx.requester);
}

pub fn validateServerName(name: []const u8) LusersError!void {
    return validateServerNameWith(.{}, name);
}

pub fn validateServerNameWith(comptime params: Params, name: []const u8) LusersError!void {
    if (name.len == 0) return error.InvalidServerName;
    if (name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (name) |ch| {
        if (!validServerNameByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateRequester(requester: []const u8) LusersError!void {
    return validateRequesterWith(.{}, requester);
}

pub fn validateRequesterWith(comptime params: Params, requester: []const u8) LusersError!void {
    if (requester.len == 0) return error.InvalidRequester;
    if (requester.len > params.max_requester_bytes) return error.RequesterTooLong;
    for (requester) |ch| {
        if (!validParamByte(ch)) return error.InvalidRequester;
    }
}

fn validServerNameByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => ch >= 0x21 and ch != 0x7f,
    };
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

    fn numericPrefix(self: *LineBuilder, reply_numeric: numeric.Numeric, ctx: ReplyContext) LusersError!void {
        try self.appendByte(':');
        try self.appendBytes(ctx.server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(reply_numeric, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(ctx.requester);
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) LusersError!void {
        var buf: [20]u8 = undefined;
        var cursor: usize = buf.len;
        var current = value;

        while (true) {
            cursor -= 1;
            buf[cursor] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[cursor..]);
    }

    fn crlf(self: *LineBuilder) LusersError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) LusersError!void {
        if (bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        if (bytes.len > self.max - self.len) return error.LineTooLong;
        @memcpy(self.out[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) LusersError!void {
        if (self.out.len - self.len < 1) return error.OutputTooSmall;
        if (self.max - self.len < 1) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

const TestSink = struct {
    lines: [][]const u8,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    fn send(self: *TestSink, line: []const u8) LusersError!void {
        if (self.count >= self.lines.len) return error.OutputTooSmall;
        if (line.len > self.storage.len - self.used) return error.OutputTooSmall;
        const start = self.used;
        const end = start + line.len;
        @memcpy(self.storage[start..end], line);
        self.lines[self.count] = self.storage[start..end];
        self.count += 1;
        self.used = end;
    }

    fn slice(self: *const TestSink) []const []const u8 {
        return self.lines[0..self.count];
    }
};

fn sampleContext() ReplyContext {
    return .{ .server_name = "irc.local", .requester = "alice" };
}

fn sampleCounts() Counts {
    return .{
        .users = 42,
        .invisible = 7,
        .servers = 3,
        .opers = 2,
        .unknown = 5,
        .channels = 11,
        .local_clients = 13,
        .local_max = 21,
        .global_clients = 49,
        .global_max = 88,
    };
}

test "full LUSERS sequence uses RFC2812 reply text" {
    var scratch: [160]u8 = undefined;
    var slots: [7][]const u8 = undefined;
    var storage: [1024]u8 = undefined;
    var sink = TestSink{ .lines = &slots, .storage = &storage };

    try emit(sampleContext(), sampleCounts(), &scratch, &sink);

    try std.testing.expectEqual(@as(usize, 7), sink.slice().len);
    try std.testing.expectEqualStrings(
        ":irc.local 251 alice :There are 42 users and 7 invisible on 3 servers\r\n",
        sink.slice()[0],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 252 alice 2 :IRC Operators online\r\n",
        sink.slice()[1],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 253 alice 5 :unknown connection(s)\r\n",
        sink.slice()[2],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 254 alice 11 :channels formed\r\n",
        sink.slice()[3],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 255 alice :I have 13 clients and 3 servers\r\n",
        sink.slice()[4],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 265 alice :Current local users 13, max 21\r\n",
        sink.slice()[5],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 266 alice :Current global users 49, max 88\r\n",
        sink.slice()[6],
    );
}

test "zero counts still emit the complete sequence" {
    const zeros = Counts{
        .users = 0,
        .invisible = 0,
        .servers = 0,
        .opers = 0,
        .unknown = 0,
        .channels = 0,
        .local_clients = 0,
        .local_max = 0,
        .global_clients = 0,
        .global_max = 0,
    };

    var scratch: [160]u8 = undefined;
    var slots: [7][]const u8 = undefined;
    var storage: [1024]u8 = undefined;
    var sink = TestSink{ .lines = &slots, .storage = &storage };

    try emit(sampleContext(), zeros, &scratch, &sink);

    try std.testing.expectEqual(@as(usize, 7), sink.slice().len);
    try std.testing.expectEqualStrings(
        ":irc.local 251 alice :There are 0 users and 0 invisible on 0 servers\r\n",
        sink.slice()[0],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 252 alice 0 :IRC Operators online\r\n",
        sink.slice()[1],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 253 alice 0 :unknown connection(s)\r\n",
        sink.slice()[2],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 254 alice 0 :channels formed\r\n",
        sink.slice()[3],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 255 alice :I have 0 clients and 0 servers\r\n",
        sink.slice()[4],
    );
}

test "u64 bounds render without overflow" {
    const max = std.math.maxInt(u64);
    const counts = Counts{
        .users = max,
        .invisible = max,
        .servers = max,
        .opers = max,
        .unknown = max,
        .channels = max,
        .local_clients = max,
        .local_max = max,
        .global_clients = max,
        .global_max = max,
    };

    var scratch: [260]u8 = undefined;
    var slots: [7][]const u8 = undefined;
    var storage: [2048]u8 = undefined;
    var sink = TestSink{ .lines = &slots, .storage = &storage };

    try emit(sampleContext(), counts, &scratch, &sink);

    try std.testing.expectEqualStrings(
        ":irc.local 251 alice :There are 18446744073709551615 users and 18446744073709551615 invisible on 18446744073709551615 servers\r\n",
        sink.slice()[0],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 265 alice :Current local users 18446744073709551615, max 18446744073709551615\r\n",
        sink.slice()[5],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 266 alice :Current global users 18446744073709551615, max 18446744073709551615\r\n",
        sink.slice()[6],
    );
}

test "invalid bytes and tight bounds fail before emission" {
    var scratch: [160]u8 = undefined;
    var slots: [7][]const u8 = undefined;
    var storage: [1024]u8 = undefined;
    var sink = TestSink{ .lines = &slots, .storage = &storage };

    try std.testing.expectError(
        error.InvalidServerName,
        emit(.{ .server_name = "bad server", .requester = "alice" }, sampleCounts(), &scratch, &sink),
    );
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);

    try std.testing.expectError(
        error.InvalidRequester,
        emit(.{ .server_name = "irc.local", .requester = "bad user" }, sampleCounts(), &scratch, &sink),
    );
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);

    try std.testing.expectError(
        error.OutputTooSmall,
        writeLuserClient(scratch[0..12], sampleContext(), sampleCounts()),
    );
    try std.testing.expectError(
        error.LineTooLong,
        writeLuserClientWith(.{ .max_line_bytes = 24 }, &scratch, sampleContext(), sampleCounts()),
    );
}
