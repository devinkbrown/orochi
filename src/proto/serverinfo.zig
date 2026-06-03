//! VERSION, TIME, and ADMIN numeric reply builders.
//!
//! These helpers write complete IRC reply lines into caller-owned buffers.
//! They preserve the RFC numeric surface and Ophion's VERSION wire shape while
//! keeping all attacker-controlled bytes validated before emission.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_TOKEN_BYTES: usize = 128;
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 256;
pub const DEFAULT_MAX_TIME_BYTES: usize = 128;
pub const DEFAULT_MAX_ADMIN_BYTES: usize = 256;

pub const ServerInfoError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidRequester,
    RequesterTooLong,
    InvalidVersionToken,
    VersionTokenTooLong,
    InvalidDescription,
    DescriptionTooLong,
    InvalidSid,
    SidTooLong,
    InvalidTime,
    TimeTooLong,
    InvalidAdminInfo,
    AdminInfoTooLong,
    LineTooLong,
    OutputTooSmall,
    TooManyAdminReplies,
};

/// Compile-time limits for server information reply builders.
pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_token_bytes: usize = DEFAULT_MAX_TOKEN_BYTES,
    max_description_bytes: usize = DEFAULT_MAX_DESCRIPTION_BYTES,
    max_time_bytes: usize = DEFAULT_MAX_TIME_BYTES,
    max_admin_bytes: usize = DEFAULT_MAX_ADMIN_BYTES,
};

/// Shared numeric reply prefix data.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

/// Data rendered by RPL_VERSION (351).
pub const VersionInfo = struct {
    version: []const u8,
    build: []const u8,
    branding: ?[]const u8 = null,
    reply_server: []const u8,
    description: []const u8,
    ts_version: u16 = 1,
    sid: []const u8,
};

/// Data rendered by ADMIN numerics.
pub const AdminInfo = struct {
    reply_server: []const u8,
    location1: ?[]const u8 = null,
    location2: ?[]const u8 = null,
    email: ?[]const u8 = null,
};

/// One complete IRC numeric line stored in caller-owned output bytes.
pub const ReplyLine = struct {
    bytes: []const u8,
};

/// Caller-provided storage for ADMIN reply line slices.
pub const ReplyLineSink = struct {
    lines: []ReplyLine,
    count: usize = 0,

    pub fn append(self: *ReplyLineSink, bytes: []const u8) ServerInfoError!void {
        if (self.count >= self.lines.len) return error.TooManyAdminReplies;
        self.lines[self.count] = .{ .bytes = bytes };
        self.count += 1;
    }

    pub fn slice(self: *const ReplyLineSink) []const ReplyLine {
        return self.lines[0..self.count];
    }

    pub fn reset(self: *ReplyLineSink) void {
        self.count = 0;
    }
};

/// Build one Ophion-shaped RPL_VERSION (351) line.
///
/// Wire format:
/// `:<server> 351 <requester> <version>(<build>[,<branding>]). <reply-server> :<description> TS<n>ow <sid>\r\n`
pub fn writeVersionReply(
    out: []u8,
    ctx: ReplyContext,
    info: VersionInfo,
) ServerInfoError![]const u8 {
    return writeVersionReplyWith(.{}, out, ctx, info);
}

/// Build one RPL_VERSION line using caller-selected validation limits.
pub fn writeVersionReplyWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    info: VersionInfo,
) ServerInfoError![]const u8 {
    try validateContextWith(params, ctx);
    try validateVersionInfoWith(params, info);

    const line_len = versionReplyLen(ctx, info);
    try ensureCapacity(params, out, line_len);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .RPL_VERSION, ctx);
    try writer.appendByte(' ');
    try writer.appendBytes(info.version);
    try writer.appendByte('(');
    try writer.appendBytes(info.build);
    if (info.branding) |branding| {
        try writer.appendByte(',');
        try writer.appendBytes(branding);
    }
    try writer.appendBytes("). ");
    try writer.appendBytes(info.reply_server);
    try writer.appendBytes(" :");
    try writer.appendBytes(info.description);
    try writer.appendBytes(" TS");
    try writer.appendUnsigned(info.ts_version);
    try writer.appendBytes("ow ");
    try writer.appendBytes(info.sid);
    try writer.crlf();
    return writer.slice();
}

/// Build one RPL_TIME (391) line.
///
/// Wire format: `:<server> 391 <requester> <reply-server> :<time-string>\r\n`
pub fn writeTimeReply(
    out: []u8,
    ctx: ReplyContext,
    reply_server: []const u8,
    time_string: []const u8,
) ServerInfoError![]const u8 {
    return writeTimeReplyWith(.{}, out, ctx, reply_server, time_string);
}

/// Build one RPL_TIME line using caller-selected validation limits.
pub fn writeTimeReplyWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    reply_server: []const u8,
    time_string: []const u8,
) ServerInfoError![]const u8 {
    try validateContextWith(params, ctx);
    try validateServerNameWith(params, reply_server);
    try validateTimeStringWith(params, time_string);

    const line_len = numericHeaderLen(ctx) + 1 + reply_server.len + 2 + time_string.len + 2;
    try ensureCapacity(params, out, line_len);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .RPL_TIME, ctx);
    try writer.appendByte(' ');
    try writer.appendBytes(reply_server);
    try writer.appendBytes(" :");
    try writer.appendBytes(time_string);
    try writer.crlf();
    return writer.slice();
}

/// Build ADMIN replies into one caller-owned byte buffer and append line slices.
///
/// RPL_ADMINME (256) is always emitted. RPL_ADMINLOC1 (257),
/// RPL_ADMINLOC2 (258), and RPL_ADMINEMAIL (259) are emitted when their
/// corresponding `AdminInfo` field is non-null, matching Ophion's behavior.
pub fn writeAdminReplies(
    out: []u8,
    ctx: ReplyContext,
    info: AdminInfo,
    sink: *ReplyLineSink,
) ServerInfoError!void {
    return writeAdminRepliesWith(.{}, out, ctx, info, sink);
}

/// Build ADMIN replies using caller-selected validation limits.
pub fn writeAdminRepliesWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    info: AdminInfo,
    sink: *ReplyLineSink,
) ServerInfoError!void {
    try validateContextWith(params, ctx);
    try validateAdminInfoWith(params, info);

    try ensureCapacity(params, out, adminMeLen(ctx, info.reply_server));
    if (info.location1) |value| try ensureCapacity(params, out, adminTrailingLen(ctx, value));
    if (info.location2) |value| try ensureCapacity(params, out, adminTrailingLen(ctx, value));
    if (info.email) |value| try ensureCapacity(params, out, adminTrailingLen(ctx, value));

    const total_len = adminRepliesLen(ctx, info);
    if (total_len > out.len) return error.OutputTooSmall;

    const required_lines = adminReplyCount(info);
    if (sink.lines.len - sink.count < required_lines) return error.TooManyAdminReplies;

    var writer = BufferWriter.init(out);
    try appendAdminMe(&writer, ctx, info.reply_server, sink);
    if (info.location1) |value| try appendAdminTrailing(&writer, ctx, .RPL_ADMINLOC1, value, sink);
    if (info.location2) |value| try appendAdminTrailing(&writer, ctx, .RPL_ADMINLOC2, value, sink);
    if (info.email) |value| try appendAdminTrailing(&writer, ctx, .RPL_ADMINEMAIL, value, sink);
}

/// Build the mandatory RPL_ADMINME (256) line.
pub fn writeAdminMeReply(
    out: []u8,
    ctx: ReplyContext,
    reply_server: []const u8,
) ServerInfoError![]const u8 {
    return writeAdminMeReplyWith(.{}, out, ctx, reply_server);
}

/// Build RPL_ADMINME using caller-selected validation limits.
pub fn writeAdminMeReplyWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    reply_server: []const u8,
) ServerInfoError![]const u8 {
    try validateContextWith(params, ctx);
    try validateServerNameWith(params, reply_server);

    const line_len = adminMeLen(ctx, reply_server);
    try ensureCapacity(params, out, line_len);

    var writer = BufferWriter.init(out);
    try writeAdminMeLine(&writer, ctx, reply_server);
    return writer.slice();
}

/// Build one trailing ADMIN detail line: RPL_ADMINLOC1/2 or RPL_ADMINEMAIL.
pub fn writeAdminDetailReply(
    out: []u8,
    ctx: ReplyContext,
    reply_numeric: numeric.Numeric,
    value: []const u8,
) ServerInfoError![]const u8 {
    return writeAdminDetailReplyWith(.{}, out, ctx, reply_numeric, value);
}

/// Build one ADMIN detail line using caller-selected validation limits.
pub fn writeAdminDetailReplyWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    reply_numeric: numeric.Numeric,
    value: []const u8,
) ServerInfoError![]const u8 {
    try validateContextWith(params, ctx);
    try validateAdminDetailNumeric(reply_numeric);
    try validateAdminValueWith(params, value);

    const line_len = adminTrailingLen(ctx, value);
    try ensureCapacity(params, out, line_len);

    var writer = BufferWriter.init(out);
    try writeAdminTrailingLine(&writer, ctx, reply_numeric, value);
    return writer.slice();
}

pub fn validateContext(ctx: ReplyContext) ServerInfoError!void {
    return validateContextWith(.{}, ctx);
}

pub fn validateVersionInfo(info: VersionInfo) ServerInfoError!void {
    return validateVersionInfoWith(.{}, info);
}

pub fn validateTimeString(time_string: []const u8) ServerInfoError!void {
    return validateTimeStringWith(.{}, time_string);
}

pub fn validateAdminInfo(info: AdminInfo) ServerInfoError!void {
    return validateAdminInfoWith(.{}, info);
}

pub fn validateContextWith(comptime params: Params, ctx: ReplyContext) ServerInfoError!void {
    try validateServerNameWith(params, ctx.server_name);
    try validateRequesterWith(params, ctx.requester);
}

pub fn validateVersionInfoWith(comptime params: Params, info: VersionInfo) ServerInfoError!void {
    try validateTokenWith(params, info.version);
    try validateTokenWith(params, info.build);
    if (info.branding) |branding| try validateTokenWith(params, branding);
    try validateServerNameWith(params, info.reply_server);
    try validateDescriptionWith(params, info.description);
    try validateSidWith(params, info.sid);
}

pub fn validateTimeStringWith(comptime params: Params, time_string: []const u8) ServerInfoError!void {
    if (time_string.len == 0) return error.InvalidTime;
    if (time_string.len > params.max_time_bytes) return error.TimeTooLong;
    for (time_string) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidTime;
    }
}

pub fn validateAdminInfoWith(comptime params: Params, info: AdminInfo) ServerInfoError!void {
    try validateServerNameWith(params, info.reply_server);
    if (info.location1) |value| try validateAdminValueWith(params, value);
    if (info.location2) |value| try validateAdminValueWith(params, value);
    if (info.email) |value| try validateAdminValueWith(params, value);
}

fn validateAdminDetailNumeric(reply_numeric: numeric.Numeric) ServerInfoError!void {
    switch (reply_numeric) {
        .RPL_ADMINLOC1, .RPL_ADMINLOC2, .RPL_ADMINEMAIL => {},
        else => return error.InvalidAdminInfo,
    }
}

fn validateServerNameWith(comptime params: Params, server_name: []const u8) ServerInfoError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validServerNameByte(ch)) return error.InvalidServerName;
    }
}

fn validateRequesterWith(comptime params: Params, requester: []const u8) ServerInfoError!void {
    if (requester.len == 0) return error.InvalidRequester;
    if (requester.len > params.max_requester_bytes) return error.RequesterTooLong;
    for (requester) |ch| {
        if (!validParamByte(ch)) return error.InvalidRequester;
    }
}

fn validateTokenWith(comptime params: Params, token: []const u8) ServerInfoError!void {
    if (token.len == 0) return error.InvalidVersionToken;
    if (token.len > params.max_token_bytes) return error.VersionTokenTooLong;
    for (token) |ch| {
        if (!validTokenByte(ch)) return error.InvalidVersionToken;
    }
}

fn validateDescriptionWith(comptime params: Params, description: []const u8) ServerInfoError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (description.len > params.max_description_bytes) return error.DescriptionTooLong;
    for (description) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidDescription;
    }
}

fn validateSidWith(comptime params: Params, sid: []const u8) ServerInfoError!void {
    if (sid.len == 0) return error.InvalidSid;
    if (sid.len > params.max_token_bytes) return error.SidTooLong;
    for (sid) |ch| {
        if (!validTokenByte(ch)) return error.InvalidSid;
    }
}

fn validateAdminValueWith(comptime params: Params, value: []const u8) ServerInfoError!void {
    if (value.len == 0) return error.InvalidAdminInfo;
    if (value.len > params.max_admin_bytes) return error.AdminInfoTooLong;
    for (value) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidAdminInfo;
    }
}

fn ensureCapacity(comptime params: Params, out: []u8, line_len: usize) ServerInfoError!void {
    if (line_len > params.max_line_bytes) return error.LineTooLong;
    if (line_len > out.len) return error.OutputTooSmall;
}

fn versionReplyLen(ctx: ReplyContext, info: VersionInfo) usize {
    const branding_len: usize = if (info.branding) |branding| 1 + branding.len else 0;
    return numericHeaderLen(ctx) + 1 + info.version.len + 1 + info.build.len + branding_len +
        3 + info.reply_server.len + 2 + info.description.len + 3 + decimalLen(info.ts_version) +
        3 + info.sid.len + 2;
}

fn adminRepliesLen(ctx: ReplyContext, info: AdminInfo) usize {
    var len = adminMeLen(ctx, info.reply_server);
    if (info.location1) |value| len += adminTrailingLen(ctx, value);
    if (info.location2) |value| len += adminTrailingLen(ctx, value);
    if (info.email) |value| len += adminTrailingLen(ctx, value);
    return len;
}

fn adminReplyCount(info: AdminInfo) usize {
    var count: usize = 1;
    if (info.location1 != null) count += 1;
    if (info.location2 != null) count += 1;
    if (info.email != null) count += 1;
    return count;
}

fn adminMeLen(ctx: ReplyContext, reply_server: []const u8) usize {
    return numericHeaderLen(ctx) + 1 + reply_server.len + " :Administrative info\r\n".len;
}

fn adminTrailingLen(ctx: ReplyContext, value: []const u8) usize {
    return numericHeaderLen(ctx) + 2 + value.len + 2;
}

fn numericHeaderLen(ctx: ReplyContext) usize {
    return 1 + ctx.server_name.len + 1 + 3 + 1 + ctx.requester.len;
}

fn appendAdminMe(
    writer: *BufferWriter,
    ctx: ReplyContext,
    reply_server: []const u8,
    sink: *ReplyLineSink,
) ServerInfoError!void {
    const start = writer.len;
    try writeAdminMeLine(writer, ctx, reply_server);
    try sink.append(writer.out[start..writer.len]);
}

fn appendAdminTrailing(
    writer: *BufferWriter,
    ctx: ReplyContext,
    reply_numeric: numeric.Numeric,
    value: []const u8,
    sink: *ReplyLineSink,
) ServerInfoError!void {
    const start = writer.len;
    try writeAdminTrailingLine(writer, ctx, reply_numeric, value);
    try sink.append(writer.out[start..writer.len]);
}

fn writeAdminMeLine(
    writer: *BufferWriter,
    ctx: ReplyContext,
    reply_server: []const u8,
) ServerInfoError!void {
    try writeNumericHeader(writer, .RPL_ADMINME, ctx);
    try writer.appendByte(' ');
    try writer.appendBytes(reply_server);
    try writer.appendBytes(" :Administrative info");
    try writer.crlf();
}

fn writeAdminTrailingLine(
    writer: *BufferWriter,
    ctx: ReplyContext,
    reply_numeric: numeric.Numeric,
    value: []const u8,
) ServerInfoError!void {
    try writeNumericHeader(writer, reply_numeric, ctx);
    try writer.appendBytes(" :");
    try writer.appendBytes(value);
    try writer.crlf();
}

fn writeNumericHeader(
    writer: *BufferWriter,
    reply_numeric: numeric.Numeric,
    ctx: ReplyContext,
) ServerInfoError!void {
    var code_buf: [3]u8 = undefined;

    try writer.appendByte(':');
    try writer.appendBytes(ctx.server_name);
    try writer.appendByte(' ');
    try writer.appendBytes(numeric.formatCode(reply_numeric, &code_buf));
    try writer.appendByte(' ');
    try writer.appendBytes(ctx.requester);
}

fn decimalLen(value: u16) usize {
    var current = value;
    var len: usize = 1;
    while (current >= 10) {
        current /= 10;
        len += 1;
    }
    return len;
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

fn validTokenByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', '+', '~' => true,
        else => false,
    };
}

fn validTrailingByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn crlf(self: *BufferWriter) ServerInfoError!void {
        try self.appendBytes("\r\n");
    }

    fn appendUnsigned(self: *BufferWriter, value: u16) ServerInfoError!void {
        var buf: [5]u8 = undefined;
        var n = buf.len;
        var current = value;

        while (true) {
            n -= 1;
            buf[n] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[n..]);
    }

    fn appendBytes(self: *BufferWriter, bytes: []const u8) ServerInfoError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *BufferWriter, byte: u8) ServerInfoError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

fn sampleContext() ReplyContext {
    return .{
        .server_name = "irc.example.test",
        .requester = "alice",
    };
}

fn sampleVersion() VersionInfo {
    return .{
        .version = "mizuchi",
        .build = "9f7c14a",
        .reply_server = "irc.example.test",
        .description = "Mizuchi IRCX daemon",
        .ts_version = 1,
        .sid = "001",
    };
}

test "VERSION builds Ophion-shaped RPL_VERSION 351" {
    var out: [160]u8 = undefined;

    const line = try writeVersionReply(&out, sampleContext(), sampleVersion());

    try std.testing.expectEqualStrings(
        ":irc.example.test 351 alice mizuchi(9f7c14a). irc.example.test :Mizuchi IRCX daemon TS1ow 001\r\n",
        line,
    );
}

test "VERSION includes optional branding tag" {
    var out: [192]u8 = undefined;
    var info = sampleVersion();
    info.branding = "dev";

    const line = try writeVersionReply(&out, sampleContext(), info);

    try std.testing.expectEqualStrings(
        ":irc.example.test 351 alice mizuchi(9f7c14a,dev). irc.example.test :Mizuchi IRCX daemon TS1ow 001\r\n",
        line,
    );
}

test "TIME builds RPL_TIME 391" {
    var out: [160]u8 = undefined;

    const line = try writeTimeReply(
        &out,
        sampleContext(),
        "irc.example.test",
        "Wednesday June 3 2026 -- 14:05:09 +02:00",
    );

    try std.testing.expectEqualStrings(
        ":irc.example.test 391 alice irc.example.test :Wednesday June 3 2026 -- 14:05:09 +02:00\r\n",
        line,
    );
}

test "ADMIN builds RPL_ADMINME and configured detail replies" {
    var out: [320]u8 = undefined;
    var slots: [4]ReplyLine = undefined;
    var sink = ReplyLineSink{ .lines = &slots };

    try writeAdminReplies(
        &out,
        sampleContext(),
        .{
            .reply_server = "irc.example.test",
            .location1 = "Example Network",
            .location2 = "Berlin, DE",
            .email = "admin@example.test",
        },
        &sink,
    );

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 4), lines.len);
    try std.testing.expectEqualStrings(
        ":irc.example.test 256 alice irc.example.test :Administrative info\r\n",
        lines[0].bytes,
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 257 alice :Example Network\r\n",
        lines[1].bytes,
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 258 alice :Berlin, DE\r\n",
        lines[2].bytes,
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 259 alice :admin@example.test\r\n",
        lines[3].bytes,
    );
}

test "ADMIN can build individual detail replies" {
    var out: [96]u8 = undefined;

    const line = try writeAdminDetailReply(&out, sampleContext(), .RPL_ADMINEMAIL, "admin@example.test");

    try std.testing.expectEqualStrings(
        ":irc.example.test 259 alice :admin@example.test\r\n",
        line,
    );
}

test "ADMIN line ceiling is checked per reply, not per batch" {
    const long_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const long_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const long_c = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    var out: [640]u8 = undefined;
    var slots: [4]ReplyLine = undefined;
    var sink = ReplyLineSink{ .lines = &slots };

    try writeAdminReplies(
        &out,
        sampleContext(),
        .{
            .reply_server = "irc.example.test",
            .location1 = long_a,
            .location2 = long_b,
            .email = long_c,
        },
        &sink,
    );

    try std.testing.expectEqual(@as(usize, 4), sink.slice().len);
}

test "validation rejects control bytes before output" {
    var out: [160]u8 = undefined;

    try std.testing.expectError(
        error.InvalidDescription,
        writeVersionReply(&out, sampleContext(), .{
            .version = "mizuchi",
            .build = "9f7c14a",
            .reply_server = "irc.example.test",
            .description = "bad\rdescription",
            .sid = "001",
        }),
    );

    try std.testing.expectError(
        error.InvalidTime,
        writeTimeReply(&out, sampleContext(), "irc.example.test", "bad\ntime"),
    );

    try std.testing.expectError(
        error.InvalidAdminInfo,
        writeAdminDetailReply(&out, sampleContext(), .RPL_ADMINLOC1, "bad\x7fadmin"),
    );
}

test "small buffers and line ceilings return typed errors" {
    var tiny: [12]u8 = undefined;

    try std.testing.expectError(
        error.OutputTooSmall,
        writeVersionReply(&tiny, sampleContext(), sampleVersion()),
    );

    var out: [160]u8 = undefined;
    try std.testing.expectError(
        error.LineTooLong,
        writeTimeReplyWith(
            .{ .max_line_bytes = 32 },
            &out,
            sampleContext(),
            "irc.example.test",
            "Wednesday June 3 2026 -- 14:05:09 +02:00",
        ),
    );
}
