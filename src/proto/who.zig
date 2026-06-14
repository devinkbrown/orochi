//! IRC WHO and WHOX parsing plus numeric reply emission.
//!
//! This module is deliberately allocator-free: callers pass tokenized command
//! parameters, immutable client/member context, and an output buffer for one
//! numeric line at a time.
const std = @import("std");
const numeric = @import("../proto/numeric.zig");

pub const MAX_TARGET_BYTES: usize = 128;
pub const MAX_SELECTOR_FIELDS: usize = 16;

pub const WhoError = error{
    InvalidTarget,
    InvalidParameter,
    InvalidSelector,
    InvalidValue,
    OutputTooSmall,
};

/// Parsed WHO command parameters.
pub const Request = struct {
    target: []const u8 = "*",
    oper_only: bool = false,
    whox: ?WhoxRequest = null,
};

/// Parsed WHOX selector token.
pub const WhoxRequest = struct {
    selector: FieldSelector,
    query_type: ?[]const u8 = null,
};

/// WHOX field selector set in caller-requested order.
pub const FieldSelector = struct {
    fields: [MAX_SELECTOR_FIELDS]Field = undefined,
    count: usize = 0,

    /// Parse a runtime WHOX token such as `%cuhsnfdlaor`.
    pub fn parse(token: []const u8) WhoError!FieldSelector {
        if (token.len < 2 or token[0] != '%') return error.InvalidSelector;

        const comma = findByte(token, 1, ',') orelse token.len;
        if (comma == 1) return error.InvalidSelector;

        var out = FieldSelector{};
        for (token[1..comma]) |ch| {
            try out.append(try parseField(ch));
        }
        return out;
    }

    /// Build a selector at comptime, failing compilation for bad field bytes.
    pub fn initComptime(comptime text: []const u8) FieldSelector {
        const start: usize = if (text.len != 0 and text[0] == '%') 1 else 0;
        if (text.len == start) @compileError("empty WHOX selector");
        if (text.len - start > MAX_SELECTOR_FIELDS) @compileError("too many WHOX selector fields");

        var out = FieldSelector{};
        inline for (text[start..]) |ch| {
            const field = comptimeParseField(ch);
            out.fields[out.count] = field;
            out.count += 1;
        }
        return out;
    }

    pub fn slice(self: *const FieldSelector) []const Field {
        return self.fields[0..self.count];
    }

    fn append(self: *FieldSelector, field: Field) WhoError!void {
        if (self.count >= self.fields.len) return error.InvalidSelector;
        self.fields[self.count] = field;
        self.count += 1;
    }
};

/// WHOX fields supported by Orochi M0.
pub const Field = enum(u8) {
    channel = 'c',
    user = 'u',
    host = 'h',
    server = 's',
    nick = 'n',
    flags = 'f',
    distance = 'd',
    idle = 'l',
    account = 'a',
    oper_level = 'o',
    realname = 'r',
};

/// User/client data visible to WHO replies.
pub const ClientContext = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    server: []const u8,
    realname: []const u8,
    away: bool = false,
    oper: bool = false,
    account: ?[]const u8 = null,
};

/// Channel membership data used when a WHO result is channel-scoped.
pub const MemberContext = struct {
    channel: ?[]const u8 = null,
    channel_prefix: ?u8 = null,
    hops: u32 = 0,
    distance: u32 = 0,
    idle_seconds: u32 = 0,
    oper_level: ?[]const u8 = null,
};

/// Reply-level data shared by 315/352/354 builders.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
    target: []const u8,
    client: ClientContext,
    member: MemberContext = .{},
};

/// Parse tokenized WHO parameters.
pub fn parse(params: []const []const u8) WhoError!Request {
    if (params.len > 2) return error.InvalidParameter;
    if (params.len == 0) return .{};

    try validateTarget(params[0]);
    var request = Request{ .target = params[0] };

    if (params.len == 2) {
        const option = params[1];
        if (option.len == 1 and (option[0] == 'o' or option[0] == 'O')) {
            request.oper_only = true;
        } else if (option.len != 0 and option[0] == '%') {
            request.whox = try parseWhox(option);
        } else {
            return error.InvalidParameter;
        }
    }

    return request;
}

/// Parse a standalone WHOX token, including optional query type after comma.
pub fn parseWhox(token: []const u8) WhoError!WhoxRequest {
    const selector = try FieldSelector.parse(token);
    const comma = findByte(token, 1, ',') orelse return .{ .selector = selector };
    const query_type = token[comma + 1 ..];
    if (query_type.len == 0) return error.InvalidSelector;
    try validateParam(query_type);
    return .{ .selector = selector, .query_type = query_type };
}

/// Build a classic RPL_WHOREPLY (352) line.
pub fn writeWhoReply(out: []u8, ctx: ReplyContext) WhoError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(.RPL_WHOREPLY, ctx.server_name, ctx.requester);
    try b.spaceParam(channelName(ctx.member));
    try b.spaceParam(ctx.client.user);
    try b.spaceParam(ctx.client.host);
    try b.spaceParam(ctx.client.server);
    try b.spaceParam(ctx.client.nick);

    var flags_buf: [3]u8 = undefined;
    const flags = try flagsText(ctx.client, ctx.member, &flags_buf);
    try b.spaceParam(flags);

    try b.appendBytes(" :");
    try b.appendUnsigned(ctx.member.hops);
    try b.appendByte(' ');
    try b.appendTrailingBytes(ctx.client.realname);
    try b.crlf();
    return b.slice();
}

/// Build a WHOX RPL_WHOSPCRPL (354) line from `selector` field order.
pub fn writeWhoxReply(
    out: []u8,
    selector: FieldSelector,
    ctx: ReplyContext,
) WhoError![]const u8 {
    if (selector.count == 0) return error.InvalidSelector;

    var b = LineBuilder.init(out);
    try b.numericPrefix(.RPL_WHOSPCRPL, ctx.server_name, ctx.requester);

    var flags_buf: [3]u8 = undefined;
    const fields = selector.slice();
    for (fields, 0..) |field, index| {
        const last = index + 1 == fields.len;
        switch (field) {
            .channel => try b.spaceParam(channelName(ctx.member)),
            .user => try b.spaceParam(ctx.client.user),
            .host => try b.spaceParam(ctx.client.host),
            .server => try b.spaceParam(ctx.client.server),
            .nick => try b.spaceParam(ctx.client.nick),
            .flags => try b.spaceParam(try flagsText(ctx.client, ctx.member, &flags_buf)),
            .distance => try b.spaceUnsigned(ctx.member.distance),
            .idle => try b.spaceUnsigned(ctx.member.idle_seconds),
            .account => try b.spaceParam(ctx.client.account orelse "0"),
            .oper_level => try b.spaceParam(operLevel(ctx.client, ctx.member)),
            .realname => {
                if (last) {
                    try b.spaceTrailing(ctx.client.realname);
                } else {
                    try b.spaceParam(ctx.client.realname);
                }
            },
        }
    }

    try b.crlf();
    return b.slice();
}

/// Build RPL_ENDOFWHO (315) for a completed WHO request.
pub fn writeEndOfWho(out: []u8, server_name: []const u8, requester: []const u8, target: []const u8) WhoError![]const u8 {
    try validateTarget(target);

    var b = LineBuilder.init(out);
    try b.numericPrefix(.RPL_ENDOFWHO, server_name, requester);
    try b.spaceParam(target);
    try b.spaceTrailing("End of WHO list");
    try b.crlf();
    return b.slice();
}

fn parseField(ch: u8) WhoError!Field {
    return switch (ch) {
        'c' => .channel,
        'u' => .user,
        'h' => .host,
        's' => .server,
        'n' => .nick,
        'f' => .flags,
        'd' => .distance,
        'l' => .idle,
        'a' => .account,
        'o' => .oper_level,
        'r' => .realname,
        else => error.InvalidSelector,
    };
}

fn comptimeParseField(comptime ch: u8) Field {
    return switch (ch) {
        'c' => .channel,
        'u' => .user,
        'h' => .host,
        's' => .server,
        'n' => .nick,
        'f' => .flags,
        'd' => .distance,
        'l' => .idle,
        'a' => .account,
        'o' => .oper_level,
        'r' => .realname,
        else => @compileError("invalid WHOX selector field"),
    };
}

fn validateTarget(target: []const u8) WhoError!void {
    if (target.len == 0 or target.len > MAX_TARGET_BYTES) return error.InvalidTarget;
    for (target) |ch| {
        if (!validParamByte(ch)) return error.InvalidTarget;
    }
}

fn validateParam(param: []const u8) WhoError!void {
    if (param.len == 0) return error.InvalidValue;
    for (param) |ch| {
        if (!validParamByte(ch)) return error.InvalidValue;
    }
}

fn validateTrailing(param: []const u8) WhoError!void {
    for (param) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidValue,
            else => {},
        }
    }
}

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => true,
    };
}

fn channelName(member: MemberContext) []const u8 {
    return member.channel orelse "*";
}

fn operLevel(client: ClientContext, member: MemberContext) []const u8 {
    if (member.oper_level) |level| return level;
    return if (client.oper) "1" else "0";
}

fn flagsText(client: ClientContext, member: MemberContext, out: []u8) WhoError![]const u8 {
    if (out.len < 3) return error.OutputTooSmall;

    var n: usize = 0;
    out[n] = if (client.away) 'G' else 'H';
    n += 1;

    if (client.oper) {
        out[n] = '*';
        n += 1;
    }

    if (member.channel_prefix) |prefix| {
        if (!validParamByte(prefix)) return error.InvalidValue;
        out[n] = prefix;
        n += 1;
    }

    return out[0..n];
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
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

    fn numericPrefix(
        self: *LineBuilder,
        code: numeric.Numeric,
        server_name: []const u8,
        requester: []const u8,
    ) WhoError!void {
        try self.appendByte(':');
        try self.appendParam(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendParam(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) WhoError!void {
        try self.appendByte(' ');
        try self.appendParam(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) WhoError!void {
        try self.appendBytes(" :");
        try self.appendTrailingBytes(param);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u32) WhoError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendParam(self: *LineBuilder, param: []const u8) WhoError!void {
        try validateParam(param);
        try self.appendBytes(param);
    }

    fn appendTrailingBytes(self: *LineBuilder, param: []const u8) WhoError!void {
        try validateTrailing(param);
        try self.appendBytes(param);
    }

    fn appendUnsigned(self: *LineBuilder, value: u32) WhoError!void {
        var buf: [10]u8 = undefined;
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

    fn crlf(self: *LineBuilder) WhoError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) WhoError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) WhoError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

fn sampleContext() ReplyContext {
    return .{
        .server_name = "irc.example.test",
        .requester = "dan",
        .target = "#zig",
        .client = .{
            .nick = "alice",
            .user = "auser",
            .host = "host.example",
            .server = "irc.example.test",
            .realname = "Alice Example",
            .away = false,
            .oper = true,
            .account = "alice-account",
        },
        .member = .{
            .channel = "#zig",
            .channel_prefix = '@',
            .hops = 0,
            .distance = 4,
            .idle_seconds = 90,
            .oper_level = "netadmin",
        },
    };
}

test "classic WHO 352 format" {
    var out: [256]u8 = undefined;
    const line = try writeWhoReply(&out, sampleContext());
    try std.testing.expectEqualStrings(
        ":irc.example.test 352 dan #zig auser host.example irc.example.test alice H*@ :0 Alice Example\r\n",
        line,
    );
}

test "WHOX field selection 354" {
    const request = try parse(&.{ "#zig", "%cuhsnfdlaor" });
    const whox = request.whox.?;

    var out: [256]u8 = undefined;
    const line = try writeWhoxReply(&out, whox.selector, sampleContext());
    try std.testing.expectEqualStrings(
        ":irc.example.test 354 dan #zig auser host.example irc.example.test alice H*@ 4 90 alice-account netadmin :Alice Example\r\n",
        line,
    );
}

test "flags include away oper and channel prefix" {
    var ctx = sampleContext();
    ctx.client.away = true;
    ctx.member.channel_prefix = '+';

    var out: [256]u8 = undefined;
    const line = try writeWhoReply(&out, ctx);
    try std.testing.expectEqualStrings(
        ":irc.example.test 352 dan #zig auser host.example irc.example.test alice G*+ :0 Alice Example\r\n",
        line,
    );
}

test "flags omit hidden oper marker when oper flag is false" {
    var ctx = sampleContext();
    ctx.client.away = false;
    ctx.client.oper = false;
    ctx.member.channel_prefix = '+';

    var out: [256]u8 = undefined;
    const line = try writeWhoReply(&out, ctx);
    try std.testing.expectEqualStrings(
        ":irc.example.test 352 dan #zig auser host.example irc.example.test alice H+ :0 Alice Example\r\n",
        line,
    );
}

test "end-of-who" {
    var out: [128]u8 = undefined;
    const line = try writeEndOfWho(&out, "irc.example.test", "dan", "#zig");
    try std.testing.expectEqualStrings(
        ":irc.example.test 315 dan #zig :End of WHO list\r\n",
        line,
    );
}

test "bad selector rejected" {
    try std.testing.expectError(error.InvalidSelector, parseWhox("%cx"));
}

test "comptime selector matches runtime field order" {
    const selector = FieldSelector.initComptime("%cuhsnfdlaor");
    try std.testing.expectEqual(@as(usize, 11), selector.count);
    try std.testing.expectEqual(Field.channel, selector.fields[0]);
    try std.testing.expectEqual(Field.realname, selector.fields[10]);
}
