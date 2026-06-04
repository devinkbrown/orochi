//! WHOX (extended WHO) selector parsing and RPL_WHOSPCRPL emission.
//!
//! Plain WHO matching and RPL_WHOREPLY (352) live in `who.zig`. This module is
//! only the WHOX `WHO <target> %<fields>[,token]` selector and 354 formatter.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const MAX_TOKEN_BYTES: usize = 32;

const whospcrpl_code = numeric.Numeric.RPL_WHOSPCRPL;

pub const WhoxError = error{
    InvalidSelector,
    InvalidToken,
    InvalidValue,
    DuplicateField,
    OutputTooSmall,
} || std.mem.Allocator.Error;

/// WHOX fields in wire-canonical order.
pub const Field = enum(u8) {
    token = 't',
    channel = 'c',
    user = 'u',
    ip = 'i',
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

pub const canonical_fields = [_]Field{
    .token,
    .channel,
    .user,
    .ip,
    .host,
    .server,
    .nick,
    .flags,
    .distance,
    .idle,
    .account,
    .oper_level,
    .realname,
};

/// Bitset-style selector parsed from the WHOX field list.
pub const FieldSet = struct {
    token: bool = false,
    channel: bool = false,
    user: bool = false,
    ip: bool = false,
    host: bool = false,
    server: bool = false,
    nick: bool = false,
    flags: bool = false,
    distance: bool = false,
    idle: bool = false,
    account: bool = false,
    oper_level: bool = false,
    realname: bool = false,

    pub fn contains(self: FieldSet, field: Field) bool {
        return switch (field) {
            .token => self.token,
            .channel => self.channel,
            .user => self.user,
            .ip => self.ip,
            .host => self.host,
            .server => self.server,
            .nick => self.nick,
            .flags => self.flags,
            .distance => self.distance,
            .idle => self.idle,
            .account => self.account,
            .oper_level => self.oper_level,
            .realname => self.realname,
        };
    }

    fn set(self: *FieldSet, field: Field) WhoxError!void {
        switch (field) {
            .token => {
                if (self.token) return error.DuplicateField;
                self.token = true;
            },
            .channel => {
                if (self.channel) return error.DuplicateField;
                self.channel = true;
            },
            .user => {
                if (self.user) return error.DuplicateField;
                self.user = true;
            },
            .ip => {
                if (self.ip) return error.DuplicateField;
                self.ip = true;
            },
            .host => {
                if (self.host) return error.DuplicateField;
                self.host = true;
            },
            .server => {
                if (self.server) return error.DuplicateField;
                self.server = true;
            },
            .nick => {
                if (self.nick) return error.DuplicateField;
                self.nick = true;
            },
            .flags => {
                if (self.flags) return error.DuplicateField;
                self.flags = true;
            },
            .distance => {
                if (self.distance) return error.DuplicateField;
                self.distance = true;
            },
            .idle => {
                if (self.idle) return error.DuplicateField;
                self.idle = true;
            },
            .account => {
                if (self.account) return error.DuplicateField;
                self.account = true;
            },
            .oper_level => {
                if (self.oper_level) return error.DuplicateField;
                self.oper_level = true;
            },
            .realname => {
                if (self.realname) return error.DuplicateField;
                self.realname = true;
            },
        }
    }
};

pub const Request = struct {
    fields: FieldSet,
    token: ?[]const u8 = null,
};

/// Caller-provided values for one WHOX result row.
pub const MemberValues = struct {
    channel: []const u8 = "*",
    user: []const u8,
    ip: []const u8 = "0",
    host: []const u8,
    server: []const u8,
    nick: []const u8,
    flags: []const u8,
    distance: u32 = 0,
    idle_seconds: u32 = 0,
    account: []const u8 = "0",
    oper_level: []const u8 = "0",
    realname: []const u8,
};

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
    request: Request,
    member: MemberValues,
};

/// Parse a standalone WHOX selector such as `%tcuihsnfdlar,42`.
pub fn parse(selector: []const u8) WhoxError!Request {
    if (selector.len < 2 or selector[0] != '%') return error.InvalidSelector;

    const comma = std.mem.indexOfScalar(u8, selector, ',') orelse selector.len;
    if (comma == 1) return error.InvalidSelector;
    if (comma != selector.len and std.mem.indexOfScalar(u8, selector[comma + 1 ..], ',') != null) {
        return error.InvalidSelector;
    }

    var fields = FieldSet{};
    for (selector[1..comma]) |byte| {
        try fields.set(try parseField(byte));
    }

    const token = if (comma == selector.len) null else blk: {
        const raw = selector[comma + 1 ..];
        try validateToken(raw);
        break :blk raw;
    };

    return .{ .fields = fields, .token = token };
}

/// Append one complete RPL_WHOSPCRPL (354) line to `out`.
pub fn writeReply(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    ctx: ReplyContext,
) WhoxError!void {
    var b = LineBuilder.init(allocator, out);
    try b.numericPrefix(whospcrpl_code, ctx.server_name, ctx.requester);

    var emitted = false;
    inline for (canonical_fields) |field| {
        if (ctx.request.fields.contains(field)) {
            emitted = true;
            try appendField(&b, field, ctx.request.token, ctx.member);
        }
    }

    if (!emitted) return error.InvalidSelector;
    try b.crlf();
}

/// Allocate and return one complete RPL_WHOSPCRPL (354) line.
pub fn buildReply(allocator: std.mem.Allocator, ctx: ReplyContext) WhoxError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try writeReply(allocator, &out, ctx);
    return try out.toOwnedSlice(allocator);
}

fn appendField(
    b: *LineBuilder,
    field: Field,
    token: ?[]const u8,
    member: MemberValues,
) WhoxError!void {
    switch (field) {
        .token => try b.spaceParam(token orelse "0"),
        .channel => try b.spaceParam(member.channel),
        .user => try b.spaceParam(member.user),
        .ip => try b.spaceParam(member.ip),
        .host => try b.spaceParam(member.host),
        .server => try b.spaceParam(member.server),
        .nick => try b.spaceParam(member.nick),
        .flags => try b.spaceParam(member.flags),
        .distance => try b.spaceUnsigned(member.distance),
        .idle => try b.spaceUnsigned(member.idle_seconds),
        .account => try b.spaceParam(member.account),
        .oper_level => try b.spaceParam(member.oper_level),
        .realname => try b.spaceTrailing(member.realname),
    }
}

fn parseField(byte: u8) WhoxError!Field {
    return switch (byte) {
        't' => .token,
        'c' => .channel,
        'u' => .user,
        'i' => .ip,
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

fn validateToken(token: []const u8) WhoxError!void {
    if (token.len == 0 or token.len > MAX_TOKEN_BYTES) return error.InvalidToken;
    for (token) |byte| {
        if (!validParamByte(byte)) return error.InvalidToken;
    }
}

fn validateParam(param: []const u8) WhoxError!void {
    if (param.len == 0) return error.InvalidValue;
    for (param) |byte| {
        if (!validParamByte(byte)) return error.InvalidValue;
    }
}

fn validateTrailing(param: []const u8) WhoxError!void {
    for (param) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidValue,
            else => {},
        }
    }
}

fn validParamByte(byte: u8) bool {
    return switch (byte) {
        0, ' ', '\t', '\r', '\n' => false,
        else => true,
    };
}

const LineBuilder = struct {
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) LineBuilder {
        return .{ .allocator = allocator, .out = out };
    }

    fn numericPrefix(
        self: *LineBuilder,
        code: numeric.Numeric,
        server_name: []const u8,
        requester: []const u8,
    ) WhoxError!void {
        try self.appendByte(':');
        try self.appendParam(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendParam(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) WhoxError!void {
        try self.appendByte(' ');
        try self.appendParam(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) WhoxError!void {
        try self.appendBytes(" :");
        try self.appendTrailingBytes(param);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u32) WhoxError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendParam(self: *LineBuilder, param: []const u8) WhoxError!void {
        try validateParam(param);
        try self.appendBytes(param);
    }

    fn appendTrailingBytes(self: *LineBuilder, param: []const u8) WhoxError!void {
        try validateTrailing(param);
        try self.appendBytes(param);
    }

    fn appendUnsigned(self: *LineBuilder, value: u32) WhoxError!void {
        var buf: [10]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return error.OutputTooSmall;
        try self.appendBytes(text);
    }

    fn crlf(self: *LineBuilder) WhoxError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) WhoxError!void {
        try self.out.appendSlice(self.allocator, bytes);
    }

    fn appendByte(self: *LineBuilder, byte: u8) WhoxError!void {
        try self.out.append(self.allocator, byte);
    }
};

fn sampleMember() MemberValues {
    return .{
        .channel = "#zig",
        .user = "alice",
        .ip = "192.0.2.7",
        .host = "host.example",
        .server = "irc.example.test",
        .nick = "Alice",
        .flags = "H*@",
        .distance = 3,
        .idle_seconds = 45,
        .account = "alice-account",
        .oper_level = "netadmin",
        .realname = "Alice Example",
    };
}

test "parse selector with token" {
    const request = try parse("%tcuihsnfdlaor,77");

    try std.testing.expect(request.fields.token);
    try std.testing.expect(request.fields.channel);
    try std.testing.expect(request.fields.ip);
    try std.testing.expect(request.fields.realname);
    try std.testing.expectEqualStrings("77", request.token.?);
}

test "parse selector without token" {
    const request = try parse("%cnfr");

    try std.testing.expect(!request.fields.token);
    try std.testing.expect(request.fields.channel);
    try std.testing.expect(request.fields.nick);
    try std.testing.expect(request.fields.flags);
    try std.testing.expect(request.fields.realname);
    try std.testing.expect(request.token == null);
}

test "build full canonical 354 line" {
    const allocator = std.testing.allocator;
    const request = try parse("%rfoalducsihnt,42");
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(allocator);

    try writeReply(allocator, &line, .{
        .server_name = "irc.example.test",
        .requester = "dan",
        .request = request,
        .member = sampleMember(),
    });

    try std.testing.expectEqualStrings(
        ":irc.example.test 354 dan 42 #zig alice 192.0.2.7 host.example irc.example.test Alice H*@ 3 45 alice-account netadmin :Alice Example\r\n",
        line.items,
    );
}

test "build subset 354 line" {
    const allocator = std.testing.allocator;
    const request = try parse("%tnf,99");
    const line = try buildReply(allocator, .{
        .server_name = "irc.example.test",
        .requester = "dan",
        .request = request,
        .member = sampleMember(),
    });
    defer allocator.free(line);

    try std.testing.expectEqualStrings(
        ":irc.example.test 354 dan 99 Alice H*@\r\n",
        line,
    );
}

test "reject malformed selectors" {
    try std.testing.expectError(error.InvalidSelector, parse(""));
    try std.testing.expectError(error.InvalidSelector, parse("cuh"));
    try std.testing.expectError(error.InvalidSelector, parse("%"));
    try std.testing.expectError(error.InvalidSelector, parse("%c,x,y"));
    try std.testing.expectError(error.InvalidSelector, parse("%cx"));
    try std.testing.expectError(error.DuplicateField, parse("%cc"));
    try std.testing.expectError(error.InvalidToken, parse("%c,"));
    try std.testing.expectError(error.InvalidToken, parse("%c,bad token"));
}
