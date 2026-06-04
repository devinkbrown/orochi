//! USERIP (340) command argument parser and numeric reply builder.
//!
//! USERIP is a charybdis oper command shaped like USERHOST, but the host
//! component is the user's visible IP address. This module is deliberately
//! pure protocol code: callers provide resolved per-nick identity records and
//! caller-owned output storage.
const std = @import("std");
const ison_userhost = @import("ison_userhost.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = ison_userhost.DEFAULT_MAX_LINE_BYTES;
pub const DEFAULT_MAX_SERVER_BYTES: usize = ison_userhost.DEFAULT_MAX_SERVER_BYTES;
pub const DEFAULT_MAX_NICK_BYTES: usize = ison_userhost.DEFAULT_MAX_NICK_BYTES;
pub const DEFAULT_MAX_USER_BYTES: usize = ison_userhost.DEFAULT_MAX_USER_BYTES;
pub const DEFAULT_MAX_IP_BYTES: usize = ison_userhost.DEFAULT_MAX_HOST_BYTES;
pub const USERIP_MAX_TARGETS: usize = 5;

const USERIP_CODE = "340";

pub const UseripError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidIp,
    IpTooLong,
    TooManyUseripTargets,
    NeedMoreParams,
    TooManyArgs,
    OutputTooSmall,
    TokenTooLong,
};

pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_ip_bytes: usize = DEFAULT_MAX_IP_BYTES,
};

pub const UseripTarget = struct {
    nick: []const u8,
    oper: bool = false,
    away: bool = false,
    user: []const u8,
    ip: []const u8,
};

pub fn parseUseripArgs(out: [][]const u8, raw: []const u8) UseripError![]const []const u8 {
    return parseUseripArgsWith(.{}, out, raw);
}

pub fn parseUseripArgsWith(
    comptime params: Params,
    out: [][]const u8,
    raw: []const u8,
) UseripError![]const []const u8 {
    var it = std.mem.tokenizeScalar(u8, raw, ' ');
    var count: usize = 0;

    if (it.next()) |first| {
        if (std.ascii.eqlIgnoreCase(first, "USERIP")) {
            if (it.next()) |nick| {
                try appendParsedNick(params, out, &count, nick);
            } else {
                return error.NeedMoreParams;
            }
        } else {
            try appendParsedNick(params, out, &count, first);
        }
    } else {
        return error.NeedMoreParams;
    }

    while (it.next()) |nick| {
        try appendParsedNick(params, out, &count, nick);
    }

    return out[0..count];
}

pub fn writeUseripReply(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    targets: []const UseripTarget,
) UseripError![]const u8 {
    return writeUseripReplyWith(.{}, out, server_name, requester_nick, targets);
}

pub fn writeUseripReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    targets: []const UseripTarget,
) UseripError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    if (targets.len > USERIP_MAX_TARGETS) return error.TooManyUseripTargets;

    var line_len = numericHeaderLen(server_name, requester_nick) + 2 + 2;
    for (targets, 0..) |target, index| {
        try validateUseripTargetWith(params, target);
        const separator_len: usize = if (index == 0) 0 else 1;
        line_len += separator_len + useripTokenLen(target);
    }
    if (line_len > params.max_line_bytes) return error.TokenTooLong;

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, server_name, requester_nick);
    try writer.appendBytes(" :");
    for (targets, 0..) |target, index| {
        if (index != 0) try writer.appendByte(' ');
        try writeUseripToken(&writer, target);
    }
    try writer.appendBytes("\r\n");
    return writer.slice();
}

pub fn validateUseripTarget(target: UseripTarget) UseripError!void {
    return validateUseripTargetWith(.{}, target);
}

pub fn validateUseripTargetWith(comptime params: Params, target: UseripTarget) UseripError!void {
    try validateNickWith(params, target.nick);
    try validateUserWith(params, target.user);
    try validateIpWith(params, target.ip);
}

pub fn validateNick(nick: []const u8) UseripError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) UseripError!void {
    ison_userhost.validateNickWith(toIsonParams(params), nick) catch |err| switch (err) {
        error.InvalidNick => return error.InvalidNick,
        error.NickTooLong => return error.NickTooLong,
        else => unreachable,
    };
}

pub fn validateUser(user: []const u8) UseripError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) UseripError!void {
    ison_userhost.validateUserWith(toIsonParams(params), user) catch |err| switch (err) {
        error.InvalidUser => return error.InvalidUser,
        error.UserTooLong => return error.UserTooLong,
        else => unreachable,
    };
}

pub fn validateIp(ip: []const u8) UseripError!void {
    return validateIpWith(.{}, ip);
}

pub fn validateIpWith(comptime params: Params, ip: []const u8) UseripError!void {
    ison_userhost.validateHostWith(toIsonParams(params), ip) catch |err| switch (err) {
        error.InvalidHost => return error.InvalidIp,
        error.HostTooLong => return error.IpTooLong,
        else => unreachable,
    };
}

pub fn validateServerName(server_name: []const u8) UseripError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) UseripError!void {
    ison_userhost.validateServerNameWith(toIsonParams(params), server_name) catch |err| switch (err) {
        error.InvalidServerName => return error.InvalidServerName,
        error.ServerNameTooLong => return error.ServerNameTooLong,
        else => unreachable,
    };
}

fn appendParsedNick(
    comptime params: Params,
    out: [][]const u8,
    count: *usize,
    nick: []const u8,
) UseripError!void {
    try validateNickWith(params, nick);
    if (count.* >= USERIP_MAX_TARGETS) return error.TooManyUseripTargets;
    if (count.* >= out.len) return error.OutputTooSmall;
    out[count.*] = nick;
    count.* += 1;
}

fn toIsonParams(comptime params: Params) ison_userhost.Params {
    return .{
        .max_line_bytes = params.max_line_bytes,
        .max_server_bytes = params.max_server_bytes,
        .max_nick_bytes = params.max_nick_bytes,
        .max_user_bytes = params.max_user_bytes,
        .max_host_bytes = params.max_ip_bytes,
    };
}

fn numericHeaderLen(server_name: []const u8, requester_nick: []const u8) usize {
    return 1 + server_name.len + 1 + USERIP_CODE.len + 1 + requester_nick.len;
}

fn writeNumericHeader(
    writer: *BufferWriter,
    server_name: []const u8,
    requester_nick: []const u8,
) UseripError!void {
    try writer.appendByte(':');
    try writer.appendBytes(server_name);
    try writer.appendByte(' ');
    try writer.appendBytes(USERIP_CODE);
    try writer.appendByte(' ');
    try writer.appendBytes(requester_nick);
}

fn useripTokenLen(target: UseripTarget) usize {
    const oper_len: usize = if (target.oper) 1 else 0;
    return target.nick.len + oper_len + 2 + target.user.len + 1 + target.ip.len;
}

fn writeUseripToken(writer: *BufferWriter, target: UseripTarget) UseripError!void {
    try writer.appendBytes(target.nick);
    if (target.oper) try writer.appendByte('*');
    try writer.appendByte('=');
    try writer.appendByte(if (target.away) '-' else '+');
    try writer.appendBytes(target.user);
    try writer.appendByte('@');
    try writer.appendBytes(target.ip);
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

    fn appendBytes(self: *BufferWriter, bytes: []const u8) UseripError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *BufferWriter, byte: u8) UseripError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "USERIP builds reply bytes" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 128);
    defer allocator.free(out);

    const line = try writeUseripReply(out, "irc.example.test", "dan", &.{
        .{ .nick = "alice", .user = "aliceu", .ip = "203.0.113.7" },
    });

    try std.testing.expectEqualStrings(
        ":irc.example.test 340 dan :alice=+aliceu@203.0.113.7\r\n",
        line,
    );
}

test "USERIP renders oper and away flags" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 160);
    defer allocator.free(out);

    const line = try writeUseripReply(out, "irc.example.test", "dan", &.{
        .{ .nick = "alice", .oper = true, .away = false, .user = "aliceu", .ip = "203.0.113.7" },
        .{ .nick = "bob", .oper = false, .away = true, .user = "bobu", .ip = "2001:db8::1" },
    });

    try std.testing.expectEqualStrings(
        ":irc.example.test 340 dan :alice*=+aliceu@203.0.113.7 bob=-bobu@2001:db8::1\r\n",
        line,
    );
}

test "USERIP builds multi-nick reply" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 192);
    defer allocator.free(out);

    const line = try writeUseripReply(out, "irc.example.test", "dan", &.{
        .{ .nick = "alice", .user = "aliceu", .ip = "203.0.113.7" },
        .{ .nick = "carol", .user = "carolu", .ip = "198.51.100.9" },
        .{ .nick = "erin", .user = "erinu", .ip = "192.0.2.44" },
    });

    try std.testing.expectEqualStrings(
        ":irc.example.test 340 dan :alice=+aliceu@203.0.113.7 carol=+carolu@198.51.100.9 erin=+erinu@192.0.2.44\r\n",
        line,
    );
}

test "USERIP parses command target list" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc([]const u8, USERIP_MAX_TARGETS);
    defer allocator.free(scratch);

    const nicks = try parseUseripArgs(scratch, "USERIP alice bob carol dave erin");

    try std.testing.expectEqual(@as(usize, 5), nicks.len);
    try std.testing.expectEqualStrings("alice", nicks[0]);
    try std.testing.expectEqualStrings("erin", nicks[4]);
}

test "USERIP parser accepts bare arg list and enforces five targets" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc([]const u8, USERIP_MAX_TARGETS);
    defer allocator.free(scratch);

    const nicks = try parseUseripArgs(scratch, "alice bob");
    try std.testing.expectEqual(@as(usize, 2), nicks.len);
    try std.testing.expectEqualStrings("bob", nicks[1]);

    try std.testing.expectError(
        error.TooManyUseripTargets,
        parseUseripArgs(scratch, "USERIP a b c d e f"),
    );
}

test "USERIP rejects invalid identities and tiny output" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 8);
    defer allocator.free(out);

    try std.testing.expectError(
        error.OutputTooSmall,
        writeUseripReply(out, "irc.example.test", "dan", &.{
            .{ .nick = "alice", .user = "aliceu", .ip = "203.0.113.7" },
        }),
    );

    var larger: [128]u8 = undefined;
    try std.testing.expectError(
        error.InvalidIp,
        writeUseripReply(&larger, "irc.example.test", "dan", &.{
            .{ .nick = "alice", .user = "aliceu", .ip = "bad ip" },
        }),
    );
}
