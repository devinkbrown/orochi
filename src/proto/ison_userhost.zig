//! ISON (303) and USERHOST (302) numeric reply builders.
//!
//! Both builders are allocator-free and write complete IRC numeric lines into
//! caller-owned buffers. Attacker-controlled identity bytes are validated before
//! they are appended, and ISON replies are folded so no emitted line exceeds the
//! configured IRC line limit.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const USERHOST_MAX_TARGETS: usize = 5;

const ison_code = numeric.Numeric.RPL_ISON;
const userhost_code = numeric.Numeric.RPL_USERHOST;

pub const IsonUserhostError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    TooManyUserhostTargets,
    TooManyReplies,
    OutputTooSmall,
    TokenTooLong,
};

/// Compile-time limits for ISON and USERHOST reply builders.
pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` is a wire budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_server_bytes = limits.server_name_len,
            .max_nick_bytes = limits.nick_len,
            .max_user_bytes = limits.user_len,
            .max_host_bytes = limits.host_len,
        };
    }
};

/// One complete IRC numeric line stored in caller-owned output bytes.
pub const ReplyLine = struct {
    bytes: []const u8,
};

/// Caller-provided storage for folded ISON reply lines.
pub const ReplyLineSink = struct {
    lines: []ReplyLine,
    count: usize = 0,

    pub fn append(self: *ReplyLineSink, bytes: []const u8) IsonUserhostError!void {
        if (self.count >= self.lines.len) return error.TooManyReplies;
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

/// One visible USERHOST target.
pub const UserhostTarget = struct {
    nick: []const u8,
    is_oper: bool = false,
    is_away: bool = false,
    user: []const u8,
    host: []const u8,
};

/// Build folded `RPL_ISON` lines for online nicks selected by `is_online`.
///
/// `is_online` is any callable value with signature `fn ([]const u8) bool`.
/// Offline nicks are still validated before filtering because command targets
/// are attacker input. At least one reply is emitted; if no nick is online, the
/// trailing parameter is empty.
pub fn writeIsonReplies(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    nicks: []const []const u8,
    is_online: anytype,
    sink: *ReplyLineSink,
) IsonUserhostError!void {
    return writeIsonRepliesWith(.{}, out, server_name, requester_nick, nicks, is_online, sink);
}

/// Build folded `RPL_ISON` lines using caller-selected compile-time limits.
pub fn writeIsonRepliesWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    nicks: []const []const u8,
    is_online: anytype,
    sink: *ReplyLineSink,
) IsonUserhostError!void {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);

    const header_len = numericHeaderLen(server_name, requester_nick) + 2;
    const empty_line_len = header_len + 2;
    if (empty_line_len > params.max_line_bytes) return error.OutputTooSmall;

    var writer = BufferWriter.init(out);
    var line_start: usize = 0;
    var line_len: usize = 0;
    var nicks_in_line: usize = 0;
    var line_open = false;
    var any_online = false;

    for (nicks) |nick| {
        try validateNickWith(params, nick);
        if (!is_online(nick)) continue;
        any_online = true;

        const token_len = nick.len;
        if (header_len + token_len + 2 > params.max_line_bytes) return error.TokenTooLong;

        if (!line_open) {
            line_start = writer.len;
            try writeNumericHeader(&writer, ison_code, server_name, requester_nick);
            try writer.appendBytes(" :");
            line_len = header_len;
            nicks_in_line = 0;
            line_open = true;
        }

        const separator_len: usize = if (nicks_in_line == 0) 0 else 1;
        if (line_len + separator_len + token_len + 2 > params.max_line_bytes) {
            try writer.appendBytes("\r\n");
            try sink.append(out[line_start..writer.len]);

            line_start = writer.len;
            try writeNumericHeader(&writer, ison_code, server_name, requester_nick);
            try writer.appendBytes(" :");
            line_len = header_len;
            nicks_in_line = 0;
        }

        if (nicks_in_line != 0) {
            try writer.appendByte(' ');
            line_len += 1;
        }
        try writer.appendBytes(nick);
        line_len += token_len;
        nicks_in_line += 1;
    }

    if (!any_online) {
        line_start = writer.len;
        try writeNumericHeader(&writer, ison_code, server_name, requester_nick);
        try writer.appendBytes(" :\r\n");
        try sink.append(out[line_start..writer.len]);
        return;
    }

    if (line_open) {
        try writer.appendBytes("\r\n");
        try sink.append(out[line_start..writer.len]);
    }
}

/// Build one `RPL_USERHOST` reply line for up to five targets.
pub fn writeUserhostReply(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    targets: []const UserhostTarget,
) IsonUserhostError![]const u8 {
    return writeUserhostReplyWith(.{}, out, server_name, requester_nick, targets);
}

/// Build one `RPL_USERHOST` reply line using caller-selected compile-time limits.
pub fn writeUserhostReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    targets: []const UserhostTarget,
) IsonUserhostError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    if (targets.len > USERHOST_MAX_TARGETS) return error.TooManyUserhostTargets;

    var line_len = numericHeaderLen(server_name, requester_nick) + 2 + 2;
    for (targets, 0..) |target, index| {
        try validateUserhostTargetWith(params, target);
        const separator_len: usize = if (index == 0) 0 else 1;
        line_len += separator_len + userhostTokenLen(target);
    }
    if (line_len > params.max_line_bytes) return error.TokenTooLong;

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, userhost_code, server_name, requester_nick);
    try writer.appendBytes(" :");
    for (targets, 0..) |target, index| {
        if (index != 0) try writer.appendByte(' ');
        try writeUserhostToken(&writer, target);
    }
    try writer.appendBytes("\r\n");
    return writer.slice();
}

pub fn validateUserhostTarget(target: UserhostTarget) IsonUserhostError!void {
    return validateUserhostTargetWith(.{}, target);
}

pub fn validateUserhostTargetWith(comptime params: Params, target: UserhostTarget) IsonUserhostError!void {
    try validateNickWith(params, target.nick);
    try validateUserWith(params, target.user);
    try validateHostWith(params, target.host);
}

pub fn validateNick(nick: []const u8) IsonUserhostError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) IsonUserhostError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) IsonUserhostError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) IsonUserhostError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) IsonUserhostError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) IsonUserhostError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateServerName(server_name: []const u8) IsonUserhostError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) IsonUserhostError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

fn numericHeaderLen(server_name: []const u8, requester_nick: []const u8) usize {
    return 1 + server_name.len + 1 + 3 + 1 + requester_nick.len;
}

fn writeNumericHeader(
    writer: *BufferWriter,
    reply_numeric: numeric.Numeric,
    server_name: []const u8,
    requester_nick: []const u8,
) IsonUserhostError!void {
    var code_buf: [3]u8 = undefined;
    const code = numeric.formatCode(reply_numeric, &code_buf);

    try writer.appendByte(':');
    try writer.appendBytes(server_name);
    try writer.appendByte(' ');
    try writer.appendBytes(code);
    try writer.appendByte(' ');
    try writer.appendBytes(requester_nick);
}

fn userhostTokenLen(target: UserhostTarget) usize {
    const oper_len: usize = if (target.is_oper) 1 else 0;
    return target.nick.len + oper_len + 2 + target.user.len + 1 + target.host.len;
}

fn writeUserhostToken(writer: *BufferWriter, target: UserhostTarget) IsonUserhostError!void {
    try writer.appendBytes(target.nick);
    if (target.is_oper) try writer.appendByte('*');
    try writer.appendByte('=');
    try writer.appendByte(if (target.is_away) '-' else '+');
    try writer.appendBytes(target.user);
    try writer.appendByte('@');
    try writer.appendBytes(target.host);
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validUserByte(ch: u8) bool {
    if (ch <= 0x1f or ch == 0x7f) return false;
    return switch (ch) {
        '!', '@', ':', ' ' => false,
        else => true,
    };
}

fn validHostByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
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

    fn appendBytes(self: *BufferWriter, bytes: []const u8) IsonUserhostError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *BufferWriter, byte: u8) IsonUserhostError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

fn onlineForSubset(nick: []const u8) bool {
    return std.mem.eql(u8, nick, "alice") or std.mem.eql(u8, nick, "carol");
}

fn allOnline(_: []const u8) bool {
    return true;
}

fn noneOnline(_: []const u8) bool {
    return false;
}

test "ISON emits online subset" {
    const nicks = [_][]const u8{ "alice", "bob", "carol" };
    var out: [128]u8 = undefined;
    var line_storage: [2]ReplyLine = undefined;
    var sink = ReplyLineSink{ .lines = &line_storage };

    try writeIsonReplies(&out, "irc.example.test", "dan", &nicks, onlineForSubset, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), lines.len);
    try std.testing.expectEqualStrings(":irc.example.test 303 dan :alice carol\r\n", lines[0].bytes);
}

test "ISON folds before the configured line limit" {
    const nicks = [_][]const u8{ "alice", "bob", "carol", "dave" };
    var out: [160]u8 = undefined;
    var line_storage: [4]ReplyLine = undefined;
    var sink = ReplyLineSink{ .lines = &line_storage };

    try writeIsonRepliesWith(.{ .max_line_bytes = 30 }, &out, "irc.test", "dan", &nicks, allOnline, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings(":irc.test 303 dan :alice bob\r\n", lines[0].bytes);
    try std.testing.expectEqualStrings(":irc.test 303 dan :carol\r\n", lines[1].bytes);
    try std.testing.expectEqualStrings(":irc.test 303 dan :dave\r\n", lines[2].bytes);
}

test "USERHOST renders oper and away flags" {
    const targets = [_]UserhostTarget{
        .{ .nick = "alice", .is_oper = true, .is_away = false, .user = "aliceu", .host = "a.example" },
        .{ .nick = "bob", .is_oper = false, .is_away = true, .user = "bobu", .host = "b.example" },
    };
    var out: [160]u8 = undefined;

    const line = try writeUserhostReply(&out, "irc.example.test", "dan", &targets);
    try std.testing.expectEqualStrings(
        ":irc.example.test 302 dan :alice*=+aliceu@a.example bob=-bobu@b.example\r\n",
        line,
    );
}

test "buffer too small is reported" {
    const nicks = [_][]const u8{"alice"};
    var tiny: [8]u8 = undefined;
    var line_storage: [1]ReplyLine = undefined;
    var sink = ReplyLineSink{ .lines = &line_storage };

    try std.testing.expectError(
        error.OutputTooSmall,
        writeIsonReplies(&tiny, "irc.example.test", "dan", &nicks, allOnline, &sink),
    );

    const targets = [_]UserhostTarget{
        .{ .nick = "alice", .user = "aliceu", .host = "a.example" },
    };
    try std.testing.expectError(
        error.OutputTooSmall,
        writeUserhostReply(&tiny, "irc.example.test", "dan", &targets),
    );
}

test "empty ISON and USERHOST replies are valid" {
    const nicks = [_][]const u8{ "alice", "bob" };
    var out: [128]u8 = undefined;
    var line_storage: [1]ReplyLine = undefined;
    var sink = ReplyLineSink{ .lines = &line_storage };

    try writeIsonReplies(&out, "irc.example.test", "dan", &nicks, noneOnline, &sink);
    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), lines.len);
    try std.testing.expectEqualStrings(":irc.example.test 303 dan :\r\n", lines[0].bytes);

    const line = try writeUserhostReply(&out, "irc.example.test", "dan", &.{});
    try std.testing.expectEqualStrings(":irc.example.test 302 dan :\r\n", line);
}

test "validation rejects control and delimiter bytes" {
    var out: [128]u8 = undefined;
    var line_storage: [1]ReplyLine = undefined;
    var sink = ReplyLineSink{ .lines = &line_storage };

    try std.testing.expectError(
        error.InvalidNick,
        writeIsonReplies(&out, "irc.example.test", "dan", &.{ "ok", "bad nick" }, allOnline, &sink),
    );

    try std.testing.expectError(
        error.InvalidUser,
        writeUserhostReply(&out, "irc.example.test", "dan", &.{
            .{ .nick = "alice", .user = "bad@user", .host = "a.example" },
        }),
    );
}

test "USERHOST enforces five target limit" {
    const targets = [_]UserhostTarget{
        .{ .nick = "a", .user = "u", .host = "h" },
        .{ .nick = "b", .user = "u", .host = "h" },
        .{ .nick = "c", .user = "u", .host = "h" },
        .{ .nick = "d", .user = "u", .host = "h" },
        .{ .nick = "e", .user = "u", .host = "h" },
        .{ .nick = "f", .user = "u", .host = "h" },
    };
    var out: [128]u8 = undefined;

    try std.testing.expectError(
        error.TooManyUserhostTargets,
        writeUserhostReply(&out, "irc.example.test", "dan", &targets),
    );
}
