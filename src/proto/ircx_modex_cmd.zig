// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX MODEX command parser and extended channel-mode reply builder.
const std = @import("std");
const irc_line = @import("irc_line.zig");
const named_modex = @import("ircx_modex.zig");

pub const RPL_MODEXLIST: u16 = named_modex.RPL_MODEXLIST;
pub const RPL_MODEXEND: u16 = named_modex.RPL_MODEXEND;

pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_PARAM_BYTES: usize = 256;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_CHANGES: usize = 32;

pub const Params = struct {
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_param_bytes: usize = DEFAULT_MAX_PARAM_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_changes: usize = DEFAULT_MAX_CHANGES,
};

pub const ModexCmdError = irc_line.ParseError || error{
    UnknownCommand,
    NeedMoreParams,
    InvalidChannelName,
    InvalidModeString,
    MissingOperation,
    UnknownMode,
    MissingParameter,
    UnexpectedParameter,
    TooManyChanges,
    InvalidParameter,
    InvalidLimit,
    InvalidModeState,
    InvalidServerName,
    InvalidNick,
    OutputTooSmall,
    LineTooLong,
};

pub const ModeOp = enum {
    add,
    remove,
};

pub const ChannelMode = enum {
    ban,
    exempt,
    invex,
    key,
    limit,
    private,
    hidden,
    secret,
    moderated,
    topicop,
    inviteonly,
    noextern,
    knock,
    authonly,
    noformat,
    cloneable,
    clone,
    registered,
    service,
    auditorium,
    nowhisper,
    nocomics,
};

pub const ParamKind = enum { none, always, add_only };

pub const ModeSpec = struct {
    mode: ChannelMode,
    letter: u8,
    name: []const u8,
    param_kind: ParamKind = .none,
    oper_only: bool = false,
    visibility: bool = false,
};

pub const mode_specs = [_]ModeSpec{
    .{ .mode = .ban, .letter = 'b', .name = "BAN", .param_kind = .always },
    .{ .mode = .exempt, .letter = 'e', .name = "EXEMPT", .param_kind = .always },
    .{ .mode = .invex, .letter = 'I', .name = "INVEX", .param_kind = .always },
    .{ .mode = .key, .letter = 'k', .name = "KEY", .param_kind = .always },
    .{ .mode = .limit, .letter = 'l', .name = "LIMIT", .param_kind = .add_only },
    .{ .mode = .private, .letter = 'p', .name = "PRIVATE", .visibility = true },
    .{ .mode = .hidden, .letter = 'h', .name = "HIDDEN", .visibility = true },
    .{ .mode = .secret, .letter = 's', .name = "SECRET", .visibility = true },
    .{ .mode = .moderated, .letter = 'm', .name = "MODERATED" },
    .{ .mode = .topicop, .letter = 't', .name = "TOPICOP" },
    .{ .mode = .inviteonly, .letter = 'i', .name = "INVITEONLY" },
    .{ .mode = .noextern, .letter = 'n', .name = "NOEXTERN" },
    .{ .mode = .knock, .letter = 'u', .name = "KNOCK" },
    .{ .mode = .authonly, .letter = 'a', .name = "AUTHONLY" },
    .{ .mode = .noformat, .letter = 'f', .name = "NOFORMAT" },
    .{ .mode = .cloneable, .letter = 'd', .name = "CLONEABLE" },
    .{ .mode = .clone, .letter = 'E', .name = "CLONE", .oper_only = true },
    .{ .mode = .registered, .letter = 'r', .name = "REGISTERED", .oper_only = true },
    .{ .mode = .service, .letter = 'z', .name = "SERVICE", .oper_only = true },
    .{ .mode = .auditorium, .letter = 'x', .name = "AUDITORIUM" },
    .{ .mode = .nowhisper, .letter = 'w', .name = "NOWHISPER" },
    .{ .mode = .nocomics, .letter = 'V', .name = "NOCOMICDATA" },
};

comptime {
    for (mode_specs, 0..) |left, left_index| {
        for (mode_specs[left_index + 1 ..]) |right| {
            if (left.letter == right.letter) @compileError("duplicate MODEX mode letter");
            if (std.mem.eql(u8, left.name, right.name)) @compileError("duplicate MODEX mode name");
        }
    }
}

pub const ModeChange = struct {
    op: ModeOp,
    mode: ChannelMode,
    letter: u8,
    name: []const u8,
    param: ?[]const u8 = null,
};

pub const Request = struct {
    channel: []const u8,
    changes: []const ModeChange,

    pub fn isQuery(self: Request) bool {
        return self.changes.len == 0;
    }
};

pub const ChannelState = struct {
    key: ?[]const u8 = null,
    limit: ?[]const u8 = null,
    private: bool = false,
    hidden: bool = false,
    secret: bool = false,
    moderated: bool = false,
    topicop: bool = false,
    inviteonly: bool = false,
    noextern: bool = false,
    knock: bool = false,
    authonly: bool = false,
    noformat: bool = false,
    cloneable: bool = false,
    clone: bool = false,
    registered: bool = false,
    service: bool = false,
    auditorium: bool = false,
    nowhisper: bool = false,
    nocomics: bool = false,
    ownerkey: bool = false,
    hostkey: bool = false,

    pub fn contains(self: ChannelState, mode: ChannelMode) bool {
        return switch (mode) {
            .ban, .exempt, .invex => false,
            .key => self.key != null,
            .limit => self.limit != null,
            .private => self.private,
            .hidden => self.hidden,
            .secret => self.secret,
            .moderated => self.moderated,
            .topicop => self.topicop,
            .inviteonly => self.inviteonly,
            .noextern => self.noextern,
            .knock => self.knock,
            .authonly => self.authonly,
            .noformat => self.noformat,
            .cloneable => self.cloneable,
            .clone => self.clone,
            .registered => self.registered,
            .service => self.service,
            .auditorium => self.auditorium,
            .nowhisper => self.nowhisper,
            .nocomics => self.nocomics,
        };
    }
};

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

pub fn parse(line: []const u8, out: []ModeChange) ModexCmdError!Request {
    return parseWith(.{}, line, out);
}

pub fn parseWith(comptime params: Params, line: []const u8, out: []ModeChange) ModexCmdError!Request {
    const parsed = try irc_line.parseLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, "MODEX")) return error.UnknownCommand;
    return parseParamsWith(params, parsed.paramSlice(), out);
}

pub fn parseParams(params_slice: []const []const u8, out: []ModeChange) ModexCmdError!Request {
    return parseParamsWith(.{}, params_slice, out);
}

pub fn parseParamsWith(comptime params: Params, params_slice: []const []const u8, out: []ModeChange) ModexCmdError!Request {
    if (params_slice.len == 0) return error.NeedMoreParams;
    try validateChannelWith(params, params_slice[0]);

    if (params_slice.len == 1) {
        return .{ .channel = params_slice[0], .changes = out[0..0] };
    }

    const changes = try parseModeStringWith(params, params_slice[1], params_slice[2..], out);
    return .{ .channel = params_slice[0], .changes = changes };
}

pub fn parseModeString(mode_string: []const u8, mode_params: []const []const u8, out: []ModeChange) ModexCmdError![]const ModeChange {
    return parseModeStringWith(.{}, mode_string, mode_params, out);
}

pub fn parseModeStringWith(
    comptime params: Params,
    mode_string: []const u8,
    mode_params: []const []const u8,
    out: []ModeChange,
) ModexCmdError![]const ModeChange {
    if (mode_string.len == 0) return error.InvalidModeString;

    var op: ?ModeOp = null;
    var param_index: usize = 0;
    var count: usize = 0;
    var saw_mode = false;

    for (mode_string) |byte| {
        switch (byte) {
            '+' => op = .add,
            '-' => op = .remove,
            else => {
                const active_op = op orelse return error.MissingOperation;
                const spec = specFromLetter(byte) orelse return error.UnknownMode;
                if (count >= out.len or count >= params.max_changes) return error.TooManyChanges;
                const param = try consumeParamWith(params, spec, active_op, mode_params, &param_index);
                out[count] = .{
                    .op = active_op,
                    .mode = spec.mode,
                    .letter = spec.letter,
                    .name = spec.name,
                    .param = param,
                };
                count += 1;
                saw_mode = true;
            },
        }
    }

    if (!saw_mode) return error.InvalidModeString;
    if (param_index != mode_params.len) return error.UnexpectedParameter;
    return out[0..count];
}

pub fn specFromLetter(letter: u8) ?ModeSpec {
    for (mode_specs) |spec| {
        if (spec.letter == letter) return spec;
    }
    return null;
}

pub fn buildReply(out: []u8, ctx: ReplyContext, channel: []const u8, state: ChannelState) ModexCmdError![]const u8 {
    return buildReplyWith(.{}, out, ctx, channel, state);
}

pub fn buildReplyWith(comptime params: Params, out: []u8, ctx: ReplyContext, channel: []const u8, state: ChannelState) ModexCmdError![]const u8 {
    try validateContextWith(params, ctx);
    try validateChannelWith(params, channel);
    try validateStateWith(params, state);

    var writer = Writer.init(out, params.max_line_bytes);
    try writeListLine(&writer, ctx, channel, state);
    try writeEndLine(&writer, ctx, channel);
    return writer.slice();
}

pub fn validateState(state: ChannelState) ModexCmdError!void {
    return validateStateWith(.{}, state);
}

pub fn validateStateWith(comptime params: Params, state: ChannelState) ModexCmdError!void {
    var vis_count: u8 = 0;
    if (state.private) vis_count += 1;
    if (state.hidden) vis_count += 1;
    if (state.secret) vis_count += 1;
    if (vis_count > 1) return error.InvalidModeState;

    if (state.key) |key| try validateParamWith(params, key);
    if (state.limit) |limit| {
        try validateParamWith(params, limit);
        _ = std.fmt.parseUnsigned(u64, limit, 10) catch return error.InvalidLimit;
        if (limit.len == 0 or limit[0] == '0') return error.InvalidLimit;
    }
}

fn writeListLine(writer: *Writer, ctx: ReplyContext, channel: []const u8, state: ChannelState) ModexCmdError!void {
    try writer.numericPrefix(RPL_MODEXLIST, ctx.server_name, ctx.requester);
    try writer.spaceParam(channel);
    try writer.append(" :");

    var first = true;
    if (!state.private and !state.hidden and !state.secret) {
        try appendName(writer, &first, "PUBLIC");
    }

    for (mode_specs) |spec| {
        if (spec.mode == .ban or spec.mode == .exempt or spec.mode == .invex) continue;
        if (state.contains(spec.mode)) try appendName(writer, &first, spec.name);
    }
    if (state.ownerkey) try appendName(writer, &first, "OWNERKEY");
    if (state.hostkey) try appendName(writer, &first, "HOSTKEY");

    try writer.crlf();
}

fn writeEndLine(writer: *Writer, ctx: ReplyContext, channel: []const u8) ModexCmdError!void {
    try writer.numericPrefix(RPL_MODEXEND, ctx.server_name, ctx.requester);
    try writer.spaceParam(channel);
    try writer.append(" :End of modes");
    try writer.crlf();
}

fn appendName(writer: *Writer, first: *bool, name: []const u8) ModexCmdError!void {
    if (!first.*) try writer.appendByte(' ');
    try writer.append(name);
    first.* = false;
}

fn consumeParamWith(
    comptime params: Params,
    spec: ModeSpec,
    op: ModeOp,
    mode_params: []const []const u8,
    param_index: *usize,
) ModexCmdError!?[]const u8 {
    const needs_param = switch (spec.param_kind) {
        .none => false,
        .always => true,
        .add_only => op == .add,
    };
    if (!needs_param) return null;
    if (param_index.* >= mode_params.len) return error.MissingParameter;

    const param = mode_params[param_index.*];
    param_index.* += 1;
    try validateParamWith(params, param);
    if (spec.mode == .limit) {
        _ = std.fmt.parseUnsigned(u64, param, 10) catch return error.InvalidLimit;
        if (param[0] == '0') return error.InvalidLimit;
    }
    return param;
}

fn validateContextWith(comptime params: Params, ctx: ReplyContext) ModexCmdError!void {
    try validateAtom(ctx.server_name, params.max_server_bytes, error.InvalidServerName);
    try validateAtom(ctx.requester, params.max_nick_bytes, error.InvalidNick);
}

fn validateChannelWith(comptime params: Params, channel: []const u8) ModexCmdError!void {
    if (channel.len == 0 or channel.len > params.max_channel_bytes) return error.InvalidChannelName;
    switch (channel[0]) {
        '#', '&', '+', '%' => {},
        else => return error.InvalidChannelName,
    }
    for (channel) |byte| {
        switch (byte) {
            0, ' ', '\t', '\r', '\n', ',', 7, 0x7f => return error.InvalidChannelName,
            else => {},
        }
    }
}

fn validateParamWith(comptime params: Params, param: []const u8) ModexCmdError!void {
    if (param.len == 0 or param.len > params.max_param_bytes) return error.InvalidParameter;
    for (param) |byte| {
        switch (byte) {
            0, ' ', '\t', '\r', '\n', 0x7f => return error.InvalidParameter,
            else => {},
        }
    }
}

fn validateAtom(atom: []const u8, max_len: usize, err: ModexCmdError) ModexCmdError!void {
    if (atom.len == 0 or atom.len > max_len or atom[0] == ':') return err;
    for (atom) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn specFromMode(mode: ChannelMode) ModeSpec {
    for (mode_specs) |spec| {
        if (spec.mode == mode) return spec;
    }
    unreachable;
}

fn formatCode(code: u16, buf: *[3]u8) []const u8 {
    buf[0] = @as(u8, '0') + @as(u8, @intCast((code / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((code / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(code % 10));
    return buf[0..3];
}

const Writer = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,
    line_len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) Writer {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const Writer) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *Writer, code: u16, server_name: []const u8, nick: []const u8) ModexCmdError!void {
        try self.appendByte(':');
        try self.append(server_name);
        try self.appendByte(' ');
        var code_buf: [3]u8 = undefined;
        try self.append(formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.append(nick);
    }

    fn spaceParam(self: *Writer, param: []const u8) ModexCmdError!void {
        try self.appendByte(' ');
        try self.append(param);
    }

    fn crlf(self: *Writer) ModexCmdError!void {
        try self.append("\r\n");
        self.line_len = 0;
    }

    fn append(self: *Writer, bytes: []const u8) ModexCmdError!void {
        if (self.out.len - self.len < bytes.len) return error.OutputTooSmall;
        if (self.line_len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
        self.line_len += bytes.len;
    }

    fn appendByte(self: *Writer, byte: u8) ModexCmdError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.line_len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
        self.line_len += 1;
    }
};

test "parse query request" {
    var changes: [4]ModeChange = undefined;
    const request = try parse("MODEX #team\r\n", &changes);

    try std.testing.expect(request.isQuery());
    try std.testing.expectEqualStrings("#team", request.channel);
    try std.testing.expectEqual(@as(usize, 0), request.changes.len);
}

test "parse set modes with parameters" {
    var changes: [6]ModeChange = undefined;
    const request = try parse("MODEX #team +hxkl secret 42", &changes);

    try std.testing.expect(!request.isQuery());
    try std.testing.expectEqual(@as(usize, 4), request.changes.len);
    try std.testing.expectEqual(ModeOp.add, request.changes[0].op);
    try std.testing.expectEqual(ChannelMode.hidden, request.changes[0].mode);
    try std.testing.expectEqualStrings("HIDDEN", request.changes[0].name);
    try std.testing.expectEqual(ChannelMode.auditorium, request.changes[1].mode);
    try std.testing.expectEqual(ChannelMode.key, request.changes[2].mode);
    try std.testing.expectEqualStrings("secret", request.changes[2].param.?);
    try std.testing.expectEqual(ChannelMode.limit, request.changes[3].mode);
    try std.testing.expectEqualStrings("42", request.changes[3].param.?);
}

test "parse unset modes consumes only required parameters" {
    var changes: [4]ModeChange = undefined;
    const request = try parse("MODEX #team -lk oldkey", &changes);

    try std.testing.expectEqual(@as(usize, 2), request.changes.len);
    try std.testing.expectEqual(ModeOp.remove, request.changes[0].op);
    try std.testing.expectEqual(ChannelMode.limit, request.changes[0].mode);
    try std.testing.expectEqual(@as(?[]const u8, null), request.changes[0].param);
    try std.testing.expectEqual(ChannelMode.key, request.changes[1].mode);
    try std.testing.expectEqualStrings("oldkey", request.changes[1].param.?);
}

test "build reply bytes from supplied state" {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try out.resize(allocator, 256);

    const reply = try buildReply(out.items, .{
        .server_name = "irc.example",
        .requester = "alice",
    }, "#team", .{
        .hidden = true,
        .moderated = true,
        .topicop = true,
        .auditorium = true,
        .ownerkey = true,
        .hostkey = true,
    });

    try std.testing.expectEqualStrings(
        ":irc.example 826 alice #team :HIDDEN MODERATED TOPICOP AUDITORIUM OWNERKEY HOSTKEY\r\n" ++
            ":irc.example 827 alice #team :End of modes\r\n",
        reply,
    );
}

test "public reply is the no-visibility fallback" {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try out.resize(allocator, 128);

    const reply = try buildReply(out.items, .{ .server_name = "s", .requester = "n" }, "#plain", .{});
    try std.testing.expectEqualStrings(
        ":s 826 n #plain :PUBLIC\r\n:s 827 n #plain :End of modes\r\n",
        reply,
    );
}

test "validation rejects malformed requests and state" {
    var changes: [2]ModeChange = undefined;

    try std.testing.expectError(error.UnknownCommand, parse("MODE #team +h", &changes));
    try std.testing.expectError(error.InvalidChannelName, parse("MODEX team +h", &changes));
    try std.testing.expectError(error.MissingOperation, parse("MODEX #team h", &changes));
    try std.testing.expectError(error.UnknownMode, parse("MODEX #team +?", &changes));
    try std.testing.expectError(error.MissingParameter, parse("MODEX #team +k", &changes));
    try std.testing.expectError(error.UnexpectedParameter, parse("MODEX #team +h extra", &changes));
    try std.testing.expectError(error.InvalidLimit, parse("MODEX #team +l 0", &changes));
    try std.testing.expectError(error.InvalidModeState, validateState(.{ .hidden = true, .secret = true }));
}
