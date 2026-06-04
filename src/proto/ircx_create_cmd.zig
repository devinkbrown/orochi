//! Pure IRCX CREATE command parser and reply builder.
//!
//! This command layer consumes the lower-level validation and initial JOIN/NAMES
//! helpers from `ircx_create.zig`. It parses caller-owned IRC lines into borrowed
//! request views, exposes an iterator for optional initial mode changes, and
//! renders the CREATE acknowledgement/error bytes into caller-provided buffers.
const std = @import("std");
const irc_line = @import("irc_line.zig");
const create = @import("ircx_create.zig");
const numeric = @import("numeric.zig");

pub const Params = create.Params;
pub const Prefix = create.Prefix;
pub const MemberTier = create.MemberTier;
pub const DEFAULT_MAX_MODE_BYTES = create.DEFAULT_MAX_MODE_BYTES;

pub const ParseError = irc_line.ParseError || create.IrcxCreateError || error{
    UnknownCommand,
};

pub const BuildError = create.IrcxCreateError;

pub const ModeOp = enum {
    add,
    remove,

    pub fn sign(self: ModeOp) u8 {
        return switch (self) {
            .add => '+',
            .remove => '-',
        };
    }
};

pub const ModeChange = struct {
    op: ModeOp,
    mode: u8,
};

pub const InitialModes = struct {
    raw: []const u8,

    pub fn iterator(self: InitialModes) ModeIterator {
        return .{ .raw = self.raw };
    }
};

/// Parsed `CREATE <channel> [modes]` request.
pub const Request = struct {
    channel: []const u8,
    initial_modes: ?InitialModes = null,
    creator_status: MemberTier = .founder,

    pub fn requestedModes(self: Request) ?[]const u8 {
        if (self.initial_modes) |modes| return modes.raw;
        return null;
    }
};

pub const AckContext = struct {
    server_name: []const u8,
    recipient_nick: []const u8,
    creator: Prefix,
    end_names_text: []const u8 = "End of /NAMES list",
};

pub const ErrorContext = struct {
    server_name: []const u8,
    recipient_nick: []const u8,
};

pub const ModeIterator = struct {
    raw: []const u8,
    index: usize = 0,
    current_op: ModeOp = .add,

    pub fn next(self: *ModeIterator) ?ModeChange {
        while (self.index < self.raw.len) {
            const ch = self.raw[self.index];
            self.index += 1;

            switch (ch) {
                '+' => self.current_op = .add,
                '-' => self.current_op = .remove,
                else => return .{ .op = self.current_op, .mode = ch },
            }
        }
        return null;
    }
};

/// Parse a raw IRC line whose command must be `CREATE`.
pub fn parse(line: []const u8) ParseError!Request {
    return parseWith(.{}, line);
}

/// Parse a raw IRC line using caller-selected compile-time limits.
pub fn parseWith(comptime params: Params, line: []const u8) ParseError!Request {
    const parsed = try irc_line.parseLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, "CREATE")) return error.UnknownCommand;
    return parseParamsWith(params, parsed.paramSlice());
}

/// Parse CREATE parameters excluding the command name.
pub fn parseParams(params: []const []const u8) ParseError!Request {
    return parseParamsWith(.{}, params);
}

/// Parse tokenized CREATE parameters using caller-selected compile-time limits.
pub fn parseParamsWith(comptime params_config: Params, params: []const []const u8) ParseError!Request {
    const args = try create.parseCreateArgsWith(params_config, params);
    if (args.modes) |raw_modes| try validateInitialModesWith(params_config, raw_modes);

    return .{
        .channel = args.channel,
        .initial_modes = if (args.modes) |raw_modes| .{ .raw = raw_modes } else null,
        .creator_status = .founder,
    };
}

pub fn validateChannel(channel: []const u8) create.IrcxCreateError!void {
    return create.validateChannel(channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) create.IrcxCreateError!void {
    return create.validateChannelWith(params, channel);
}

pub fn validateInitialModes(modes: []const u8) create.IrcxCreateError!void {
    return validateInitialModesWith(.{}, modes);
}

pub fn validateInitialModesWith(comptime params: Params, modes: []const u8) create.IrcxCreateError!void {
    try create.validateModesWith(params, modes);
    for (modes) |ch| {
        if (ch != '+' and ch != '-') return;
    }
    return error.InvalidModes;
}

/// Build the initial CREATE acknowledgement block:
/// JOIN broadcast, founder NAMES reply, and end-of-NAMES reply, each with CRLF.
pub fn buildAckReplies(out: []u8, context: AckContext, request: Request) BuildError![]const u8 {
    return buildAckRepliesWith(.{}, out, context, request);
}

/// Build the acknowledgement block using caller-selected compile-time limits.
pub fn buildAckRepliesWith(
    comptime params: Params,
    out: []u8,
    context: AckContext,
    request: Request,
) BuildError![]const u8 {
    try validateRequestWith(params, request);

    var writer = ReplyWriter.init(out);
    const join = try create.buildJoinBroadcastWith(params, writer.remaining(), context.creator, request.channel);
    try writer.advance(join.len);
    try writer.crlf();
    const names = try create.buildFounderNamesReplyWith(
        params,
        writer.remaining(),
        context.server_name,
        context.recipient_nick,
        request.channel,
    );
    try writer.advance(names.len);
    try writer.crlf();
    const end = try create.buildEndOfNamesReplyWith(
        params,
        writer.remaining(),
        context.server_name,
        context.recipient_nick,
        request.channel,
        context.end_names_text,
    );
    try writer.advance(end.len);
    try writer.crlf();
    return writer.slice();
}

pub fn buildNeedMoreParamsReply(out: []u8, context: ErrorContext) BuildError![]const u8 {
    return create.buildNeedMoreParamsReply(out, context.server_name, context.recipient_nick);
}

pub fn buildBadChannelNameReply(
    out: []u8,
    context: ErrorContext,
    channel: []const u8,
) BuildError![]const u8 {
    return create.buildBadChannelNameReply(out, context.server_name, context.recipient_nick, channel);
}

pub fn buildInvalidModesReply(out: []u8, context: ErrorContext) BuildError![]const u8 {
    try create.validateServerName(context.server_name);
    try create.validateNick(context.recipient_nick);

    var writer = ReplyWriter.init(out);
    try writer.append(":");
    try writer.append(context.server_name);
    try writer.append(" ");
    try writer.appendNumeric(.ERR_UNKNOWNMODE);
    try writer.append(" ");
    try writer.append(context.recipient_nick);
    try writer.append(" * :Invalid channel modes");
    return writer.slice();
}

pub fn validateRequest(request: Request) create.IrcxCreateError!void {
    return validateRequestWith(.{}, request);
}

pub fn validateRequestWith(comptime params: Params, request: Request) create.IrcxCreateError!void {
    try create.validateChannelWith(params, request.channel);
    if (request.initial_modes) |modes| try validateInitialModesWith(params, modes.raw);
}

fn BufferWriterFor(comptime Error: type) type {
    return struct {
        out: []u8,
        len: usize = 0,

        fn init(out: []u8) @This() {
            return .{ .out = out };
        }

        fn slice(self: *const @This()) []const u8 {
            return self.out[0..self.len];
        }

        fn remaining(self: *@This()) []u8 {
            return self.out[self.len..];
        }

        fn advance(self: *@This(), count: usize) Error!void {
            if (self.len > self.out.len or count > self.out.len - self.len) return error.OutputTooSmall;
            self.len += count;
        }

        fn append(self: *@This(), bytes: []const u8) Error!void {
            if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
            @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
            self.len += bytes.len;
        }

        fn crlf(self: *@This()) Error!void {
            try self.append("\r\n");
        }

        fn appendNumeric(self: *@This(), code: numeric.Numeric) Error!void {
            var code_buf: [3]u8 = undefined;
            try self.append(numeric.formatCode(code, &code_buf));
        }
    };
}

const ReplyWriter = BufferWriterFor(BuildError);

test "parse CREATE without modes" {
    const allocator = std.testing.allocator;
    const params = try allocator.alloc([]const u8, 1);
    defer allocator.free(params);
    params[0] = "#mizuchi";

    const request = try parseParams(params);
    try std.testing.expectEqualStrings("#mizuchi", request.channel);
    try std.testing.expectEqual(@as(?[]const u8, null), request.requestedModes());
    try std.testing.expectEqual(.founder, request.creator_status);

    const line_request = try parse("CREATE #mizuchi\r\n");
    try std.testing.expectEqualStrings("#mizuchi", line_request.channel);
    try std.testing.expect(line_request.initial_modes == null);
}

test "parse CREATE with modes and iterate changes" {
    const allocator = std.testing.allocator;
    const params = try allocator.alloc([]const u8, 2);
    defer allocator.free(params);
    params[0] = "#mizuchi";
    params[1] = "+nt-i";

    const request = try parseParams(params);
    try std.testing.expectEqualStrings("#mizuchi", request.channel);
    try std.testing.expectEqualStrings("+nt-i", request.requestedModes().?);

    var it = request.initial_modes.?.iterator();
    try std.testing.expectEqual(ModeChange{ .op = .add, .mode = 'n' }, it.next().?);
    try std.testing.expectEqual(ModeChange{ .op = .add, .mode = 't' }, it.next().?);
    try std.testing.expectEqual(ModeChange{ .op = .remove, .mode = 'i' }, it.next().?);
    try std.testing.expectEqual(@as(?ModeChange, null), it.next());

    const line_request = try parse("CREATE #mizuchi :+nt\r\n");
    try std.testing.expectEqualStrings("+nt", line_request.requestedModes().?);
}

test "validation rejects malformed CREATE input" {
    const allocator = std.testing.allocator;
    const missing = try allocator.alloc([]const u8, 0);
    defer allocator.free(missing);
    try std.testing.expectError(error.MissingChannel, parseParams(missing));

    const bad_channel = [_][]const u8{"mizuchi"};
    try std.testing.expectError(error.InvalidChannel, parseParams(&bad_channel));

    const too_many = [_][]const u8{ "#mizuchi", "+nt", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseParams(&too_many));

    const bad_modes = [_][]const u8{ "#mizuchi", "+n t" };
    try std.testing.expectError(error.InvalidModes, parseParams(&bad_modes));

    const sign_only = [_][]const u8{ "#mizuchi", "+-" };
    try std.testing.expectError(error.InvalidModes, parseParams(&sign_only));

    try std.testing.expectError(error.UnknownCommand, parse("JOIN #mizuchi"));
}

test "reply builders render ack and error bytes" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 512);
    defer allocator.free(out);

    const request = try parse("CREATE #mizuchi +nt");
    const ack = try buildAckReplies(out, .{
        .server_name = "irc.example",
        .recipient_nick = "alice",
        .creator = .{ .nick = "alice", .user = "u", .host = "cloak.example" },
    }, request);
    try std.testing.expectEqualStrings(
        ":alice!u@cloak.example JOIN #mizuchi\r\n" ++
            ":irc.example 353 alice = #mizuchi :~alice\r\n" ++
            ":irc.example 366 alice #mizuchi :End of /NAMES list\r\n",
        ack,
    );

    const err_ctx = ErrorContext{ .server_name = "irc.example", .recipient_nick = "alice" };
    const need_more = try buildNeedMoreParamsReply(out, err_ctx);
    try std.testing.expectEqualStrings(":irc.example 461 alice CREATE :Not enough parameters", need_more);

    const bad_channel = try buildBadChannelNameReply(out, err_ctx, "#bad channel");
    try std.testing.expectEqualStrings(":irc.example 479 alice #bad channel :Invalid channel name", bad_channel);

    const bad_modes = try buildInvalidModesReply(out, err_ctx);
    try std.testing.expectEqualStrings(":irc.example 472 alice * :Invalid channel modes", bad_modes);
}

test "reply builders validate requests and buffer size" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 16);
    defer allocator.free(out);

    const request = try parse("CREATE #mizuchi");
    try std.testing.expectError(error.OutputTooSmall, buildAckReplies(out, .{
        .server_name = "irc.example",
        .recipient_nick = "alice",
        .creator = .{ .nick = "alice", .user = "u", .host = "cloak.example" },
    }, request));

    const invalid = Request{ .channel = "bad channel" };
    try std.testing.expectError(error.InvalidChannel, validateRequest(invalid));
}
