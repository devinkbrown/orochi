// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure parser and reply formatter for Onyx Server-native channel registration commands.
//!
//! `parse` accepts a tokenized IRC command where `args[0]` is `CHANNEL` or its
//! short alias `CS`. Parse results borrow slices from the caller-provided token
//! array and token bytes; callers must keep those inputs alive while using the
//! returned request.
const std = @import("std");

pub const MAX_TOKEN_BYTES: usize = 512;
pub const MAX_CHANNEL_BYTES: usize = 200;
pub const MAX_ACCOUNT_BYTES: usize = 64;
pub const MAX_PASSWORD_BYTES: usize = 128;
pub const MAX_VALUE_BYTES: usize = 512;
pub const MAX_MASK_BYTES: usize = 256;
pub const MAX_REASON_TOKEN_BYTES: usize = 256;

/// Parser limits used for validation and boundary tests.
pub const Params = struct {
    max_token_bytes: usize = MAX_TOKEN_BYTES,
    max_channel_bytes: usize = MAX_CHANNEL_BYTES,
    max_account_bytes: usize = MAX_ACCOUNT_BYTES,
    max_password_bytes: usize = MAX_PASSWORD_BYTES,
    max_value_bytes: usize = MAX_VALUE_BYTES,
    max_mask_bytes: usize = MAX_MASK_BYTES,
    max_reason_token_bytes: usize = MAX_REASON_TOKEN_BYTES,
};

/// Errors produced while parsing a tokenized CHANNEL command.
pub const ParseError = error{
    EmptyToken,
    TokenTooLong,
    InvalidCommand,
    InvalidSubcommand,
    NeedMoreParams,
    TooManyParams,
    InvalidChannel,
    ChannelTooLong,
    InvalidField,
    InvalidAction,
    InvalidLevel,
};

/// Errors produced by standard-reply formatting.
pub const BuildError = error{
    EmptyToken,
    TokenTooLong,
    MessageTooLong,
    OutputTooSmall,
};

/// Accepted command names for this command surface.
pub const CommandName = enum {
    channel,
    cs,

    /// Parses `CHANNEL` and its short `CS` alias.
    pub fn parse(raw: []const u8) ?CommandName {
        if (std.ascii.eqlIgnoreCase(raw, "CHANNEL")) return .channel;
        if (std.ascii.eqlIgnoreCase(raw, "CS")) return .cs;
        return null;
    }

    /// Returns the command token used in generated standard replies.
    pub fn token(self: CommandName) []const u8 {
        return switch (self) {
            .channel => "CHANNEL",
            .cs => "CS",
        };
    }
};

/// CHANNEL subcommands supported by the parser.
pub const Subcommand = enum {
    register,
    drop,
    info,
    set,
    access,
    akick,
    transfer,

    /// Parses a CHANNEL subcommand token case-insensitively.
    pub fn parse(raw: []const u8) ?Subcommand {
        if (std.ascii.eqlIgnoreCase(raw, "REGISTER")) return .register;
        if (std.ascii.eqlIgnoreCase(raw, "DROP")) return .drop;
        if (std.ascii.eqlIgnoreCase(raw, "INFO")) return .info;
        if (std.ascii.eqlIgnoreCase(raw, "SET")) return .set;
        if (std.ascii.eqlIgnoreCase(raw, "ACCESS")) return .access;
        if (std.ascii.eqlIgnoreCase(raw, "AKICK")) return .akick;
        if (std.ascii.eqlIgnoreCase(raw, "TRANSFER")) return .transfer;
        return null;
    }

    /// Returns the canonical uppercase token for this subcommand.
    pub fn token(self: Subcommand) []const u8 {
        return switch (self) {
            .register => "REGISTER",
            .drop => "DROP",
            .info => "INFO",
            .set => "SET",
            .access => "ACCESS",
            .akick => "AKICK",
            .transfer => "TRANSFER",
        };
    }
};

/// SET fields accepted by the parser.
pub const SetField = enum {
    topiclock,
    guard,
    private,
    desc,
    url,
    mlock,
    keeptopic,

    /// Parses a SET field token case-insensitively.
    pub fn parse(raw: []const u8) ?SetField {
        if (std.ascii.eqlIgnoreCase(raw, "TOPICLOCK")) return .topiclock;
        if (std.ascii.eqlIgnoreCase(raw, "GUARD")) return .guard;
        if (std.ascii.eqlIgnoreCase(raw, "PRIVATE")) return .private;
        if (std.ascii.eqlIgnoreCase(raw, "DESC")) return .desc;
        if (std.ascii.eqlIgnoreCase(raw, "URL")) return .url;
        if (std.ascii.eqlIgnoreCase(raw, "MLOCK")) return .mlock;
        if (std.ascii.eqlIgnoreCase(raw, "KEEPTOPIC")) return .keeptopic;
        return null;
    }

    /// Returns the canonical uppercase token for this SET field.
    pub fn token(self: SetField) []const u8 {
        return switch (self) {
            .topiclock => "TOPICLOCK",
            .guard => "GUARD",
            .private => "PRIVATE",
            .desc => "DESC",
            .url => "URL",
            .mlock => "MLOCK",
            .keeptopic => "KEEPTOPIC",
        };
    }
};

/// ACCESS actions accepted by the parser.
pub const AccessAction = enum {
    add,
    del,
    list,

    /// Parses an ACCESS action token case-insensitively.
    pub fn parse(raw: []const u8) ?AccessAction {
        if (std.ascii.eqlIgnoreCase(raw, "ADD")) return .add;
        if (std.ascii.eqlIgnoreCase(raw, "DEL")) return .del;
        if (std.ascii.eqlIgnoreCase(raw, "LIST")) return .list;
        return null;
    }

    /// Returns the canonical uppercase token for this ACCESS action.
    pub fn token(self: AccessAction) []const u8 {
        return switch (self) {
            .add => "ADD",
            .del => "DEL",
            .list => "LIST",
        };
    }
};

/// ACCESS levels accepted by the parser.
pub const AccessLevel = enum {
    founder,
    op,
    voice,
    akick,

    /// Parses an ACCESS level token case-insensitively.
    pub fn parse(raw: []const u8) ?AccessLevel {
        if (std.ascii.eqlIgnoreCase(raw, "FOUNDER")) return .founder;
        if (std.ascii.eqlIgnoreCase(raw, "OP")) return .op;
        if (std.ascii.eqlIgnoreCase(raw, "VOICE")) return .voice;
        if (std.ascii.eqlIgnoreCase(raw, "AKICK")) return .akick;
        return null;
    }

    /// Returns the canonical uppercase token for this ACCESS level.
    pub fn token(self: AccessLevel) []const u8 {
        return switch (self) {
            .founder => "FOUNDER",
            .op => "OP",
            .voice => "VOICE",
            .akick => "AKICK",
        };
    }
};

/// AKICK actions accepted by the parser.
pub const AkickAction = enum {
    add,
    del,
    list,

    /// Parses an AKICK action token case-insensitively.
    pub fn parse(raw: []const u8) ?AkickAction {
        if (std.ascii.eqlIgnoreCase(raw, "ADD")) return .add;
        if (std.ascii.eqlIgnoreCase(raw, "DEL")) return .del;
        if (std.ascii.eqlIgnoreCase(raw, "LIST")) return .list;
        return null;
    }

    /// Returns the canonical uppercase token for this AKICK action.
    pub fn token(self: AkickAction) []const u8 {
        return switch (self) {
            .add => "ADD",
            .del => "DEL",
            .list => "LIST",
        };
    }
};

/// Standard-reply code tokens used by the channel registration command surface.
pub const ChanServNumeric = enum {
    REGISTERED,
    DROPPED,
    INFO,
    SET_UPDATED,
    ACCESS_UPDATED,
    AKICK_UPDATED,
    TRANSFERRED,
    NEED_MORE_PARAMS,
    INVALID_PARAMS,
    INVALID_CHANNEL,
    CHANNEL_TOO_LONG,
    TOKEN_TOO_LONG,
    UNKNOWN_COMMAND,
    UNKNOWN_SUBCOMMAND,
    INVALID_FIELD,
    INVALID_ACTION,
    INVALID_LEVEL,
    CHANNEL_NOT_REGISTERED,
    CHANNEL_ALREADY_REGISTERED,
    PERMISSION_DENIED,
    TEMPORARILY_UNAVAILABLE,

    /// Returns the standard-reply code token.
    pub fn token(self: ChanServNumeric) []const u8 {
        return switch (self) {
            .REGISTERED => "REGISTERED",
            .DROPPED => "DROPPED",
            .INFO => "INFO",
            .SET_UPDATED => "SET_UPDATED",
            .ACCESS_UPDATED => "ACCESS_UPDATED",
            .AKICK_UPDATED => "AKICK_UPDATED",
            .TRANSFERRED => "TRANSFERRED",
            .NEED_MORE_PARAMS => "NEED_MORE_PARAMS",
            .INVALID_PARAMS => "INVALID_PARAMS",
            .INVALID_CHANNEL => "INVALID_CHANNEL",
            .CHANNEL_TOO_LONG => "CHANNEL_TOO_LONG",
            .TOKEN_TOO_LONG => "TOKEN_TOO_LONG",
            .UNKNOWN_COMMAND => "UNKNOWN_COMMAND",
            .UNKNOWN_SUBCOMMAND => "UNKNOWN_SUBCOMMAND",
            .INVALID_FIELD => "INVALID_FIELD",
            .INVALID_ACTION => "INVALID_ACTION",
            .INVALID_LEVEL => "INVALID_LEVEL",
            .CHANNEL_NOT_REGISTERED => "CHANNEL_NOT_REGISTERED",
            .CHANNEL_ALREADY_REGISTERED => "CHANNEL_ALREADY_REGISTERED",
            .PERMISSION_DENIED => "PERMISSION_DENIED",
            .TEMPORARILY_UNAVAILABLE => "TEMPORARILY_UNAVAILABLE",
        };
    }
};

/// Standard-reply verbs emitted by the formatter.
pub const StandardReplyKind = enum {
    fail,

    /// Returns the uppercase standard-reply verb.
    pub fn token(self: StandardReplyKind) []const u8 {
        return switch (self) {
            .fail => "FAIL",
        };
    }
};

/// Borrowed payload for `CHANNEL REGISTER <#channel> [password]`.
pub const RegisterRequest = struct { channel: []const u8, password: ?[]const u8 = null };

/// Borrowed payload for `CHANNEL DROP <#channel>`.
pub const DropRequest = struct { channel: []const u8 };

/// Borrowed payload for `CHANNEL INFO <#channel>`.
pub const InfoRequest = struct { channel: []const u8 };

/// Borrowed payload for `CHANNEL SET <#channel> <field> <value>`.
pub const SetRequest = struct { channel: []const u8, field: SetField, value: []const u8 };

/// Borrowed payload for `CHANNEL ACCESS <#channel> <action> [account level]`.
pub const AccessRequest = struct {
    channel: []const u8,
    action: AccessAction,
    account: ?[]const u8 = null,
    level: ?AccessLevel = null,
};

/// Borrowed payload for `CHANNEL AKICK <#channel> <action> [mask [reason...]]`.
pub const AkickRequest = struct {
    channel: []const u8,
    action: AkickAction,
    mask: ?[]const u8 = null,
    reason: []const []const u8 = &.{},
};

/// Borrowed payload for `CHANNEL TRANSFER <#channel> <account>`.
pub const TransferRequest = struct { channel: []const u8, account: []const u8 };

/// Parsed request union for all supported channel registration subcommands.
pub const Request = union(enum) {
    register: RegisterRequest,
    drop: DropRequest,
    info: InfoRequest,
    set: SetRequest,
    access: AccessRequest,
    akick: AkickRequest,
    transfer: TransferRequest,

    /// Returns the subcommand represented by this request.
    pub fn subcommand(self: Request) Subcommand {
        return switch (self) {
            .register => .register,
            .drop => .drop,
            .info => .info,
            .set => .set,
            .access => .access,
            .akick => .akick,
            .transfer => .transfer,
        };
    }
};

/// Parses a tokenized `CHANNEL` or `CS` command with default validation limits.
pub fn parse(args: []const []const u8) ParseError!Request {
    return parseWithParams(.{}, args);
}

/// Parses a tokenized command with caller-supplied compile-time validation limits.
pub fn parseWithParams(comptime params: Params, args: []const []const u8) ParseError!Request {
    comptime {
        if (params.max_token_bytes == 0) @compileError("CHANNEL parser needs token storage");
        if (params.max_channel_bytes == 0) @compileError("CHANNEL parser needs channel storage");
        if (params.max_account_bytes == 0) @compileError("CHANNEL parser needs account storage");
        if (params.max_password_bytes == 0) @compileError("CHANNEL parser needs password storage");
        if (params.max_value_bytes == 0) @compileError("CHANNEL parser needs value storage");
        if (params.max_mask_bytes == 0) @compileError("CHANNEL parser needs mask storage");
        if (params.max_reason_token_bytes == 0) @compileError("CHANNEL parser needs reason storage");
    }

    if (args.len < 1) return error.NeedMoreParams;
    for (args) |arg| try validateTokenWith(params.max_token_bytes, arg);

    _ = CommandName.parse(args[0]) orelse return error.InvalidCommand;
    if (args.len < 2) return error.NeedMoreParams;
    const subcommand = Subcommand.parse(args[1]) orelse return error.InvalidSubcommand;

    return switch (subcommand) {
        .register => parseRegisterWith(params, args),
        .drop => parseDropWith(params, args),
        .info => parseInfoWith(params, args),
        .set => parseSetWith(params, args),
        .access => parseAccessWith(params, args),
        .akick => parseAkickWith(params, args),
        .transfer => parseTransferWith(params, args),
    };
}

/// Returns the canonical usage string for a CHANNEL subcommand.
pub fn fmtUsage(subcommand: Subcommand) []const u8 {
    return switch (subcommand) {
        .register => "CHANNEL REGISTER <#channel> [password]",
        .drop => "CHANNEL DROP <#channel>",
        .info => "CHANNEL INFO <#channel>",
        .set => "CHANNEL SET <#channel> <TOPICLOCK|GUARD|PRIVATE|DESC|URL|MLOCK> <value>",
        .access => "CHANNEL ACCESS <#channel> <ADD|DEL|LIST> [account level]",
        .akick => "CHANNEL AKICK <#channel> <ADD|DEL|LIST> [mask [reason...]]",
        .transfer => "CHANNEL TRANSFER <#channel> <account>",
    };
}

/// Formats a standard-reply line into `out` and returns the written slice.
pub fn formatStandardReply(
    out: []u8,
    kind: StandardReplyKind,
    command: CommandName,
    code: ChanServNumeric,
    params: []const []const u8,
    message: []const u8,
) BuildError![]const u8 {
    if (message.len == 0) return error.EmptyToken;
    if (message.len > MAX_TOKEN_BYTES) return error.MessageTooLong;

    var writer = BufferWriter.init(out);
    try writer.append(kind.token());
    try writer.byte(' ');
    try writer.append(command.token());
    try writer.byte(' ');
    try writer.append(code.token());
    for (params) |param| {
        try validateTokenBuild(param);
        try writer.byte(' ');
        try writer.append(param);
    }
    try writer.append(" :");
    try writer.append(message);
    try writer.crlf();
    return writer.slice();
}

fn parseRegisterWith(comptime params: Params, args: []const []const u8) ParseError!Request {
    if (args.len < 3) return error.NeedMoreParams;
    if (args.len > 4) return error.TooManyParams;
    try validateChannelWith(params, args[2]);
    if (args.len == 4) try validateBoundedToken(params.max_password_bytes, args[3]);
    return .{ .register = .{ .channel = args[2], .password = if (args.len == 4) args[3] else null } };
}

fn parseDropWith(comptime params: Params, args: []const []const u8) ParseError!Request {
    if (args.len < 3) return error.NeedMoreParams;
    if (args.len > 3) return error.TooManyParams;
    try validateChannelWith(params, args[2]);
    return .{ .drop = .{ .channel = args[2] } };
}

fn parseInfoWith(comptime params: Params, args: []const []const u8) ParseError!Request {
    if (args.len < 3) return error.NeedMoreParams;
    if (args.len > 3) return error.TooManyParams;
    try validateChannelWith(params, args[2]);
    return .{ .info = .{ .channel = args[2] } };
}

fn parseSetWith(comptime params: Params, args: []const []const u8) ParseError!Request {
    if (args.len < 5) return error.NeedMoreParams;
    if (args.len > 5) return error.TooManyParams;
    try validateChannelWith(params, args[2]);
    const field = SetField.parse(args[3]) orelse return error.InvalidField;
    try validateBoundedToken(params.max_value_bytes, args[4]);
    return .{ .set = .{ .channel = args[2], .field = field, .value = args[4] } };
}

fn parseAccessWith(comptime params: Params, args: []const []const u8) ParseError!Request {
    if (args.len < 4) return error.NeedMoreParams;
    if (args.len == 5) return error.NeedMoreParams;
    if (args.len > 6) return error.TooManyParams;
    try validateChannelWith(params, args[2]);
    const action = AccessAction.parse(args[3]) orelse return error.InvalidAction;
    if (args.len == 4) return .{ .access = .{ .channel = args[2], .action = action } };

    try validateBoundedToken(params.max_account_bytes, args[4]);
    const level = AccessLevel.parse(args[5]) orelse return error.InvalidLevel;
    return .{ .access = .{ .channel = args[2], .action = action, .account = args[4], .level = level } };
}

fn parseAkickWith(comptime params: Params, args: []const []const u8) ParseError!Request {
    if (args.len < 4) return error.NeedMoreParams;
    try validateChannelWith(params, args[2]);
    const action = AkickAction.parse(args[3]) orelse return error.InvalidAction;
    if (args.len == 4) return .{ .akick = .{ .channel = args[2], .action = action } };

    try validateBoundedToken(params.max_mask_bytes, args[4]);
    for (args[5..]) |token| try validateBoundedToken(params.max_reason_token_bytes, token);
    return .{ .akick = .{ .channel = args[2], .action = action, .mask = args[4], .reason = args[5..] } };
}

fn parseTransferWith(comptime params: Params, args: []const []const u8) ParseError!Request {
    if (args.len < 4) return error.NeedMoreParams;
    if (args.len > 4) return error.TooManyParams;
    try validateChannelWith(params, args[2]);
    try validateBoundedToken(params.max_account_bytes, args[3]);
    return .{ .transfer = .{ .channel = args[2], .account = args[3] } };
}

fn validateChannelWith(comptime params: Params, channel: []const u8) ParseError!void {
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (channel[0] != '#' and channel[0] != '&') return error.InvalidChannel;
}

fn validateTokenWith(max_len: usize, token: []const u8) ParseError!void {
    if (token.len == 0) return error.EmptyToken;
    if (token.len > max_len) return error.TokenTooLong;
}

fn validateBoundedToken(max_len: usize, token: []const u8) ParseError!void {
    if (token.len == 0) return error.EmptyToken;
    if (token.len > max_len) return error.TokenTooLong;
}

fn validateTokenBuild(token: []const u8) BuildError!void {
    if (token.len == 0) return error.EmptyToken;
    if (token.len > MAX_TOKEN_BYTES) return error.TokenTooLong;
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

    fn append(self: *BufferWriter, bytes: []const u8) BuildError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn byte(self: *BufferWriter, value: u8) BuildError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = value;
        self.len += 1;
    }

    fn crlf(self: *BufferWriter) BuildError!void {
        try self.append("\r\n");
    }
};

fn ownedArgs(tokens: []const []const u8) ![][]const u8 {
    return std.testing.allocator.dupe([]const u8, tokens);
}

test "parse register with optional password borrows args" {
    // Arrange
    const args = try ownedArgs(&.{ "CHANNEL", "REGISTER", "#onyx", "correct-horse" });
    defer std.testing.allocator.free(args);

    // Act
    const request = try parse(args);

    // Assert
    try std.testing.expectEqual(Subcommand.register, request.subcommand());
    try std.testing.expectEqualStrings("#onyx", request.register.channel);
    try std.testing.expectEqualStrings("correct-horse", request.register.password.?);
}

test "parse register without password accepts ampersand channels" {
    // Arrange
    const args = try ownedArgs(&.{ "CHANNEL", "REGISTER", "&local" });
    defer std.testing.allocator.free(args);

    // Act
    const request = try parse(args);

    // Assert
    try std.testing.expectEqual(Subcommand.register, request.subcommand());
    try std.testing.expectEqualStrings("&local", request.register.channel);
    try std.testing.expect(request.register.password == null);
}

test "parse drop and info commands" {
    // Arrange
    const drop_args = try ownedArgs(&.{ "CHANNEL", "DROP", "#gone" });
    defer std.testing.allocator.free(drop_args);
    const info_args = try ownedArgs(&.{ "CHANNEL", "INFO", "#there" });
    defer std.testing.allocator.free(info_args);

    // Act
    const drop_request = try parse(drop_args);
    const info_request = try parse(info_args);

    // Assert
    try std.testing.expectEqual(Subcommand.drop, drop_request.subcommand());
    try std.testing.expectEqualStrings("#gone", drop_request.drop.channel);
    try std.testing.expectEqual(Subcommand.info, info_request.subcommand());
    try std.testing.expectEqualStrings("#there", info_request.info.channel);
}

test "parse set command for every field" {
    const cases = [_]struct {
        token: []const u8,
        field: SetField,
        value: []const u8,
    }{
        .{ .token = "TOPICLOCK", .field = .topiclock, .value = "on" },
        .{ .token = "GUARD", .field = .guard, .value = "off" },
        .{ .token = "PRIVATE", .field = .private, .value = "on" },
        .{ .token = "DESC", .field = .desc, .value = "mesh" },
        .{ .token = "URL", .field = .url, .value = "https://example.test" },
        .{ .token = "MLOCK", .field = .mlock, .value = "+nt" },
    };

    for (cases) |case| {
        // Arrange
        const args = try ownedArgs(&.{ "CHANNEL", "SET", "#cfg", case.token, case.value });
        defer std.testing.allocator.free(args);

        // Act
        const request = try parse(args);

        // Assert
        try std.testing.expectEqual(Subcommand.set, request.subcommand());
        try std.testing.expectEqual(case.field, request.set.field);
        try std.testing.expectEqualStrings(case.value, request.set.value);
    }
}

test "parse access actions and levels" {
    const cases = [_]struct {
        action_token: []const u8,
        action: AccessAction,
        level_token: []const u8,
        level: AccessLevel,
    }{
        .{ .action_token = "ADD", .action = .add, .level_token = "FOUNDER", .level = .founder },
        .{ .action_token = "DEL", .action = .del, .level_token = "OP", .level = .op },
        .{ .action_token = "LIST", .action = .list, .level_token = "VOICE", .level = .voice },
        .{ .action_token = "add", .action = .add, .level_token = "akick", .level = .akick },
    };

    for (cases) |case| {
        // Arrange
        const args = try ownedArgs(&.{ "CHANNEL", "ACCESS", "#acl", case.action_token, "alice", case.level_token });
        defer std.testing.allocator.free(args);

        // Act
        const request = try parse(args);

        // Assert
        try std.testing.expectEqual(Subcommand.access, request.subcommand());
        try std.testing.expectEqual(case.action, request.access.action);
        try std.testing.expectEqualStrings("alice", request.access.account.?);
        try std.testing.expectEqual(case.level, request.access.level.?);
    }
}

test "parse access list without account level pair" {
    // Arrange
    const args = try ownedArgs(&.{ "CHANNEL", "ACCESS", "#acl", "LIST" });
    defer std.testing.allocator.free(args);

    // Act
    const request = try parse(args);

    // Assert
    try std.testing.expectEqual(Subcommand.access, request.subcommand());
    try std.testing.expectEqual(AccessAction.list, request.access.action);
    try std.testing.expect(request.access.account == null);
    try std.testing.expectEqual(@as(?AccessLevel, null), request.access.level);
}

test "parse akick list and add with reason tokens" {
    // Arrange
    const list_args = try ownedArgs(&.{ "CHANNEL", "AKICK", "#acl", "LIST" });
    defer std.testing.allocator.free(list_args);
    const add_args = try ownedArgs(&.{ "CHANNEL", "AKICK", "#acl", "ADD", "*!*@example.test", "repeated", "spam", "source" });
    defer std.testing.allocator.free(add_args);

    // Act
    const list_request = try parse(list_args);
    const add_request = try parse(add_args);

    // Assert
    try std.testing.expectEqual(Subcommand.akick, list_request.subcommand());
    try std.testing.expectEqual(AkickAction.list, list_request.akick.action);
    try std.testing.expect(list_request.akick.mask == null);
    try std.testing.expectEqual(@as(usize, 0), list_request.akick.reason.len);
    try std.testing.expectEqual(AkickAction.add, add_request.akick.action);
    try std.testing.expectEqualStrings("*!*@example.test", add_request.akick.mask.?);
    try std.testing.expectEqual(@as(usize, 3), add_request.akick.reason.len);
    try std.testing.expectEqualStrings("repeated", add_request.akick.reason[0]);
    try std.testing.expectEqualStrings("source", add_request.akick.reason[2]);
}

test "parse transfer and cs alias" {
    // Arrange
    const args = try ownedArgs(&.{ "CS", "TRANSFER", "#owned", "bob" });
    defer std.testing.allocator.free(args);

    // Act
    const request = try parse(args);

    // Assert
    try std.testing.expectEqual(Subcommand.transfer, request.subcommand());
    try std.testing.expectEqualStrings("#owned", request.transfer.channel);
    try std.testing.expectEqualStrings("bob", request.transfer.account);
}

test "bad input returns typed parser errors" {
    // Arrange
    const empty_args = [_][]const u8{};
    const empty_token = [_][]const u8{ "CHANNEL", "", "#chan" };
    const bad_command = [_][]const u8{ "CHANSERV", "INFO", "#chan" };
    const bad_subcommand = [_][]const u8{ "CHANNEL", "FLAGS", "#chan" };
    const bad_channel = [_][]const u8{ "CHANNEL", "INFO", "chan" };
    const missing_access_level = [_][]const u8{ "CHANNEL", "ACCESS", "#chan", "ADD", "alice" };
    const bad_field = [_][]const u8{ "CHANNEL", "SET", "#chan", "LIMIT", "1" };
    const bad_action = [_][]const u8{ "CHANNEL", "ACCESS", "#chan", "GRANT" };
    const bad_level = [_][]const u8{ "CHANNEL", "ACCESS", "#chan", "ADD", "alice", "ADMIN" };

    // Act and Assert
    try std.testing.expectError(error.NeedMoreParams, parse(&empty_args));
    try std.testing.expectError(error.EmptyToken, parse(&empty_token));
    try std.testing.expectError(error.InvalidCommand, parse(&bad_command));
    try std.testing.expectError(error.InvalidSubcommand, parse(&bad_subcommand));
    try std.testing.expectError(error.InvalidChannel, parse(&bad_channel));
    try std.testing.expectError(error.NeedMoreParams, parse(&missing_access_level));
    try std.testing.expectError(error.InvalidField, parse(&bad_field));
    try std.testing.expectError(error.InvalidAction, parse(&bad_action));
    try std.testing.expectError(error.InvalidLevel, parse(&bad_level));
}

test "boundary sizes reject oversized tokens and channels" {
    // Arrange
    const long_token = "abcdef";
    const long_channel = "#abcd";
    const token_args = [_][]const u8{ "CHANNEL", "INFO", long_token };
    const channel_args = [_][]const u8{ "CHANNEL", "INFO", long_channel };
    const ok_args = [_][]const u8{ "CHANNEL", "INFO", "#abc" };

    // Act and Assert
    try std.testing.expectError(error.TokenTooLong, parseWithParams(.{ .max_token_bytes = 5 }, &token_args));
    try std.testing.expectError(error.ChannelTooLong, parseWithParams(.{ .max_channel_bytes = 4 }, &channel_args));
    const request = try parseWithParams(.{ .max_channel_bytes = 4 }, &ok_args);
    try std.testing.expectEqualStrings("#abc", request.info.channel);
}

test "usage formatter returns every canonical usage string" {
    // Arrange
    const cases = [_]struct {
        subcommand: Subcommand,
        usage: []const u8,
    }{
        .{ .subcommand = .register, .usage = "CHANNEL REGISTER <#channel> [password]" },
        .{ .subcommand = .drop, .usage = "CHANNEL DROP <#channel>" },
        .{ .subcommand = .info, .usage = "CHANNEL INFO <#channel>" },
        .{ .subcommand = .set, .usage = "CHANNEL SET <#channel> <TOPICLOCK|GUARD|PRIVATE|DESC|URL|MLOCK> <value>" },
        .{ .subcommand = .access, .usage = "CHANNEL ACCESS <#channel> <ADD|DEL|LIST> [account level]" },
        .{ .subcommand = .akick, .usage = "CHANNEL AKICK <#channel> <ADD|DEL|LIST> [mask [reason...]]" },
        .{ .subcommand = .transfer, .usage = "CHANNEL TRANSFER <#channel> <account>" },
    };

    for (cases) |case| {
        // Act
        const usage = fmtUsage(case.subcommand);

        // Assert
        try std.testing.expectEqualStrings(case.usage, usage);
    }
}

test "standard reply formatter writes fail lines" {
    // Arrange
    var fail_out: [256]u8 = undefined;
    const fail_params = [_][]const u8{"REGISTER"};

    // Act
    const fail_line = try formatStandardReply(
        &fail_out,
        .fail,
        .channel,
        .NEED_MORE_PARAMS,
        &fail_params,
        fmtUsage(.register),
    );

    // Assert
    try std.testing.expectEqualStrings("FAIL CHANNEL NEED_MORE_PARAMS REGISTER :CHANNEL REGISTER <#channel> [password]\r\n", fail_line);
}

test "standard reply formatter rejects empty params and short buffers" {
    // Arrange
    var short_out: [8]u8 = undefined;
    var out: [128]u8 = undefined;
    const bad_params = [_][]const u8{""};

    // Act and Assert
    try std.testing.expectError(error.EmptyToken, formatStandardReply(&out, .fail, .channel, .INVALID_PARAMS, &bad_params, "Bad input"));
    try std.testing.expectError(error.OutputTooSmall, formatStandardReply(&short_out, .fail, .channel, .INFO, &.{}, "Channel info"));
}
