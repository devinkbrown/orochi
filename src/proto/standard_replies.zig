//! IRCv3 standard-replies composer.
//!
//! Standard replies are Mizuchi's typed error/warning/note primitive for native
//! services and command handlers. The hot path is allocation-free: callers pass
//! command, code, context, description, and a destination buffer.
const std = @import("std");

/// Mizuchi's modern IRC line-body ceiling. Send paths may choose a lower cap.
pub const MAX_LINE_BODY: usize = 8191;

/// Traditional IRC line body limit without CRLF.
pub const MAX_LEGACY_BODY: usize = 510;

/// Reply severity token.
pub const ReplyType = enum {
    fail,
    warn,
    note,

    pub fn token(self: ReplyType) []const u8 {
        return switch (self) {
            .fail => "FAIL",
            .warn => "WARN",
            .note => "NOTE",
        };
    }
};

/// Common IRCv3 standard-replies and Mizuchi/IRCX service reply codes.
///
/// The enum tag name is the wire token. Keep codes uppercase and descriptive so
/// service results can carry this type directly.
pub const Code = enum {
    ACCOUNT_ALREADY_EXISTS,
    ACCOUNT_REQUIRED,
    ALREADY_AUTHENTICATED,
    ALREADY_REGISTERED,
    AUTHENTICATION_FAILED,
    BAD_ACCOUNT_NAME,
    BAD_CHANNEL_NAME,
    BAD_PASSWORD,
    BAD_TARGET,
    BANNED_FROM_CHANNEL,
    CANNOT_SEND_TO_CHANNEL,
    CHANNEL_DISABLED,
    CHANNEL_DOES_NOT_EXIST,
    CHANNEL_FULL,
    CHANNEL_RENAMED,
    CHANNEL_REQUIRED,
    COMMAND_DISABLED,
    COMMAND_RATE_LIMITED,
    EXPIRED_TOKEN,
    HOST_REQUIRED,
    INVALID_ACCOUNT_NAME,
    INVALID_CREDENTIALS,
    INVALID_KEY,
    INVALID_MODE,
    INVALID_PARAMS,
    INVALID_PROPERTY,
    INVALID_TARGET,
    INVALID_TOKEN,
    LIST_EMPTY,
    MESSAGE_RATE_LIMITED,
    MESSAGE_TOO_LONG,
    METADATA_LIMIT_REACHED,
    MONITOR_LIMIT_REACHED,
    NEED_MORE_PARAMS,
    NETWORK_ERROR,
    NICK_LOCKED,
    NO_MATCHING_KEY,
    NOT_AUTHENTICATED,
    NOT_CHANNEL_OPERATOR,
    NOT_ON_CHANNEL,
    NOT_REGISTERED,
    PERMISSION_DENIED,
    PRIVILEGES_REQUIRED,
    PROPERTY_REQUIRED,
    REGISTRATION_IS_DISABLED,
    SILENTLY_DROPPED,
    TARGET_REQUIRED,
    TOKEN_REQUIRED,
    TOO_MANY_CHANNELS,
    TOO_MANY_MATCHES,
    TOO_MANY_MONITOR_TARGETS,
    UNKNOWN_COMMAND,
    UNKNOWN_ERROR,
    UNKNOWN_PROPERTY,
    UNSUPPORTED_MEDIA_TYPE,
};

/// Reply code, either from the typed catalog or a validated extension token.
pub const CodeToken = union(enum) {
    catalog: Code,
    custom: []const u8,

    pub fn token(self: CodeToken) []const u8 {
        return switch (self) {
            .catalog => |code| @tagName(code),
            .custom => |code| code,
        };
    }
};

/// Builder controls for environments with narrower wire limits.
pub const BuildOptions = struct {
    max_body_len: usize = MAX_LINE_BODY,
    escape_description_controls: bool = true,
};

pub const BuildError = error{
    InvalidCommand,
    InvalidCode,
    InvalidContext,
    InvalidDescription,
    MessageTooLong,
    OutputTooSmall,
};

/// Value-style builder for one standard reply line.
pub const Builder = struct {
    kind: ReplyType,
    command: []const u8,
    code: CodeToken,
    context_params: []const []const u8 = &.{},
    description: []const u8,
    options: BuildOptions = .{},

    /// Attach IRC middle parameters between code and description.
    pub fn withContext(self: Builder, context_params: []const []const u8) Builder {
        var next = self;
        next.context_params = context_params;
        return next;
    }

    /// Use a custom maximum line-body length for this build.
    pub fn withMaxBodyLen(self: Builder, max_body_len: usize) Builder {
        var next = self;
        next.options.max_body_len = max_body_len;
        return next;
    }

    /// Reject CR/LF/NUL in descriptions instead of rendering visible escapes.
    pub fn withStrictDescription(self: Builder) Builder {
        var next = self;
        next.options.escape_description_controls = false;
        return next;
    }

    /// Return the exact line-body size that `write` will produce.
    pub fn requiredLen(self: Builder) BuildError!usize {
        try validateBuilder(self);

        var total: usize = 0;
        try addLen(&total, self.kind.token().len);
        try addLen(&total, 1 + self.command.len);
        try addLen(&total, 1 + self.code.token().len);
        for (self.context_params) |param| {
            try addLen(&total, 1 + param.len);
        }
        try addLen(&total, 2);
        const description_len = try escapedDescriptionLen(self.description, self.options);
        try addLen(&total, description_len);

        if (total > self.options.max_body_len) return error.MessageTooLong;
        return total;
    }

    /// Build `<TYPE> <command> <code> [context...] :description` into `out`.
    pub fn write(self: Builder, out: []u8) BuildError![]const u8 {
        const needed = try self.requiredLen();
        if (out.len < needed) return error.OutputTooSmall;

        var writer = SliceWriter{ .buf = out };
        try writer.append(self.kind.token());
        try writer.appendByte(' ');
        try writer.append(self.command);
        try writer.appendByte(' ');
        try writer.append(self.code.token());
        for (self.context_params) |param| {
            try writer.appendByte(' ');
            try writer.append(param);
        }
        try writer.append(" :");
        try writer.appendDescription(self.description, self.options);
        return out[0..writer.len];
    }

    /// Build a complete wire line by appending CRLF after the reply body.
    pub fn writeCrlf(self: Builder, out: []u8) BuildError![]const u8 {
        const body_len = try self.requiredLen();
        const needed = body_len + 2;
        if (out.len < needed) return error.OutputTooSmall;
        const body = try self.write(out[0..body_len]);
        out[body.len] = '\r';
        out[body.len + 1] = '\n';
        return out[0..needed];
    }
};

/// Start a FAIL reply with a catalog code.
pub fn fail(command: []const u8, code: Code, description: []const u8) Builder {
    return build(.fail, command, .{ .catalog = code }, description);
}

/// Start a WARN reply with a catalog code.
pub fn warn(command: []const u8, code: Code, description: []const u8) Builder {
    return build(.warn, command, .{ .catalog = code }, description);
}

/// Start a NOTE reply with a catalog code.
pub fn note(command: []const u8, code: Code, description: []const u8) Builder {
    return build(.note, command, .{ .catalog = code }, description);
}

/// Start a reply with an extension code token.
pub fn custom(kind: ReplyType, command: []const u8, code: []const u8, description: []const u8) Builder {
    return build(kind, command, .{ .custom = code }, description);
}

/// Parse a catalog code from its wire token.
pub fn parseCatalogCode(token: []const u8) ?Code {
    inline for (@typeInfo(Code).@"enum".fields) |field| {
        if (std.mem.eql(u8, token, field.name)) {
            return @field(Code, field.name);
        }
    }
    return null;
}

/// Validate a custom extension code token.
pub fn validCodeToken(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token, 0..) |ch, index| {
        switch (ch) {
            'A'...'Z' => {},
            '0'...'9', '_' => if (index == 0) return false,
            else => return false,
        }
    }
    return true;
}

/// Validate an IRC middle parameter for command and context positions.
pub fn validMiddleParam(param: []const u8) bool {
    if (param.len == 0 or param[0] == ':') return false;
    for (param) |ch| {
        if (ch <= ' ' or ch == 0x7f) return false;
    }
    return true;
}

fn build(kind: ReplyType, command: []const u8, code: CodeToken, description: []const u8) Builder {
    return .{
        .kind = kind,
        .command = command,
        .code = code,
        .description = description,
    };
}

fn validateBuilder(builder: Builder) BuildError!void {
    if (!validMiddleParam(builder.command)) return error.InvalidCommand;
    if (!validCodeToken(builder.code.token())) return error.InvalidCode;
    for (builder.context_params) |param| {
        if (!validMiddleParam(param)) return error.InvalidContext;
    }
    if (!builder.options.escape_description_controls) {
        for (builder.description) |ch| {
            if (unsafeDescriptionByte(ch)) return error.InvalidDescription;
        }
    }
}

fn escapedDescriptionLen(description: []const u8, options: BuildOptions) BuildError!usize {
    var total: usize = 0;
    for (description) |ch| {
        const add = try escapedDescriptionByteLen(ch, options);
        try addLen(&total, add);
    }
    return total;
}

fn escapedDescriptionByteLen(ch: u8, options: BuildOptions) BuildError!usize {
    if (options.escape_description_controls) {
        return switch (ch) {
            0, '\r', '\n', '\t', '\\' => 2,
            0x01...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => 4,
            else => 1,
        };
    }
    if (unsafeDescriptionByte(ch)) return error.InvalidDescription;
    return 1;
}

fn unsafeDescriptionByte(ch: u8) bool {
    return ch < ' ' or ch == 0x7f;
}

fn addLen(total: *usize, add: usize) BuildError!void {
    if (add > std.math.maxInt(usize) - total.*) return error.MessageTooLong;
    total.* += add;
}

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) BuildError!void {
        if (bytes.len > self.buf.len - self.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *SliceWriter, byte: u8) BuildError!void {
        if (self.len >= self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = byte;
        self.len += 1;
    }

    fn appendDescription(self: *SliceWriter, description: []const u8, options: BuildOptions) BuildError!void {
        for (description) |ch| {
            if (options.escape_description_controls) {
                switch (ch) {
                    0 => try self.append("\\0"),
                    '\r' => try self.append("\\r"),
                    '\n' => try self.append("\\n"),
                    '\t' => try self.append("\\t"),
                    '\\' => try self.append("\\\\"),
                    0x01...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => try self.appendHexEscape(ch),
                    else => try self.appendByte(ch),
                }
            } else {
                if (unsafeDescriptionByte(ch)) return error.InvalidDescription;
                try self.appendByte(ch);
            }
        }
    }

    fn appendHexEscape(self: *SliceWriter, byte: u8) BuildError!void {
        const HEX = "0123456789ABCDEF";
        try self.append("\\x");
        try self.appendByte(HEX[byte >> 4]);
        try self.appendByte(HEX[byte & 0x0f]);
    }
};

test "builds FAIL WARN and NOTE replies" {
    var buf: [256]u8 = undefined;

    const fail_line = try fail("REGISTER", .ACCOUNT_REQUIRED, "Authentication is required").write(&buf);
    try std.testing.expectEqualStrings(
        "FAIL REGISTER ACCOUNT_REQUIRED :Authentication is required",
        fail_line,
    );

    const warn_line = try warn("CHATHISTORY", .MESSAGE_RATE_LIMITED, "History query was throttled").write(&buf);
    try std.testing.expectEqualStrings(
        "WARN CHATHISTORY MESSAGE_RATE_LIMITED :History query was throttled",
        warn_line,
    );

    const note_line = try note("ACCESS", .LIST_EMPTY, "No access entries matched").write(&buf);
    try std.testing.expectEqualStrings(
        "NOTE ACCESS LIST_EMPTY :No access entries matched",
        note_line,
    );
}

test "builds replies with context params" {
    var buf: [256]u8 = undefined;
    const line = try fail("PROP", .INVALID_PROPERTY, "Property cannot be set")
        .withContext(&.{ "#mizuchi", "topic.locked" })
        .write(&buf);

    try std.testing.expectEqualStrings(
        "FAIL PROP INVALID_PROPERTY #mizuchi topic.locked :Property cannot be set",
        line,
    );
}

test "escapes description controls and enforces length" {
    var buf: [128]u8 = undefined;
    const line = try note("MEMO", .UNKNOWN_ERROR, "bad\r\n\x00\\tab\tbell\x07end").write(&buf);
    try std.testing.expectEqualStrings(
        "NOTE MEMO UNKNOWN_ERROR :bad\\r\\n\\0\\\\tab\\tbell\\x07end",
        line,
    );

    try std.testing.expectError(
        error.MessageTooLong,
        fail("REGISTER", .INVALID_PARAMS, "too long").withMaxBodyLen(16).write(&buf),
    );
    try std.testing.expectError(
        error.InvalidDescription,
        fail("REGISTER", .INVALID_PARAMS, "bad\nline").withStrictDescription().write(&buf),
    );
}

test "validates command code and context tokens" {
    var buf: [128]u8 = undefined;

    try std.testing.expectError(
        error.InvalidCommand,
        fail("BAD COMMAND", .INVALID_PARAMS, "bad command").write(&buf),
    );
    try std.testing.expectError(
        error.InvalidContext,
        warn("ACCESS", .INVALID_TARGET, "bad context").withContext(&.{"bad\tcontext"}).write(&buf),
    );
    try std.testing.expectError(
        error.InvalidCode,
        custom(.fail, "REGISTER", "bad_code", "bad code").write(&buf),
    );
}

test "code catalog round-trip" {
    inline for (@typeInfo(Code).@"enum".fields) |field| {
        const code = @field(Code, field.name);
        try std.testing.expectEqual(code, parseCatalogCode(field.name).?);
        try std.testing.expectEqualStrings(field.name, (CodeToken{ .catalog = code }).token());
        try std.testing.expect(validCodeToken(field.name));
    }

    try std.testing.expectEqual(@as(?Code, null), parseCatalogCode("DOES_NOT_EXIST"));
}

test "caller-owned buffer path uses std.testing.allocator without leaks" {
    const allocator = std.testing.allocator;
    const buf = try allocator.alloc(u8, MAX_LEGACY_BODY);
    defer allocator.free(buf);

    const line = try custom(.fail, "IRCX", "IRCX_POLICY_DENIED", "Denied by event policy")
        .withContext(&.{ "EVENT", "message.create" })
        .withMaxBodyLen(MAX_LEGACY_BODY)
        .write(buf);

    try std.testing.expectEqualStrings(
        "FAIL IRCX IRCX_POLICY_DENIED EVENT message.create :Denied by event policy",
        line,
    );
}
