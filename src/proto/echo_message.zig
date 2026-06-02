//! IRCv3 echo-message helpers.
//!
//! Delivery routing, message tag construction, and normal PRIVMSG/NOTICE/TAGMSG
//! authorization are owned by the caller. This module validates the fields that
//! form the echoed IRC line, gates self-echoes on negotiated capabilities, and
//! builds the final line into caller-provided storage.
const std = @import("std");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_TARGET_BYTES: usize = 512;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 4096;
pub const DEFAULT_MAX_TAG_PREFIX_BYTES: usize = 8191;

pub const EchoMessageError = error{
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidTarget,
    TargetTooLong,
    InvalidText,
    TextTooLong,
    InvalidTagPrefix,
    TagPrefixTooLong,
    MissingText,
    UnexpectedText,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits for echo-message builders and validators.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_target_bytes: usize = DEFAULT_MAX_TARGET_BYTES,
    max_text_bytes: usize = DEFAULT_MAX_TEXT_BYTES,
    max_tag_prefix_bytes: usize = DEFAULT_MAX_TAG_PREFIX_BYTES,
    allow_empty_text: bool = false,
};

/// Message commands covered by IRCv3 echo-message.
pub const MsgKind = enum {
    privmsg,
    notice,
    tagmsg,

    pub fn command(self: MsgKind) []const u8 {
        return switch (self) {
            .privmsg => "PRIVMSG",
            .notice => "NOTICE",
            .tagmsg => "TAGMSG",
        };
    }
};

/// Identity used as the IRC message prefix: `:nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Negotiated client capabilities relevant to echo-message.
pub const Caps = struct {
    echo_message: bool = false,
    message_tags: bool = false,
};

/// One client that may receive its own echoed message.
pub const EchoCandidate = struct {
    client: ClientId,
    caps: Caps = .{},
};

/// One selected echo-message recipient.
pub const EchoRecipient = struct {
    client: ClientId,
};

/// Caller-provided storage for selected echo-message recipients.
pub const EchoRecipientSink = struct {
    recipients: []EchoRecipient,
    count: usize = 0,

    pub fn append(self: *EchoRecipientSink, client: ClientId) EchoMessageError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client };
        self.count += 1;
    }

    pub fn slice(self: *const EchoRecipientSink) []const EchoRecipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *EchoRecipientSink) void {
        self.count = 0;
    }
};

/// Return whether a client should receive this self-echo.
pub fn shouldEcho(kind: MsgKind, caps: Caps) bool {
    if (!caps.echo_message) return false;
    return kind != .tagmsg or caps.message_tags;
}

/// Select the originating client when its capabilities allow this self-echo.
pub fn selectEchoRecipient(
    kind: MsgKind,
    candidate: EchoCandidate,
    sink: *EchoRecipientSink,
) EchoMessageError!void {
    if (shouldEcho(kind, candidate.caps)) try sink.append(candidate.client);
}

/// Build an echoed PRIVMSG, NOTICE, or TAGMSG line into caller-owned storage.
pub fn buildEchoLine(
    out: []u8,
    kind: MsgKind,
    prefix: Prefix,
    target: []const u8,
    text: ?[]const u8,
    tag_prefix: ?[]const u8,
) EchoMessageError![]const u8 {
    return buildEchoLineWith(.{}, out, kind, prefix, target, text, tag_prefix);
}

/// Build an echoed line using caller-selected compile-time limits.
pub fn buildEchoLineWith(
    comptime params: Params,
    out: []u8,
    kind: MsgKind,
    prefix: Prefix,
    target: []const u8,
    text: ?[]const u8,
    tag_prefix: ?[]const u8,
) EchoMessageError![]const u8 {
    try validatePrefix(params, prefix);
    try validateTargetWith(params, target);
    if (tag_prefix) |tags| try validateTagPrefixWith(params, tags);

    const body = switch (kind) {
        .privmsg, .notice => text orelse return error.MissingText,
        .tagmsg => blk: {
            if (text != null) return error.UnexpectedText;
            break :blk null;
        },
    };
    if (body) |bytes| try validateTextWith(params, bytes);

    var n: usize = 0;
    if (tag_prefix) |tags| try append(out, &n, tags);
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try appendByte(out, &n, ' ');
    try append(out, &n, kind.command());
    try appendByte(out, &n, ' ');
    try append(out, &n, target);
    if (body) |bytes| {
        try append(out, &n, " :");
        try append(out, &n, bytes);
    }
    return out[0..n];
}

pub fn validateNick(nick: []const u8) EchoMessageError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) EchoMessageError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) EchoMessageError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) EchoMessageError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) EchoMessageError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) EchoMessageError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateTarget(target: []const u8) EchoMessageError!void {
    return validateTargetWith(.{}, target);
}

pub fn validateTargetWith(comptime params: Params, target: []const u8) EchoMessageError!void {
    if (target.len == 0) return error.InvalidTarget;
    if (target.len > params.max_target_bytes) return error.TargetTooLong;
    for (target) |ch| {
        if (!validTargetByte(ch)) return error.InvalidTarget;
    }
}

pub fn validateText(text: []const u8) EchoMessageError!void {
    return validateTextWith(.{}, text);
}

pub fn validateTextWith(comptime params: Params, text: []const u8) EchoMessageError!void {
    if (!params.allow_empty_text and text.len == 0) return error.InvalidText;
    if (text.len > params.max_text_bytes) return error.TextTooLong;
    for (text) |ch| {
        if (!validTextByte(ch)) return error.InvalidText;
    }
}

pub fn validateTagPrefix(tag_prefix: []const u8) EchoMessageError!void {
    return validateTagPrefixWith(.{}, tag_prefix);
}

pub fn validateTagPrefixWith(comptime params: Params, tag_prefix: []const u8) EchoMessageError!void {
    if (tag_prefix.len == 0) return;
    if (tag_prefix.len > params.max_tag_prefix_bytes) return error.TagPrefixTooLong;
    if (tag_prefix.len < 3 or tag_prefix[0] != '@' or tag_prefix[tag_prefix.len - 1] != ' ') {
        return error.InvalidTagPrefix;
    }
    for (tag_prefix[1 .. tag_prefix.len - 1]) |ch| {
        if (!validTagDataByte(ch)) return error.InvalidTagPrefix;
    }
}

fn validatePrefix(comptime params: Params, prefix: Prefix) EchoMessageError!void {
    try validateNickWith(params, prefix.nick);
    try validateUserWith(params, prefix.user);
    try validateHostWith(params, prefix.host);
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

fn validTargetByte(ch: u8) bool {
    return switch (ch) {
        0, '\r', '\n', ' ', 0x07 => false,
        else => ch >= 0x20 and ch != 0x7f,
    };
}

fn validTextByte(ch: u8) bool {
    return ch != 0 and ch != '\r' and ch != '\n';
}

fn validTagDataByte(ch: u8) bool {
    return ch != 0 and ch != '\r' and ch != '\n' and ch != ' ';
}

fn append(out: []u8, n: *usize, bytes: []const u8) EchoMessageError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) EchoMessageError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

test "echo-message builds tagged privmsg and notice lines" {
    var buf: [256]u8 = undefined;
    const privmsg = try buildEchoLine(&buf, .privmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "cloak.example",
    }, "#chat", "hello there", "@time=2026-06-02T12:00:00.000Z;msgid=abc;account=alice ");
    try std.testing.expectEqualStrings(
        "@time=2026-06-02T12:00:00.000Z;msgid=abc;account=alice :alice!u@cloak.example PRIVMSG #chat :hello there",
        privmsg,
    );

    const notice = try buildEchoLine(&buf, .notice, .{
        .nick = "alice",
        .user = "u",
        .host = "cloak.example",
    }, "bob", "heads up", null);
    try std.testing.expectEqualStrings(":alice!u@cloak.example NOTICE bob :heads up", notice);
}

test "echo-message builds tagmsg without text or trailing parameter" {
    var buf: [160]u8 = undefined;
    const line = try buildEchoLine(&buf, .tagmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "cloak.example",
    }, "#chat", null, "@msgid=abc;+typing=active ");

    try std.testing.expectEqualStrings("@msgid=abc;+typing=active :alice!u@cloak.example TAGMSG #chat", line);
    try std.testing.expectError(error.UnexpectedText, buildEchoLine(&buf, .tagmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "cloak.example",
    }, "#chat", "", null));
}

test "echo-message cap gating and recipient sink" {
    try std.testing.expect(!shouldEcho(.privmsg, .{}));
    try std.testing.expect(shouldEcho(.privmsg, .{ .echo_message = true }));
    try std.testing.expect(shouldEcho(.notice, .{ .echo_message = true }));
    try std.testing.expect(!shouldEcho(.tagmsg, .{ .echo_message = true }));
    try std.testing.expect(shouldEcho(.tagmsg, .{ .echo_message = true, .message_tags = true }));

    var storage: [1]EchoRecipient = undefined;
    var sink = EchoRecipientSink{ .recipients = &storage };
    try selectEchoRecipient(.privmsg, .{ .client = 42, .caps = .{ .echo_message = true } }, &sink);
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try std.testing.expectEqual(@as(ClientId, 42), sink.slice()[0].client);

    sink.reset();
    try selectEchoRecipient(.tagmsg, .{ .client = 42, .caps = .{ .echo_message = true } }, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);

    try selectEchoRecipient(.notice, .{ .client = 42, .caps = .{ .echo_message = true } }, &sink);
    try std.testing.expectError(error.TooManyRecipients, selectEchoRecipient(.notice, .{
        .client = 43,
        .caps = .{ .echo_message = true },
    }, &sink));
}

test "echo-message reports output too small" {
    var buf: [12]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildEchoLine(&buf, .privmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#chat", "hello", null));
}

test "echo-message rejects invalid attacker-controlled bytes" {
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidNick, buildEchoLine(&buf, .privmsg, .{
        .nick = "bad nick",
        .user = "u",
        .host = "h",
    }, "#chat", "hello", null));
    try std.testing.expectError(error.InvalidUser, buildEchoLine(&buf, .privmsg, .{
        .nick = "alice",
        .user = "bad:user",
        .host = "h",
    }, "#chat", "hello", null));
    try std.testing.expectError(error.InvalidHost, buildEchoLine(&buf, .privmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "bad host",
    }, "#chat", "hello", null));
    try std.testing.expectError(error.InvalidTarget, buildEchoLine(&buf, .privmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#chat\rINJECT", "hello", null));
    try std.testing.expectError(error.InvalidTarget, buildEchoLine(&buf, .privmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#bad target", "hello", null));
    try std.testing.expectError(error.InvalidText, buildEchoLine(&buf, .privmsg, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#chat", "hello\nINJECT", null));
    try std.testing.expectError(error.InvalidTagPrefix, buildEchoLine(&buf, .notice, .{
        .nick = "alice",
        .user = "u",
        .host = "h",
    }, "#chat", "hello", "@msgid=abc"));
}
