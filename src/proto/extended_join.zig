//! IRCv3 extended-join broadcast helpers.
//!
//! Channel membership and visibility are owned by the caller. This module
//! validates attacker-controlled JOIN fields, builds canonical IRC lines into
//! caller-provided storage, and selects which already-visible clients receive
//! extended JOINs versus plain legacy JOINs.
const std = @import("std");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 64;
pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 64;
pub const DEFAULT_MAX_REALNAME_BYTES: usize = 256;

pub const ExtendedJoinError = error{
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidChannel,
    ChannelTooLong,
    InvalidAccount,
    AccountTooLong,
    InvalidRealname,
    RealnameTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits for builders and validators.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_account_bytes: usize = DEFAULT_MAX_ACCOUNT_BYTES,
    max_realname_bytes: usize = DEFAULT_MAX_REALNAME_BYTES,
    allow_empty_realname: bool = false,
};

/// Identity used as the IRC message prefix: `:nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Account state emitted in an extended JOIN.
pub const Account = union(enum) {
    logged_in: []const u8,
    none,
};

/// One visible client that may receive an IRCv3 extended-join broadcast.
pub const Watcher = struct {
    client: ClientId,
    extended_join: bool = false,
};

/// The JOIN representation selected for one visible recipient.
pub const JoinForm = enum {
    plain,
    extended,
};

/// One selected JOIN recipient and the message form it negotiated.
pub const JoinRecipient = struct {
    client: ClientId,
    form: JoinForm,
};

/// Caller-provided storage for selected JOIN recipients.
pub const JoinRecipientSink = struct {
    recipients: []JoinRecipient,
    count: usize = 0,

    pub fn append(self: *JoinRecipientSink, client: ClientId, form: JoinForm) ExtendedJoinError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client, .form = form };
        self.count += 1;
    }

    pub fn slice(self: *const JoinRecipientSink) []const JoinRecipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *JoinRecipientSink) void {
        self.count = 0;
    }
};

/// Build `:nick!user@host JOIN <channel> <account> :<realname>` into caller-owned storage.
pub fn buildExtendedJoinLine(
    out: []u8,
    prefix: Prefix,
    channel: []const u8,
    account: Account,
    realname: []const u8,
) ExtendedJoinError![]const u8 {
    return buildExtendedJoinLineWith(.{}, out, prefix, channel, account, realname);
}

/// Build an extended JOIN line using caller-selected compile-time limits.
pub fn buildExtendedJoinLineWith(
    comptime params: Params,
    out: []u8,
    prefix: Prefix,
    channel: []const u8,
    account: Account,
    realname: []const u8,
) ExtendedJoinError![]const u8 {
    try validatePrefix(params, prefix);
    try validateChannelWith(params, channel);
    try validateAccountWith(params, account);
    try validateRealnameWith(params, realname);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try append(out, &n, " JOIN ");
    try append(out, &n, channel);
    try appendByte(out, &n, ' ');
    switch (account) {
        .logged_in => |name| try append(out, &n, name),
        .none => try appendByte(out, &n, '*'),
    }
    try append(out, &n, " :");
    try append(out, &n, realname);
    return out[0..n];
}

/// Build `:nick!user@host JOIN <channel>` into caller-owned storage.
pub fn buildPlainJoinLine(
    out: []u8,
    prefix: Prefix,
    channel: []const u8,
) ExtendedJoinError![]const u8 {
    return buildPlainJoinLineWith(.{}, out, prefix, channel);
}

/// Build a plain JOIN line using caller-selected compile-time limits.
pub fn buildPlainJoinLineWith(
    comptime params: Params,
    out: []u8,
    prefix: Prefix,
    channel: []const u8,
) ExtendedJoinError![]const u8 {
    try validatePrefix(params, prefix);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, prefix.nick);
    try appendByte(out, &n, '!');
    try append(out, &n, prefix.user);
    try appendByte(out, &n, '@');
    try append(out, &n, prefix.host);
    try append(out, &n, " JOIN ");
    try append(out, &n, channel);
    return out[0..n];
}

/// Select visible clients for a JOIN broadcast.
pub fn selectJoinRecipients(
    watchers: []const Watcher,
    sink: *JoinRecipientSink,
) ExtendedJoinError!void {
    for (watchers) |watcher| {
        try sink.append(watcher.client, if (watcher.extended_join) .extended else .plain);
    }
}

pub fn validateNick(nick: []const u8) ExtendedJoinError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) ExtendedJoinError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) ExtendedJoinError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) ExtendedJoinError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) ExtendedJoinError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) ExtendedJoinError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateChannel(channel: []const u8) ExtendedJoinError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) ExtendedJoinError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefixByte(channel[0])) return error.InvalidChannel;
    for (channel[1..]) |ch| {
        if (!validChannelNameByte(ch)) return error.InvalidChannel;
    }
}

pub fn validateAccount(account: Account) ExtendedJoinError!void {
    return validateAccountWith(.{}, account);
}

pub fn validateAccountWith(comptime params: Params, account: Account) ExtendedJoinError!void {
    switch (account) {
        .none => {},
        .logged_in => |name| {
            if (name.len == 0) return error.InvalidAccount;
            if (name.len > params.max_account_bytes) return error.AccountTooLong;
            if (std.mem.eql(u8, name, "*")) return error.InvalidAccount;
            for (name) |ch| {
                if (!validAccountByte(ch)) return error.InvalidAccount;
            }
        },
    }
}

pub fn validateRealname(realname: []const u8) ExtendedJoinError!void {
    return validateRealnameWith(.{}, realname);
}

pub fn validateRealnameWith(comptime params: Params, realname: []const u8) ExtendedJoinError!void {
    if (!params.allow_empty_realname and realname.len == 0) return error.InvalidRealname;
    if (realname.len > params.max_realname_bytes) return error.RealnameTooLong;
    for (realname) |ch| {
        if (!validRealnameByte(ch)) return error.InvalidRealname;
    }
}

fn validatePrefix(comptime params: Params, prefix: Prefix) ExtendedJoinError!void {
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

fn validChannelPrefixByte(ch: u8) bool {
    return switch (ch) {
        '#', '&', '+', '!' => true,
        else => false,
    };
}

fn validChannelNameByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return switch (ch) {
        ',', ':' => false,
        else => true,
    };
}

fn validAccountByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return switch (ch) {
        ':' => false,
        else => true,
    };
}

fn validRealnameByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn append(out: []u8, n: *usize, bytes: []const u8) ExtendedJoinError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) ExtendedJoinError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectJoinRecipient(
    recipient: JoinRecipient,
    client: ClientId,
    form: JoinForm,
) !void {
    try std.testing.expectEqual(client, recipient.client);
    try std.testing.expectEqual(form, recipient.form);
}

test "extended join line build with account" {
    var buf: [128]u8 = undefined;
    const line = try buildExtendedJoinLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "#chat", .{ .logged_in = "alice-account" }, "Alice Example");

    try std.testing.expectEqualStrings(":alice!user@cloak.example JOIN #chat alice-account :Alice Example", line);
}

test "extended join line build with account sentinel" {
    var buf: [128]u8 = undefined;
    const line = try buildExtendedJoinLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "#chat", .none, "Alice Example");

    try std.testing.expectEqualStrings(":alice!user@cloak.example JOIN #chat * :Alice Example", line);
}

test "plain join line build" {
    var buf: [128]u8 = undefined;
    const line = try buildPlainJoinLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "#chat");

    try std.testing.expectEqualStrings(":alice!user@cloak.example JOIN #chat", line);
}

test "cap-gated recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .extended_join = true },
        .{ .client = 2, .extended_join = false },
        .{ .client = 3, .extended_join = true },
    };

    var storage: [3]JoinRecipient = undefined;
    var sink = JoinRecipientSink{ .recipients = &storage };
    try selectJoinRecipients(&watchers, &sink);

    try std.testing.expectEqual(@as(usize, 3), sink.slice().len);
    try expectJoinRecipient(sink.slice()[0], 1, .extended);
    try expectJoinRecipient(sink.slice()[1], 2, .plain);
    try expectJoinRecipient(sink.slice()[2], 3, .extended);

    sink.reset();
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
}

test "output too small rejected" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildPlainJoinLine(&buf, .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "#chat"));
}

test "too many recipients rejected" {
    const watchers = [_]Watcher{
        .{ .client = 1, .extended_join = true },
        .{ .client = 2, .extended_join = false },
    };

    var storage: [1]JoinRecipient = undefined;
    var sink = JoinRecipientSink{ .recipients = &storage };
    try std.testing.expectError(error.TooManyRecipients, selectJoinRecipients(&watchers, &sink));
}

test "invalid identity fields rejected" {
    try std.testing.expectError(error.InvalidNick, validateNick("bad nick"));
    try std.testing.expectError(error.InvalidUser, validateUser("bad user"));
    try std.testing.expectError(error.InvalidUser, validateUser("bad\ruser"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad host.example"));
    try std.testing.expectError(error.InvalidHost, validateHost("bad\nhost.example"));

    var buf: [128]u8 = undefined;
    try std.testing.expectError(error.InvalidNick, buildPlainJoinLine(&buf, .{
        .nick = "bad nick",
        .user = "user",
        .host = "cloak.example",
    }, "#chat"));
}

test "invalid channel account and realname rejected" {
    try std.testing.expectError(error.InvalidChannel, validateChannel("chat"));
    try std.testing.expectError(error.InvalidChannel, validateChannel("#bad channel"));
    try std.testing.expectError(error.InvalidChannel, validateChannel("#bad,channel"));
    try std.testing.expectError(error.InvalidAccount, validateAccount(.{ .logged_in = "" }));
    try std.testing.expectError(error.InvalidAccount, validateAccount(.{ .logged_in = "*" }));
    try std.testing.expectError(error.InvalidAccount, validateAccount(.{ .logged_in = "bad account" }));
    try std.testing.expectError(error.InvalidAccount, validateAccount(.{ .logged_in = "bad:account" }));
    try validateAccount(.none);
    try std.testing.expectError(error.InvalidRealname, validateRealname(""));
    try std.testing.expectError(error.InvalidRealname, validateRealname("bad\nrealname"));
}

test "custom limits are enforced" {
    try std.testing.expectError(error.NickTooLong, validateNickWith(.{ .max_nick_bytes = 3 }, "alice"));
    try std.testing.expectError(error.ChannelTooLong, validateChannelWith(.{ .max_channel_bytes = 4 }, "#chat"));
    try std.testing.expectError(error.AccountTooLong, validateAccountWith(.{ .max_account_bytes = 3 }, .{ .logged_in = "alice" }));
    try std.testing.expectError(error.RealnameTooLong, validateRealnameWith(.{ .max_realname_bytes = 3 }, "Alice"));
    try validateRealnameWith(.{ .allow_empty_realname = true }, "");
}
