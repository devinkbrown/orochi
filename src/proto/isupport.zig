// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRC RPL_ISUPPORT (005) token builder.
//!
//! The module keeps ISUPPORT composition allocation-free: callers own token
//! storage, reply storage, and output bytes. Tokens are validated before they
//! can reach the wire, then chunked by both IRC's 13-token 005 convention and
//! the 512-octet message limit including CRLF.
const std = @import("std");
const numeric = @import("../proto/numeric.zig");
const limits_config = @import("limits_config.zig");

pub const MAX_TOKENS_PER_LINE: usize = 13;
pub const MAX_IRC_LINE_BYTES: usize = 512;
pub const DEFAULT_TRAILING: []const u8 = "are supported by this server";

pub const IsupportError = error{
    InvalidLimit,
    InvalidParameter,
    InvalidTokenName,
    InvalidTokenValue,
    InvalidTrailing,
    LineTooLong,
    NegatedTokenHasValue,
    OutputTooSmall,
    TokenTooLong,
    TooManyLines,
    TooManyTokens,
};

/// One ISUPPORT token. `value == null` renders as a valueless token, while
/// `negated` renders as `-TOKEN` and must not carry a value.
pub const Token = struct {
    name: []const u8,
    value: ?[]const u8 = null,
    negated: bool = false,

    pub fn valueless(name: []const u8) IsupportError!Token {
        const token = Token{ .name = name };
        try token.validate();
        return token;
    }

    pub fn valued(name: []const u8, value: []const u8) IsupportError!Token {
        const token = Token{ .name = name, .value = value };
        try token.validate();
        return token;
    }

    pub fn negation(name: []const u8) IsupportError!Token {
        const token = Token{ .name = name, .negated = true };
        try token.validate();
        return token;
    }

    pub fn validate(self: Token) IsupportError!void {
        if (!validTokenName(self.name)) return error.InvalidTokenName;
        if (self.negated and self.value != null) return error.NegatedTokenHasValue;
        if (self.value) |bytes| {
            if (!validTokenValue(bytes)) return error.InvalidTokenValue;
        }
    }

    pub fn renderedLen(self: Token) IsupportError!usize {
        try self.validate();
        if (self.negated) return self.name.len + 1;
        return self.name.len + if (self.value) |bytes| bytes.len + 1 else 0;
    }

    pub fn write(self: Token, out: []u8) IsupportError![]const u8 {
        const len = try self.renderedLen();
        if (len > out.len) return error.OutputTooSmall;

        var cursor: usize = 0;
        if (self.negated) {
            out[cursor] = '-';
            cursor += 1;
        }

        @memcpy(out[cursor .. cursor + self.name.len], self.name);
        cursor += self.name.len;

        if (self.value) |bytes| {
            out[cursor] = '=';
            cursor += 1;
            @memcpy(out[cursor .. cursor + bytes.len], bytes);
            cursor += bytes.len;
        }

        return out[0..cursor];
    }
};

/// Fixed-capacity token map. Adding a token with an existing name replaces it,
/// so module registries can override defaults without heap traffic.
pub fn TokenMap(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        entries: [capacity]Token = [_]Token{.{ .name = "" }} ** capacity,
        count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn put(self: *Self, token: Token) IsupportError!void {
            try token.validate();
            if (self.findIndex(token.name)) |index| {
                self.entries[index] = token;
                return;
            }
            if (self.count >= capacity) return error.TooManyTokens;
            self.entries[self.count] = token;
            self.count += 1;
        }

        pub fn putValueless(self: *Self, name: []const u8) IsupportError!void {
            try self.put(try Token.valueless(name));
        }

        pub fn putValue(self: *Self, name: []const u8, value: []const u8) IsupportError!void {
            try self.put(try Token.valued(name, value));
        }

        pub fn putNegation(self: *Self, name: []const u8) IsupportError!void {
            try self.put(try Token.negation(name));
        }

        pub fn get(self: *const Self, name: []const u8) ?Token {
            if (self.findIndex(name)) |index| return self.entries[index];
            return null;
        }

        pub fn slice(self: *const Self) []const Token {
            return self.entries[0..self.count];
        }

        pub fn loadDefaults(self: *Self) IsupportError!void {
            for (default_tokens) |token| {
                try self.put(token);
            }
        }

        fn findIndex(self: *const Self, name: []const u8) ?usize {
            var index: usize = 0;
            while (index < self.count) : (index += 1) {
                if (std.mem.eql(u8, self.entries[index].name, name)) return index;
            }
            return null;
        }
    };
}

/// One emitted 005 line, including prefix and CRLF.
pub const ReplyLine = struct {
    bytes: []const u8,
};

/// Caller-owned storage for emitted RPL_ISUPPORT lines.
pub const ReplySink = struct {
    lines: []ReplyLine,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(self: *ReplySink, bytes: []const u8) IsupportError!void {
        if (self.count >= self.lines.len) return error.TooManyLines;
        if (self.used + bytes.len > self.storage.len) return error.OutputTooSmall;

        const start = self.used;
        const end = start + bytes.len;
        @memcpy(self.storage[start..end], bytes);
        self.lines[self.count] = .{ .bytes = self.storage[start..end] };
        self.count += 1;
        self.used = end;
    }

    pub fn slice(self: *const ReplySink) []const ReplyLine {
        return self.lines[0..self.count];
    }
};

/// Complete RPL_ISUPPORT emitter configuration.
pub const Builder = struct {
    server_name: []const u8,
    requester: []const u8,
    tokens: []const Token,
    trailing: []const u8 = DEFAULT_TRAILING,
    max_line_bytes: usize = MAX_IRC_LINE_BYTES,
    max_tokens_per_line: usize = MAX_TOKENS_PER_LINE,

    pub fn emit(self: Builder, sink: *ReplySink) IsupportError!void {
        try validateParam(self.server_name);
        try validateParam(self.requester);
        try validateTrailing(self.trailing);
        if (self.max_line_bytes == 0 or self.max_tokens_per_line == 0) {
            return error.InvalidLimit;
        }

        const line_limit = @min(self.max_line_bytes, MAX_IRC_LINE_BYTES);
        const token_limit = @min(self.max_tokens_per_line, MAX_TOKENS_PER_LINE);
        const fixed_len = fixedLineLen(self.server_name, self.requester, self.trailing);
        if (fixed_len > line_limit) return error.LineTooLong;

        if (self.tokens.len == 0) {
            var line_buf: [MAX_IRC_LINE_BYTES]u8 = undefined;
            const line = try writeLine(&line_buf, self.server_name, self.requester, self.tokens, self.trailing);
            if (line.len > line_limit) return error.LineTooLong;
            try sink.append(line);
            return;
        }

        var start: usize = 0;
        while (start < self.tokens.len) {
            var token_count: usize = 0;
            var line_len = fixed_len;

            while (start + token_count < self.tokens.len and token_count < token_limit) {
                const token_len = try self.tokens[start + token_count].renderedLen();
                const candidate_len = line_len + 1 + token_len;
                if (candidate_len > line_limit) {
                    if (token_count == 0) return error.TokenTooLong;
                    break;
                }
                line_len = candidate_len;
                token_count += 1;
            }

            var line_buf: [MAX_IRC_LINE_BYTES]u8 = undefined;
            const line = try writeLine(
                &line_buf,
                self.server_name,
                self.requester,
                self.tokens[start .. start + token_count],
                self.trailing,
            );
            try sink.append(line);
            start += token_count;
        }
    }
};

/// Emit the default modern IRCv3/IRCX ISUPPORT surface.
pub fn emitDefault(server_name: []const u8, requester: []const u8, sink: *ReplySink) IsupportError!void {
    try (Builder{
        .server_name = server_name,
        .requester = requester,
        .tokens = &default_tokens,
    }).emit(sink);
}

/// Modern default token set. Modules may copy these into a `TokenMap` and
/// replace entries as policy/config changes.
pub const default_tokens = [_]Token{
    .{ .name = "CHANTYPES", .value = "#&" },
    .{ .name = "PREFIX", .value = "(qaohv)~&@%+" },
    .{ .name = "CHANMODES", .value = "b,k,l,imnpst" },
    .{ .name = "NICKLEN", .value = "64" },
    .{ .name = "CHANNELLEN", .value = "64" },
    .{ .name = "TOPICLEN", .value = "512" },
    .{ .name = "AWAYLEN", .value = "390" },
    .{ .name = "CASEMAPPING", .value = "ascii" },
    .{ .name = "NETWORK", .value = "Orochi" },
    .{ .name = "ELIST", .value = "CMNTU" },
    .{ .name = "MONITOR", .value = "512" },
    .{ .name = "CHATHISTORY", .value = "1000" },
    .{ .name = "UTF8ONLY" },
    .{ .name = "BOT" },
    .{ .name = "SAFELIST" },
    .{ .name = "STATUSMSG", .value = "~&@%+" },
    .{ .name = "TARGMAX", .value = "JOIN:,WHOIS:1,PRIVMSG:,NOTICE:,MONITOR:" },
    .{ .name = "CHANLIMIT", .value = "#:100" },
    .{ .name = "MAXLIST", .value = "b:100,e:100,I:100" },
    .{ .name = "MODES", .value = "4" },
    .{ .name = "EXCEPTS", .value = "e" },
    .{ .name = "INVEX", .value = "I" },
    .{ .name = "EXTBAN", .value = "$,acgmrz" },
    .{ .name = "ACCOUNTEXTBAN", .value = "a" },
    .{ .name = "WHOX" },
    .{ .name = "IRCX" },
    .{ .name = "MAXCODEPAGE", .value = "0" },
    .{ .name = "MAXLANGUAGE", .value = "0" },
    .{ .name = "MAXPROP", .value = "512" },
    .{ .name = "MAXACCESS", .value = "128" },
};

/// Config-driven ISUPPORT token surface.
///
/// `TokenSet` owns inline storage for the numeric/composite token values that
/// vary with policy (NICKLEN, CHANLIMIT, MAXLIST, ...) so the resulting `Token`
/// slice can be emitted exactly like `default_tokens`. The valueless capability
/// tokens (UTF8ONLY, BOT, IRCX, ...) are preserved in the same order as
/// `default_tokens`, so a `Limits{}` default reproduces the historical 005
/// surface byte-for-byte.
///
/// Build with `TokenSet.fromLimits`, then pass `set.slice()` to a `Builder` or
/// call `emitFromLimits` directly.
pub const TokenSet = struct {
    /// Inline scratch for all formatted token values. 512 bytes is comfortably
    /// larger than the sum of every value the default surface produces.
    storage: [512]u8 = undefined,
    used: usize = 0,
    tokens: [default_tokens.len]Token = undefined,
    count: usize = 0,

    fn fmtUint(self: *TokenSet, value: u64) []const u8 {
        const start = self.used;
        const written = std.fmt.bufPrint(self.storage[start..], "{d}", .{value}) catch unreachable;
        self.used += written.len;
        return self.storage[start .. start + written.len];
    }

    fn fmtComposite(self: *TokenSet, comptime tmpl: []const u8, args: anytype) []const u8 {
        const start = self.used;
        const written = std.fmt.bufPrint(self.storage[start..], tmpl, args) catch unreachable;
        self.used += written.len;
        return self.storage[start .. start + written.len];
    }

    fn pushValue(self: *TokenSet, name: []const u8, value: []const u8) void {
        self.tokens[self.count] = .{ .name = name, .value = value };
        self.count += 1;
    }

    fn pushValueless(self: *TokenSet, name: []const u8) void {
        self.tokens[self.count] = .{ .name = name };
        self.count += 1;
    }

    pub fn slice(self: *const TokenSet) []const Token {
        return self.tokens[0..self.count];
    }

    /// Build the ISUPPORT token surface from policy limits into caller-owned
    /// `self`. Order matches `default_tokens`. The caller must keep `self` alive
    /// while emitting, because token values alias `self.storage`.
    pub fn build(self: *TokenSet, limits: *const limits_config.Limits) void {
        self.used = 0;
        self.count = 0;
        self.pushValue("CHANTYPES", limits.chantypes.slice());
        self.pushValue("PREFIX", limits.prefix.slice());
        self.pushValue("CHANMODES", limits.chanmodes.slice());
        self.pushValue("NICKLEN", self.fmtUint(limits.nick_len));
        self.pushValue("CHANNELLEN", self.fmtUint(limits.channel_len));
        self.pushValue("TOPICLEN", self.fmtUint(limits.topic_len));
        self.pushValue("AWAYLEN", self.fmtUint(limits.away_len));
        self.pushValue("CASEMAPPING", limits.casemapping.slice());
        self.pushValue("NETWORK", limits.network.slice());
        self.pushValue("ELIST", limits.elist.slice());
        self.pushValue("MONITOR", self.fmtUint(limits.monitor_targets));
        self.pushValue("CHATHISTORY", self.fmtUint(limits.history_max_messages_advertised));
        self.pushValueless("UTF8ONLY");
        self.pushValueless("BOT");
        self.pushValueless("SAFELIST");
        self.pushValue("STATUSMSG", limits.statusmsg.slice());
        self.pushValue("TARGMAX", limits.targmax.slice());
        self.pushValue("CHANLIMIT", self.fmtComposite("#:{d}", .{limits.chan_limit}));
        self.pushValue("MAXLIST", self.fmtComposite("b:{d},e:{d},I:{d}", .{
            limits.max_ban_list,
            limits.max_except_list,
            limits.max_invex_list,
        }));
        self.pushValue("MODES", self.fmtUint(limits.modes_per_line));
        self.pushValue("EXCEPTS", limits.excepts_mode.slice());
        self.pushValue("INVEX", limits.invex_mode.slice());
        self.pushValue("EXTBAN", limits.extban.slice());
        self.pushValue("ACCOUNTEXTBAN", limits.account_extban.slice());
        self.pushValueless("WHOX");
        self.pushValueless("IRCX");
        self.pushValue("MAXCODEPAGE", self.fmtUint(limits.ircx_max_codepage));
        self.pushValue("MAXLANGUAGE", self.fmtUint(limits.ircx_max_language));
        self.pushValue("MAXPROP", self.fmtUint(limits.ircx_max_prop));
        self.pushValue("MAXACCESS", self.fmtUint(limits.ircx_max_access));
    }
};

/// Emit the ISUPPORT surface derived from policy `limits`. The orchestrator
/// calls this once `Limits` has been overlaid from config; with `Limits{}` the
/// output matches `emitDefault` exactly.
pub fn emitFromLimits(
    server_name: []const u8,
    requester: []const u8,
    limits: *const limits_config.Limits,
    sink: *ReplySink,
) IsupportError!void {
    var set = TokenSet{};
    set.build(limits);
    try (Builder{
        .server_name = server_name,
        .requester = requester,
        .tokens = set.slice(),
        .trailing = limits.isupport_trailing.slice(),
    }).emit(sink);
}

fn fixedLineLen(server_name: []const u8, requester: []const u8, trailing: []const u8) usize {
    return 1 + server_name.len + 1 + 3 + 1 + requester.len +
        2 + trailing.len + 2;
}

fn writeLine(
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
    tokens: []const Token,
    trailing: []const u8,
) IsupportError![]const u8 {
    var builder = LineBuilder.init(out);
    try builder.appendByte(':');
    try builder.appendParam(server_name);
    try builder.appendByte(' ');

    var code_buf: [3]u8 = undefined;
    try builder.appendBytes(numeric.formatCode(.RPL_ISUPPORT, &code_buf));
    try builder.appendByte(' ');
    try builder.appendParam(requester);

    for (tokens) |token| {
        try builder.appendByte(' ');
        var token_buf: [MAX_IRC_LINE_BYTES]u8 = undefined;
        try builder.appendBytes(try token.write(&token_buf));
    }

    try builder.appendBytes(" :");
    try builder.appendTrailing(trailing);
    try builder.appendBytes("\r\n");
    return builder.slice();
}

fn validateParam(param: []const u8) IsupportError!void {
    if (param.len == 0 or param[0] == ':') return error.InvalidParameter;
    for (param) |byte| {
        if (byte <= ' ' or byte == 0x7f) return error.InvalidParameter;
    }
}

fn validateTrailing(text: []const u8) IsupportError!void {
    for (text) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidTrailing,
            else => {},
        }
    }
}

fn validTokenName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (!isUpperAscii(name[0])) return false;
    for (name[1..]) |byte| {
        if (!isUpperAscii(byte) and !std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn validTokenValue(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte <= ' ' or byte == 0x7f) return false;
    }
    return true;
}

fn isUpperAscii(byte: u8) bool {
    return byte >= 'A' and byte <= 'Z';
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

    fn appendParam(self: *LineBuilder, param: []const u8) IsupportError!void {
        try validateParam(param);
        try self.appendBytes(param);
    }

    fn appendTrailing(self: *LineBuilder, text: []const u8) IsupportError!void {
        try validateTrailing(text);
        try self.appendBytes(text);
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) IsupportError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) IsupportError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "token map adds replaces and formats tokens" {
    var map = TokenMap(4).init();
    try map.putValue("NICKLEN", "64");
    try map.putValueless("UTF8ONLY");
    try map.putValue("NICKLEN", "32");

    try std.testing.expectEqual(@as(usize, 2), map.slice().len);
    try std.testing.expectEqualStrings("32", map.get("NICKLEN").?.value.?);

    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("NICKLEN=32", try map.get("NICKLEN").?.write(&buf));
    try std.testing.expectEqualStrings("UTF8ONLY", try map.get("UTF8ONLY").?.write(&buf));
}

test "value and valueless tokens emit distinct parameters" {
    const tokens = [_]Token{
        try Token.valued("NETWORK", "Orochi"),
        try Token.valueless("UTF8ONLY"),
    };
    var line_slots: [2]ReplyLine = undefined;
    var storage: [160]u8 = undefined;
    var sink = ReplySink{ .lines = &line_slots, .storage = &storage };

    try (Builder{
        .server_name = "irc.test",
        .requester = "dan",
        .tokens = &tokens,
    }).emit(&sink);

    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try std.testing.expectEqualStrings(
        ":irc.test 005 dan NETWORK=Orochi UTF8ONLY :are supported by this server\r\n",
        sink.slice()[0].bytes,
    );
}

test "negated token formats with leading dash and no value" {
    const token = try Token.negation("EXCEPTS");
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("-EXCEPTS", try token.write(&buf));

    const tokens = [_]Token{token};
    var line_slots: [1]ReplyLine = undefined;
    var storage: [96]u8 = undefined;
    var sink = ReplySink{ .lines = &line_slots, .storage = &storage };

    try (Builder{
        .server_name = "s",
        .requester = "n",
        .tokens = &tokens,
        .trailing = "ok",
    }).emit(&sink);

    try std.testing.expectEqualStrings(":s 005 n -EXCEPTS :ok\r\n", sink.slice()[0].bytes);
}

test "chunking respects thirteen token limit" {
    const tokens = [_]Token{
        try Token.valueless("A"),
        try Token.valueless("B"),
        try Token.valueless("C"),
        try Token.valueless("D"),
        try Token.valueless("E"),
        try Token.valueless("F"),
        try Token.valueless("G"),
        try Token.valueless("H"),
        try Token.valueless("I"),
        try Token.valueless("J"),
        try Token.valueless("K"),
        try Token.valueless("L"),
        try Token.valueless("M"),
        try Token.valueless("N"),
    };
    var line_slots: [2]ReplyLine = undefined;
    var storage: [256]u8 = undefined;
    var sink = ReplySink{ .lines = &line_slots, .storage = &storage };

    try (Builder{
        .server_name = "s",
        .requester = "n",
        .tokens = &tokens,
        .trailing = "ok",
    }).emit(&sink);

    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try std.testing.expectEqualStrings(":s 005 n A B C D E F G H I J K L M :ok\r\n", sink.slice()[0].bytes);
    try std.testing.expectEqualStrings(":s 005 n N :ok\r\n", sink.slice()[1].bytes);
}

test "chunking respects line length limit" {
    const tokens = [_]Token{
        try Token.valued("AAAA", "111111"),
        try Token.valued("BBBB", "222222"),
        try Token.valued("CCCC", "333333"),
    };
    var line_slots: [3]ReplyLine = undefined;
    var storage: [128]u8 = undefined;
    var sink = ReplySink{ .lines = &line_slots, .storage = &storage };

    try (Builder{
        .server_name = "s",
        .requester = "n",
        .tokens = &tokens,
        .trailing = "x",
        .max_line_bytes = 28,
    }).emit(&sink);

    try std.testing.expectEqual(@as(usize, 3), sink.slice().len);
    try std.testing.expectEqualStrings(":s 005 n AAAA=111111 :x\r\n", sink.slice()[0].bytes);
    try std.testing.expectEqualStrings(":s 005 n BBBB=222222 :x\r\n", sink.slice()[1].bytes);
    try std.testing.expectEqualStrings(":s 005 n CCCC=333333 :x\r\n", sink.slice()[2].bytes);
}

test "validation rejects malformed tokens and parameters" {
    try std.testing.expectError(error.InvalidTokenName, Token.valueless("nicklen"));
    try std.testing.expectError(error.InvalidTokenValue, Token.valued("NETWORK", "bad value"));
    try std.testing.expectError(error.NegatedTokenHasValue, (Token{
        .name = "EXCEPTS",
        .value = "e",
        .negated = true,
    }).validate());

    const tokens = [_]Token{try Token.valueless("UTF8ONLY")};
    var line_slots: [1]ReplyLine = undefined;
    var storage: [96]u8 = undefined;
    var sink = ReplySink{ .lines = &line_slots, .storage = &storage };

    try std.testing.expectError(error.InvalidParameter, (Builder{
        .server_name = "bad server",
        .requester = "n",
        .tokens = &tokens,
    }).emit(&sink));
}

test "limits-derived token surface matches default_tokens with default limits" {
    const limits = limits_config.Limits{};
    var set = TokenSet{};
    set.build(&limits);
    const tokens = set.slice();

    try std.testing.expectEqual(default_tokens.len, tokens.len);
    for (default_tokens, tokens) |want, got| {
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqual(want.value == null, got.value == null);
        if (want.value) |wv| try std.testing.expectEqualStrings(wv, got.value.?);
    }
}

test "emitFromLimits reflects overridden policy values" {
    var limits = limits_config.Limits{};
    limits.nick_len = 32;
    limits.network.set("TestNet");

    var line_slots: [8]ReplyLine = undefined;
    var storage: [2048]u8 = undefined;
    var sink = ReplySink{ .lines = &line_slots, .storage = &storage };
    try emitFromLimits("irc.example.test", "alice", &limits, &sink);

    var saw_nicklen = false;
    var saw_network = false;
    for (sink.slice()) |line| {
        if (std.mem.indexOf(u8, line.bytes, "NICKLEN=32") != null) saw_nicklen = true;
        if (std.mem.indexOf(u8, line.bytes, "NETWORK=TestNet") != null) saw_network = true;
    }
    try std.testing.expect(saw_nicklen);
    try std.testing.expect(saw_network);
}

test "default tokens are valid and emit multiple bounded lines" {
    var line_slots: [8]ReplyLine = undefined;
    var storage: [2048]u8 = undefined;
    var sink = ReplySink{ .lines = &line_slots, .storage = &storage };

    try emitDefault("irc.example.test", "alice", &sink);

    try std.testing.expect(sink.slice().len >= 3);
    for (sink.slice()) |line| {
        try std.testing.expect(line.bytes.len <= MAX_IRC_LINE_BYTES);
        try std.testing.expect(std.mem.endsWith(u8, line.bytes, "\r\n"));
    }
}
