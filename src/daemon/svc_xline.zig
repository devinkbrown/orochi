//! Standalone oper X-line support for GECOS / realname bans.
//!
//! This module intentionally models real server commands (`XLINE`, `UNXLINE`,
//! `STATS x`) and server numerics only. It does not create or depend on
//! service pseudo-clients such as ChanServ, NickServ, or OperServ.

const std = @import("std");

const testing = std.testing;

pub const STATS_QUERY: u8 = 'x';

/// Server numerics a caller can use when exposing X-line operations.
pub const Numeric = enum(u16) {
    RPL_STATSXLINE = 247,
    RPL_ENDOFSTATS = 219,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NEEDMOREPARAMS = 461,
    ERR_NOPRIVILEGES = 481,

    pub fn code(self: Numeric) u16 {
        return @intFromEnum(self);
    }

    pub fn format(self: Numeric, buf: []u8) error{OutputTooSmall}![]const u8 {
        if (buf.len < 3) return error.OutputTooSmall;
        const value = self.code();
        buf[0] = @intCast('0' + (value / 100) % 10);
        buf[1] = @intCast('0' + (value / 10) % 10);
        buf[2] = @intCast('0' + value % 10);
        return buf[0..3];
    }
};

/// Bounds for owned X-line storage.
pub const Params = struct {
    max_entries: usize = 4096,
    max_gecos_glob_bytes: usize = 256,
    max_reason_bytes: usize = 512,
    max_setter_bytes: usize = 128,
};

pub const StoreError = std.mem.Allocator.Error || error{
    EmptyGecosGlob,
    GecosGlobTooLong,
    EmptyReason,
    ReasonTooLong,
    EmptySetter,
    SetterTooLong,
    TooManyEntries,
};

pub const ParseError = error{
    EmptyLine,
    MissingParameter,
    TooManyParameters,
    UnknownCommand,
    UnsupportedStatsQuery,
    InvalidDuration,
    DurationOverflow,
    ExpirationOverflow,
};

/// Borrowed view of one X-line.
pub const Entry = struct {
    /// Case-insensitive glob matched against a client's realname / GECOS.
    gecos_glob: []const u8,
    reason: []const u8,
    setter: []const u8,
    /// Absolute expiration time in milliseconds, or null for permanent.
    expires_ms: ?i64 = null,

    pub fn expired(self: Entry, now_ms: i64) bool {
        return if (self.expires_ms) |expires| now_ms >= expires else false;
    }
};

pub const AddRequest = struct {
    gecos_glob: []const u8,
    reason: []const u8,
    setter: []const u8,
    expires_ms: ?i64 = null,
};

pub const AddResult = enum {
    added,
    replaced,
};

pub const XLineStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.ArrayList(OwnedEntry) = .empty,

    pub fn init(allocator: std.mem.Allocator) XLineStore {
        return initWithParams(allocator, .{});
    }

    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) XLineStore {
        return .{
            .allocator = allocator,
            .params = params,
        };
    }

    pub fn deinit(self: *XLineStore) void {
        for (self.entries.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add a new X-line or replace an existing one with the same folded glob.
    pub fn add(self: *XLineStore, request: AddRequest) StoreError!AddResult {
        try self.validate(request);

        var replacement = try OwnedEntry.init(self.allocator, request);
        errdefer replacement.deinit(self.allocator);

        if (self.findIndex(request.gecos_glob)) |idx| {
            self.entries.items[idx].deinit(self.allocator);
            self.entries.items[idx] = replacement;
            return .replaced;
        }

        if (self.entries.items.len >= self.params.max_entries) return error.TooManyEntries;
        try self.entries.append(self.allocator, replacement);
        return .added;
    }

    /// Remove an X-line by GECOS glob. Matching is case-insensitive.
    pub fn remove(self: *XLineStore, gecos_glob: []const u8) bool {
        const idx = self.findIndex(gecos_glob) orelse return false;
        var removed = self.entries.orderedRemove(idx);
        removed.deinit(self.allocator);
        return true;
    }

    /// Return the first non-expired X-line matching a realname.
    pub fn match(self: *const XLineStore, realname: []const u8, now_ms: i64) ?Entry {
        for (self.entries.items) |owned| {
            const entry = owned.entry;
            if (!entry.expired(now_ms) and globMatch(entry.gecos_glob, realname)) return entry;
        }
        return null;
    }

    pub fn matches(self: *const XLineStore, realname: []const u8, now_ms: i64) bool {
        return self.match(realname, now_ms) != null;
    }

    /// Copy non-expired entries into caller-owned storage, preserving order.
    pub fn list(self: *const XLineStore, now_ms: i64, out: []Entry) usize {
        var written: usize = 0;
        for (self.entries.items) |owned| {
            const entry = owned.entry;
            if (entry.expired(now_ms)) continue;
            if (written == out.len) break;
            out[written] = entry;
            written += 1;
        }
        return written;
    }

    pub fn activeCount(self: *const XLineStore, now_ms: i64) usize {
        var count: usize = 0;
        for (self.entries.items) |owned| {
            if (!owned.entry.expired(now_ms)) count += 1;
        }
        return count;
    }

    /// Remove expired entries and return the number removed.
    pub fn sweep(self: *XLineStore, now_ms: i64) usize {
        var removed_count: usize = 0;
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            if (self.entries.items[idx].entry.expired(now_ms)) {
                var removed = self.entries.orderedRemove(idx);
                removed.deinit(self.allocator);
                removed_count += 1;
            } else {
                idx += 1;
            }
        }
        return removed_count;
    }

    fn validate(self: *const XLineStore, request: AddRequest) StoreError!void {
        if (request.gecos_glob.len == 0) return error.EmptyGecosGlob;
        if (request.gecos_glob.len > self.params.max_gecos_glob_bytes) return error.GecosGlobTooLong;
        if (request.reason.len == 0) return error.EmptyReason;
        if (request.reason.len > self.params.max_reason_bytes) return error.ReasonTooLong;
        if (request.setter.len == 0) return error.EmptySetter;
        if (request.setter.len > self.params.max_setter_bytes) return error.SetterTooLong;
    }

    fn findIndex(self: *const XLineStore, gecos_glob: []const u8) ?usize {
        for (self.entries.items, 0..) |owned, idx| {
            if (globNameEqual(owned.entry.gecos_glob, gecos_glob)) return idx;
        }
        return null;
    }
};

const OwnedEntry = struct {
    entry: Entry,

    fn init(allocator: std.mem.Allocator, request: AddRequest) std.mem.Allocator.Error!OwnedEntry {
        const gecos_glob = try allocator.dupe(u8, request.gecos_glob);
        errdefer allocator.free(gecos_glob);
        const reason = try allocator.dupe(u8, request.reason);
        errdefer allocator.free(reason);
        const setter = try allocator.dupe(u8, request.setter);
        errdefer allocator.free(setter);

        return .{
            .entry = .{
                .gecos_glob = gecos_glob,
                .reason = reason,
                .setter = setter,
                .expires_ms = request.expires_ms,
            },
        };
    }

    fn deinit(self: *OwnedEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.entry.gecos_glob);
        allocator.free(self.entry.reason);
        allocator.free(self.entry.setter);
        self.* = undefined;
    }
};

pub const CommandName = enum {
    XLINE,
    UNXLINE,
    STATS,

    pub fn text(self: CommandName) []const u8 {
        return switch (self) {
            .XLINE => "XLINE",
            .UNXLINE => "UNXLINE",
            .STATS => "STATS",
        };
    }
};

pub const ParsedCommand = union(CommandName) {
    XLINE: ParsedAdd,
    UNXLINE: ParsedRemove,
    STATS: ParsedList,
};

pub const ParsedAdd = struct {
    gecos_glob: []const u8,
    reason: []const u8,
    duration_ms: ?i64 = null,
    expires_ms: ?i64 = null,
};

pub const ParsedRemove = struct {
    gecos_glob: []const u8,
};

pub const ParsedList = struct {
    query: u8 = STATS_QUERY,
};

/// Parse a complete IRC command line for the X-line command surface.
///
/// Accepted add forms:
///   XLINE <gecos-glob> :<reason>
///   XLINE <duration> <gecos-glob> :<reason>
///   XLINE <gecos-glob> <duration> :<reason>
///
/// `duration` is a positive integer with an optional `s`, `m`, `h`, `d`, or
/// `w` suffix. Bare integers are seconds.
pub fn parseOperLine(line: []const u8, now_ms: i64) ParseError!ParsedCommand {
    var params_buf: [16][]const u8 = undefined;
    const message = try parseMessage(line, &params_buf);

    if (commandEqual(message.command, "XLINE")) {
        return .{ .XLINE = try parseAdd(message.params, now_ms) };
    }
    if (commandEqual(message.command, "UNXLINE")) {
        if (message.params.len < 1) return error.MissingParameter;
        return .{ .UNXLINE = .{ .gecos_glob = message.params[0] } };
    }
    if (commandEqual(message.command, "STATS")) {
        if (message.params.len < 1) return error.MissingParameter;
        if (message.params[0].len != 1 or fold(message.params[0][0]) != STATS_QUERY) {
            return error.UnsupportedStatsQuery;
        }
        return .{ .STATS = .{} };
    }

    return error.UnknownCommand;
}

fn parseAdd(params: []const []const u8, now_ms: i64) ParseError!ParsedAdd {
    if (params.len < 2) return error.MissingParameter;

    if (params.len >= 3) {
        if (try parseMaybeDuration(params[0])) |duration_ms| {
            return .{
                .duration_ms = duration_ms,
                .gecos_glob = params[1],
                .reason = params[2],
                .expires_ms = try expirationFromDuration(now_ms, duration_ms),
            };
        }
        if (try parseMaybeDuration(params[1])) |duration_ms| {
            return .{
                .gecos_glob = params[0],
                .duration_ms = duration_ms,
                .reason = params[2],
                .expires_ms = try expirationFromDuration(now_ms, duration_ms),
            };
        }
    }

    return .{
        .gecos_glob = params[0],
        .reason = params[1],
    };
}

const ParsedMessage = struct {
    command: []const u8,
    params: []const []const u8,
};

fn parseMessage(line: []const u8, params_buf: []([]const u8)) ParseError!ParsedMessage {
    var rest = std.mem.trim(u8, line, " \t\r\n");
    if (rest.len == 0) return error.EmptyLine;

    if (rest[0] == ':') {
        const prefix_end = indexOfSpace(rest) orelse return error.EmptyLine;
        rest = trimLeadingSpaces(rest[prefix_end..]);
        if (rest.len == 0) return error.EmptyLine;
    }

    const command_end = indexOfSpace(rest) orelse {
        return .{ .command = rest, .params = params_buf[0..0] };
    };
    const command = rest[0..command_end];
    rest = trimLeadingSpaces(rest[command_end..]);

    var count: usize = 0;
    while (rest.len > 0) {
        if (count == params_buf.len) return error.TooManyParameters;

        if (rest[0] == ':') {
            params_buf[count] = rest[1..];
            count += 1;
            break;
        }

        const end = indexOfSpace(rest) orelse rest.len;
        params_buf[count] = rest[0..end];
        count += 1;
        rest = trimLeadingSpaces(rest[end..]);
    }

    return .{ .command = command, .params = params_buf[0..count] };
}

fn parseMaybeDuration(token: []const u8) ParseError!?i64 {
    if (token.len == 0 or !std.ascii.isDigit(token[0])) return null;

    var digits_end: usize = 0;
    while (digits_end < token.len and std.ascii.isDigit(token[digits_end])) : (digits_end += 1) {}
    if (digits_end == 0) return error.InvalidDuration;

    const value = std.fmt.parseInt(i64, token[0..digits_end], 10) catch return error.InvalidDuration;
    if (value <= 0) return error.InvalidDuration;

    const factor_ms: i64 = if (digits_end == token.len)
        1000
    else if (digits_end + 1 == token.len)
        switch (token[digits_end]) {
            's', 'S' => 1000,
            'm', 'M' => 60 * 1000,
            'h', 'H' => 60 * 60 * 1000,
            'd', 'D' => 24 * 60 * 60 * 1000,
            'w', 'W' => 7 * 24 * 60 * 60 * 1000,
            else => return error.InvalidDuration,
        }
    else
        return error.InvalidDuration;

    return std.math.mul(i64, value, factor_ms) catch error.DurationOverflow;
}

fn expirationFromDuration(now_ms: i64, duration_ms: i64) ParseError!i64 {
    return std.math.add(i64, now_ms, duration_ms) catch error.ExpirationOverflow;
}

fn indexOfSpace(bytes: []const u8) ?usize {
    for (bytes, 0..) |byte, idx| {
        if (byte == ' ' or byte == '\t') return idx;
    }
    return null;
}

fn trimLeadingSpaces(bytes: []const u8) []const u8 {
    var idx: usize = 0;
    while (idx < bytes.len and (bytes[idx] == ' ' or bytes[idx] == '\t')) : (idx += 1) {}
    return bytes[idx..];
}

fn commandEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toUpper(ca) != cb) return false;
    }
    return true;
}

fn globNameEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (fold(ca) != fold(cb)) return false;
    }
    return true;
}

const TokenKind = enum {
    literal,
    any_one,
    any_run,
};

const Token = struct {
    kind: TokenKind,
    byte: u8 = 0,
    next: usize,
};

/// Case-insensitive IRC glob: `*` matches any run, `?` matches one byte, and
/// backslash escapes only `*`, `?`, and `\`.
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var star_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len) {
            const token = nextToken(pattern, pattern_index);
            switch (token.kind) {
                .any_run => {
                    star_index = pattern_index;
                    pattern_index = token.next;
                    star_text_index = text_index;
                    continue;
                },
                .any_one => {
                    pattern_index = token.next;
                    text_index += 1;
                    continue;
                },
                .literal => {
                    if (fold(token.byte) == fold(text[text_index])) {
                        pattern_index = token.next;
                        text_index += 1;
                        continue;
                    }
                },
            }
        }

        if (star_index) |index| {
            const token = nextToken(pattern, index);
            star_text_index += 1;
            text_index = star_text_index;
            pattern_index = token.next;
        } else {
            return false;
        }
    }

    while (pattern_index < pattern.len) {
        const token = nextToken(pattern, pattern_index);
        if (token.kind != .any_run) return false;
        pattern_index = token.next;
    }

    return true;
}

fn nextToken(pattern: []const u8, index: usize) Token {
    const byte = pattern[index];
    if (byte == '\\' and index + 1 < pattern.len and isEscapable(pattern[index + 1])) {
        return .{
            .kind = .literal,
            .byte = pattern[index + 1],
            .next = index + 2,
        };
    }

    return switch (byte) {
        '*' => .{ .kind = .any_run, .next = index + 1 },
        '?' => .{ .kind = .any_one, .next = index + 1 },
        else => .{ .kind = .literal, .byte = byte, .next = index + 1 },
    };
}

fn isEscapable(byte: u8) bool {
    return byte == '*' or byte == '?' or byte == '\\';
}

fn fold(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        '^' => '~',
        else => byte,
    };
}

test "numeric formatting uses three digit server numerics" {
    var buf: [3]u8 = undefined;
    try testing.expectEqualStrings("247", try Numeric.RPL_STATSXLINE.format(&buf));
    try testing.expectEqualStrings("219", try Numeric.RPL_ENDOFSTATS.format(&buf));
    try testing.expectEqualStrings("461", try Numeric.ERR_NEEDMOREPARAMS.format(&buf));
    try testing.expectError(error.OutputTooSmall, Numeric.RPL_STATSXLINE.format(buf[0..2]));
}

test "glob supports star question mark anchoring and case folding" {
    try testing.expect(globMatch("*bot*", "friendly BOT scanner"));
    try testing.expect(globMatch("bad?name", "bad-name"));
    try testing.expect(globMatch("real*", "real"));
    try testing.expect(globMatch("[\\]^", "{|}~"));
    try testing.expect(!globMatch("bad?name", "bad--name"));
    try testing.expect(!globMatch("*bot", "bot runner"));
}

test "glob escapes wildcard bytes literally" {
    try testing.expect(globMatch("literal\\*bot", "literal*bot"));
    try testing.expect(globMatch("question\\?", "question?"));
    try testing.expect(globMatch("slash\\\\name", "slash\\name"));
    try testing.expect(!globMatch("literal\\*bot", "literal evil bot"));
    try testing.expect(!globMatch("question\\?", "questionx"));
}

test "store adds lists and matches active xlines" {
    var store = XLineStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectEqual(AddResult.added, try store.add(.{
        .gecos_glob = "*proxy*",
        .reason = "open proxy farm",
        .setter = "oper",
    }));

    try testing.expect(store.matches("Open Proxy 123", 1000));
    try testing.expect(!store.matches("ordinary client", 1000));
    try testing.expectEqual(@as(usize, 1), store.activeCount(1000));

    var out: [2]Entry = undefined;
    const n = store.list(1000, &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("*proxy*", out[0].gecos_glob);
    try testing.expectEqualStrings("open proxy farm", out[0].reason);
    try testing.expectEqualStrings("oper", out[0].setter);
}

test "store replaces same folded glob without duplicating" {
    var store = XLineStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectEqual(AddResult.added, try store.add(.{
        .gecos_glob = "*Drone*",
        .reason = "first",
        .setter = "oper-a",
    }));
    try testing.expectEqual(AddResult.replaced, try store.add(.{
        .gecos_glob = "*drone*",
        .reason = "second",
        .setter = "oper-b",
        .expires_ms = 5000,
    }));

    try testing.expectEqual(@as(usize, 1), store.activeCount(1000));
    const entry = store.match("DRONE", 1000).?;
    try testing.expectEqualStrings("second", entry.reason);
    try testing.expectEqualStrings("oper-b", entry.setter);
    try testing.expectEqual(@as(?i64, 5000), entry.expires_ms);
}

test "remove deletes one xline and reports misses" {
    var store = XLineStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add(.{ .gecos_glob = "*a*", .reason = "a", .setter = "oper" });
    _ = try store.add(.{ .gecos_glob = "*b*", .reason = "b", .setter = "oper" });

    try testing.expect(store.remove("*A*"));
    try testing.expect(!store.remove("*missing*"));
    try testing.expect(!store.matches("alpha", 1));
    try testing.expect(store.matches("bravo", 1));
}

test "expired entries are skipped until swept" {
    var store = XLineStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add(.{
        .gecos_glob = "*old*",
        .reason = "expired",
        .setter = "oper",
        .expires_ms = 1000,
    });
    _ = try store.add(.{
        .gecos_glob = "*new*",
        .reason = "active",
        .setter = "oper",
        .expires_ms = 3000,
    });

    try testing.expect(store.matches("old client", 999));
    try testing.expect(!store.matches("old client", 1000));
    try testing.expect(store.matches("new client", 1000));
    try testing.expectEqual(@as(usize, 1), store.activeCount(1000));
    try testing.expectEqual(@as(usize, 1), store.sweep(1000));
    try testing.expectEqual(@as(usize, 1), store.entries.items.len);
    try testing.expectEqual(@as(usize, 0), store.sweep(1000));
}

test "list respects caller capacity and omits expired entries" {
    var store = XLineStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add(.{ .gecos_glob = "*one*", .reason = "one", .setter = "oper" });
    _ = try store.add(.{ .gecos_glob = "*two*", .reason = "two", .setter = "oper", .expires_ms = 1 });
    _ = try store.add(.{ .gecos_glob = "*three*", .reason = "three", .setter = "oper" });

    var out: [1]Entry = undefined;
    try testing.expectEqual(@as(usize, 1), store.list(2, &out));
    try testing.expectEqualStrings("*one*", out[0].gecos_glob);
    try testing.expectEqual(@as(usize, 2), store.activeCount(2));
}

test "store validates bounds before owning input" {
    var store = XLineStore.initWithParams(testing.allocator, .{
        .max_entries = 1,
        .max_gecos_glob_bytes = 4,
        .max_reason_bytes = 6,
        .max_setter_bytes = 5,
    });
    defer store.deinit();

    try testing.expectError(error.EmptyGecosGlob, store.add(.{ .gecos_glob = "", .reason = "reason", .setter = "oper" }));
    try testing.expectError(error.GecosGlobTooLong, store.add(.{ .gecos_glob = "12345", .reason = "reason", .setter = "oper" }));
    try testing.expectError(error.EmptyReason, store.add(.{ .gecos_glob = "*", .reason = "", .setter = "oper" }));
    try testing.expectError(error.ReasonTooLong, store.add(.{ .gecos_glob = "*", .reason = "1234567", .setter = "oper" }));
    try testing.expectError(error.EmptySetter, store.add(.{ .gecos_glob = "*", .reason = "reason", .setter = "" }));
    try testing.expectError(error.SetterTooLong, store.add(.{ .gecos_glob = "*", .reason = "reason", .setter = "123456" }));

    _ = try store.add(.{ .gecos_glob = "*a", .reason = "first", .setter = "oper" });
    try testing.expectError(error.TooManyEntries, store.add(.{ .gecos_glob = "*b", .reason = "second", .setter = "oper" }));
}

test "parse xline permanent add with trailing reason" {
    const parsed = try parseOperLine("XLINE *bot* :abusive realname", 1000);
    switch (parsed) {
        .XLINE => |add| {
            try testing.expectEqualStrings("*bot*", add.gecos_glob);
            try testing.expectEqualStrings("abusive realname", add.reason);
            try testing.expectEqual(@as(?i64, null), add.duration_ms);
            try testing.expectEqual(@as(?i64, null), add.expires_ms);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse xline temporary add with duration before glob" {
    const parsed = try parseOperLine(":oper.example XLINE 2h *proxy* :open proxy", 10_000);
    switch (parsed) {
        .XLINE => |add| {
            try testing.expectEqualStrings("*proxy*", add.gecos_glob);
            try testing.expectEqualStrings("open proxy", add.reason);
            try testing.expectEqual(@as(?i64, 7_200_000), add.duration_ms);
            try testing.expectEqual(@as(?i64, 7_210_000), add.expires_ms);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse xline temporary add with duration after glob" {
    const parsed = try parseOperLine("XLINE *drone* 30m :bot swarm", 100);
    switch (parsed) {
        .XLINE => |add| {
            try testing.expectEqualStrings("*drone*", add.gecos_glob);
            try testing.expectEqualStrings("bot swarm", add.reason);
            try testing.expectEqual(@as(?i64, 1_800_000), add.duration_ms);
            try testing.expectEqual(@as(?i64, 1_800_100), add.expires_ms);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse unxline and stats x commands" {
    const remove = try parseOperLine("UNXLINE *bot*", 0);
    switch (remove) {
        .UNXLINE => |cmd| try testing.expectEqualStrings("*bot*", cmd.gecos_glob),
        else => return error.TestUnexpectedResult,
    }

    const list = try parseOperLine("STATS X", 0);
    switch (list) {
        .STATS => |cmd| try testing.expectEqual(@as(u8, 'x'), cmd.query),
        else => return error.TestUnexpectedResult,
    }
}

test "parse rejects incomplete unsupported or pseudo-client service commands" {
    try testing.expectError(error.EmptyLine, parseOperLine("   \r\n", 0));
    try testing.expectError(error.MissingParameter, parseOperLine("XLINE *bot*", 0));
    try testing.expectError(error.MissingParameter, parseOperLine("UNXLINE", 0));
    try testing.expectError(error.UnsupportedStatsQuery, parseOperLine("STATS k", 0));
    try testing.expectError(error.UnknownCommand, parseOperLine("CHANSERV XLINE *bot* :no pseudo clients", 0));
    try testing.expectError(error.UnknownCommand, parseOperLine("PRIVMSG OperServ :XLINE *bot*", 0));
}

test "duration parser accepts supported units and rejects bad durations" {
    try testing.expectEqual(@as(?i64, 1000), try parseMaybeDuration("1"));
    try testing.expectEqual(@as(?i64, 1000), try parseMaybeDuration("1s"));
    try testing.expectEqual(@as(?i64, 60_000), try parseMaybeDuration("1m"));
    try testing.expectEqual(@as(?i64, 3_600_000), try parseMaybeDuration("1h"));
    try testing.expectEqual(@as(?i64, 86_400_000), try parseMaybeDuration("1d"));
    try testing.expectEqual(@as(?i64, 604_800_000), try parseMaybeDuration("1w"));
    try testing.expectEqual(@as(?i64, null), try parseMaybeDuration("*bot*"));
    try testing.expectError(error.InvalidDuration, parseMaybeDuration("0s"));
    try testing.expectError(error.InvalidDuration, parseMaybeDuration("1mo"));
    try testing.expectError(error.InvalidDuration, parseMaybeDuration("1x"));
}

test "parse rejects overflowing expiration" {
    try testing.expectError(error.ExpirationOverflow, parseOperLine("XLINE 1s *bot* :overflow", std.math.maxInt(i64)));
}
