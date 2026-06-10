//! Native ENTRYMSG support for per-channel join-time entry messages.
//!
//! This module is deliberately standalone: it owns an in-memory channel ->
//! message map, parses the real IRC `ENTRYMSG` command shape, and formats
//! server-origin replies/delivery lines. It never models ChanServ/NickServ style
//! pseudo-clients.
const std = @import("std");

pub const default_max_channels: usize = 4096;
pub const default_max_channel_bytes: usize = 128;
pub const default_max_text_bytes: usize = 400;

pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    InvalidChannel,
    ChannelTooLong,
    EmptyText,
    TextTooLong,
    TooManyChannels,
    NeedMoreParams,
    UnknownCommand,
    UnknownAction,
    InvalidServerName,
    InvalidTargetNick,
    InvalidWireText,
    OutputTooSmall,
};

pub const Config = struct {
    max_channels: usize = default_max_channels,
    max_channel_bytes: usize = default_max_channel_bytes,
    max_text_bytes: usize = default_max_text_bytes,
};

pub const Numeric = enum(u16) {
    rpl_text = 304,
    err_no_such_channel = 403,
    err_need_more_params = 461,
    err_chan_op_privs_needed = 482,
};

pub const SetCommand = struct {
    channel: []const u8,
    text: []const u8,
};

pub const EntrymsgCommand = union(enum) {
    query: []const u8,
    set: SetCommand,
    clear: []const u8,
};

pub const ApplyResult = union(enum) {
    query: ?[]const u8,
    set: []const u8,
    clear: bool,
};

pub const EntrymsgStore = struct {
    allocator: std.mem.Allocator,
    config: Config,
    entries: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator) EntrymsgStore {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) EntrymsgStore {
        return .{
            .allocator = allocator,
            .config = config,
            .entries = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *EntrymsgStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn set(self: *EntrymsgStore, channel: []const u8, text: []const u8) Error!void {
        try validateChannelWith(self.config, channel);

        const owned_text = try sanitizeOwned(self.allocator, self.config, text);
        errdefer self.allocator.free(owned_text);

        if (self.entries.getPtr(channel)) |slot| {
            self.allocator.free(slot.*);
            slot.* = owned_text;
            return;
        }

        if (self.entries.count() >= self.config.max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);

        try self.entries.putNoClobber(owned_channel, owned_text);
    }

    pub fn get(self: *const EntrymsgStore, channel: []const u8) ?[]const u8 {
        return self.entries.get(channel);
    }

    pub fn clear(self: *EntrymsgStore, channel: []const u8) bool {
        const entry = self.entries.getEntry(channel) orelse return false;
        const owned_channel = entry.key_ptr.*;
        const owned_text = entry.value_ptr.*;
        self.entries.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_channel);
        self.allocator.free(owned_text);
        return true;
    }

    pub fn apply(self: *EntrymsgStore, command: EntrymsgCommand) Error!ApplyResult {
        return switch (command) {
            .query => |channel| .{ .query = self.get(channel) },
            .set => |item| {
                try self.set(item.channel, item.text);
                return .{ .set = self.get(item.channel).? };
            },
            .clear => |channel| .{ .clear = self.clear(channel) },
        };
    }

    pub fn count(self: *const EntrymsgStore) usize {
        return self.entries.count();
    }
};

pub fn numericCode(code: Numeric) u16 {
    return @intFromEnum(code);
}

pub fn validateChannel(channel: []const u8) Error!void {
    try validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(config: Config, channel: []const u8) Error!void {
    if (channel.len == 0) return error.EmptyChannel;
    if (channel.len > config.max_channel_bytes) return error.ChannelTooLong;
    switch (channel[0]) {
        '#', '&', '+', '!' => {},
        else => return error.InvalidChannel,
    }
    for (channel) |byte| {
        if (isControlByte(byte) or byte == ' ' or byte == ',') return error.InvalidChannel;
    }
}

pub fn sanitizedLength(text: []const u8) usize {
    var len: usize = 0;
    for (text) |byte| {
        if (!isControlByte(byte)) len += 1;
    }
    return len;
}

pub fn sanitizeInto(dest: []u8, text: []const u8) usize {
    var cursor: usize = 0;
    for (text) |byte| {
        if (!isControlByte(byte)) {
            dest[cursor] = byte;
            cursor += 1;
        }
    }
    return cursor;
}

pub fn sanitizeOwned(allocator: std.mem.Allocator, config: Config, text: []const u8) Error![]u8 {
    const len = sanitizedLength(text);
    if (len == 0) return error.EmptyText;
    if (len > config.max_text_bytes) return error.TextTooLong;

    const owned = try allocator.alloc(u8, len);
    const written = sanitizeInto(owned, text);
    std.debug.assert(written == len);
    return owned;
}

pub fn parseEntrymsgParams(params: []const []const u8) Error!EntrymsgCommand {
    if (params.len == 0) return error.NeedMoreParams;
    if (params.len == 1) return .{ .query = params[0] };

    if (asciiEql(params[1], "CLEAR")) {
        if (params.len != 2) return error.UnknownAction;
        return .{ .clear = params[0] };
    }

    if (asciiEql(params[1], "SET")) {
        if (params.len < 3) return error.NeedMoreParams;
        if (params.len != 3) return error.UnknownAction;
        return .{ .set = .{ .channel = params[0], .text = params[2] } };
    }

    if (params.len == 2) return .{ .set = .{ .channel = params[0], .text = params[1] } };
    return error.UnknownAction;
}

pub fn parseEntrymsgLine(line: []const u8) Error!EntrymsgCommand {
    const trimmed = trimLineEnd(line);
    var cursor = skipSpaces(trimmed, 0);
    const command = readToken(trimmed, &cursor);
    if (!asciiEql(command, "ENTRYMSG")) return error.UnknownCommand;

    cursor = skipSpaces(trimmed, cursor);
    if (cursor >= trimmed.len) return error.NeedMoreParams;
    const channel = readToken(trimmed, &cursor);

    cursor = skipSpaces(trimmed, cursor);
    if (cursor >= trimmed.len) return .{ .query = channel };

    if (trimmed[cursor] == ':') {
        return .{ .set = .{ .channel = channel, .text = trimmed[cursor + 1 ..] } };
    }

    const action_start = cursor;
    const action = readToken(trimmed, &cursor);
    cursor = skipSpaces(trimmed, cursor);

    if (asciiEql(action, "CLEAR")) {
        if (cursor != trimmed.len) return error.UnknownAction;
        return .{ .clear = channel };
    }

    if (asciiEql(action, "SET")) {
        if (cursor >= trimmed.len) return error.NeedMoreParams;
        const text = if (trimmed[cursor] == ':') trimmed[cursor + 1 ..] else trimmed[cursor..];
        return .{ .set = .{ .channel = channel, .text = text } };
    }

    return .{ .set = .{ .channel = channel, .text = trimmed[action_start..] } };
}

pub fn formatJoinNotice(
    out: []u8,
    server_name: []const u8,
    target_nick: []const u8,
    channel: []const u8,
    text: []const u8,
) Error![]const u8 {
    try validateServerName(server_name);
    try validateTargetNick(target_nick);
    try validateChannel(channel);
    try validateWireText(text);

    var cursor: usize = 0;
    try append(out, &cursor, ":");
    try append(out, &cursor, server_name);
    try append(out, &cursor, " NOTICE ");
    try append(out, &cursor, target_nick);
    try append(out, &cursor, " :[");
    try append(out, &cursor, channel);
    try append(out, &cursor, "] ");
    try append(out, &cursor, text);
    try append(out, &cursor, "\r\n");
    return out[0..cursor];
}

pub fn formatNumeric(
    out: []u8,
    server_name: []const u8,
    target_nick: []const u8,
    code: Numeric,
    params: []const []const u8,
    trailing: []const u8,
) Error![]const u8 {
    try validateServerName(server_name);
    try validateTargetNick(target_nick);
    for (params) |param| try validateMiddleParam(param);
    try validateWireText(trailing);

    var cursor: usize = 0;
    try append(out, &cursor, ":");
    try append(out, &cursor, server_name);
    try append(out, &cursor, " ");
    try appendNumericCode(out, &cursor, code);
    try append(out, &cursor, " ");
    try append(out, &cursor, target_nick);
    for (params) |param| {
        try append(out, &cursor, " ");
        try append(out, &cursor, param);
    }
    if (trailing.len > 0) {
        try append(out, &cursor, " :");
        try append(out, &cursor, trailing);
    }
    try append(out, &cursor, "\r\n");
    return out[0..cursor];
}

pub fn isControlByte(byte: u8) bool {
    return byte < 0x20 or byte == 0x7f;
}

fn validateServerName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidServerName;
    for (name) |byte| {
        if (isControlByte(byte) or byte == ' ' or byte == ':') return error.InvalidServerName;
    }
}

fn validateTargetNick(nick: []const u8) Error!void {
    if (nick.len == 0) return error.InvalidTargetNick;
    for (nick) |byte| {
        if (isControlByte(byte) or byte == ' ' or byte == ':' or byte == ',') return error.InvalidTargetNick;
    }
}

fn validateMiddleParam(param: []const u8) Error!void {
    if (param.len == 0 or param[0] == ':') return error.InvalidWireText;
    for (param) |byte| {
        if (isControlByte(byte) or byte == ' ') return error.InvalidWireText;
    }
}

fn validateWireText(text: []const u8) Error!void {
    for (text) |byte| {
        if (isControlByte(byte)) return error.InvalidWireText;
    }
}

fn append(out: []u8, cursor: *usize, text: []const u8) Error!void {
    if (out.len - cursor.* < text.len) return error.OutputTooSmall;
    @memcpy(out[cursor.* .. cursor.* + text.len], text);
    cursor.* += text.len;
}

fn appendNumericCode(out: []u8, cursor: *usize, code: Numeric) Error!void {
    if (out.len - cursor.* < 3) return error.OutputTooSmall;
    const value: u16 = @intFromEnum(code);
    out[cursor.*] = @intCast('0' + (value / 100));
    out[cursor.* + 1] = @intCast('0' + ((value / 10) % 10));
    out[cursor.* + 2] = @intCast('0' + (value % 10));
    cursor.* += 3;
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn trimLineEnd(line: []const u8) []const u8 {
    var end = line.len;
    while (end > 0 and (line[end - 1] == '\r' or line[end - 1] == '\n')) {
        end -= 1;
    }
    return line[0..end];
}

fn skipSpaces(line: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < line.len and (line[cursor] == ' ' or line[cursor] == '\t')) {
        cursor += 1;
    }
    return cursor;
}

fn readToken(line: []const u8, cursor: *usize) []const u8 {
    const start = cursor.*;
    while (cursor.* < line.len and line[cursor.*] != ' ' and line[cursor.*] != '\t') {
        cursor.* += 1;
    }
    return line[start..cursor.*];
}

const testing = std.testing;

test "set get and clear own sanitized entry messages" {
    var store = EntrymsgStore.init(testing.allocator);
    defer store.deinit();

    try store.set("#zig", "Welcome\x02 to \x03Zig\r\n");
    try testing.expectEqualStrings("Welcome to Zig", store.get("#zig").?);
    try testing.expectEqual(@as(usize, 1), store.count());

    try testing.expect(store.clear("#zig"));
    try testing.expect(!store.clear("#zig"));
    try testing.expect(store.get("#zig") == null);
}

test "set replaces only message storage and keeps unrelated channels" {
    var store = EntrymsgStore.init(testing.allocator);
    defer store.deinit();

    try store.set("#ops", "first");
    const first = store.get("#ops").?;
    try store.set("#random", "hello");
    try store.set("#ops", "second");

    try testing.expect(first.ptr != store.get("#ops").?.ptr);
    try testing.expectEqualStrings("second", store.get("#ops").?);
    try testing.expectEqualStrings("hello", store.get("#random").?);
}

test "store enforces channel text and count bounds" {
    var store = EntrymsgStore.initWithConfig(testing.allocator, .{
        .max_channels = 1,
        .max_channel_bytes = 4,
        .max_text_bytes = 3,
    });
    defer store.deinit();

    try testing.expectError(error.EmptyChannel, store.set("", "ok"));
    try testing.expectError(error.InvalidChannel, store.set("zig", "ok"));
    try testing.expectError(error.InvalidChannel, store.set("# b", "ok"));
    try testing.expectError(error.ChannelTooLong, store.set("#long", "ok"));
    try testing.expectError(error.EmptyText, store.set("#ok", "\x02\r\n"));
    try testing.expectError(error.TextTooLong, store.set("#ok", "long"));

    try store.set("#one", "one");
    try testing.expectError(error.TooManyChannels, store.set("#two", "two"));
}

test "message length is measured after control stripping" {
    var store = EntrymsgStore.initWithConfig(testing.allocator, .{ .max_text_bytes = 4 });
    defer store.deinit();

    try store.set("#a", "a\x02b\x03c\x1fd");
    try testing.expectEqualStrings("abcd", store.get("#a").?);
    try testing.expectError(error.TextTooLong, store.set("#a", "a\x02bcde"));
    try testing.expectEqualStrings("abcd", store.get("#a").?);
}

test "clear on missing channel is side-effect free" {
    var store = EntrymsgStore.init(testing.allocator);
    defer store.deinit();

    try store.set("#a", "alpha");
    try testing.expect(!store.clear("#b"));
    try testing.expectEqualStrings("alpha", store.get("#a").?);
}

test "parse ENTRYMSG params supports query set and clear" {
    const query = try parseEntrymsgParams(&.{"#zig"});
    try testing.expectEqualStrings("#zig", query.query);

    const set_short = try parseEntrymsgParams(&.{ "#zig", "hello" });
    try testing.expectEqualStrings("#zig", set_short.set.channel);
    try testing.expectEqualStrings("hello", set_short.set.text);

    const set_explicit = try parseEntrymsgParams(&.{ "#zig", "SET", "hello there" });
    try testing.expectEqualStrings("hello there", set_explicit.set.text);

    const clear = try parseEntrymsgParams(&.{ "#zig", "clear" });
    try testing.expectEqualStrings("#zig", clear.clear);
}

test "parse ENTRYMSG params rejects malformed command shapes" {
    try testing.expectError(error.NeedMoreParams, parseEntrymsgParams(&.{}));
    try testing.expectError(error.NeedMoreParams, parseEntrymsgParams(&.{ "#zig", "SET" }));
    try testing.expectError(error.UnknownAction, parseEntrymsgParams(&.{ "#zig", "CLEAR", "extra" }));
    try testing.expectError(error.UnknownAction, parseEntrymsgParams(&.{ "#zig", "SET", "ok", "extra" }));
    try testing.expectError(error.UnknownAction, parseEntrymsgParams(&.{ "#zig", "one", "two" }));
}

test "parse ENTRYMSG line handles IRC trailing text" {
    const parsed = try parseEntrymsgLine("entrymsg #zig SET :Welcome to Zig\r\n");
    try testing.expectEqualStrings("#zig", parsed.set.channel);
    try testing.expectEqualStrings("Welcome to Zig", parsed.set.text);

    const implicit = try parseEntrymsgLine("ENTRYMSG #zig :Read the topic");
    try testing.expectEqualStrings("Read the topic", implicit.set.text);

    const clear = try parseEntrymsgLine(" ENTRYMSG   #zig   CLEAR ");
    try testing.expectEqualStrings("#zig", clear.clear);

    const query = try parseEntrymsgLine("ENTRYMSG #zig");
    try testing.expectEqualStrings("#zig", query.query);
}

test "parse ENTRYMSG line rejects unknown commands and missing text" {
    try testing.expectError(error.UnknownCommand, parseEntrymsgLine("PRIVMSG #zig :not this feature"));
    try testing.expectError(error.NeedMoreParams, parseEntrymsgLine("ENTRYMSG"));
    try testing.expectError(error.NeedMoreParams, parseEntrymsgLine("ENTRYMSG #zig SET"));
    try testing.expectError(error.UnknownAction, parseEntrymsgLine("ENTRYMSG #zig CLEAR :extra"));
}

test "apply command mutates store and reports result" {
    var store = EntrymsgStore.init(testing.allocator);
    defer store.deinit();

    const set_result = try store.apply(.{ .set = .{ .channel = "#zig", .text = "Hello\x02" } });
    try testing.expectEqualStrings("Hello", set_result.set);

    const query_result = try store.apply(.{ .query = "#zig" });
    try testing.expectEqualStrings("Hello", query_result.query.?);

    const clear_result = try store.apply(.{ .clear = "#zig" });
    try testing.expect(clear_result.clear);
    try testing.expect(store.get("#zig") == null);
}

test "format join delivery uses server NOTICE not pseudo clients" {
    var buf: [256]u8 = undefined;
    const line = try formatJoinNotice(&buf, "irc.orochi.test", "alice", "#zig", "Welcome to Zig");

    try testing.expectEqualStrings(":irc.orochi.test NOTICE alice :[#zig] Welcome to Zig\r\n", line);
    try testing.expect(std.mem.indexOf(u8, line, "ChanServ") == null);
    try testing.expect(std.mem.indexOf(u8, line, "NickServ") == null);
    try testing.expect(std.mem.indexOf(u8, line, "OperServ") == null);
}

test "format numeric emits three digit real IRC replies" {
    var buf: [256]u8 = undefined;
    const line = try formatNumeric(&buf, "irc.orochi.test", "alice", .rpl_text, &.{ "#zig", "ENTRYMSG" }, "Welcome to Zig");

    try testing.expectEqual(@as(u16, 304), numericCode(.rpl_text));
    try testing.expectEqualStrings(":irc.orochi.test 304 alice #zig ENTRYMSG :Welcome to Zig\r\n", line);
}

test "formatters reject unsafe wire bytes and small buffers" {
    var small: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, formatJoinNotice(&small, "irc.test", "alice", "#zig", "hello"));

    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidServerName, formatJoinNotice(&buf, "irc test", "alice", "#zig", "hello"));
    try testing.expectError(error.InvalidTargetNick, formatJoinNotice(&buf, "irc.test", "bad nick", "#zig", "hello"));
    try testing.expectError(error.InvalidWireText, formatJoinNotice(&buf, "irc.test", "alice", "#zig", "bad\ntext"));
    try testing.expectError(error.InvalidWireText, formatNumeric(&buf, "irc.test", "alice", .err_need_more_params, &.{":bad"}, "Need more params"));
}

test "channel validation accepts real IRC channel prefixes" {
    try validateChannel("#hash");
    try validateChannel("&local");
    try validateChannel("+modeless");
    try validateChannel("!safeid");

    try testing.expectError(error.InvalidChannel, validateChannel("@not-a-channel"));
    try testing.expectError(error.InvalidChannel, validateChannel("#bad,chan"));
    try testing.expectError(error.InvalidChannel, validateChannel("#bad\x07chan"));
}
