// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRC LIST and IRCX LISTX filtering plus numeric reply emission.
//!
//! The module is allocator-free: parsed filters borrow command parameter
//! slices, channel data is supplied by caller-owned iterators, and emission
//! writes one numeric line at a time into caller scratch storage.
const std = @import("std");
const numeric = @import("../proto/numeric.zig");

pub const MAX_FILTERS: usize = 16;
pub const MAX_MASK_BYTES: usize = 128;
pub const MAX_PARAM_BYTES: usize = 512;

pub const ListError = error{
    InvalidParameter,
    InvalidFilter,
    InvalidMask,
    InvalidValue,
    TooManyFilters,
    OutputTooSmall,
};

/// LIST-family command flavor.
pub const Command = enum {
    list,
    listx,
};

/// Parsed LIST/LISTX filter.
pub const Filter = union(enum) {
    min_users: u32,
    max_users: u32,
    topic_older_than: u32,
    topic_younger_than: u32,
    created_older_than: u32,
    created_younger_than: u32,
    include_mask: []const u8,
    exclude_mask: []const u8,
};

/// Channel state exposed by the daemon's channel iterator.
pub const ChannelInfo = struct {
    name: []const u8,
    users: u32,
    topic: []const u8 = "",
    topic_set_at: ?i64 = null,
    created_at: i64 = 0,
};

/// Shared context for LIST numeric replies.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
    now_seconds: i64,
};

/// Compile-time sized parsed request. Filter text is borrowed from params.
pub fn RequestType(comptime max_filters: usize) type {
    if (max_filters == 0) @compileError("LIST request needs at least one filter slot");

    return struct {
        filters: [max_filters]Filter = undefined,
        count: usize = 0,

        const Self = @This();

        pub fn slice(self: *const Self) []const Filter {
            return self.filters[0..self.count];
        }

        pub fn matches(self: *const Self, channel: ChannelInfo, now_seconds: i64) bool {
            var has_include_mask = false;
            var include_matched = false;

            for (self.slice()) |filter| {
                switch (filter) {
                    .min_users => |min| {
                        if (channel.users < min) return false;
                    },
                    .max_users => |max| {
                        if (channel.users > max) return false;
                    },
                    .topic_older_than => |seconds| {
                        const set_at = channel.topic_set_at orelse return false;
                        if (ageSeconds(now_seconds, set_at) < seconds) return false;
                    },
                    .topic_younger_than => |seconds| {
                        const set_at = channel.topic_set_at orelse return false;
                        if (ageSeconds(now_seconds, set_at) > seconds) return false;
                    },
                    .created_older_than => |seconds| {
                        if (ageSeconds(now_seconds, channel.created_at) < seconds) return false;
                    },
                    .created_younger_than => |seconds| {
                        if (ageSeconds(now_seconds, channel.created_at) > seconds) return false;
                    },
                    .include_mask => |mask| {
                        has_include_mask = true;
                        include_matched = include_matched or globMatch(mask, channel.name);
                    },
                    .exclude_mask => |mask| {
                        if (globMatch(mask, channel.name)) return false;
                    },
                }
            }

            return !has_include_mask or include_matched;
        }

        fn append(self: *Self, filter: Filter) ListError!void {
            if (self.count >= self.filters.len) return error.TooManyFilters;
            self.filters[self.count] = filter;
            self.count += 1;
        }
    };
}

pub const Request = RequestType(MAX_FILTERS);

/// Parse tokenized LIST parameters into the default request size.
pub fn parseList(params: []const []const u8) ListError!Request {
    return parse(.list, params);
}

/// Parse tokenized LISTX parameters into the default request size.
pub fn parseListx(params: []const []const u8) ListError!Request {
    return parse(.listx, params);
}

/// Parse LIST or LISTX parameters. Orochi accepts a single comma-separated
/// filter parameter for both commands.
pub fn parse(command: Command, params: []const []const u8) ListError!Request {
    return parseWithMax(MAX_FILTERS, command, params);
}

/// Parse LIST/LISTX parameters with caller-chosen filter capacity.
pub fn parseWithMax(
    comptime max_filters: usize,
    command: Command,
    params: []const []const u8,
) ListError!RequestType(max_filters) {
    _ = command;
    if (params.len > 1) return error.InvalidParameter;

    var request = RequestType(max_filters){};
    if (params.len == 0 or params[0].len == 0) return request;
    if (params[0].len > MAX_PARAM_BYTES) return error.InvalidParameter;

    var cursor: usize = 0;
    while (cursor <= params[0].len) {
        const next = findByte(params[0], cursor, ',') orelse params[0].len;
        const token = params[0][cursor..next];
        try request.append(try parseFilter(token));
        if (next == params[0].len) break;
        cursor = next + 1;
    }

    return request;
}

/// Build RPL_LISTSTART (321).
pub fn writeListStart(out: []u8, server_name: []const u8, requester: []const u8) ListError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(.RPL_LISTSTART, server_name, requester);
    try b.spaceParam("Channel");
    try b.spaceTrailing("Users Name");
    try b.crlf();
    return b.slice();
}

/// Build one RPL_LIST (322) line.
pub fn writeListReply(
    out: []u8,
    server_name: []const u8,
    requester: []const u8,
    channel: ChannelInfo,
) ListError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(.RPL_LIST, server_name, requester);
    try b.spaceParam(channel.name);
    try b.spaceUnsigned(channel.users);
    try b.spaceTrailing(channel.topic);
    try b.crlf();
    return b.slice();
}

/// Build RPL_LISTEND (323).
pub fn writeListEnd(out: []u8, server_name: []const u8, requester: []const u8) ListError![]const u8 {
    var b = LineBuilder.init(out);
    try b.numericPrefix(.RPL_LISTEND, server_name, requester);
    try b.spaceTrailing("End of LIST");
    try b.crlf();
    return b.slice();
}

/// Emit LIST numerics to `sink.send(line)`, reusing `scratch` for each line.
/// The iterator must expose `next() ?ChannelInfo`.
pub fn emitList(
    comptime Iterator: type,
    iterator: *Iterator,
    request: anytype,
    ctx: ReplyContext,
    scratch: []u8,
    sink: anytype,
) ListError!void {
    try sink.send(try writeListStart(scratch, ctx.server_name, ctx.requester));

    while (iterator.next()) |channel| {
        if (!request.matches(channel, ctx.now_seconds)) continue;
        try sink.send(try writeListReply(scratch, ctx.server_name, ctx.requester, channel));
    }

    try sink.send(try writeListEnd(scratch, ctx.server_name, ctx.requester));
}

/// Emit LISTX numerics. LISTX shares the same output numerics as LIST.
pub fn emitListx(
    comptime Iterator: type,
    iterator: *Iterator,
    request: anytype,
    ctx: ReplyContext,
    scratch: []u8,
    sink: anytype,
) ListError!void {
    try emitList(Iterator, iterator, request, ctx, scratch, sink);
}

/// Case-insensitive ASCII glob matcher for LIST channel masks.
pub fn globMatch(mask: []const u8, text: []const u8) bool {
    var mask_i: usize = 0;
    var text_i: usize = 0;
    var star_i: ?usize = null;
    var retry_text_i: usize = 0;

    while (text_i < text.len) {
        if (mask_i < mask.len and (mask[mask_i] == '?' or asciiEqual(mask[mask_i], text[text_i]))) {
            mask_i += 1;
            text_i += 1;
        } else if (mask_i < mask.len and mask[mask_i] == '*') {
            star_i = mask_i;
            mask_i += 1;
            retry_text_i = text_i;
        } else if (star_i) |star| {
            mask_i = star + 1;
            retry_text_i += 1;
            text_i = retry_text_i;
        } else {
            return false;
        }
    }

    while (mask_i < mask.len and mask[mask_i] == '*') {
        mask_i += 1;
    }
    return mask_i == mask.len;
}

fn parseFilter(token: []const u8) ListError!Filter {
    if (token.len == 0) return error.InvalidFilter;
    try validateToken(token);

    if (token[0] == '>' or token[0] == '<') {
        const value = try parseDecimal(token[1..]);
        return if (token[0] == '>')
            Filter{ .min_users = value }
        else
            Filter{ .max_users = value };
    }

    if (token.len >= 3 and (token[0] == 'T' or token[0] == 't') and isComparator(token[1])) {
        const value = try parseDecimal(token[2..]);
        return if (token[1] == '>')
            Filter{ .topic_older_than = value }
        else
            Filter{ .topic_younger_than = value };
    }

    if (token.len >= 3 and (token[0] == 'C' or token[0] == 'c') and isComparator(token[1])) {
        const value = try parseDecimal(token[2..]);
        return if (token[1] == '>')
            Filter{ .created_older_than = value }
        else
            Filter{ .created_younger_than = value };
    }

    if (token[0] == '!') {
        const mask = token[1..];
        try validateMask(mask);
        return .{ .exclude_mask = mask };
    }

    try validateMask(token);
    return .{ .include_mask = token };
}

fn validateToken(token: []const u8) ListError!void {
    if (token.len > MAX_PARAM_BYTES) return error.InvalidFilter;
    for (token) |ch| {
        if (!validFilterByte(ch)) return error.InvalidFilter;
    }
}

fn validateMask(mask: []const u8) ListError!void {
    if (mask.len == 0 or mask.len > MAX_MASK_BYTES) return error.InvalidMask;
    if (mask[0] == '!') return error.InvalidMask;
    for (mask) |ch| {
        if (!validFilterByte(ch)) return error.InvalidMask;
    }
}

fn validFilterByte(ch: u8) bool {
    return switch (ch) {
        0, ',', ' ', '\t', '\r', '\n' => false,
        else => true,
    };
}

fn parseDecimal(bytes: []const u8) ListError!u32 {
    if (bytes.len == 0) return error.InvalidValue;

    var value: u32 = 0;
    for (bytes) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidValue;
        const digit: u32 = ch - '0';
        if (value > (@as(u32, std.math.maxInt(u32)) - digit) / 10) return error.InvalidValue;
        value = value * 10 + digit;
    }
    return value;
}

fn ageSeconds(now_seconds: i64, event_seconds: i64) u32 {
    if (event_seconds >= now_seconds) return 0;
    const delta: u64 = @intCast(now_seconds - event_seconds);
    return if (delta > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(delta);
}

fn isComparator(ch: u8) bool {
    return ch == '>' or ch == '<';
}

fn asciiEqual(a: u8, b: u8) bool {
    return asciiLower(a) == asciiLower(b);
}

fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + ('a' - 'A') else ch;
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn validateParam(param: []const u8) ListError!void {
    if (param.len == 0) return error.InvalidValue;
    for (param) |ch| {
        switch (ch) {
            0, ' ', '\t', '\r', '\n' => return error.InvalidValue,
            else => {},
        }
    }
}

fn validateTrailing(param: []const u8) ListError!void {
    for (param) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidValue,
            else => {},
        }
    }
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

    fn numericPrefix(
        self: *LineBuilder,
        code: numeric.Numeric,
        server_name: []const u8,
        requester: []const u8,
    ) ListError!void {
        try self.appendByte(':');
        try self.appendParam(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendParam(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) ListError!void {
        try self.appendByte(' ');
        try self.appendParam(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) ListError!void {
        try self.appendBytes(" :");
        try self.appendTrailingBytes(param);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u32) ListError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendParam(self: *LineBuilder, param: []const u8) ListError!void {
        try validateParam(param);
        try self.appendBytes(param);
    }

    fn appendTrailingBytes(self: *LineBuilder, param: []const u8) ListError!void {
        try validateTrailing(param);
        try self.appendBytes(param);
    }

    fn appendUnsigned(self: *LineBuilder, value: u32) ListError!void {
        var buf: [10]u8 = undefined;
        var n: usize = buf.len;
        var current = value;

        while (true) {
            n -= 1;
            buf[n] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[n..]);
    }

    fn crlf(self: *LineBuilder) ListError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) ListError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) ListError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

const SliceIterator = struct {
    channels: []const ChannelInfo,
    index: usize = 0,

    fn next(self: *SliceIterator) ?ChannelInfo {
        if (self.index >= self.channels.len) return null;
        const channel = self.channels[self.index];
        self.index += 1;
        return channel;
    }
};

const TestSink = struct {
    lines: [][]const u8,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    fn send(self: *TestSink, line: []const u8) ListError!void {
        if (self.count >= self.lines.len) return error.OutputTooSmall;
        if (self.used + line.len > self.storage.len) return error.OutputTooSmall;
        const start = self.used;
        const end = start + line.len;
        @memcpy(self.storage[start..end], line);
        self.lines[self.count] = self.storage[start..end];
        self.count += 1;
        self.used = end;
    }

    fn slice(self: *const TestSink) []const []const u8 {
        return self.lines[0..self.count];
    }
};

fn sampleChannels() []const ChannelInfo {
    return &.{
        .{ .name = "#zig", .users = 42, .topic = "Zig talk", .topic_set_at = 900, .created_at = 100 },
        .{ .name = "#ops", .users = 7, .topic = "Ops", .topic_set_at = 990, .created_at = 800 },
        .{ .name = "#secret", .users = 3, .topic = "hidden", .topic_set_at = null, .created_at = 950 },
    };
}

test "parse user count filters" {
    const request = try parseList(&.{">10,<50"});
    try std.testing.expectEqual(@as(usize, 2), request.count);
    try std.testing.expectEqual(@as(u32, 10), request.filters[0].min_users);
    try std.testing.expectEqual(@as(u32, 50), request.filters[1].max_users);
}

test "parse topic age filters" {
    const request = try parseList(&.{"T>60,T<600"});
    try std.testing.expectEqual(@as(u32, 60), request.filters[0].topic_older_than);
    try std.testing.expectEqual(@as(u32, 600), request.filters[1].topic_younger_than);
}

test "parse mask filters" {
    const request = try parseList(&.{"#z*,!#secret"});
    try std.testing.expectEqualStrings("#z*", request.filters[0].include_mask);
    try std.testing.expectEqualStrings("#secret", request.filters[1].exclude_mask);
}

test "parse created age filters" {
    const request = try parseListx(&.{"C>100,C<1000"});
    try std.testing.expectEqual(@as(u32, 100), request.filters[0].created_older_than);
    try std.testing.expectEqual(@as(u32, 1000), request.filters[1].created_younger_than);
}

test "filter application uses min max users and glob match" {
    const request = try parseList(&.{">5,<50,#z*"});
    const channels = sampleChannels();

    try std.testing.expect(request.matches(channels[0], 1000));
    try std.testing.expect(!request.matches(channels[1], 1000));
    try std.testing.expect(!request.matches(channels[2], 1000));
}

test "empty result still emits list start and end" {
    const request = try parseList(&.{">100"});
    var iterator = SliceIterator{ .channels = sampleChannels() };

    var scratch: [256]u8 = undefined;
    var line_slots: [4][]const u8 = undefined;
    var storage: [512]u8 = undefined;
    var sink = TestSink{ .lines = &line_slots, .storage = &storage };

    try emitList(SliceIterator, &iterator, request, .{
        .server_name = "irc.example.test",
        .requester = "dan",
        .now_seconds = 1000,
    }, &scratch, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings(":irc.example.test 321 dan Channel :Users Name\r\n", lines[0]);
    try std.testing.expectEqualStrings(":irc.example.test 323 dan :End of LIST\r\n", lines[1]);
}

test "list emission includes matching channels" {
    const request = try parseList(&.{">5,!#ops"});
    var iterator = SliceIterator{ .channels = sampleChannels() };

    var scratch: [256]u8 = undefined;
    const allocator = std.testing.allocator;
    const line_slots = try allocator.alloc([]const u8, 8);
    defer allocator.free(line_slots);
    const storage = try allocator.alloc(u8, 1024);
    defer allocator.free(storage);
    var sink = TestSink{ .lines = line_slots, .storage = storage };

    try emitList(SliceIterator, &iterator, request, .{
        .server_name = "irc.example.test",
        .requester = "dan",
        .now_seconds = 1000,
    }, &scratch, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings(":irc.example.test 322 dan #zig 42 :Zig talk\r\n", lines[1]);
}

test "malformed filters are rejected" {
    try std.testing.expectError(error.InvalidFilter, parseList(&.{","}));
    try std.testing.expectError(error.InvalidValue, parseList(&.{">"}));
    try std.testing.expectError(error.InvalidValue, parseList(&.{"T>abc"}));
    try std.testing.expectError(error.InvalidMask, parseList(&.{"!"}));
    try std.testing.expectError(error.InvalidParameter, parseList(&.{ "#zig", "extra" }));
}

test "glob match is ascii case-insensitive" {
    try std.testing.expect(globMatch("#Z*", "#zig"));
    try std.testing.expect(globMatch("#?ig", "#ZIG"));
    try std.testing.expect(!globMatch("#ops", "#zig"));
}
