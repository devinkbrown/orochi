const std = @import("std");

pub const max_channel_bytes: usize = 64;
pub const max_setter_bytes: usize = 64;
pub const max_topic_bytes: usize = 390;
pub const default_history_limit: usize = 16;
pub const default_max_channels: usize = 4096;

pub const TopicLogError = std.mem.Allocator.Error || error{
    InvalidChannel,
    InvalidSetter,
    InvalidTimestamp,
    InvalidLimit,
    TopicTooLong,
    TooManyChannels,
};

pub const ParseError = error{
    InvalidCommand,
    NeedMoreParams,
    InvalidChannel,
    InvalidLimit,
};

pub const Numeric = enum(u16) {
    RPL_NOTOPIC = 331,
    RPL_TOPIC = 332,
    RPL_TOPICWHOTIME = 333,
};

pub const Limits = struct {
    max_channels: usize = default_max_channels,
    max_entries_per_channel: usize = default_history_limit,
};

pub const TopicChange = struct {
    setter: []const u8,
    set_at: i64,
    topic: []const u8,
};

pub const TopicHistoryRequest = struct {
    channel: []const u8,
    limit: usize,
};

pub const RenderOptions = struct {
    server_name: []const u8,
    requester: []const u8,
    channel: []const u8,
    limit: usize = default_history_limit,
};

const Entry = struct {
    setter: []u8,
    set_at: i64,
    topic: []u8,

    fn view(self: *const Entry) TopicChange {
        return .{ .setter = self.setter, .set_at = self.set_at, .topic = self.topic };
    }

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.setter);
        allocator.free(self.topic);
        self.* = undefined;
    }
};

const ChannelLog = struct {
    start: usize = 0,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    fn deinit(self: *ChannelLog, allocator: std.mem.Allocator) void {
        for (self.entries.items) |*entry| entry.deinit(allocator);
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    fn record(
        self: *ChannelLog,
        allocator: std.mem.Allocator,
        capacity: usize,
        setter: []const u8,
        set_at: i64,
        topic: []const u8,
    ) TopicLogError!usize {
        if (capacity == 0) return error.InvalidLimit;

        const owned_setter = try allocator.dupe(u8, setter);
        errdefer allocator.free(owned_setter);
        const owned_topic = try allocator.dupe(u8, topic);
        errdefer allocator.free(owned_topic);

        const new_entry = Entry{ .setter = owned_setter, .set_at = set_at, .topic = owned_topic };
        if (self.entries.items.len < capacity) {
            try self.entries.append(allocator, new_entry);
        } else {
            var old = self.entries.items[self.start];
            self.entries.items[self.start] = new_entry;
            old.deinit(allocator);
            self.start = (self.start + 1) % capacity;
        }
        return self.entries.items.len;
    }

    fn newest(self: *const ChannelLog, newest_index: usize) ?*const Entry {
        if (newest_index >= self.entries.items.len) return null;
        const len = self.entries.items.len;
        const oldest_index = (self.start + len - 1 - newest_index) % len;
        return &self.entries.items[oldest_index];
    }
};

pub const TopicLog = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    channels: std.StringHashMap(ChannelLog),

    pub fn init(allocator: std.mem.Allocator, limits: Limits) TopicLog {
        return .{
            .allocator = allocator,
            .limits = limits,
            .channels = std.StringHashMap(ChannelLog).init(allocator),
        };
    }

    pub fn deinit(self: *TopicLog) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn record(
        self: *TopicLog,
        channel: []const u8,
        setter: []const u8,
        set_at: i64,
        topic: []const u8,
    ) TopicLogError!usize {
        try validateChannel(channel);
        try validateSetter(setter);
        try validateTimestamp(set_at);
        try validateTopic(topic);

        const log = try self.ensureChannel(channel);
        return log.record(self.allocator, self.limits.max_entries_per_channel, setter, set_at, topic);
    }

    pub fn recent(self: *const TopicLog, channel: []const u8, out: []TopicChange) []TopicChange {
        const log = self.channels.getPtr(channel) orelse return out[0..0];
        const n = @min(out.len, log.entries.items.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            out[i] = log.newest(i).?.view();
        }
        return out[0..n];
    }

    pub fn count(self: *const TopicLog, channel: []const u8) usize {
        const log = self.channels.getPtr(channel) orelse return 0;
        return log.entries.items.len;
    }

    pub fn clear(self: *TopicLog, channel: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
        return true;
    }

    pub fn renderRecent(self: *const TopicLog, writer: anytype, options: RenderOptions) !usize {
        try validateChannel(options.channel);
        if (options.limit == 0) return error.InvalidLimit;

        const log = self.channels.getPtr(options.channel) orelse {
            return renderTopicHistory(writer, options, &.{});
        };
        const n = @min(options.limit, log.entries.items.len);
        if (n == 0) return renderTopicHistory(writer, options, &.{});

        var emitted: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const entry = log.newest(i).?.view();
            try renderTopicEntry(writer, options.server_name, options.requester, options.channel, entry);
            emitted += 2;
        }
        return emitted;
    }

    fn ensureChannel(self: *TopicLog, channel: []const u8) TopicLogError!*ChannelLog {
        if (self.channels.getPtr(channel)) |log| return log;
        if (self.channels.count() >= self.limits.max_channels) return error.TooManyChannels;

        const owned_key = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_key);
        try self.channels.putNoClobber(owned_key, .{});
        return self.channels.getPtr(channel).?;
    }
};

pub fn parseTopicHistoryParams(params: []const []const u8) ParseError!?TopicHistoryRequest {
    if (params.len < 1) return error.NeedMoreParams;
    try validateChannelForParse(params[0]);
    if (params.len < 2) return null;
    if (!std.ascii.eqlIgnoreCase(params[1], "HISTORY")) return null;

    const limit = if (params.len >= 3) try parseLimit(params[2]) else default_history_limit;
    if (params.len > 3) return error.InvalidLimit;
    return .{ .channel = params[0], .limit = limit };
}

pub fn parseTopicHistoryLine(line: []const u8) ParseError!?TopicHistoryRequest {
    var cursor = std.mem.trim(u8, std.mem.trimEnd(u8, line, "\r\n"), " \t");
    if (cursor.len == 0) return error.InvalidCommand;

    if (cursor[0] == '@') {
        _ = nextToken(&cursor) orelse return error.InvalidCommand;
    }
    if (cursor.len > 0 and cursor[0] == ':') {
        _ = nextToken(&cursor) orelse return error.InvalidCommand;
    }

    const command = nextToken(&cursor) orelse return error.InvalidCommand;
    if (!std.ascii.eqlIgnoreCase(command, "TOPIC")) return error.InvalidCommand;

    var params_buf: [4][]const u8 = undefined;
    var params_len: usize = 0;
    var trailing_index: ?usize = null;
    while (cursor.len > 0 and params_len < params_buf.len) {
        if (cursor[0] == ':') {
            trailing_index = params_len;
            params_buf[params_len] = cursor[1..];
            params_len += 1;
            cursor = "";
            break;
        }
        params_buf[params_len] = nextToken(&cursor) orelse break;
        params_len += 1;
    }
    if (cursor.len > 0) return error.InvalidLimit;
    if (trailing_index != null and trailing_index.? <= 1) return null;

    return parseTopicHistoryParams(params_buf[0..params_len]);
}

pub fn renderTopicHistory(writer: anytype, options: RenderOptions, entries: []const TopicChange) !usize {
    try validateChannel(options.channel);
    if (entries.len == 0) {
        try numericPrefix(writer, .RPL_NOTOPIC, options.server_name, options.requester);
        try writer.print("{s} :No topic history is available\r\n", .{options.channel});
        return 1;
    }

    var emitted: usize = 0;
    const count = @min(options.limit, entries.len);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try renderTopicEntry(writer, options.server_name, options.requester, options.channel, entries[i]);
        emitted += 2;
    }
    return emitted;
}

pub fn formatCode(numeric: Numeric, buf: *[3]u8) []const u8 {
    const value: u16 = @intFromEnum(numeric);
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

fn renderTopicEntry(
    writer: anytype,
    server_name: []const u8,
    requester: []const u8,
    channel: []const u8,
    entry: TopicChange,
) !void {
    try numericPrefix(writer, .RPL_TOPIC, server_name, requester);
    try writer.print("{s} :{s}\r\n", .{ channel, entry.topic });
    try numericPrefix(writer, .RPL_TOPICWHOTIME, server_name, requester);
    try writer.print("{s} {s} {d}\r\n", .{ channel, entry.setter, entry.set_at });
}

fn numericPrefix(writer: anytype, numeric: Numeric, server_name: []const u8, requester: []const u8) !void {
    var code_buf: [3]u8 = undefined;
    try writer.print(":{s} {s} {s} ", .{ server_name, formatCode(numeric, &code_buf), requester });
}

fn validateChannel(channel: []const u8) TopicLogError!void {
    if (!validChannelName(channel)) return error.InvalidChannel;
}

fn validateChannelForParse(channel: []const u8) ParseError!void {
    if (!validChannelName(channel)) return error.InvalidChannel;
}

fn validChannelName(channel: []const u8) bool {
    if (channel.len == 0 or channel.len > max_channel_bytes) return false;
    if (channel[0] != '#' and channel[0] != '&') return false;
    for (channel) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or byte == ' ' or byte == ',' or byte == ':') return false;
    }
    return true;
}

fn validateSetter(setter: []const u8) TopicLogError!void {
    if (setter.len == 0 or setter.len > max_setter_bytes) return error.InvalidSetter;
    for (setter) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or byte == ' ') return error.InvalidSetter;
    }
}

fn validateTimestamp(set_at: i64) TopicLogError!void {
    if (set_at < 0) return error.InvalidTimestamp;
}

fn validateTopic(topic: []const u8) TopicLogError!void {
    if (topic.len > max_topic_bytes) return error.TopicTooLong;
    for (topic) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return error.TopicTooLong;
    }
}

fn parseLimit(text: []const u8) ParseError!usize {
    if (text.len == 0) return error.InvalidLimit;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidLimit;
    }
    const value = std.fmt.parseUnsigned(usize, text, 10) catch return error.InvalidLimit;
    if (value == 0) return error.InvalidLimit;
    return value;
}

fn nextToken(cursor: *[]const u8) ?[]const u8 {
    cursor.* = std.mem.trimStart(u8, cursor.*, " \t");
    if (cursor.len == 0) return null;
    const end = std.mem.indexOfAny(u8, cursor.*, " \t") orelse cursor.len;
    const token = cursor.*[0..end];
    cursor.* = cursor.*[end..];
    cursor.* = std.mem.trimStart(u8, cursor.*, " \t");
    return token;
}

const testing = std.testing;

test "record owns borrowed setter and topic bytes" {
    var log = TopicLog.init(testing.allocator, .{ .max_entries_per_channel = 4 });
    defer log.deinit();

    var setter = [_]u8{ 'a', 'l', 'i', 'c', 'e' };
    var topic = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    try testing.expectEqual(@as(usize, 1), try log.record("#ops", setter[0..], 100, topic[0..]));
    setter[0] = 'm';
    topic[0] = 'j';

    var out: [4]TopicChange = undefined;
    const recent = log.recent("#ops", &out);
    try testing.expectEqual(@as(usize, 1), recent.len);
    try testing.expectEqualStrings("alice", recent[0].setter);
    try testing.expectEqualStrings("hello", recent[0].topic);
    try testing.expectEqual(@as(i64, 100), recent[0].set_at);
}

test "bounded ring keeps newest entries per channel" {
    var log = TopicLog.init(testing.allocator, .{ .max_entries_per_channel = 3 });
    defer log.deinit();

    try testing.expectEqual(@as(usize, 1), try log.record("#ops", "u1", 1, "one"));
    try testing.expectEqual(@as(usize, 2), try log.record("#ops", "u2", 2, "two"));
    try testing.expectEqual(@as(usize, 3), try log.record("#ops", "u3", 3, "three"));
    try testing.expectEqual(@as(usize, 3), try log.record("#ops", "u4", 4, "four"));
    _ = try log.record("#dev", "u5", 5, "other");

    var out: [4]TopicChange = undefined;
    const recent = log.recent("#ops", &out);
    try testing.expectEqual(@as(usize, 3), recent.len);
    try testing.expectEqualStrings("four", recent[0].topic);
    try testing.expectEqualStrings("three", recent[1].topic);
    try testing.expectEqualStrings("two", recent[2].topic);
    try testing.expectEqual(@as(usize, 1), log.count("#dev"));
}

test "recent respects caller output capacity and missing channels are empty" {
    var log = TopicLog.init(testing.allocator, .{ .max_entries_per_channel = 4 });
    defer log.deinit();

    _ = try log.record("#ops", "u1", 1, "one");
    _ = try log.record("#ops", "u2", 2, "two");

    var one: [1]TopicChange = undefined;
    const recent = log.recent("#ops", &one);
    try testing.expectEqual(@as(usize, 1), recent.len);
    try testing.expectEqualStrings("two", recent[0].topic);

    var none: [2]TopicChange = undefined;
    try testing.expectEqual(@as(usize, 0), log.recent("#missing", &none).len);
}

test "clear frees one channel log and leaves other channels intact" {
    var log = TopicLog.init(testing.allocator, .{ .max_entries_per_channel = 2 });
    defer log.deinit();

    _ = try log.record("#ops", "u1", 1, "one");
    _ = try log.record("#dev", "u2", 2, "two");
    try testing.expect(log.clear("#ops"));
    try testing.expect(!log.clear("#ops"));
    try testing.expectEqual(@as(usize, 0), log.count("#ops"));
    try testing.expectEqual(@as(usize, 1), log.count("#dev"));
}

test "validation rejects invalid channels setters timestamps topics and limits" {
    var log = TopicLog.init(testing.allocator, .{ .max_channels = 1, .max_entries_per_channel = 1 });
    defer log.deinit();

    try testing.expectError(error.InvalidChannel, log.record("ops", "u", 1, "ok"));
    try testing.expectError(error.InvalidSetter, log.record("#ops", "", 1, "ok"));
    try testing.expectError(error.InvalidTimestamp, log.record("#ops", "u", -1, "ok"));
    try testing.expectError(error.TopicTooLong, log.record("#ops", "u", 1, "x" ** (max_topic_bytes + 1)));
    _ = try log.record("#ops", "u", 1, "ok");
    try testing.expectError(error.TooManyChannels, log.record("#dev", "u", 1, "ok"));

    var zero = TopicLog.init(testing.allocator, .{ .max_entries_per_channel = 0 });
    defer zero.deinit();
    try testing.expectError(error.InvalidLimit, zero.record("#ops", "u", 1, "ok"));
}

test "parse TOPIC HISTORY params without confusing topic text for history" {
    const p1 = [_][]const u8{ "#ops", "HISTORY" };
    const req1 = (try parseTopicHistoryParams(&p1)).?;
    try testing.expectEqualStrings("#ops", req1.channel);
    try testing.expectEqual(@as(usize, default_history_limit), req1.limit);

    const p2 = [_][]const u8{ "#ops", "history", "3" };
    const req2 = (try parseTopicHistoryParams(&p2)).?;
    try testing.expectEqual(@as(usize, 3), req2.limit);

    const p3 = [_][]const u8{ "#ops", "new topic text" };
    try testing.expectEqual(@as(?TopicHistoryRequest, null), try parseTopicHistoryParams(&p3));
    const p4 = [_][]const u8{ "#ops", "HISTORY", "0" };
    try testing.expectError(error.InvalidLimit, parseTopicHistoryParams(&p4));
}

test "parse raw TOPIC HISTORY lines with tags prefixes and trailing topics" {
    const req1 = (try parseTopicHistoryLine("TOPIC #ops HISTORY 2\r\n")).?;
    try testing.expectEqualStrings("#ops", req1.channel);
    try testing.expectEqual(@as(usize, 2), req1.limit);

    const req2 = (try parseTopicHistoryLine("@aaa=bbb :nick!u@h TOPIC #dev history")).?;
    try testing.expectEqualStrings("#dev", req2.channel);
    try testing.expectEqual(@as(usize, default_history_limit), req2.limit);

    try testing.expectEqual(@as(?TopicHistoryRequest, null), try parseTopicHistoryLine("TOPIC #ops :HISTORY"));
    try testing.expectEqual(@as(?TopicHistoryRequest, null), try parseTopicHistoryLine("TOPIC #ops :HISTORY 2"));
    try testing.expectError(error.InvalidCommand, parseTopicHistoryLine("PRIVMSG #ops HISTORY"));
    try testing.expectError(error.InvalidLimit, parseTopicHistoryLine("TOPIC #ops HISTORY x"));
}

test "render standalone history uses only server numerics" {
    const entries = [_]TopicChange{
        .{ .setter = "alice", .set_at = 10, .topic = "newest" },
        .{ .setter = "bob", .set_at = 9, .topic = "older topic" },
    };
    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    const emitted = try renderTopicHistory(&writer, .{
        .server_name = "mizuchi.local",
        .requester = "kain",
        .channel = "#ops",
        .limit = 2,
    }, &entries);

    try testing.expectEqual(@as(usize, 4), emitted);
    try testing.expectEqualStrings(
        ":mizuchi.local 332 kain #ops :newest\r\n" ++
            ":mizuchi.local 333 kain #ops alice 10\r\n" ++
            ":mizuchi.local 332 kain #ops :older topic\r\n" ++
            ":mizuchi.local 333 kain #ops bob 9\r\n",
        writer.buffered(),
    );
}

test "renderRecent applies limit and empty history emits 331" {
    var log = TopicLog.init(testing.allocator, .{ .max_entries_per_channel = 4 });
    defer log.deinit();

    _ = try log.record("#ops", "alice", 10, "first");
    _ = try log.record("#ops", "bob", 20, "second");

    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try testing.expectEqual(@as(usize, 2), try log.renderRecent(&writer, .{
        .server_name = "mizuchi.local",
        .requester = "kain",
        .channel = "#ops",
        .limit = 1,
    }));
    try testing.expectEqualStrings(
        ":mizuchi.local 332 kain #ops :second\r\n" ++
            ":mizuchi.local 333 kain #ops bob 20\r\n",
        writer.buffered(),
    );

    var empty_buf: [128]u8 = undefined;
    var empty_writer = std.Io.Writer.fixed(&empty_buf);
    try testing.expectEqual(@as(usize, 1), try log.renderRecent(&empty_writer, .{
        .server_name = "mizuchi.local",
        .requester = "kain",
        .channel = "#none",
    }));
    try testing.expectEqualStrings(
        ":mizuchi.local 331 kain #none :No topic history is available\r\n",
        empty_writer.buffered(),
    );
}

test "formatCode renders fixed-width topic numerics" {
    var buf: [3]u8 = undefined;
    try testing.expectEqualStrings("331", formatCode(.RPL_NOTOPIC, &buf));
    try testing.expectEqualStrings("332", formatCode(.RPL_TOPIC, &buf));
    try testing.expectEqualStrings("333", formatCode(.RPL_TOPICWHOTIME, &buf));
}
