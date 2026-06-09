//! Services quiet-ban state for real server-command handling.
//!
//! This module intentionally has no daemon/protocol imports. It carries only
//! the quiet/mute list data structure, a small borrowed-slice command parser,
//! and hostmask glob matching. Quiet bans suppress channel speech; they do not
//! kick users and are distinct from AKICK-style enforcement.
const std = @import("std");

pub const command_name = "SVCQUIETBAN";

pub const Numeric = struct {
    pub const list: u16 = 728;
    pub const list_end: u16 = 729;
    pub const added: u16 = 730;
    pub const removed: u16 = 731;
    pub const not_found: u16 = 732;
};

pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    ChannelTooLong,
    EmptyMask,
    MaskTooLong,
    BadMask,
    EmptySetter,
    SetterTooLong,
    TooManyChannels,
    TooManyEntries,
};

pub const ParseError = error{
    EmptyCommand,
    UnknownCommand,
    UnknownAction,
    BadArity,
    InvalidDuration,
    InvalidTimestamp,
    TimestampOverflow,
};

pub const Config = struct {
    max_channels: usize = 16384,
    max_entries_per_channel: usize = 512,
    max_channel_len: usize = 128,
    max_mask_len: usize = 256,
    max_setter_len: usize = 128,
};

pub const Entry = struct {
    mask: []const u8,
    setter: []const u8,
    expires_at_ms: ?i64 = null,

    pub fn isExpired(self: Entry, now_ms: i64) bool {
        return if (self.expires_at_ms) |expires_at| expires_at <= now_ms else false;
    }
};

pub const AddResult = enum {
    inserted,
    updated,
};

pub const Command = union(enum) {
    add: Add,
    remove: Remove,
    list: List,
    sweep: Sweep,

    pub const Add = struct {
        channel: []const u8,
        mask: []const u8,
        setter: []const u8,
        expires_at_ms: ?i64 = null,
    };

    pub const Remove = struct {
        channel: []const u8,
        mask: []const u8,
    };

    pub const List = struct {
        channel: []const u8,
    };

    pub const Sweep = struct {
        now_ms: i64,
    };
};

const ChannelList = struct {
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    fn deinit(self: *ChannelList, allocator: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            allocator.free(entry.mask);
            allocator.free(entry.setter);
        }
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const ChannelList, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (ircEql(entry.mask, mask)) return idx;
        }
        return null;
    }

    fn removeAt(self: *ChannelList, allocator: std.mem.Allocator, idx: usize) void {
        allocator.free(self.entries.items[idx].mask);
        allocator.free(self.entries.items[idx].setter);
        _ = self.entries.orderedRemove(idx);
    }

    fn sweep(self: *ChannelList, allocator: std.mem.Allocator, now_ms: i64) usize {
        var removed: usize = 0;
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            if (self.entries.items[idx].isExpired(now_ms)) {
                self.removeAt(allocator, idx);
                removed += 1;
            } else {
                idx += 1;
            }
        }
        return removed;
    }
};

pub const QuietBanStore = struct {
    allocator: std.mem.Allocator,
    config: Config,
    channels: std.StringHashMap(ChannelList),

    pub fn init(allocator: std.mem.Allocator) QuietBanStore {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) QuietBanStore {
        return .{
            .allocator = allocator,
            .config = config,
            .channels = std.StringHashMap(ChannelList).init(allocator),
        };
    }

    pub fn deinit(self: *QuietBanStore) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn add(
        self: *QuietBanStore,
        channel: []const u8,
        mask: []const u8,
        setter: []const u8,
        expires_at_ms: ?i64,
    ) Error!AddResult {
        try self.validateChannel(channel);
        try self.validateMask(mask);
        try self.validateSetter(setter);

        const channel_list = try self.ensureChannel(channel);
        if (channel_list.indexOf(mask)) |idx| {
            const owned_mask = try self.allocator.dupe(u8, mask);
            errdefer self.allocator.free(owned_mask);
            const owned_setter = try self.allocator.dupe(u8, setter);
            errdefer self.allocator.free(owned_setter);

            self.allocator.free(channel_list.entries.items[idx].mask);
            self.allocator.free(channel_list.entries.items[idx].setter);
            channel_list.entries.items[idx] = .{
                .mask = owned_mask,
                .setter = owned_setter,
                .expires_at_ms = expires_at_ms,
            };
            return .updated;
        }

        if (channel_list.entries.items.len >= self.config.max_entries_per_channel) return error.TooManyEntries;
        const owned_mask = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(owned_mask);
        const owned_setter = try self.allocator.dupe(u8, setter);
        errdefer self.allocator.free(owned_setter);
        try channel_list.entries.append(self.allocator, .{
            .mask = owned_mask,
            .setter = owned_setter,
            .expires_at_ms = expires_at_ms,
        });
        return .inserted;
    }

    pub fn remove(self: *QuietBanStore, channel: []const u8, mask: []const u8) bool {
        const entry = self.channels.getEntryAdapted(channel, ChannelLookupAdapter{}) orelse return false;
        const idx = entry.value_ptr.indexOf(mask) orelse return false;
        entry.value_ptr.removeAt(self.allocator, idx);
        if (entry.value_ptr.entries.items.len == 0) self.dropChannel(entry);
        return true;
    }

    pub fn list(self: *const QuietBanStore, channel: []const u8) []const Entry {
        const list_ptr = self.channels.getPtrAdapted(channel, ChannelLookupAdapter{}) orelse return &.{};
        return list_ptr.entries.items;
    }

    pub fn listActive(self: *QuietBanStore, channel: []const u8, now_ms: i64) []const Entry {
        _ = self.sweepChannel(channel, now_ms);
        return self.list(channel);
    }

    pub fn isQuieted(self: *const QuietBanStore, channel: []const u8, hostmask: []const u8, now_ms: i64) bool {
        const list_ptr = self.channels.getPtrAdapted(channel, ChannelLookupAdapter{}) orelse return false;
        if (toMask(hostmask) == null) return false;
        for (list_ptr.entries.items) |entry| {
            if (!entry.isExpired(now_ms) and matchMask(entry.mask, hostmask)) return true;
        }
        return false;
    }

    pub fn sweep(self: *QuietBanStore, now_ms: i64) usize {
        var removed: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            removed += entry.value_ptr.sweep(self.allocator, now_ms);
        }
        while (self.dropFirstEmptyChannel()) {}
        return removed;
    }

    pub fn sweepChannel(self: *QuietBanStore, channel: []const u8, now_ms: i64) usize {
        const entry = self.channels.getEntryAdapted(channel, ChannelLookupAdapter{}) orelse return 0;
        const removed = entry.value_ptr.sweep(self.allocator, now_ms);
        if (entry.value_ptr.entries.items.len == 0) self.dropChannel(entry);
        return removed;
    }

    fn ensureChannel(self: *QuietBanStore, channel: []const u8) Error!*ChannelList {
        if (self.channels.getPtrAdapted(channel, ChannelLookupAdapter{})) |channel_list| return channel_list;
        if (self.channels.count() >= self.config.max_channels) return error.TooManyChannels;

        const key = try foldAlloc(self.allocator, channel);
        errdefer self.allocator.free(key);
        try self.channels.putNoClobber(key, .{});
        return self.channels.getPtr(key).?;
    }

    fn dropChannel(self: *QuietBanStore, entry: std.StringHashMap(ChannelList).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn dropFirstEmptyChannel(self: *QuietBanStore) bool {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.entries.items.len == 0) {
                self.dropChannel(entry);
                return true;
            }
        }
        return false;
    }

    fn validateChannel(self: *const QuietBanStore, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.config.max_channel_len) return error.ChannelTooLong;
    }

    fn validateMask(self: *const QuietBanStore, mask: []const u8) Error!void {
        if (mask.len == 0) return error.EmptyMask;
        if (mask.len > self.config.max_mask_len) return error.MaskTooLong;
        if (toMask(mask) == null) return error.BadMask;
    }

    fn validateSetter(self: *const QuietBanStore, setter: []const u8) Error!void {
        if (setter.len == 0) return error.EmptySetter;
        if (setter.len > self.config.max_setter_len) return error.SetterTooLong;
    }
};

pub fn parseCommand(line: []const u8, now_ms: i64) ParseError!Command {
    var tok = std.mem.tokenizeAny(u8, line, " \t\r\n");
    const command = tok.next() orelse return error.EmptyCommand;
    if (!asciiEql(command, command_name) and !asciiEql(command, "QUIETBAN")) return error.UnknownCommand;

    const action = tok.next() orelse return error.BadArity;
    if (asciiEql(action, "ADD")) {
        const channel = tok.next() orelse return error.BadArity;
        const mask = tok.next() orelse return error.BadArity;
        const setter = tok.next() orelse return error.BadArity;
        const expires_at_ms = if (tok.next()) |expiry| try parseExpiry(expiry, now_ms) else null;
        if (tok.next() != null) return error.BadArity;
        return .{ .add = .{
            .channel = channel,
            .mask = mask,
            .setter = setter,
            .expires_at_ms = expires_at_ms,
        } };
    }

    if (asciiEql(action, "DEL") or asciiEql(action, "REMOVE")) {
        const channel = tok.next() orelse return error.BadArity;
        const mask = tok.next() orelse return error.BadArity;
        if (tok.next() != null) return error.BadArity;
        return .{ .remove = .{ .channel = channel, .mask = mask } };
    }

    if (asciiEql(action, "LIST")) {
        const channel = tok.next() orelse return error.BadArity;
        if (tok.next() != null) return error.BadArity;
        return .{ .list = .{ .channel = channel } };
    }

    if (asciiEql(action, "SWEEP")) {
        const now = if (tok.next()) |value| try parseTimestamp(value) else now_ms;
        if (tok.next() != null) return error.BadArity;
        return .{ .sweep = .{ .now_ms = now } };
    }

    return error.UnknownAction;
}

pub fn matchGlob(pattern: []const u8, text: []const u8) bool {
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
                    if (ircFold(token.byte) == ircFold(text[text_index])) {
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

pub fn matchMask(pattern: []const u8, hostmask: []const u8) bool {
    const pattern_mask = toMask(pattern) orelse return false;
    const user_mask = toMask(hostmask) orelse return false;

    return matchGlob(pattern_mask.nick, user_mask.nick) and
        matchGlob(pattern_mask.user, user_mask.user) and
        matchGlob(pattern_mask.host, user_mask.host);
}

const HostMask = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

fn toMask(source: []const u8) ?HostMask {
    const bang = indexOf(source, '!', 0) orelse return null;
    const at = indexOf(source, '@', bang + 1) orelse return null;

    if (bang == 0 or at == bang + 1 or at + 1 == source.len) return null;
    if (indexOf(source, '!', bang + 1) != null) return null;
    if (indexOf(source, '@', at + 1) != null) return null;

    return .{
        .nick = source[0..bang],
        .user = source[bang + 1 .. at],
        .host = source[at + 1 ..],
    };
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

fn parseExpiry(text: []const u8, now_ms: i64) ParseError!?i64 {
    if (asciiEql(text, "PERMANENT") or asciiEql(text, "NEVER") or std.mem.eql(u8, text, "-")) return null;
    if (text.len > 1 and text[0] == '@') return try parseTimestamp(text[1..]);

    const duration = try parseDurationMs(text);
    const now = @as(i128, now_ms);
    const expires = now + @as(i128, duration);
    if (expires > std.math.maxInt(i64) or expires < std.math.minInt(i64)) return error.TimestampOverflow;
    return @intCast(expires);
}

fn parseTimestamp(text: []const u8) ParseError!i64 {
    if (text.len == 0) return error.InvalidTimestamp;
    return std.fmt.parseInt(i64, text, 10) catch error.InvalidTimestamp;
}

fn parseDurationMs(text: []const u8) ParseError!i64 {
    if (text.len == 0) return error.InvalidDuration;
    var digits_end: usize = 0;
    var value: i128 = 0;
    while (digits_end < text.len and text[digits_end] >= '0' and text[digits_end] <= '9') : (digits_end += 1) {
        value = value * 10 + (text[digits_end] - '0');
        if (value > std.math.maxInt(i64)) return error.InvalidDuration;
    }
    if (digits_end == 0) return error.InvalidDuration;

    const suffix = text[digits_end..];
    const multiplier: i128 = if (suffix.len == 0 or asciiEql(suffix, "MS"))
        1
    else if (asciiEql(suffix, "S"))
        1000
    else if (asciiEql(suffix, "M"))
        60 * 1000
    else if (asciiEql(suffix, "H"))
        60 * 60 * 1000
    else if (asciiEql(suffix, "D"))
        24 * 60 * 60 * 1000
    else
        return error.InvalidDuration;

    const total = value * multiplier;
    if (total <= 0 or total > std.math.maxInt(i64)) return error.InvalidDuration;
    return @intCast(total);
}

const ChannelLookupAdapter = struct {
    pub fn hash(_: ChannelLookupAdapter, key: []const u8) u64 {
        var h = std.hash.Wyhash.init(0);
        for (key) |byte| h.update(&.{ircFold(byte)});
        return h.final();
    }

    pub fn eql(_: ChannelLookupAdapter, a: []const u8, b: []const u8) bool {
        return ircEql(a, b);
    }
};

fn foldAlloc(allocator: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, value.len);
    for (value, 0..) |byte, idx| out[idx] = ircFold(byte);
    return out;
}

fn ircEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (ircFold(left) != ircFold(right)) return false;
    }
    return true;
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiFold(left) != asciiFold(right)) return false;
    }
    return true;
}

fn asciiFold(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        else => byte,
    };
}

fn ircFold(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        '^' => '~',
        else => byte,
    };
}

fn indexOf(bytes: []const u8, needle: u8, start: usize) ?usize {
    var index = start;
    while (index < bytes.len) : (index += 1) {
        if (bytes[index] == needle) return index;
    }
    return null;
}

const testing = std.testing;

test "add list remove and channel pruning" {
    var store = QuietBanStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectEqual(AddResult.inserted, try store.add("#ops", "*!*@bad.example", "services", null));
    try testing.expectEqual(@as(usize, 1), store.list("#ops").len);
    try testing.expectEqualStrings("*!*@bad.example", store.list("#ops")[0].mask);
    try testing.expect(store.remove("#ops", "*!*@bad.example"));
    try testing.expect(!store.remove("#ops", "*!*@bad.example"));
    try testing.expectEqual(@as(usize, 0), store.list("#ops").len);
}

test "duplicate add updates setter and expiry without leaking old entry" {
    var store = QuietBanStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectEqual(AddResult.inserted, try store.add("#ops", "*!*@bad.example", "one", null));
    try testing.expectEqual(AddResult.updated, try store.add("#OPS", "*!*@BAD.example", "two", 9000));
    const entries = store.list("#ops");
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqualStrings("*!*@BAD.example", entries[0].mask);
    try testing.expectEqualStrings("two", entries[0].setter);
    try testing.expectEqual(@as(?i64, 9000), entries[0].expires_at_ms);
}

test "quiet matching is channel scoped and case insensitive" {
    var store = QuietBanStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("#ops", "Bad?Nick!*@*.Example.COM", "services", null);
    try testing.expect(store.isQuieted("#OPS", "bad1nick!user@chat.example.com", 1000));
    try testing.expect(!store.isQuieted("#random", "bad1nick!user@chat.example.com", 1000));
    try testing.expect(!store.isQuieted("#ops", "other!user@chat.example.com", 1000));
}

test "expired quiets are skipped before sweep" {
    var store = QuietBanStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("#ops", "*!*@old.example", "services", 2000);
    _ = try store.add("#ops", "*!*@live.example", "services", 4000);
    try testing.expect(!store.isQuieted("#ops", "nick!user@old.example", 2000));
    try testing.expect(store.isQuieted("#ops", "nick!user@live.example", 2000));
    try testing.expectEqual(@as(usize, 2), store.list("#ops").len);
}

test "sweep removes expired entries globally and keeps live entries" {
    var store = QuietBanStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("#a", "*!*@one.example", "services", 100);
    _ = try store.add("#a", "*!*@two.example", "services", 300);
    _ = try store.add("#b", "*!*@three.example", "services", null);
    try testing.expectEqual(@as(usize, 1), store.sweep(200));
    try testing.expectEqual(@as(usize, 1), store.list("#a").len);
    try testing.expectEqual(@as(usize, 1), store.list("#b").len);
    try testing.expectEqual(@as(usize, 1), store.sweep(300));
    try testing.expectEqual(@as(usize, 0), store.list("#a").len);
}

test "listActive sweeps only the requested channel" {
    var store = QuietBanStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("#a", "*!*@old.example", "services", 10);
    _ = try store.add("#b", "*!*@old.example", "services", 10);
    try testing.expectEqual(@as(usize, 0), store.listActive("#a", 10).len);
    try testing.expectEqual(@as(usize, 1), store.list("#b").len);
}

test "validation rejects malformed state inputs" {
    var store = QuietBanStore.initWithConfig(testing.allocator, .{ .max_channel_len = 4, .max_mask_len = 8, .max_setter_len = 3 });
    defer store.deinit();

    try testing.expectError(error.EmptyChannel, store.add("", "*!*@h", "svc", null));
    try testing.expectError(error.ChannelTooLong, store.add("#wide", "*!*@h", "svc", null));
    try testing.expectError(error.EmptyMask, store.add("#ok", "", "svc", null));
    try testing.expectError(error.MaskTooLong, store.add("#ok", "nick!user@host", "svc", null));
    try testing.expectError(error.BadMask, store.add("#ok", "badmask", "svc", null));
    try testing.expectError(error.EmptySetter, store.add("#ok", "*!*@h", "", null));
    try testing.expectError(error.SetterTooLong, store.add("#ok", "*!*@h", "wide", null));
}

test "caps are enforced per store and per channel" {
    var store = QuietBanStore.initWithConfig(testing.allocator, .{ .max_channels = 1, .max_entries_per_channel = 1 });
    defer store.deinit();

    _ = try store.add("#a", "*!*@one.example", "services", null);
    try testing.expectError(error.TooManyEntries, store.add("#a", "*!*@two.example", "services", null));
    try testing.expectError(error.TooManyChannels, store.add("#b", "*!*@one.example", "services", null));
}

test "glob matching is anchored and supports escaped wildcards" {
    try testing.expect(matchGlob("*", ""));
    try testing.expect(matchGlob("a*b", "ab"));
    try testing.expect(matchGlob("a*b", "axxb"));
    try testing.expect(!matchGlob("a*b", "ba"));
    try testing.expect(matchGlob("file\\*.txt", "file*.txt"));
    try testing.expect(!matchGlob("file\\*.txt", "file123.txt"));
}

test "hostmask matching does not let wildcards cross separators" {
    try testing.expect(matchMask("*!*@*.example", "nick!user@a.example"));
    try testing.expect(!matchMask("nick*@host", "nick!user@host"));
    try testing.expect(!matchMask("nick!*", "nick!user@host"));
    try testing.expect(!matchMask("*!*@host", "not-a-mask"));
}

test "parser handles real server command add variants" {
    const parsed = try parseCommand("SVCQUIETBAN ADD #ops *!*@bad.example services 5m", 1000);
    switch (parsed) {
        .add => |add| {
            try testing.expectEqualStrings("#ops", add.channel);
            try testing.expectEqualStrings("*!*@bad.example", add.mask);
            try testing.expectEqualStrings("services", add.setter);
            try testing.expectEqual(@as(?i64, 301000), add.expires_at_ms);
        },
        else => return error.TestUnexpectedResult,
    }

    const permanent = try parseCommand("quietban add #ops *!*@bad.example services never", 1000);
    switch (permanent) {
        .add => |add| try testing.expectEqual(@as(?i64, null), add.expires_at_ms),
        else => return error.TestUnexpectedResult,
    }
}

test "parser handles remove list and sweep" {
    const removed = try parseCommand("SVCQUIETBAN REMOVE #ops *!*@bad.example", 1);
    switch (removed) {
        .remove => |remove| {
            try testing.expectEqualStrings("#ops", remove.channel);
            try testing.expectEqualStrings("*!*@bad.example", remove.mask);
        },
        else => return error.TestUnexpectedResult,
    }

    const listed = try parseCommand("SVCQUIETBAN LIST #ops", 1);
    switch (listed) {
        .list => |list_cmd| try testing.expectEqualStrings("#ops", list_cmd.channel),
        else => return error.TestUnexpectedResult,
    }

    const swept = try parseCommand("SVCQUIETBAN SWEEP 42", 1);
    switch (swept) {
        .sweep => |sweep_cmd| try testing.expectEqual(@as(i64, 42), sweep_cmd.now_ms),
        else => return error.TestUnexpectedResult,
    }
}

test "parser supports absolute expiries and rejects pseudo-client command names" {
    const parsed = try parseCommand("SVCQUIETBAN ADD #ops *!*@bad.example services @9000", 1000);
    switch (parsed) {
        .add => |add| try testing.expectEqual(@as(?i64, 9000), add.expires_at_ms),
        else => return error.TestUnexpectedResult,
    }

    try testing.expectError(error.UnknownCommand, parseCommand("ChanServ QUIET #ops *!*@bad.example", 1));
    try testing.expectError(error.BadArity, parseCommand("SVCQUIETBAN ADD #ops *!*@bad.example", 1));
    try testing.expectError(error.InvalidDuration, parseCommand("SVCQUIETBAN ADD #ops *!*@bad.example services soon", 1));
}

test "parsed add can be applied to the store" {
    var store = QuietBanStore.init(testing.allocator);
    defer store.deinit();

    const parsed = try parseCommand("SVCQUIETBAN ADD #ops quiet!*@*.example services 1s", 500);
    switch (parsed) {
        .add => |add| _ = try store.add(add.channel, add.mask, add.setter, add.expires_at_ms),
        else => return error.TestUnexpectedResult,
    }

    try testing.expect(store.isQuieted("#ops", "Quiet!u@a.example", 1499));
    try testing.expect(!store.isQuieted("#ops", "Quiet!u@a.example", 1500));
}
