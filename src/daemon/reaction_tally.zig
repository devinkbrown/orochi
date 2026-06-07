const std = @import("std");
const toml = @import("../proto/toml.zig");

pub const max_messages: usize = 4096;
pub const max_msgid_len: usize = 128;
pub const max_emoji_len: usize = 64;
pub const max_reactor_len: usize = 128;
pub const max_emojis_per_message: usize = 64;
pub const max_reactors_per_emoji: usize = 1024;

/// Runtime-tunable reaction-tally bounds. Defaults equal the bare constants
/// above; `applyToml` overlays the `[media.reactions]` section.
pub const Config = struct {
    max_messages: usize = max_messages,
    max_msgid_len: usize = max_msgid_len,
    max_emoji_len: usize = max_emoji_len,
    max_reactor_len: usize = max_reactor_len,
    max_emojis_per_message: usize = max_emojis_per_message,
    max_reactors_per_emoji: usize = max_reactors_per_emoji,
};

/// Overlay `[media.reactions]` keys from a parsed TOML document onto `cfg`.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.reactions.max_messages")) |v| cfg.max_messages = @intCast(v);
    if (doc.getUint("media.reactions.max_msgid_bytes")) |v| cfg.max_msgid_len = @intCast(v);
    if (doc.getUint("media.reactions.max_emoji_bytes")) |v| cfg.max_emoji_len = @intCast(v);
    if (doc.getUint("media.reactions.max_reactor_bytes")) |v| cfg.max_reactor_len = @intCast(v);
    if (doc.getUint("media.reactions.max_emojis_per_message")) |v| cfg.max_emojis_per_message = @intCast(v);
    if (doc.getUint("media.reactions.max_reactors_per_emoji")) |v| cfg.max_reactors_per_emoji = @intCast(v);
}

pub const Error = std.mem.Allocator.Error || error{
    MessageIdTooLong,
    EmojiTooLong,
    ReactorTooLong,
    EmptyEmoji,
    EmptyReactor,
    TooManyMessages,
    TooManyEmojis,
    TooManyReactors,
};

pub const EmojiCount = struct {
    emoji: []u8,
    count: u32,
    reactors: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *EmojiCount, allocator: std.mem.Allocator) void {
        allocator.free(self.emoji);
        for (self.reactors.items) |reactor| allocator.free(reactor);
        self.reactors.deinit(allocator);
    }

    fn findReactor(self: *const EmojiCount, reactor: []const u8) ?usize {
        for (self.reactors.items, 0..) |known, i| {
            if (std.mem.eql(u8, known, reactor)) return i;
        }
        return null;
    }
};

const MessageReactions = struct {
    counts: std.ArrayListUnmanaged(EmojiCount) = .empty,

    fn deinit(self: *MessageReactions, allocator: std.mem.Allocator) void {
        for (self.counts.items) |*bucket| bucket.deinit(allocator);
        self.counts.deinit(allocator);
    }

    fn findEmoji(self: *const MessageReactions, emoji: []const u8) ?usize {
        for (self.counts.items, 0..) |bucket, i| {
            if (std.mem.eql(u8, bucket.emoji, emoji)) return i;
        }
        return null;
    }
};

pub const ReactionTally = struct {
    allocator: std.mem.Allocator,
    messages: std.StringHashMap(MessageReactions),
    config: Config,

    pub fn init(allocator: std.mem.Allocator) ReactionTally {
        return initConfig(allocator, .{});
    }

    pub fn initConfig(allocator: std.mem.Allocator, config: Config) ReactionTally {
        return .{ .allocator = allocator, .messages = std.StringHashMap(MessageReactions).init(allocator), .config = config };
    }

    pub fn deinit(self: *ReactionTally) void {
        var it = self.messages.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.messages.deinit();
        self.* = undefined;
    }

    pub fn react(self: *ReactionTally, msgid: []const u8, emoji: []const u8, reactor: []const u8) Error!u32 {
        try validateInput(self, msgid, emoji, reactor);
        const message = try self.ensureMessage(msgid);
        const bucket = try self.ensureEmoji(message, emoji);
        if (bucket.findReactor(reactor) != null) return bucket.count;
        if (bucket.reactors.items.len >= self.config.max_reactors_per_emoji) return error.TooManyReactors;

        const owned_reactor = try self.allocator.dupe(u8, reactor);
        errdefer self.allocator.free(owned_reactor);
        try bucket.reactors.append(self.allocator, owned_reactor);
        bucket.count += 1;
        return bucket.count;
    }

    pub fn unreact(self: *ReactionTally, msgid: []const u8, emoji: []const u8, reactor: []const u8) bool {
        const entry = self.messages.getEntry(msgid) orelse return false;
        const emoji_idx = entry.value_ptr.findEmoji(emoji) orelse return false;
        const bucket = &entry.value_ptr.counts.items[emoji_idx];
        const reactor_idx = bucket.findReactor(reactor) orelse return false;

        const owned_reactor = bucket.reactors.orderedRemove(reactor_idx);
        self.allocator.free(owned_reactor);
        bucket.count -= 1;

        if (bucket.count == 0) {
            var removed = entry.value_ptr.counts.orderedRemove(emoji_idx);
            removed.deinit(self.allocator);
            if (entry.value_ptr.counts.items.len == 0) self.dropMessage(entry);
        }
        return true;
    }

    pub fn counts(self: *const ReactionTally, msgid: []const u8) []const EmojiCount {
        const message = self.messages.getPtr(msgid) orelse return &.{};
        return message.counts.items;
    }

    fn ensureMessage(self: *ReactionTally, msgid: []const u8) Error!*MessageReactions {
        if (self.messages.getPtr(msgid)) |message| return message;
        if (self.messages.count() >= self.config.max_messages) return error.TooManyMessages;

        const owned_key = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_key);
        try self.messages.putNoClobber(owned_key, .{});
        return self.messages.getPtr(msgid).?;
    }

    fn ensureEmoji(self: *ReactionTally, message: *MessageReactions, emoji: []const u8) Error!*EmojiCount {
        if (message.findEmoji(emoji)) |idx| return &message.counts.items[idx];
        if (message.counts.items.len >= self.config.max_emojis_per_message) return error.TooManyEmojis;

        const owned_emoji = try self.allocator.dupe(u8, emoji);
        errdefer self.allocator.free(owned_emoji);
        try message.counts.append(self.allocator, .{ .emoji = owned_emoji, .count = 0 });
        return &message.counts.items[message.counts.items.len - 1];
    }

    fn dropMessage(self: *ReactionTally, entry: std.StringHashMap(MessageReactions).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.messages.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }
};

fn validateInput(self: *const ReactionTally, msgid: []const u8, emoji: []const u8, reactor: []const u8) Error!void {
    if (msgid.len > self.config.max_msgid_len) return error.MessageIdTooLong;
    if (emoji.len == 0) return error.EmptyEmoji;
    if (emoji.len > self.config.max_emoji_len) return error.EmojiTooLong;
    if (reactor.len == 0) return error.EmptyReactor;
    if (reactor.len > self.config.max_reactor_len) return error.ReactorTooLong;
}

const testing = std.testing;

test "react counts each reactor once per emoji" {
    var tally = ReactionTally.init(testing.allocator);
    defer tally.deinit();

    try testing.expectEqual(@as(u32, 1), try tally.react("m1", "+", "a"));
    try testing.expectEqual(@as(u32, 1), try tally.react("m1", "+", "a"));
    try testing.expectEqual(@as(u32, 2), try tally.react("m1", "+", "b"));

    const got = tally.counts("m1");
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("+", got[0].emoji);
    try testing.expectEqual(@as(u32, 2), got[0].count);
}

test "unreact removes reactor and prunes empty buckets" {
    var tally = ReactionTally.init(testing.allocator);
    defer tally.deinit();

    _ = try tally.react("m2", "ok", "a");
    _ = try tally.react("m2", "ok", "b");
    try testing.expect(tally.unreact("m2", "ok", "a"));
    try testing.expect(!tally.unreact("m2", "ok", "a"));
    try testing.expectEqual(@as(u32, 1), tally.counts("m2")[0].count);
    try testing.expect(tally.unreact("m2", "ok", "b"));
    try testing.expectEqual(@as(usize, 0), tally.counts("m2").len);
}

test "different emojis and messages are isolated" {
    var tally = ReactionTally.init(testing.allocator);
    defer tally.deinit();

    _ = try tally.react("m3", "yes", "a");
    _ = try tally.react("m3", "no", "a");
    _ = try tally.react("m4", "yes", "a");

    try testing.expectEqual(@as(usize, 2), tally.counts("m3").len);
    try testing.expectEqual(@as(usize, 1), tally.counts("m4").len);
    try testing.expect(tally.unreact("m3", "yes", "a"));
    try testing.expectEqual(@as(usize, 1), tally.counts("m3").len);
    try testing.expectEqual(@as(usize, 1), tally.counts("m4").len);
}

test "input caps are enforced" {
    var tally = ReactionTally.init(testing.allocator);
    defer tally.deinit();

    try testing.expectError(error.EmptyEmoji, tally.react("m", "", "a"));
    try testing.expectError(error.EmptyReactor, tally.react("m", "ok", ""));
    try testing.expectError(error.MessageIdTooLong, tally.react("m" ** (max_msgid_len + 1), "ok", "a"));
    try testing.expectError(error.EmojiTooLong, tally.react("m", "e" ** (max_emoji_len + 1), "a"));
    try testing.expectError(error.ReactorTooLong, tally.react("m", "ok", "r" ** (max_reactor_len + 1)));
}

test "applyToml defaults match historical constants" {
    var doc = try toml.parse(testing.allocator, "");
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(max_messages, cfg.max_messages);
    try testing.expectEqual(max_msgid_len, cfg.max_msgid_len);
    try testing.expectEqual(max_emoji_len, cfg.max_emoji_len);
    try testing.expectEqual(max_reactor_len, cfg.max_reactor_len);
    try testing.expectEqual(max_emojis_per_message, cfg.max_emojis_per_message);
    try testing.expectEqual(max_reactors_per_emoji, cfg.max_reactors_per_emoji);
}

test "applyToml overlays media.reactions keys and drives caps" {
    const src =
        \\[media.reactions]
        \\max_messages = 5
        \\max_msgid_bytes = 4
        \\max_emoji_bytes = 8
        \\max_reactor_bytes = 8
        \\max_emojis_per_message = 2
        \\max_reactors_per_emoji = 2
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(usize, 5), cfg.max_messages);
    try testing.expectEqual(@as(usize, 2), cfg.max_reactors_per_emoji);

    var tally = ReactionTally.initConfig(testing.allocator, cfg);
    defer tally.deinit();
    _ = try tally.react("m", "+", "a");
    _ = try tally.react("m", "+", "b");
    try testing.expectError(error.TooManyReactors, tally.react("m", "+", "c"));
    try testing.expectError(error.MessageIdTooLong, tally.react("toolong", "+", "a"));
}
