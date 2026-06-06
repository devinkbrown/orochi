//! Bounded server emoji shortcode registry.
const std = @import("std");

pub const max_emojis: usize = 4096;
pub const max_code_len: usize = 64;
pub const max_url_len: usize = 2048;

pub const Error = std.mem.Allocator.Error || error{
    InvalidCode,
    FieldTooLong,
    TooManyEmoji,
};

pub const EmojiPack = struct {
    allocator: std.mem.Allocator,
    items: std.StringHashMap([]u8),
    limit: usize,

    pub fn init(allocator: std.mem.Allocator) EmojiPack {
        return initWithLimit(allocator, max_emojis);
    }

    pub fn initWithLimit(allocator: std.mem.Allocator, limit: usize) EmojiPack {
        return .{
            .allocator = allocator,
            .items = std.StringHashMap([]u8).init(allocator),
            .limit = limit,
        };
    }

    pub fn deinit(self: *EmojiPack) void {
        var it = self.items.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.items.deinit();
        self.* = undefined;
    }

    pub fn add(self: *EmojiPack, code: []const u8, url: []const u8) Error!void {
        try validate(code, url);

        if (self.items.getEntry(code)) |entry| {
            const next_url = try self.allocator.dupe(u8, url);
            errdefer self.allocator.free(next_url);
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = next_url;
            return;
        }

        if (self.items.count() >= self.limit) return error.TooManyEmoji;
        const owned_code = try self.allocator.dupe(u8, code);
        errdefer self.allocator.free(owned_code);
        const owned_url = try self.allocator.dupe(u8, url);
        errdefer self.allocator.free(owned_url);
        try self.items.putNoClobber(owned_code, owned_url);
    }

    pub fn get(self: *const EmojiPack, code: []const u8) ?[]const u8 {
        const url = self.items.get(code) orelse return null;
        return url;
    }

    pub fn remove(self: *EmojiPack, code: []const u8) bool {
        const kv = self.items.fetchRemove(code) orelse return false;
        self.allocator.free(kv.key);
        self.allocator.free(kv.value);
        return true;
    }

    pub fn count(self: *const EmojiPack) usize {
        return self.items.count();
    }

    fn validate(code: []const u8, url: []const u8) Error!void {
        if (code.len == 0) return error.InvalidCode;
        if (code.len > max_code_len or url.len == 0 or url.len > max_url_len) return error.FieldTooLong;
    }
};

const testing = std.testing;

test "add and get stores shortcode urls" {
    var pack = EmojiPack.init(testing.allocator);
    defer pack.deinit();

    try pack.add(":wave:", "https://m.example/wave.png");
    try testing.expectEqualStrings("https://m.example/wave.png", pack.get(":wave:").?);
    try testing.expect(pack.get(":missing:") == null);
    try testing.expectEqual(@as(usize, 1), pack.count());
}

test "add replaces an existing shortcode url" {
    var pack = EmojiPack.init(testing.allocator);
    defer pack.deinit();

    try pack.add(":wave:", "https://m.example/old.png");
    try pack.add(":wave:", "https://m.example/new.png");
    try testing.expectEqualStrings("https://m.example/new.png", pack.get(":wave:").?);
    try testing.expectEqual(@as(usize, 1), pack.count());
}

test "remove reports whether a shortcode existed" {
    var pack = EmojiPack.init(testing.allocator);
    defer pack.deinit();

    try pack.add(":wave:", "https://m.example/wave.png");
    try testing.expect(pack.remove(":wave:"));
    try testing.expect(!pack.remove(":wave:"));
    try testing.expect(pack.get(":wave:") == null);
}

test "emoji registry cap is enforced" {
    var pack = EmojiPack.initWithLimit(testing.allocator, 1);
    defer pack.deinit();

    try pack.add(":one:", "https://m.example/1.png");
    try testing.expectError(error.TooManyEmoji, pack.add(":two:", "https://m.example/2.png"));
}
