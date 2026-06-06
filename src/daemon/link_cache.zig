//! Bounded URL title cache with oldest-entry eviction.
const std = @import("std");

pub const LinkCache = struct {
    pub const max_entries: usize = 1024;
    pub const max_url_len: usize = 2048;
    pub const max_title_len: usize = 200;

    pub const Error = std.mem.Allocator.Error || error{
        UrlTooLong,
        TitleTooLong,
    };

    allocator: std.mem.Allocator,
    entries: std.StringHashMap(Entry),

    pub fn init(allocator: std.mem.Allocator) LinkCache {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *LinkCache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.title);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn put(self: *LinkCache, url: []const u8, title: []const u8, now_ms: i64) Error!void {
        if (url.len > max_url_len) return error.UrlTooLong;
        if (title.len > max_title_len) return error.TitleTooLong;

        if (self.entries.getPtr(url)) |entry| {
            const owned_title = try self.allocator.dupe(u8, title);
            self.allocator.free(entry.title);
            entry.title = owned_title;
            entry.at_ms = now_ms;
            return;
        }

        if (self.entries.count() >= max_entries) self.evictOldest();

        const owned_url = try self.allocator.dupe(u8, url);
        errdefer self.allocator.free(owned_url);

        const owned_title = try self.allocator.dupe(u8, title);
        errdefer self.allocator.free(owned_title);

        try self.entries.putNoClobber(owned_url, .{ .title = owned_title, .at_ms = now_ms });
    }

    /// Return a borrowed title view valid until the next mutation.
    pub fn get(self: *const LinkCache, url: []const u8) ?[]const u8 {
        const entry = self.entries.getPtr(url) orelse return null;
        return entry.title;
    }

    pub fn len(self: *const LinkCache) usize {
        return self.entries.count();
    }

    fn evictOldest(self: *LinkCache) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_at: i64 = 0;

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (oldest_key == null or entry.value_ptr.at_ms < oldest_at) {
                oldest_key = entry.key_ptr.*;
                oldest_at = entry.value_ptr.at_ms;
            }
        }

        const key = oldest_key orelse return;
        const removed = self.entries.fetchRemove(key).?;
        self.allocator.free(removed.key);
        self.allocator.free(removed.value.title);
    }
};

const Entry = struct {
    title: []u8,
    at_ms: i64,
};

const testing = std.testing;

test "put and get title" {
    var cache = LinkCache.init(testing.allocator);
    defer cache.deinit();

    try cache.put("https://example.invalid/a", "Example A", 10);

    try testing.expectEqual(@as(usize, 1), cache.len());
    try testing.expectEqualStrings("Example A", cache.get("https://example.invalid/a").?);
    try testing.expectEqual(@as(?[]const u8, null), cache.get("https://example.invalid/missing"));
}

test "put updates existing entry without growing" {
    var cache = LinkCache.init(testing.allocator);
    defer cache.deinit();

    try cache.put("https://example.invalid/a", "Old", 10);
    try cache.put("https://example.invalid/a", "New", 20);

    try testing.expectEqual(@as(usize, 1), cache.len());
    try testing.expectEqualStrings("New", cache.get("https://example.invalid/a").?);
}

test "full cache evicts oldest entry" {
    var cache = LinkCache.init(testing.allocator);
    defer cache.deinit();

    for (0..LinkCache.max_entries) |i| {
        var url_buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(url_buf[0..], "https://example.invalid/{d}", .{i});
        try cache.put(url, "title", @intCast(i));
    }

    try testing.expectEqual(@as(usize, LinkCache.max_entries), cache.len());
    try cache.put("https://example.invalid/new", "new title", 10_000);

    try testing.expectEqual(@as(usize, LinkCache.max_entries), cache.len());
    try testing.expectEqual(@as(?[]const u8, null), cache.get("https://example.invalid/0"));
    try testing.expectEqualStrings("new title", cache.get("https://example.invalid/new").?);
}

test "title length cap is enforced" {
    var cache = LinkCache.init(testing.allocator);
    defer cache.deinit();

    const title = "t" ** (LinkCache.max_title_len + 1);
    try testing.expectError(error.TitleTooLong, cache.put("https://example.invalid/a", title, 1));
    try testing.expectEqual(@as(usize, 0), cache.len());
}
