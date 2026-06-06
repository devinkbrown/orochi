const std = @import("std");

pub const WarnList = struct {
    pub const max_patterns: usize = 256;
    pub const max_pattern_len: usize = 128;

    pub const Error = std.mem.Allocator.Error;

    allocator: std.mem.Allocator,
    patterns: std.ArrayList([]u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) WarnList {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *WarnList) void {
        for (self.patterns.items) |pattern| {
            self.allocator.free(pattern);
        }
        self.patterns.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *WarnList, pattern: []const u8) Error!bool {
        if (pattern.len == 0 or pattern.len > max_pattern_len) return false;
        if (self.patterns.items.len >= max_patterns) return false;
        if (self.indexOf(pattern) != null) return false;

        const owned = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned);
        try self.patterns.append(self.allocator, owned);
        return true;
    }

    pub fn del(self: *WarnList, pattern: []const u8) bool {
        const idx = self.indexOf(pattern) orelse return false;
        self.allocator.free(self.patterns.items[idx]);
        _ = self.patterns.orderedRemove(idx);
        return true;
    }

    pub fn list(self: *const WarnList) []const []u8 {
        return self.patterns.items;
    }

    pub fn firstMatch(self: *const WarnList, text: []const u8) ?[]const u8 {
        for (self.patterns.items) |pattern| {
            if (containsIgnoreCase(text, pattern)) return pattern;
        }
        return null;
    }

    fn indexOf(self: *const WarnList, pattern: []const u8) ?usize {
        for (self.patterns.items, 0..) |stored, idx| {
            if (std.ascii.eqlIgnoreCase(stored, pattern)) return idx;
        }
        return null;
    }

    fn containsIgnoreCase(text: []const u8, pattern: []const u8) bool {
        if (pattern.len == 0) return true;
        if (pattern.len > text.len) return false;

        var start: usize = 0;
        while (start + pattern.len <= text.len) : (start += 1) {
            var matched = true;
            var offset: usize = 0;
            while (offset < pattern.len) : (offset += 1) {
                const a = std.ascii.toLower(text[start + offset]);
                const b = std.ascii.toLower(pattern[offset]);
                if (a != b) {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }

        return false;
    }
};

const testing = std.testing;

test "add lists patterns and rejects duplicates" {
    var warns = WarnList.init(testing.allocator);
    defer warns.deinit();

    try testing.expect(try warns.add("bad phrase"));
    try testing.expect(!try warns.add("BAD PHRASE"));

    const patterns = warns.list();
    try testing.expectEqual(@as(usize, 1), patterns.len);
    try testing.expectEqualStrings("bad phrase", patterns[0]);
}

test "del removes patterns case-insensitively" {
    var warns = WarnList.init(testing.allocator);
    defer warns.deinit();

    _ = try warns.add("notice me");

    try testing.expect(warns.del("NOTICE ME"));
    try testing.expect(!warns.del("notice me"));
    try testing.expectEqual(@as(usize, 0), warns.list().len);
}

test "firstMatch returns the first matching pattern" {
    var warns = WarnList.init(testing.allocator);
    defer warns.deinit();

    _ = try warns.add("first");
    _ = try warns.add("second");

    try testing.expectEqualStrings("first", warns.firstMatch("the FIRST warning").?);
    try testing.expectEqualStrings("second", warns.firstMatch("the second warning").?);
    try testing.expect(warns.firstMatch("clean text") == null);
}

test "pattern count and length are bounded" {
    var warns = WarnList.init(testing.allocator);
    defer warns.deinit();

    const too_long = "x" ** (WarnList.max_pattern_len + 1);
    try testing.expect(!try warns.add(too_long));

    var i: usize = 0;
    while (i < WarnList.max_patterns) : (i += 1) {
        var buf: [32]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&buf, "p-{d}", .{i});
        try testing.expect(try warns.add(pattern));
    }
    try testing.expect(!try warns.add("overflow"));
}
