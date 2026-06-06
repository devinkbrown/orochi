const std = @import("std");

pub const max_messages: usize = 4096;
pub const max_msgid_len: usize = 128;
pub const max_quotes_per_message: usize = 256;

pub const Error = std.mem.Allocator.Error || error{
    MessageIdTooLong,
    TooManyMessages,
    TooManyQuotes,
};

const QuoteList = struct {
    items: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *QuoteList, allocator: std.mem.Allocator) void {
        for (self.items.items) |msgid| allocator.free(msgid);
        self.items.deinit(allocator);
    }

    fn contains(self: *const QuoteList, msgid: []const u8) bool {
        for (self.items.items) |known| {
            if (std.mem.eql(u8, known, msgid)) return true;
        }
        return false;
    }
};

pub const QuoteIndex = struct {
    allocator: std.mem.Allocator,
    messages: std.StringHashMap(QuoteList),

    pub fn init(allocator: std.mem.Allocator) QuoteIndex {
        return .{ .allocator = allocator, .messages = std.StringHashMap(QuoteList).init(allocator) };
    }

    pub fn deinit(self: *QuoteIndex) void {
        var it = self.messages.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.messages.deinit();
        self.* = undefined;
    }

    pub fn addQuote(self: *QuoteIndex, original: []const u8, quoter: []const u8) Error!void {
        if (original.len > max_msgid_len or quoter.len > max_msgid_len) return error.MessageIdTooLong;

        const list = try self.ensureOriginal(original);
        if (list.contains(quoter)) return;
        if (list.items.items.len >= max_quotes_per_message) return error.TooManyQuotes;

        const owned_quoter = try self.allocator.dupe(u8, quoter);
        errdefer self.allocator.free(owned_quoter);
        try list.items.append(self.allocator, owned_quoter);
    }

    pub fn quotes(self: *const QuoteIndex, original: []const u8) []const []const u8 {
        const list = self.messages.getPtr(original) orelse return &.{};
        return @ptrCast(list.items.items);
    }

    pub fn clear(self: *QuoteIndex, original: []const u8) bool {
        const entry = self.messages.getEntry(original) orelse return false;
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.messages.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
        return true;
    }

    fn ensureOriginal(self: *QuoteIndex, original: []const u8) Error!*QuoteList {
        if (self.messages.getPtr(original)) |list| return list;
        if (self.messages.count() >= max_messages) return error.TooManyMessages;

        const owned_key = try self.allocator.dupe(u8, original);
        errdefer self.allocator.free(owned_key);
        try self.messages.putNoClobber(owned_key, .{});
        return self.messages.getPtr(original).?;
    }
};

const testing = std.testing;

test "addQuote records quoted message ids in insertion order" {
    var index = QuoteIndex.init(testing.allocator);
    defer index.deinit();

    try index.addQuote("m1", "q1");
    try index.addQuote("m1", "q2");
    const got = index.quotes("m1");
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("q1", got[0]);
    try testing.expectEqualStrings("q2", got[1]);
}

test "duplicate quoter ids do not consume capacity" {
    var index = QuoteIndex.init(testing.allocator);
    defer index.deinit();

    try index.addQuote("m2", "q1");
    try index.addQuote("m2", "q1");
    try testing.expectEqual(@as(usize, 1), index.quotes("m2").len);
}

test "clear removes one original quote list" {
    var index = QuoteIndex.init(testing.allocator);
    defer index.deinit();

    try index.addQuote("a", "qa");
    try index.addQuote("b", "qb");
    try testing.expect(index.clear("a"));
    try testing.expect(!index.clear("a"));
    try testing.expectEqual(@as(usize, 0), index.quotes("a").len);
    try testing.expectEqual(@as(usize, 1), index.quotes("b").len);
}

test "caps reject long ids and quote overflow" {
    var index = QuoteIndex.init(testing.allocator);
    defer index.deinit();

    try testing.expectError(error.MessageIdTooLong, index.addQuote("x" ** (max_msgid_len + 1), "q"));

    var n: usize = 0;
    while (n < max_quotes_per_message) : (n += 1) {
        var buf: [16]u8 = undefined;
        const quoter = try std.fmt.bufPrint(&buf, "q-{d}", .{n});
        try index.addQuote("full", quoter);
    }
    try testing.expectError(error.TooManyQuotes, index.addQuote("full", "overflow"));
}
