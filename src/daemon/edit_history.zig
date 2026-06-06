const std = @import("std");

pub const max_messages: usize = 4096;
pub const max_msgid_len: usize = 128;
pub const max_text_len: usize = 400;
pub const max_revisions_per_message: usize = 16;

pub const Error = std.mem.Allocator.Error || error{ MessageIdTooLong, TextTooLong, TooManyMessages };

pub const Rev = struct {
    text: []u8,
    at_ms: i64,
};

const RevisionList = struct {
    items: std.ArrayListUnmanaged(Rev) = .empty,

    fn deinit(self: *RevisionList, allocator: std.mem.Allocator) void {
        for (self.items.items) |rev| allocator.free(rev.text);
        self.items.deinit(allocator);
    }
};

pub const EditHistory = struct {
    allocator: std.mem.Allocator,
    messages: std.StringHashMap(RevisionList),

    pub fn init(allocator: std.mem.Allocator) EditHistory {
        return .{ .allocator = allocator, .messages = std.StringHashMap(RevisionList).init(allocator) };
    }

    pub fn deinit(self: *EditHistory) void {
        var it = self.messages.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.messages.deinit();
        self.* = undefined;
    }

    pub fn push(self: *EditHistory, msgid: []const u8, text: []const u8, now_ms: i64) Error!usize {
        if (msgid.len > max_msgid_len) return error.MessageIdTooLong;
        if (text.len > max_text_len) return error.TextTooLong;

        const list = try self.ensureMessage(msgid);
        if (list.items.items.len == max_revisions_per_message) {
            const old = list.items.orderedRemove(0);
            self.allocator.free(old.text);
        }

        const owned_text = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned_text);
        try list.items.append(self.allocator, .{ .text = owned_text, .at_ms = now_ms });
        return list.items.items.len;
    }

    pub fn revisions(self: *const EditHistory, msgid: []const u8) []const Rev {
        const list = self.messages.getPtr(msgid) orelse return &.{};
        return list.items.items;
    }

    pub fn clear(self: *EditHistory, msgid: []const u8) bool {
        const entry = self.messages.getEntry(msgid) orelse return false;
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.messages.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
        return true;
    }

    fn ensureMessage(self: *EditHistory, msgid: []const u8) Error!*RevisionList {
        if (self.messages.getPtr(msgid)) |list| return list;
        if (self.messages.count() >= max_messages) return error.TooManyMessages;

        const owned_key = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_key);
        try self.messages.putNoClobber(owned_key, .{});
        return self.messages.getPtr(msgid).?;
    }
};

const testing = std.testing;

test "push stores borrowed input as owned revision text" {
    var history = EditHistory.init(testing.allocator);
    defer history.deinit();

    var buf = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    try testing.expectEqual(@as(usize, 1), try history.push("m1", buf[0..], 10));
    buf[0] = 'j';

    const revs = history.revisions("m1");
    try testing.expectEqual(@as(usize, 1), revs.len);
    try testing.expectEqualStrings("hello", revs[0].text);
    try testing.expectEqual(@as(i64, 10), revs[0].at_ms);
}

test "ring keeps the newest sixteen revisions" {
    var history = EditHistory.init(testing.allocator);
    defer history.deinit();

    var n: usize = 0;
    while (n < 20) : (n += 1) {
        var text_buf: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&text_buf, "rev-{d}", .{n});
        _ = try history.push("m2", text, @intCast(n));
    }

    const revs = history.revisions("m2");
    try testing.expectEqual(@as(usize, max_revisions_per_message), revs.len);
    try testing.expectEqualStrings("rev-4", revs[0].text);
    try testing.expectEqualStrings("rev-19", revs[15].text);
}

test "clear removes one message history" {
    var history = EditHistory.init(testing.allocator);
    defer history.deinit();

    _ = try history.push("a", "old a", 1);
    _ = try history.push("b", "old b", 2);
    try testing.expect(history.clear("a"));
    try testing.expect(!history.clear("a"));
    try testing.expectEqual(@as(usize, 0), history.revisions("a").len);
    try testing.expectEqual(@as(usize, 1), history.revisions("b").len);
}

test "caps reject oversized identifiers and text" {
    var history = EditHistory.init(testing.allocator);
    defer history.deinit();

    const long_msgid = "x" ** (max_msgid_len + 1);
    const long_text = "y" ** (max_text_len + 1);
    try testing.expectError(error.MessageIdTooLong, history.push(long_msgid, "ok", 0));
    try testing.expectError(error.TextTooLong, history.push("ok", long_text, 0));
}
