//! Time-ordered scheduled message queue for daemon-local deferred sends.
//!
//! `popDue` transfers ownership of each returned `Msg` into the caller-provided
//! output buffer. The caller must later pass every returned message to `freeMsg`.
const std = @import("std");

pub const ScheduledMessage = struct {
    pub const max_messages: usize = 4096;
    pub const max_target_len: usize = 128;
    pub const max_from_len: usize = 128;
    pub const max_text_len: usize = 400;

    pub const Error = std.mem.Allocator.Error || error{
        TooManyMessages,
        TargetTooLong,
        FromTooLong,
        TextTooLong,
    };

    pub const Msg = struct {
        due_ms: i64,
        target: []u8,
        from: []u8,
        text: []u8,
    };

    allocator: std.mem.Allocator,
    messages: std.ArrayListUnmanaged(Msg) = .empty,

    pub fn init(allocator: std.mem.Allocator) ScheduledMessage {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ScheduledMessage) void {
        for (self.messages.items) |*msg| self.freeMsg(msg);
        self.messages.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn schedule(self: *ScheduledMessage, due_ms: i64, target: []const u8, from: []const u8, text: []const u8) Error!void {
        if (target.len > max_target_len) return error.TargetTooLong;
        if (from.len > max_from_len) return error.FromTooLong;
        if (text.len > max_text_len) return error.TextTooLong;
        if (self.messages.items.len >= max_messages) return error.TooManyMessages;

        var msg = Msg{
            .due_ms = due_ms,
            .target = try self.allocator.dupe(u8, target),
            .from = undefined,
            .text = undefined,
        };
        errdefer self.allocator.free(msg.target);

        msg.from = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(msg.from);

        msg.text = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(msg.text);

        const index = self.insertIndex(due_ms);
        try self.messages.insert(self.allocator, index, msg);
    }

    /// Move up to `out.len` due messages into `out`, preserving due-time order.
    /// Ownership of returned message buffers transfers to the caller.
    pub fn popDue(self: *ScheduledMessage, now_ms: i64, out: []Msg) usize {
        var moved: usize = 0;
        while (moved < out.len and self.messages.items.len > 0 and self.messages.items[0].due_ms <= now_ms) {
            out[moved] = self.messages.orderedRemove(0);
            moved += 1;
        }
        return moved;
    }

    pub fn freeMsg(self: *ScheduledMessage, msg: *Msg) void {
        self.allocator.free(msg.target);
        self.allocator.free(msg.from);
        self.allocator.free(msg.text);
        msg.* = undefined;
    }

    pub fn len(self: *const ScheduledMessage) usize {
        return self.messages.items.len;
    }

    fn insertIndex(self: *const ScheduledMessage, due_ms: i64) usize {
        for (self.messages.items, 0..) |msg, i| {
            if (due_ms < msg.due_ms) return i;
        }
        return self.messages.items.len;
    }
};

const testing = std.testing;

test "schedule stores messages in due-time order" {
    var queue = ScheduledMessage.init(testing.allocator);
    defer queue.deinit();

    try queue.schedule(30, "#ops", "ann", "third");
    try queue.schedule(10, "#ops", "ann", "first");
    try queue.schedule(20, "#ops", "ann", "second");

    var out: [3]ScheduledMessage.Msg = undefined;
    const count = queue.popDue(100, out[0..]);
    defer for (out[0..count]) |*msg| queue.freeMsg(msg);

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqual(@as(i64, 10), out[0].due_ms);
    try testing.expectEqualStrings("first", out[0].text);
    try testing.expectEqual(@as(i64, 20), out[1].due_ms);
    try testing.expectEqualStrings("second", out[1].text);
    try testing.expectEqual(@as(i64, 30), out[2].due_ms);
    try testing.expectEqualStrings("third", out[2].text);
}

test "popDue only removes due messages and honors output capacity" {
    var queue = ScheduledMessage.init(testing.allocator);
    defer queue.deinit();

    try queue.schedule(5, "#a", "bot", "one");
    try queue.schedule(6, "#a", "bot", "two");
    try queue.schedule(50, "#a", "bot", "later");

    var out: [1]ScheduledMessage.Msg = undefined;
    var count = queue.popDue(10, out[0..]);
    defer for (out[0..count]) |*msg| queue.freeMsg(msg);

    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("one", out[0].text);
    try testing.expectEqual(@as(usize, 2), queue.len());

    var rest: [2]ScheduledMessage.Msg = undefined;
    count = queue.popDue(10, rest[0..]);
    defer for (rest[0..count]) |*msg| queue.freeMsg(msg);

    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("two", rest[0].text);
    try testing.expectEqual(@as(usize, 1), queue.len());
}

test "text length cap is enforced" {
    var queue = ScheduledMessage.init(testing.allocator);
    defer queue.deinit();

    const text = "x" ** (ScheduledMessage.max_text_len + 1);
    try testing.expectError(error.TextTooLong, queue.schedule(1, "#a", "bot", text));
    try testing.expectEqual(@as(usize, 0), queue.len());
}
