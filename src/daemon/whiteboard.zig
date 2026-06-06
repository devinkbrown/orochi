//! Per-channel collaborative whiteboard state. Each channel owns a bounded FIFO
//! ring of drawing operations so late joiners can replay recent strokes without
//! unbounded memory growth.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_channel_bytes: usize = 128;
pub const max_author_bytes: usize = 64;
pub const max_op_bytes: usize = 512;
pub const max_ops_per_channel: usize = 256;

pub const Error = std.mem.Allocator.Error || error{ TooManyChannels, InvalidOperation };

pub const Op = struct {
    author: []u8,
    op: []u8,
    at_ms: i64,

    fn deinit(self: *Op, allocator: std.mem.Allocator) void {
        allocator.free(self.author);
        allocator.free(self.op);
    }
};

const Ring = struct {
    items: std.ArrayListUnmanaged(Op) = .empty,

    fn deinit(self: *Ring, allocator: std.mem.Allocator) void {
        for (self.items.items) |*item| item.deinit(allocator);
        self.items.deinit(allocator);
    }
};

pub const Whiteboard = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(Ring),

    pub fn init(allocator: std.mem.Allocator) Whiteboard {
        return .{ .allocator = allocator, .channels = std.StringHashMap(Ring).init(allocator) };
    }

    pub fn deinit(self: *Whiteboard) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    /// Add a copied drawing operation to `channel`. Returns the retained depth.
    pub fn add(self: *Whiteboard, channel: []const u8, author: []const u8, op: []const u8, now: i64) Error!usize {
        if (!validName(channel, max_channel_bytes)) return error.InvalidOperation;
        if (!validName(author, max_author_bytes)) return error.InvalidOperation;
        if (op.len == 0 or op.len > max_op_bytes) return error.InvalidOperation;

        const ring = try self.ensureChannel(channel);
        const owned_author = try self.allocator.dupe(u8, author);
        errdefer self.allocator.free(owned_author);
        const owned_op = try self.allocator.dupe(u8, op);
        errdefer self.allocator.free(owned_op);

        try ring.items.append(self.allocator, .{ .author = owned_author, .op = owned_op, .at_ms = now });
        if (ring.items.items.len > max_ops_per_channel) {
            var removed = ring.items.orderedRemove(0);
            removed.deinit(self.allocator);
        }
        return ring.items.items.len;
    }

    /// Borrowed operations for `channel`, oldest-first. Empty if absent.
    pub fn recent(self: *const Whiteboard, channel: []const u8) []const Op {
        const ring = self.channels.getPtr(channel) orelse return &.{};
        return ring.items.items;
    }

    /// Clear one channel and return the number of discarded operations.
    pub fn clearChannel(self: *Whiteboard, channel: []const u8) usize {
        const entry = self.channels.getEntry(channel) orelse return 0;
        const n = entry.value_ptr.items.items.len;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return n;
    }

    fn ensureChannel(self: *Whiteboard, channel: []const u8) Error!*Ring {
        if (self.channels.getPtr(channel)) |ring| return ring;
        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }
};

fn validName(value: []const u8, cap: usize) bool {
    return value.len > 0 and value.len <= cap and std.mem.indexOfScalar(u8, value, 0) == null;
}

const testing = std.testing;

test "add and read recent operations" {
    var board = Whiteboard.init(testing.allocator);
    defer board.deinit();

    try testing.expectEqual(@as(usize, 1), try board.add("#art", "alice", "line 1 2 3 4", 10));
    try testing.expectEqual(@as(usize, 2), try board.add("#art", "bob", "erase 2", 20));

    const items = board.recent("#art");
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("alice", items[0].author);
    try testing.expectEqualStrings("erase 2", items[1].op);
    try testing.expectEqual(@as(i64, 20), items[1].at_ms);
}

test "ring keeps newest operations" {
    var board = Whiteboard.init(testing.allocator);
    defer board.deinit();

    var i: usize = 0;
    while (i < max_ops_per_channel + 9) : (i += 1) {
        _ = try board.add("#art", "a", "dot", @intCast(i));
    }

    const items = board.recent("#art");
    try testing.expectEqual(max_ops_per_channel, items.len);
    try testing.expectEqual(@as(i64, 9), items[0].at_ms);
}

test "clear frees a channel" {
    var board = Whiteboard.init(testing.allocator);
    defer board.deinit();

    _ = try board.add("#art", "a", "dot", 1);
    _ = try board.add("#art", "a", "dot", 2);
    try testing.expectEqual(@as(usize, 2), board.clearChannel("#art"));
    try testing.expectEqual(@as(usize, 0), board.recent("#art").len);
    try testing.expectEqual(@as(usize, 0), board.clearChannel("#art"));
}

test "rejects oversized operation payloads" {
    var board = Whiteboard.init(testing.allocator);
    defer board.deinit();

    var too_big: [max_op_bytes + 1]u8 = undefined;
    @memset(&too_big, 'x');
    try testing.expectError(error.InvalidOperation, board.add("#art", "a", &too_big, 1));
    try testing.expectError(error.InvalidOperation, board.add("#art", "a", "", 1));
}
