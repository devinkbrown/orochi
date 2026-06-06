//! Per-channel screen-share annotation tracking for the Mizuchi daemon.
//!
//! Each channel owns a bounded FIFO ring (capacity `ring_cap`) of annotation
//! ops emitted during a screen share. When the ring is full the oldest op is
//! evicted (and freed) to make room. All channel keys and op payloads are owned
//! by this module and released on `deinit`.

const std = @import("std");

/// Maximum number of ops retained per channel before FIFO eviction kicks in.
pub const ring_cap: usize = 256;

/// Maximum byte length of a single annotation op payload.
pub const max_op_len: usize = 512;

/// Error set surfaced by `add`.
pub const Error = error{AnnotationInvalid};

/// A single annotation operation. `author` and `op` are owned heap slices.
pub const Op = struct {
    author: []u8,
    op: []u8,
    at_ms: i64,
};

/// A bounded per-channel ring of ops, oldest-first.
const Ring = std.ArrayListUnmanaged(Op);

pub const ScreenAnnotation = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(Ring),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(Ring).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.freeRing(entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    fn freeOp(self: *Self, op: Op) void {
        self.allocator.free(op.author);
        self.allocator.free(op.op);
    }

    fn freeRing(self: *Self, ring: *Ring) void {
        for (ring.items) |op| self.freeOp(op);
        ring.deinit(self.allocator);
    }

    /// Append an annotation op to `channel`, returning the new ring depth.
    ///
    /// Validation: rejects an empty author, an empty op, or an op exceeding
    /// `max_op_len` with `error.AnnotationInvalid`. When the ring is already at
    /// `ring_cap`, the oldest op is evicted (and freed) before the new op is
    /// appended, so depth saturates at `ring_cap`.
    pub fn add(
        self: *Self,
        channel: []const u8,
        author: []const u8,
        op: []const u8,
        now_ms: i64,
    ) !usize {
        if (author.len == 0) return Error.AnnotationInvalid;
        if (op.len == 0 or op.len > max_op_len) return Error.AnnotationInvalid;

        const ring = try self.getOrCreateRing(channel);

        // Duplicate payloads first; if a later step fails we must not leak.
        const author_copy = try self.allocator.dupe(u8, author);
        errdefer self.allocator.free(author_copy);
        const op_copy = try self.allocator.dupe(u8, op);
        errdefer self.allocator.free(op_copy);

        const entry = Op{
            .author = author_copy,
            .op = op_copy,
            .at_ms = now_ms,
        };

        if (ring.items.len >= ring_cap) {
            // FIFO eviction: drop and free the oldest (front) op, shift down.
            const evicted = ring.orderedRemove(0);
            self.freeOp(evicted);
        }

        try ring.append(self.allocator, entry);
        return ring.items.len;
    }

    /// Look up an existing ring for `channel` or create one keyed by an owned
    /// copy of the channel name.
    fn getOrCreateRing(self: *Self, channel: []const u8) !*Ring {
        if (self.channels.getPtr(channel)) |ring| return ring;

        const key = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(key);

        try self.channels.put(key, Ring.empty);
        return self.channels.getPtr(key).?;
    }

    /// Ops for `channel`, oldest-first. Empty slice if the channel is unknown.
    pub fn recent(self: *Self, channel: []const u8) []const Op {
        if (self.channels.getPtr(channel)) |ring| return ring.items;
        return &[_]Op{};
    }

    /// Drop and free every op for `channel`, returning how many were removed.
    /// The channel key/ring entry itself is removed. Returns 0 if unknown.
    pub fn clearChannel(self: *Self, channel: []const u8) usize {
        const entry = self.channels.fetchRemove(channel) orelse return 0;
        var ring = entry.value;
        const count = ring.items.len;
        self.freeRing(&ring);
        self.allocator.free(entry.key);
        return count;
    }
};

test "add records ops, recent returns oldest-first, clear frees them" {
    const allocator = std.testing.allocator;
    var sa = ScreenAnnotation.init(allocator);
    defer sa.deinit();

    try std.testing.expectEqual(@as(usize, 1), try sa.add("#proj", "alice", "rect 0 0 10 10", 100));
    try std.testing.expectEqual(@as(usize, 2), try sa.add("#proj", "bob", "arrow 5 5", 200));
    try std.testing.expectEqual(@as(usize, 3), try sa.add("#proj", "alice", "text hi", 300));

    const ops = sa.recent("#proj");
    try std.testing.expectEqual(@as(usize, 3), ops.len);
    try std.testing.expectEqualStrings("alice", ops[0].author);
    try std.testing.expectEqualStrings("rect 0 0 10 10", ops[0].op);
    try std.testing.expectEqual(@as(i64, 100), ops[0].at_ms);
    try std.testing.expectEqualStrings("bob", ops[1].author);
    try std.testing.expectEqualStrings("text hi", ops[2].op);

    // Unknown channel yields an empty slice.
    try std.testing.expectEqual(@as(usize, 0), sa.recent("#nope").len);

    const cleared = sa.clearChannel("#proj");
    try std.testing.expectEqual(@as(usize, 3), cleared);
    try std.testing.expectEqual(@as(usize, 0), sa.recent("#proj").len);
    try std.testing.expectEqual(@as(usize, 0), sa.clearChannel("#proj"));
}

test "FIFO eviction past cap keeps newest ring_cap ops and advances the front" {
    const allocator = std.testing.allocator;
    var sa = ScreenAnnotation.init(allocator);
    defer sa.deinit();

    var buf: [32]u8 = undefined;
    const total = ring_cap + 50;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        const payload = try std.fmt.bufPrint(&buf, "op-{d}", .{i});
        const depth = try sa.add("#big", "author", payload, @as(i64, @intCast(i)));
        const expected = @min(i + 1, ring_cap);
        try std.testing.expectEqual(expected, depth);
    }

    const ops = sa.recent("#big");
    try std.testing.expectEqual(ring_cap, ops.len);

    // Front should now be the first op that survived eviction: index (total - ring_cap).
    const first_surviving = total - ring_cap;
    var expect_buf: [32]u8 = undefined;
    const front_expected = try std.fmt.bufPrint(&expect_buf, "op-{d}", .{first_surviving});
    try std.testing.expectEqualStrings(front_expected, ops[0].op);
    try std.testing.expectEqual(@as(i64, @intCast(first_surviving)), ops[0].at_ms);

    // Back should be the most recent op.
    const back_expected = try std.fmt.bufPrint(&expect_buf, "op-{d}", .{total - 1});
    try std.testing.expectEqualStrings(back_expected, ops[ops.len - 1].op);
}

test "add rejects empty author, empty op, and oversize op" {
    const allocator = std.testing.allocator;
    var sa = ScreenAnnotation.init(allocator);
    defer sa.deinit();

    try std.testing.expectError(Error.AnnotationInvalid, sa.add("#c", "", "valid", 1));
    try std.testing.expectError(Error.AnnotationInvalid, sa.add("#c", "alice", "", 1));

    const oversize = try allocator.alloc(u8, max_op_len + 1);
    defer allocator.free(oversize);
    @memset(oversize, 'x');
    try std.testing.expectError(Error.AnnotationInvalid, sa.add("#c", "alice", oversize, 1));

    // Exactly max_op_len is accepted.
    const at_limit = try allocator.alloc(u8, max_op_len);
    defer allocator.free(at_limit);
    @memset(at_limit, 'y');
    try std.testing.expectEqual(@as(usize, 1), try sa.add("#c", "alice", at_limit, 1));

    // Rejected adds must not have created a channel/ring leak (#c only exists
    // because of the accepted at-limit add, with exactly one op).
    try std.testing.expectEqual(@as(usize, 1), sa.recent("#c").len);
}
