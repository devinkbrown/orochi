const std = @import("std");

pub const Frame = struct {
    seq: u32,
    timestamp: u64,
    payload: []const u8,
};

pub const Reassembler = struct {
    allocator: std.mem.Allocator,
    window: u32,
    cursor: u32 = 0,
    started: bool = false,
    flushing: bool = false,
    entries: []Entry = &.{},
    count: usize = 0,
    borrowed_payload: ?[]u8 = null,

    const Self = @This();

    const Entry = struct {
        seq: u32,
        timestamp: u64,
        payload: []u8,
    };

    pub fn init(allocator: std.mem.Allocator, window: u32) Self {
        return .{
            .allocator = allocator,
            .window = window,
        };
    }

    pub fn push(self: *Self, f: Frame) !void {
        self.releaseBorrowed();

        const cap = self.capacity();
        if (cap == 0) return;

        if (self.started) {
            if (seqBefore(f.seq, self.cursor)) return;

            const distance = f.seq -% self.cursor;
            if (distance >= self.window) {
                const back: u32 = self.window - 1;
                self.advanceCursorTo(f.seq -% back);
            }
        }

        if (self.findIndex(f.seq) != null) return;

        while (self.count >= cap) {
            self.advancePastLowestHeld();
        }

        try self.ensureCapacity(self.count + 1);
        const payload = try self.allocator.dupe(u8, f.payload);
        self.entries[self.count] = .{
            .seq = f.seq,
            .timestamp = f.timestamp,
            .payload = payload,
        };
        self.count += 1;
    }

    pub fn pop(self: *Self) ?Frame {
        self.releaseBorrowed();

        if (self.count == 0) {
            self.flushing = false;
            return null;
        }

        if (!self.started) {
            const idx = self.lowestHeldIndex() orelse return null;
            self.cursor = self.entries[idx].seq;
            self.started = true;
        }

        while (true) {
            if (self.findIndex(self.cursor)) |idx| {
                const entry = self.entries[idx];
                self.removeAtNoFree(idx);
                self.borrowed_payload = entry.payload;
                self.cursor +%= 1;
                if (self.count == 0) self.flushing = false;
                return .{
                    .seq = entry.seq,
                    .timestamp = entry.timestamp,
                    .payload = entry.payload,
                };
            }

            if (!self.flushing) return null;

            const idx = self.lowestHeldIndex() orelse {
                self.flushing = false;
                return null;
            };
            self.cursor = self.entries[idx].seq;
            self.started = true;
        }
    }

    pub fn flush(self: *Self) void {
        self.flushing = true;
        if (!self.started) {
            if (self.lowestHeldIndex()) |idx| {
                self.cursor = self.entries[idx].seq;
                self.started = true;
            }
        }
    }

    pub fn deinit(self: *Self) void {
        self.releaseBorrowed();
        for (self.entries[0..self.count]) |entry| {
            self.allocator.free(entry.payload);
        }
        if (self.entries.len != 0) self.allocator.free(self.entries);
        self.* = .{
            .allocator = self.allocator,
            .window = self.window,
        };
    }

    fn capacity(self: *const Self) usize {
        return @intCast(self.window);
    }

    fn ensureCapacity(self: *Self, needed: usize) !void {
        if (needed <= self.entries.len) return;

        var next_len: usize = if (self.entries.len == 0) 4 else self.entries.len * 2;
        if (next_len < needed) next_len = needed;

        const cap = self.capacity();
        if (next_len > cap) next_len = cap;

        if (self.entries.len == 0) {
            self.entries = try self.allocator.alloc(Entry, next_len);
        } else {
            self.entries = try self.allocator.realloc(self.entries, next_len);
        }
    }

    fn releaseBorrowed(self: *Self) void {
        if (self.borrowed_payload) |payload| {
            self.allocator.free(payload);
            self.borrowed_payload = null;
        }
    }

    fn findIndex(self: *const Self, seq: u32) ?usize {
        for (self.entries[0..self.count], 0..) |entry, idx| {
            if (entry.seq == seq) return idx;
        }
        return null;
    }

    fn lowestHeldIndex(self: *const Self) ?usize {
        if (self.count == 0) return null;

        var best: usize = 0;
        var idx: usize = 1;
        while (idx < self.count) : (idx += 1) {
            if (seqBefore(self.entries[idx].seq, self.entries[best].seq)) {
                best = idx;
            }
        }
        return best;
    }

    fn removeAtNoFree(self: *Self, idx: usize) void {
        self.count -= 1;
        if (idx != self.count) {
            self.entries[idx] = self.entries[self.count];
        }
    }

    fn removeAtFree(self: *Self, idx: usize) void {
        self.allocator.free(self.entries[idx].payload);
        self.removeAtNoFree(idx);
    }

    fn advanceCursorTo(self: *Self, next_cursor: u32) void {
        if (!self.started or seqBefore(self.cursor, next_cursor)) {
            self.cursor = next_cursor;
            self.started = true;
            self.dropBeforeCursor();
        }
    }

    fn advancePastLowestHeld(self: *Self) void {
        const idx = self.lowestHeldIndex() orelse return;
        self.advanceCursorTo(self.entries[idx].seq +% 1);
    }

    fn dropBeforeCursor(self: *Self) void {
        var idx: usize = 0;
        while (idx < self.count) {
            if (seqBefore(self.entries[idx].seq, self.cursor)) {
                self.removeAtFree(idx);
            } else {
                idx += 1;
            }
        }
    }
};

fn seqBefore(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}

test "in-order push/pop passes through" {
    var r = Reassembler.init(std.testing.allocator, 4);
    defer r.deinit();

    try r.push(.{ .seq = 1, .timestamp = 10, .payload = "one" });
    try r.push(.{ .seq = 2, .timestamp = 20, .payload = "two" });

    const a = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 1), a.seq);
    try std.testing.expectEqual(@as(u64, 10), a.timestamp);
    try std.testing.expectEqualStrings("one", a.payload);

    const b = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 2), b.seq);
    try std.testing.expectEqual(@as(u64, 20), b.timestamp);
    try std.testing.expectEqualStrings("two", b.payload);

    try std.testing.expect(r.pop() == null);
}

test "out-of-order frames pop in sequence order" {
    var r = Reassembler.init(std.testing.allocator, 4);
    defer r.deinit();

    try r.push(.{ .seq = 3, .timestamp = 30, .payload = "three" });
    try r.push(.{ .seq = 1, .timestamp = 10, .payload = "one" });
    try r.push(.{ .seq = 2, .timestamp = 20, .payload = "two" });

    const a = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 1), a.seq);
    try std.testing.expectEqualStrings("one", a.payload);

    const b = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 2), b.seq);
    try std.testing.expectEqualStrings("two", b.payload);

    const c = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 3), c.seq);
    try std.testing.expectEqualStrings("three", c.payload);
}

test "late frame below cursor is dropped" {
    var r = Reassembler.init(std.testing.allocator, 4);
    defer r.deinit();

    try r.push(.{ .seq = 1, .timestamp = 10, .payload = "one" });
    const first = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 1), first.seq);

    try r.push(.{ .seq = 1, .timestamp = 11, .payload = "late" });
    try std.testing.expect(r.pop() == null);

    try r.push(.{ .seq = 2, .timestamp = 20, .payload = "two" });
    const second = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 2), second.seq);
    try std.testing.expectEqualStrings("two", second.payload);
}

test "window overflow advances cursor deterministically" {
    var r = Reassembler.init(std.testing.allocator, 2);
    defer r.deinit();

    try r.push(.{ .seq = 1, .timestamp = 10, .payload = "one" });
    const first = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 1), first.seq);

    try r.push(.{ .seq = 3, .timestamp = 30, .payload = "three" });
    try r.push(.{ .seq = 4, .timestamp = 40, .payload = "four" });
    try r.push(.{ .seq = 5, .timestamp = 50, .payload = "five" });

    const a = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 4), a.seq);
    try std.testing.expectEqualStrings("four", a.payload);

    const b = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 5), b.seq);
    try std.testing.expectEqualStrings("five", b.payload);
}

test "flush drains remaining frames across gaps" {
    var r = Reassembler.init(std.testing.allocator, 4);
    defer r.deinit();

    try r.push(.{ .seq = 1, .timestamp = 10, .payload = "one" });
    try r.push(.{ .seq = 3, .timestamp = 30, .payload = "three" });

    const first = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 1), first.seq);
    try std.testing.expect(r.pop() == null);

    r.flush();

    const drained = r.pop() orelse return error.MissingFrame;
    try std.testing.expectEqual(@as(u32, 3), drained.seq);
    try std.testing.expectEqualStrings("three", drained.payload);
    try std.testing.expect(r.pop() == null);
}
