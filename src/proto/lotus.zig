//! Lotus: pure in-memory IRC message history rings.
//!
//! This module performs no I/O. It owns duplicated target keys and message
//! strings, bounds target count and per-target history length at comptime, and
//! returns borrowed read views that remain valid until the next mutation.
const std = @import("std");

pub const Params = struct {
    max_targets: usize,
    max_per_target: usize,
    max_text: usize,
};

pub const InputMessage = struct {
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
};

pub const Message = struct {
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    tombstone: bool,
};

pub const AppendResult = struct {
    evicted: bool,
    target_len: usize,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidTarget,
    TargetLimitExceeded,
    TextTooLong,
    OutputTooSmall,
    NotFound,
};

pub fn Lotus(comptime params: Params) type {
    comptime validateParams(params);

    return struct {
        const Self = @This();

        const TargetLog = struct {
            entries: []StoredMessage,
            start: usize,
            len: usize,

            fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!TargetLog {
                return .{
                    .entries = try allocator.alloc(StoredMessage, params.max_per_target),
                    .start = 0,
                    .len = 0,
                };
            }

            fn deinit(self: *TargetLog, allocator: std.mem.Allocator) void {
                var index: usize = 0;
                while (index < self.len) : (index += 1) {
                    self.entryMut(index).deinit(allocator);
                }
                allocator.free(self.entries);
                self.* = .{ .entries = &.{}, .start = 0, .len = 0 };
            }

            fn appendTake(self: *TargetLog, allocator: std.mem.Allocator, msg: StoredMessage) bool {
                if (self.len == params.max_per_target) {
                    self.entries[self.start].deinit(allocator);
                    self.entries[self.start] = msg;
                    self.start = (self.start + 1) % params.max_per_target;
                    return true;
                }

                const write_index = self.slot(self.len);
                self.entries[write_index] = msg;
                self.len += 1;
                return false;
            }

            fn slot(self: *const TargetLog, logical_index: usize) usize {
                return (self.start + logical_index) % params.max_per_target;
            }

            fn entry(self: *const TargetLog, logical_index: usize) *const StoredMessage {
                return &self.entries[self.slot(logical_index)];
            }

            fn entryMut(self: *TargetLog, logical_index: usize) *StoredMessage {
                return &self.entries[self.slot(logical_index)];
            }
        };

        const QueryBound = union(enum) {
            before: u64,
        };

        allocator: std.mem.Allocator,
        targets: std.StringHashMap(TargetLog),

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .targets = std.StringHashMap(TargetLog).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.targets.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit(self.allocator);
                self.allocator.free(entry.key_ptr.*);
            }
            self.targets.deinit();
            self.* = undefined;
        }

        pub fn append(self: *Self, target: []const u8, msg: InputMessage) Error!AppendResult {
            try validateTarget(target);
            try validateText(msg.text);

            var stored = try StoredMessage.init(self.allocator, msg);
            errdefer stored.deinit(self.allocator);

            if (self.targets.getPtr(target)) |log| {
                const evicted = log.appendTake(self.allocator, stored);
                return .{ .evicted = evicted, .target_len = log.len };
            }

            if (self.targets.count() >= params.max_targets) return error.TargetLimitExceeded;

            const owned_target = try self.allocator.dupe(u8, target);
            errdefer self.allocator.free(owned_target);

            var log = try TargetLog.init(self.allocator);
            errdefer log.deinit(self.allocator);

            try self.targets.put(owned_target, log);
            const inserted = self.targets.getPtr(owned_target).?;
            const evicted = inserted.appendTake(self.allocator, stored);
            return .{ .evicted = evicted, .target_len = inserted.len };
        }

        pub fn latest(self: *const Self, target: []const u8, n: usize, out: []Message) Error![]const Message {
            try validateTarget(target);
            try validateOutput(n, out);
            const log = self.targets.get(target) orelse return out[0..0];
            return collectNewest(&log, n, out, null);
        }

        pub fn before(
            self: *const Self,
            target: []const u8,
            timestamp: u64,
            n: usize,
            out: []Message,
        ) Error![]const Message {
            try validateTarget(target);
            try validateOutput(n, out);
            const log = self.targets.get(target) orelse return out[0..0];
            return collectNewest(&log, n, out, .{ .before = timestamp });
        }

        /// Return visible entries after `timestamp`, oldest first for replay.
        pub fn after(
            self: *const Self,
            target: []const u8,
            timestamp: u64,
            n: usize,
            out: []Message,
        ) Error![]const Message {
            try validateTarget(target);
            try validateOutput(n, out);
            const log = self.targets.get(target) orelse return out[0..0];
            return collectAfter(&log, timestamp, n, out);
        }

        pub fn redact(self: *Self, target: []const u8, msgid: []const u8) Error!void {
            const entry = try self.findNewest(target, msgid);
            entry.tombstone = true;
        }

        pub fn edit(self: *Self, target: []const u8, msgid: []const u8, new_text: []const u8) Error!void {
            try validateText(new_text);
            const entry = try self.findNewest(target, msgid);
            const owned_text = try self.allocator.dupe(u8, new_text);
            self.allocator.free(entry.text);
            entry.text = owned_text;
        }

        pub fn storedCount(self: *const Self, target: []const u8) Error!usize {
            try validateTarget(target);
            const log = self.targets.get(target) orelse return 0;
            return log.len;
        }

        fn findNewest(self: *Self, target: []const u8, msgid: []const u8) Error!*StoredMessage {
            try validateTarget(target);
            const log = self.targets.getPtr(target) orelse return error.NotFound;

            var scanned: usize = 0;
            while (scanned < log.len) : (scanned += 1) {
                const logical_index = log.len - 1 - scanned;
                const entry = log.entryMut(logical_index);
                if (std.mem.eql(u8, entry.msgid, msgid)) return entry;
            }
            return error.NotFound;
        }

        fn validateText(text: []const u8) Error!void {
            if (text.len > params.max_text) return error.TextTooLong;
        }

        fn collectNewest(log: *const TargetLog, n: usize, out: []Message, bound: ?QueryBound) []const Message {
            var count: usize = 0;
            var scanned: usize = 0;
            while (scanned < log.len and count < n) : (scanned += 1) {
                const logical_index = log.len - 1 - scanned;
                const entry = log.entry(logical_index);
                if (entry.tombstone) continue;
                if (bound) |query_bound| switch (query_bound) {
                    .before => |timestamp| if (entry.timestamp >= timestamp) continue,
                };
                out[count] = entry.view();
                count += 1;
            }
            return out[0..count];
        }

        fn collectAfter(log: *const TargetLog, timestamp: u64, n: usize, out: []Message) []const Message {
            var count: usize = 0;
            var index: usize = 0;
            while (index < log.len and count < n) : (index += 1) {
                const entry = log.entry(index);
                if (entry.tombstone) continue;
                if (entry.timestamp <= timestamp) continue;
                out[count] = entry.view();
                count += 1;
            }
            return out[0..count];
        }
    };
}

pub fn HistoryStore(comptime params: Params) type {
    return Lotus(params);
}

const StoredMessage = struct {
    msgid: []u8,
    sender: []u8,
    text: []u8,
    timestamp: u64,
    tombstone: bool,

    fn init(allocator: std.mem.Allocator, msg: InputMessage) std.mem.Allocator.Error!StoredMessage {
        var stored = StoredMessage{
            .msgid = &.{},
            .sender = &.{},
            .text = &.{},
            .timestamp = msg.timestamp,
            .tombstone = false,
        };
        errdefer stored.deinit(allocator);

        stored.msgid = try allocator.dupe(u8, msg.msgid);
        stored.sender = try allocator.dupe(u8, msg.sender);
        stored.text = try allocator.dupe(u8, msg.text);
        return stored;
    }

    fn deinit(self: *StoredMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.msgid);
        allocator.free(self.sender);
        allocator.free(self.text);
        self.* = .{
            .msgid = &.{},
            .sender = &.{},
            .text = &.{},
            .timestamp = 0,
            .tombstone = false,
        };
    }

    fn view(self: *const StoredMessage) Message {
        return .{
            .msgid = self.msgid,
            .sender = self.sender,
            .text = self.text,
            .timestamp = self.timestamp,
            .tombstone = self.tombstone,
        };
    }
};

fn validateParams(comptime params: Params) void {
    if (params.max_targets == 0) @compileError("Lotus requires at least one target");
    if (params.max_per_target == 0) @compileError("Lotus requires at least one message per target");
}

fn validateTarget(target: []const u8) Error!void {
    if (target.len == 0) return error.InvalidTarget;
}

fn validateOutput(n: usize, out: []Message) Error!void {
    if (out.len < n) return error.OutputTooSmall;
}

test "append evicts oldest and latest returns newest first" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    const result = try store.append("#lotus", .{
        .msgid = "m4",
        .sender = "alice",
        .text = "four",
        .timestamp = 4,
    });

    try std.testing.expect(result.evicted);
    try std.testing.expectEqual(@as(usize, 3), result.target_len);

    var out: [3]Message = undefined;
    const got = try store.latest("#lotus", 3, &out);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try expectMsg(got[0], "m4", 4, "four");
    try expectMsg(got[1], "m3", 3, "three");
    try expectMsg(got[2], "m2", 2, "two");
}

test "latest before and after page visible messages correctly" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 5, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    try appendForTest(&store, "#lotus", "m4", 4, "four");
    try appendForTest(&store, "#lotus", "m5", 5, "five");

    var latest_out: [3]Message = undefined;
    const latest_page = try store.latest("#lotus", 3, &latest_out);
    try expectIds(latest_page, &.{ "m5", "m4", "m3" });

    var before_out: [2]Message = undefined;
    const before_page = try store.before("#lotus", 4, 2, &before_out);
    try expectIds(before_page, &.{ "m3", "m2" });

    var after_out: [3]Message = undefined;
    const after_page = try store.after("#lotus", 2, 3, &after_out);
    try expectIds(after_page, &.{ "m3", "m4", "m5" });
}

test "between window composes after() with an upper-bound filter" {
    // Mirrors the CHATHISTORY BETWEEN wiring in the daemon: collect oldest-first
    // after the low bound, then keep only those strictly before the high bound.
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 8, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    try appendForTest(&store, "#lotus", "m4", 4, "four");
    try appendForTest(&store, "#lotus", "m5", 5, "five");

    // BETWEEN (1, 5): strictly between -> m2, m3, m4.
    var buf: [8]Message = undefined;
    const raw = try store.after("#lotus", 1, buf.len, &buf);
    var k: usize = 0;
    for (raw) |m| {
        if (m.timestamp < 5) {
            buf[k] = m;
            k += 1;
        }
    }
    try expectIds(buf[0..k], &.{ "m2", "m3", "m4" });
}

test "redact hides reads but keeps slot" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    try store.redact("#lotus", "m2");

    try std.testing.expectEqual(@as(usize, 3), try store.storedCount("#lotus"));

    var out: [3]Message = undefined;
    const got = try store.latest("#lotus", 3, &out);
    try expectIds(got, &.{ "m3", "m1" });
}

test "edit replaces message text" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 2, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "kain", "m1", 1, "before");
    try store.edit("kain", "m1", "after");

    var out: [1]Message = undefined;
    const got = try store.latest("kain", 1, &out);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try expectMsg(got[0], "m1", 1, "after");
}

test "ownership remains leak free across fills evictions edits and deinit" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 4, .max_text = 64 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    var i: usize = 0;
    while (i < 24) : (i += 1) {
        var msgid_buf: [16]u8 = undefined;
        var text_buf: [32]u8 = undefined;
        const msgid = try std.fmt.bufPrint(&msgid_buf, "m{d}", .{i});
        const text = try std.fmt.bufPrint(&text_buf, "body-{d}", .{i});
        const target: []const u8 = if (i % 2 == 0) "#a" else "#b";
        _ = try store.append(target, .{
            .msgid = msgid,
            .sender = "alice",
            .text = text,
            .timestamp = @intCast(i),
        });
    }

    try store.edit("#a", "m22", "edited-body");
    try store.redact("#b", "m23");

    var out: [4]Message = undefined;
    const got = try store.latest("#a", 4, &out);
    try std.testing.expect(got.len > 0);
    try expectMsg(got[0], "m22", 22, "edited-body");
}

fn appendForTest(store: anytype, target: []const u8, msgid: []const u8, timestamp: u64, text: []const u8) !void {
    _ = try store.append(target, .{
        .msgid = msgid,
        .sender = "alice",
        .text = text,
        .timestamp = timestamp,
    });
}

fn expectMsg(msg: Message, msgid: []const u8, timestamp: u64, text: []const u8) !void {
    try std.testing.expectEqualStrings(msgid, msg.msgid);
    try std.testing.expectEqual(timestamp, msg.timestamp);
    try std.testing.expectEqualStrings(text, msg.text);
    try std.testing.expect(!msg.tombstone);
}

fn expectIds(messages: []const Message, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, messages.len);
    for (expected, 0..) |msgid, index| {
        try std.testing.expectEqualStrings(msgid, messages[index].msgid);
    }
}
