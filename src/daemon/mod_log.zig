const std = @import("std");

pub const ModLog = struct {
    pub const max_entries: usize = 512;
    pub const max_field_len: usize = 256;

    pub const Error = std.mem.Allocator.Error || error{
        EmptyActor,
        EmptyAction,
        EmptyTarget,
        ActorTooLong,
        ActionTooLong,
        TargetTooLong,
    };

    pub const Entry = struct {
        actor: []u8,
        action: []u8,
        target: []u8,
        at_ms: i64,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    next_index: usize = 0,

    pub fn init(allocator: std.mem.Allocator) ModLog {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ModLog) void {
        for (self.entries.items) |*entry| {
            freeEntry(self.allocator, entry);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn record(self: *ModLog, actor: []const u8, action: []const u8, target: []const u8, at_ms: i64) Error!usize {
        try validateField(actor, error.EmptyActor, error.ActorTooLong);
        try validateField(action, error.EmptyAction, error.ActionTooLong);
        try validateField(target, error.EmptyTarget, error.TargetTooLong);

        var owned = Entry{
            .actor = try self.allocator.dupe(u8, actor),
            .action = undefined,
            .target = undefined,
            .at_ms = at_ms,
        };
        errdefer self.allocator.free(owned.actor);

        owned.action = try self.allocator.dupe(u8, action);
        errdefer self.allocator.free(owned.action);

        owned.target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned.target);

        if (self.entries.items.len == max_entries) {
            var removed = self.entries.orderedRemove(0);
            freeEntry(self.allocator, &removed);
        }

        try self.entries.append(self.allocator, owned);
        const id = self.next_index;
        self.next_index +%= 1;
        return id;
    }

    pub fn recent(self: *const ModLog) []const Entry {
        return self.entries.items;
    }

    fn validateField(value: []const u8, empty_error: Error, long_error: Error) Error!void {
        if (value.len == 0) return empty_error;
        if (value.len > max_field_len) return long_error;
    }

    fn freeEntry(allocator: std.mem.Allocator, entry: *Entry) void {
        allocator.free(entry.actor);
        allocator.free(entry.action);
        allocator.free(entry.target);
        entry.* = undefined;
    }
};

const testing = std.testing;

test "record stores owned entries in order" {
    var log = ModLog.init(testing.allocator);
    defer log.deinit();

    try testing.expectEqual(@as(usize, 0), try log.record("oper", "quiet", "#room", 10));
    try testing.expectEqual(@as(usize, 1), try log.record("admin", "remove", "user", 20));

    const entries = log.recent();
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("oper", entries[0].actor);
    try testing.expectEqualStrings("quiet", entries[0].action);
    try testing.expectEqualStrings("#room", entries[0].target);
    try testing.expectEqual(@as(i64, 20), entries[1].at_ms);
}

test "record keeps only the bounded recent window" {
    var log = ModLog.init(testing.allocator);
    defer log.deinit();

    var i: usize = 0;
    while (i < ModLog.max_entries + 3) : (i += 1) {
        _ = try log.record("a", "b", "c", @intCast(i));
    }

    const entries = log.recent();
    try testing.expectEqual(@as(usize, ModLog.max_entries), entries.len);
    try testing.expectEqual(@as(i64, 3), entries[0].at_ms);
    try testing.expectEqual(@as(i64, ModLog.max_entries + 2), entries[entries.len - 1].at_ms);
}

test "record rejects empty and oversized fields" {
    var log = ModLog.init(testing.allocator);
    defer log.deinit();

    try testing.expectError(error.EmptyActor, log.record("", "act", "target", 1));

    const too_long = "x" ** (ModLog.max_field_len + 1);
    try testing.expectError(error.ActionTooLong, log.record("actor", too_long, "target", 1));
    try testing.expectEqual(@as(usize, 0), log.recent().len);
}
