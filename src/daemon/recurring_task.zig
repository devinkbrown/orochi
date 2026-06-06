//! Named recurring task schedule.
const std = @import("std");

pub const Entry = struct {
    name: []const u8,
    interval_ms: i64,
    last_ms: i64,
};

pub const Error = std.mem.Allocator.Error || error{InvalidInterval};

const StoredEntry = struct {
    interval_ms: i64,
    last_ms: i64,
};

pub const RecurringTask = struct {
    allocator: std.mem.Allocator,
    tasks: std.StringHashMap(StoredEntry),

    pub fn init(allocator: std.mem.Allocator) RecurringTask {
        return .{
            .allocator = allocator,
            .tasks = std.StringHashMap(StoredEntry).init(allocator),
        };
    }

    pub fn deinit(self: *RecurringTask) void {
        var iterator = self.tasks.iterator();
        while (iterator.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.tasks.deinit();
        self.* = undefined;
    }

    pub fn add(self: *RecurringTask, name: []const u8, interval_ms: i64, now_ms: i64) Error!void {
        if (interval_ms <= 0) return error.InvalidInterval;

        if (self.tasks.getPtr(name)) |task| {
            task.* = .{ .interval_ms = interval_ms, .last_ms = now_ms };
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.tasks.putNoClobber(owned_name, .{
            .interval_ms = interval_ms,
            .last_ms = now_ms,
        });
    }

    pub fn due(self: *RecurringTask, now_ms: i64, out: [][]const u8) usize {
        var count: usize = 0;
        var iterator = self.tasks.iterator();
        while (iterator.next()) |entry| {
            if (count >= out.len) break;
            const task = entry.value_ptr;
            if (now_ms < task.last_ms) continue;

            const elapsed = now_ms - task.last_ms;
            if (elapsed < task.interval_ms) continue;

            out[count] = entry.key_ptr.*;
            count += 1;
            task.last_ms += @divTrunc(elapsed, task.interval_ms) * task.interval_ms;
        }
        return count;
    }

    pub fn remove(self: *RecurringTask, name: []const u8) bool {
        const entry = self.tasks.getEntry(name) orelse return false;
        const owned_name = entry.key_ptr.*;
        self.tasks.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_name);
        return true;
    }

    pub fn get(self: *const RecurringTask, name: []const u8) ?Entry {
        const task = self.tasks.get(name) orelse return null;
        return .{
            .name = name,
            .interval_ms = task.interval_ms,
            .last_ms = task.last_ms,
        };
    }
};

const testing = std.testing;

test "add rejects zero or negative intervals" {
    var tasks = RecurringTask.init(testing.allocator);
    defer tasks.deinit();

    try testing.expectError(error.InvalidInterval, tasks.add("sweep", 0, 100));
    try testing.expectError(error.InvalidInterval, tasks.add("sweep", -1, 100));
}

test "due returns names once interval has elapsed" {
    var tasks = RecurringTask.init(testing.allocator);
    defer tasks.deinit();

    try tasks.add("sweep", 1000, 0);
    var out: [2][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 0), tasks.due(999, &out));
    try testing.expectEqual(@as(usize, 1), tasks.due(1000, &out));
    try testing.expectEqualStrings("sweep", out[0]);
}

test "due advances last by elapsed intervals" {
    var tasks = RecurringTask.init(testing.allocator);
    defer tasks.deinit();

    try tasks.add("flush", 1000, 0);
    var out: [1][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 1), tasks.due(3500, &out));
    const entry = tasks.get("flush").?;
    try testing.expectEqual(@as(i64, 3000), entry.last_ms);
    try testing.expectEqual(@as(usize, 0), tasks.due(3999, &out));
    try testing.expectEqual(@as(usize, 1), tasks.due(4000, &out));
}

test "remove drops a task once" {
    var tasks = RecurringTask.init(testing.allocator);
    defer tasks.deinit();

    try tasks.add("expire", 100, 0);
    try testing.expect(tasks.remove("expire"));
    try testing.expect(!tasks.remove("expire"));

    var out: [1][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 0), tasks.due(200, &out));
}
