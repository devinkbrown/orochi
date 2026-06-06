const std = @import("std");

pub const ReportQueue = struct {
    pub const max_reports: usize = 512;
    pub const max_name_len: usize = 128;
    pub const max_reason_len: usize = 300;

    pub const Error = std.mem.Allocator.Error || error{
        EmptyReporter,
        EmptyTarget,
        EmptyReason,
        ReporterTooLong,
        TargetTooLong,
        ReasonTooLong,
        QueueFull,
        IdOverflow,
    };

    pub const Report = struct {
        id: u64,
        reporter: []u8,
        target: []u8,
        reason: []u8,
        at_ms: i64,
        resolved: bool,
    };

    allocator: std.mem.Allocator,
    reports: std.ArrayList(Report) = .empty,
    open_count: usize = 0,
    next_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) ReportQueue {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ReportQueue) void {
        for (self.reports.items) |*report| {
            freeReport(self.allocator, report);
        }
        self.reports.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn file(self: *ReportQueue, reporter: []const u8, target: []const u8, reason: []const u8, at_ms: i64) Error!u64 {
        try validateField(reporter, max_name_len, error.EmptyReporter, error.ReporterTooLong);
        try validateField(target, max_name_len, error.EmptyTarget, error.TargetTooLong);
        try validateField(reason, max_reason_len, error.EmptyReason, error.ReasonTooLong);
        if (self.next_id == 0) return error.IdOverflow;

        try self.makeRoom();

        const id = self.next_id;
        self.next_id +%= 1;

        var owned = Report{
            .id = id,
            .reporter = try self.allocator.dupe(u8, reporter),
            .target = undefined,
            .reason = undefined,
            .at_ms = at_ms,
            .resolved = false,
        };
        errdefer self.allocator.free(owned.reporter);

        owned.target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned.target);

        owned.reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned.reason);

        try self.reports.append(self.allocator, owned);
        var idx = self.reports.items.len - 1;
        while (idx > self.open_count) : (idx -= 1) {
            self.reports.items[idx] = self.reports.items[idx - 1];
        }
        self.reports.items[self.open_count] = owned;
        self.open_count += 1;

        return id;
    }

    pub fn resolve(self: *ReportQueue, id: u64) bool {
        const idx = self.indexOfOpen(id) orelse return false;
        var resolved = self.reports.items[idx];
        resolved.resolved = true;

        var pos = idx;
        while (pos + 1 < self.open_count) : (pos += 1) {
            self.reports.items[pos] = self.reports.items[pos + 1];
        }

        self.open_count -= 1;
        self.reports.items[self.open_count] = resolved;
        return true;
    }

    pub fn open(self: *const ReportQueue) []const Report {
        return self.reports.items[0..self.open_count];
    }

    fn makeRoom(self: *ReportQueue) Error!void {
        if (self.reports.items.len < max_reports) return;
        if (self.open_count == self.reports.items.len) return error.QueueFull;

        var removed = self.reports.orderedRemove(self.reports.items.len - 1);
        freeReport(self.allocator, &removed);
    }

    fn indexOfOpen(self: *const ReportQueue, id: u64) ?usize {
        for (self.reports.items[0..self.open_count], 0..) |report, idx| {
            if (report.id == id) return idx;
        }
        return null;
    }

    fn validateField(value: []const u8, max_len: usize, empty_error: Error, long_error: Error) Error!void {
        if (value.len == 0) return empty_error;
        if (value.len > max_len) return long_error;
    }

    fn freeReport(allocator: std.mem.Allocator, report: *Report) void {
        allocator.free(report.reporter);
        allocator.free(report.target);
        allocator.free(report.reason);
        report.* = undefined;
    }
};

const testing = std.testing;

test "file returns increasing ids and open reports" {
    var queue = ReportQueue.init(testing.allocator);
    defer queue.deinit();

    const first = try queue.file("alice", "bob", "harassing users", 100);
    const second = try queue.file("carol", "#desk", "repeat flooding", 200);

    try testing.expectEqual(@as(u64, 1), first);
    try testing.expectEqual(@as(u64, 2), second);

    const open_reports = queue.open();
    try testing.expectEqual(@as(usize, 2), open_reports.len);
    try testing.expectEqualStrings("alice", open_reports[0].reporter);
    try testing.expectEqualStrings("#desk", open_reports[1].target);
    try testing.expect(!open_reports[0].resolved);
}

test "resolve hides an open report without losing others" {
    var queue = ReportQueue.init(testing.allocator);
    defer queue.deinit();

    const first = try queue.file("alice", "bob", "bad nick", 100);
    const second = try queue.file("carol", "dave", "bad text", 200);

    try testing.expect(queue.resolve(first));
    try testing.expect(!queue.resolve(first));

    const open_reports = queue.open();
    try testing.expectEqual(@as(usize, 1), open_reports.len);
    try testing.expectEqual(second, open_reports[0].id);
    try testing.expectEqualStrings("carol", open_reports[0].reporter);
}

test "bounded queue prunes resolved reports before rejecting open overflow" {
    var queue = ReportQueue.init(testing.allocator);
    defer queue.deinit();

    var i: usize = 0;
    while (i < ReportQueue.max_reports) : (i += 1) {
        _ = try queue.file("r", "t", "reason", @intCast(i));
    }

    try testing.expectError(error.QueueFull, queue.file("r", "t", "reason", 999));
    try testing.expect(queue.resolve(1));
    const added = try queue.file("r", "later", "reason", 1000);
    try testing.expectEqual(@as(u64, ReportQueue.max_reports + 1), added);
    try testing.expectEqual(@as(usize, ReportQueue.max_reports), queue.open().len);
}

test "reason length is capped at three hundred bytes" {
    var queue = ReportQueue.init(testing.allocator);
    defer queue.deinit();

    const reason_ok = "x" ** ReportQueue.max_reason_len;
    _ = try queue.file("r", "t", reason_ok, 1);

    const reason_bad = "x" ** (ReportQueue.max_reason_len + 1);
    try testing.expectError(error.ReasonTooLong, queue.file("r", "t", reason_bad, 2));
}
