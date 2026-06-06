//! Per-key rolling average over the last N floating-point samples.
const std = @import("std");

pub const RollingAverage = struct {
    allocator: std.mem.Allocator,
    sample_limit: usize,
    series: std.StringHashMap(SampleSeries),

    pub fn init(allocator: std.mem.Allocator) RollingAverage {
        return initWithLimit(allocator, 16);
    }

    pub fn initWithLimit(allocator: std.mem.Allocator, sample_limit: usize) RollingAverage {
        return .{
            .allocator = allocator,
            .sample_limit = @max(sample_limit, 1),
            .series = std.StringHashMap(SampleSeries).init(allocator),
        };
    }

    pub fn deinit(self: *RollingAverage) void {
        var it = self.series.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.series.deinit();
        self.* = undefined;
    }

    pub fn add(self: *RollingAverage, key: []const u8, value: f64) !void {
        var samples = try self.ensureSeries(key);
        if (samples.values.items.len == self.sample_limit) {
            _ = samples.values.orderedRemove(0);
        }
        try samples.values.append(self.allocator, value);
    }

    pub fn mean(self: *const RollingAverage, key: []const u8) ?f64 {
        const samples = self.series.getPtr(key) orelse return null;
        if (samples.values.items.len == 0) return null;

        var total: f64 = 0;
        for (samples.values.items) |value| total += value;
        return total / @as(f64, @floatFromInt(samples.values.items.len));
    }

    pub fn count(self: *const RollingAverage, key: []const u8) usize {
        const samples = self.series.getPtr(key) orelse return 0;
        return samples.values.items.len;
    }

    fn ensureSeries(self: *RollingAverage, key: []const u8) !*SampleSeries {
        if (self.series.getPtr(key)) |samples| return samples;
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.series.putNoClobber(owned_key, .{});
        return self.series.getPtr(key).?;
    }
};

const SampleSeries = struct {
    values: std.ArrayListUnmanaged(f64) = .empty,

    fn deinit(self: *SampleSeries, allocator: std.mem.Allocator) void {
        self.values.deinit(allocator);
        self.* = undefined;
    }
};

const testing = std.testing;

test "mean is null before samples and averages added values" {
    var averages = RollingAverage.init(testing.allocator);
    defer averages.deinit();

    try testing.expectEqual(@as(?f64, null), averages.mean("latency"));
    try averages.add("latency", 10);
    try averages.add("latency", 20);

    try testing.expectEqual(@as(usize, 2), averages.count("latency"));
    try testing.expectEqual(@as(f64, 15), averages.mean("latency").?);
}

test "rolling window keeps only the last N samples" {
    var averages = RollingAverage.initWithLimit(testing.allocator, 3);
    defer averages.deinit();

    try averages.add("load", 1);
    try averages.add("load", 2);
    try averages.add("load", 3);
    try averages.add("load", 10);

    try testing.expectEqual(@as(usize, 3), averages.count("load"));
    try testing.expectEqual(@as(f64, 5), averages.mean("load").?);
}

test "keys have independent sample windows" {
    var averages = RollingAverage.initWithLimit(testing.allocator, 2);
    defer averages.deinit();

    try averages.add("a", 2);
    try averages.add("a", 4);
    try averages.add("b", 100);
    try averages.add("a", 10);

    try testing.expectEqual(@as(f64, 7), averages.mean("a").?);
    try testing.expectEqual(@as(f64, 100), averages.mean("b").?);
    try testing.expectEqual(@as(usize, 2), averages.count("a"));
    try testing.expectEqual(@as(usize, 1), averages.count("b"));
}

test "zero limit is clamped to one retained sample" {
    var averages = RollingAverage.initWithLimit(testing.allocator, 0);
    defer averages.deinit();

    try averages.add("single", 3);
    try averages.add("single", 9);

    try testing.expectEqual(@as(usize, 1), averages.count("single"));
    try testing.expectEqual(@as(f64, 9), averages.mean("single").?);
}
