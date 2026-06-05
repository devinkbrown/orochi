const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Label = struct {
    name: []const u8,
    value: []const u8,
};

pub const Counter = struct {
    raw_value: f64 = 0,

    pub fn init() Counter {
        return .{};
    }

    pub fn inc(self: *Counter, amount: f64) !void {
        if (amount != amount or amount < 0) return error.NegativeIncrement;
        self.raw_value += amount;
    }

    pub fn value(self: Counter) f64 {
        return self.raw_value;
    }
};

pub const Gauge = struct {
    raw_value: f64 = 0,

    pub fn init() Gauge {
        return .{};
    }

    pub fn set(self: *Gauge, next: f64) void {
        self.raw_value = next;
    }

    pub fn inc(self: *Gauge, amount: f64) void {
        self.raw_value += amount;
    }

    pub fn dec(self: *Gauge, amount: f64) void {
        self.raw_value -= amount;
    }

    pub fn value(self: Gauge) f64 {
        return self.raw_value;
    }
};

pub const Histogram = struct {
    buckets: []f64,
    bucket_counts: []u64,
    raw_sum: f64 = 0,
    raw_count: u64 = 0,

    pub fn init(allocator: Allocator, buckets: []const f64) !Histogram {
        for (buckets) |bucket| {
            if (bucket != bucket or bucket == std.math.inf(f64) or bucket == -std.math.inf(f64)) {
                return error.InvalidBucket;
            }
        }

        const owned_buckets = try allocator.dupe(f64, buckets);
        errdefer allocator.free(owned_buckets);
        std.mem.sort(f64, owned_buckets, {}, floatLess);

        for (owned_buckets, 0..) |bucket, i| {
            if (i != 0 and bucket == owned_buckets[i - 1]) return error.DuplicateBucket;
        }

        const counts = try allocator.alloc(u64, buckets.len);
        errdefer allocator.free(counts);
        @memset(counts, 0);

        return .{
            .buckets = owned_buckets,
            .bucket_counts = counts,
        };
    }

    pub fn deinit(self: *Histogram, allocator: Allocator) void {
        allocator.free(self.buckets);
        allocator.free(self.bucket_counts);
        self.* = undefined;
    }

    pub fn clone(self: Histogram, allocator: Allocator) !Histogram {
        const buckets = try allocator.dupe(f64, self.buckets);
        errdefer allocator.free(buckets);
        const counts = try allocator.dupe(u64, self.bucket_counts);
        errdefer allocator.free(counts);
        return .{
            .buckets = buckets,
            .bucket_counts = counts,
            .raw_sum = self.raw_sum,
            .raw_count = self.raw_count,
        };
    }

    pub fn observe(self: *Histogram, value: f64) !void {
        if (value != value) return error.InvalidObservation;
        self.raw_sum += value;
        self.raw_count += 1;
        for (self.buckets, 0..) |bucket, i| {
            if (value <= bucket) self.bucket_counts[i] += 1;
        }
    }

    pub fn sum(self: Histogram) f64 {
        return self.raw_sum;
    }

    pub fn count(self: Histogram) u64 {
        return self.raw_count;
    }

    pub fn cumulativeCount(self: Histogram, bucket_index: usize) u64 {
        return self.bucket_counts[bucket_index];
    }
};

pub const MetricKind = enum {
    counter,
    gauge,
    histogram,
};

pub const Metric = union(MetricKind) {
    counter: Counter,
    gauge: Gauge,
    histogram: Histogram,

    fn kind(self: Metric) MetricKind {
        return switch (self) {
            .counter => .counter,
            .gauge => .gauge,
            .histogram => .histogram,
        };
    }

    fn prometheusType(self: Metric) []const u8 {
        return switch (self) {
            .counter => "counter",
            .gauge => "gauge",
            .histogram => "histogram",
        };
    }

    fn deinit(self: *Metric, allocator: Allocator) void {
        switch (self.*) {
            .counter, .gauge => {},
            .histogram => |*histogram| histogram.deinit(allocator),
        }
    }
};

const MetricEntry = struct {
    name: []const u8,
    help: []const u8,
    labels: []Label,
    metric: Metric,

    fn deinit(self: *MetricEntry, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.help);
        freeLabels(allocator, self.labels);
        self.metric.deinit(allocator);
        self.* = undefined;
    }
};

pub const Registry = struct {
    allocator: Allocator,
    metrics: std.ArrayList(MetricEntry) = .empty,

    pub fn init(allocator: Allocator) Registry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Registry) void {
        for (self.metrics.items) |*metric| metric.deinit(self.allocator);
        self.metrics.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn registerCounter(
        self: *Registry,
        name: []const u8,
        help: []const u8,
        labels: []const Label,
        counter: Counter,
    ) !void {
        try self.appendMetric(name, help, labels, .{ .counter = counter });
    }

    pub fn registerGauge(
        self: *Registry,
        name: []const u8,
        help: []const u8,
        labels: []const Label,
        gauge: Gauge,
    ) !void {
        try self.appendMetric(name, help, labels, .{ .gauge = gauge });
    }

    pub fn registerHistogram(
        self: *Registry,
        name: []const u8,
        help: []const u8,
        labels: []const Label,
        histogram: Histogram,
    ) !void {
        const cloned = try histogram.clone(self.allocator);
        errdefer {
            var rollback = cloned;
            rollback.deinit(self.allocator);
        }
        try self.appendMetric(name, help, labels, .{ .histogram = cloned });
    }

    pub fn writePrometheus(self: *const Registry, out: *std.ArrayList(u8)) !void {
        var ordered: std.ArrayList(*const MetricEntry) = .empty;
        defer ordered.deinit(self.allocator);

        for (self.metrics.items) |*metric| try ordered.append(self.allocator, metric);
        std.mem.sort(*const MetricEntry, ordered.items, {}, entryLess);

        var last_family: ?[]const u8 = null;
        for (ordered.items) |metric| {
            if (last_family == null or !std.mem.eql(u8, last_family.?, metric.name)) {
                try out.print(self.allocator, "# HELP {s} ", .{metric.name});
                try writeEscapedHelp(out, self.allocator, metric.help);
                try out.append(self.allocator, '\n');
                try out.print(self.allocator, "# TYPE {s} {s}\n", .{
                    metric.name,
                    metric.metric.prometheusType(),
                });
                last_family = metric.name;
            }

            switch (metric.metric) {
                .counter => |counter| try writeSample(out, self.allocator, metric.name, metric.labels, null, counter.value()),
                .gauge => |gauge| try writeSample(out, self.allocator, metric.name, metric.labels, null, gauge.value()),
                .histogram => |histogram| {
                    for (histogram.buckets, 0..) |bucket, i| {
                        var le = try formatFloatLabel(self.allocator, bucket);
                        defer le.deinit(self.allocator);
                        try writeCountSample(
                            out,
                            self.allocator,
                            metric.name,
                            "_bucket",
                            metric.labels,
                            .{ .name = "le", .value = le.items },
                            histogram.cumulativeCount(i),
                        );
                    }
                    try writeCountSample(
                        out,
                        self.allocator,
                        metric.name,
                        "_bucket",
                        metric.labels,
                        .{ .name = "le", .value = "+Inf" },
                        histogram.count(),
                    );
                    try writeSampleWithSuffix(out, self.allocator, metric.name, "_sum", metric.labels, null, histogram.sum());
                    try writeCountSample(out, self.allocator, metric.name, "_count", metric.labels, null, histogram.count());
                },
            }
        }
    }

    fn appendMetric(
        self: *Registry,
        name: []const u8,
        help: []const u8,
        labels: []const Label,
        metric: Metric,
    ) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_help = try self.allocator.dupe(u8, help);
        errdefer self.allocator.free(owned_help);
        const owned_labels = try copyAndSortLabels(self.allocator, labels);
        errdefer freeLabels(self.allocator, owned_labels);

        for (self.metrics.items) |existing| {
            if (!std.mem.eql(u8, existing.name, owned_name)) continue;
            if (existing.metric.kind() != metric.kind() or !std.mem.eql(u8, existing.help, owned_help)) {
                return error.ConflictingMetricFamily;
            }
            if (labelsEqual(existing.labels, owned_labels)) return error.DuplicateMetric;
        }

        try self.metrics.append(self.allocator, .{
            .name = owned_name,
            .help = owned_help,
            .labels = owned_labels,
            .metric = metric,
        });
    }
};

fn floatLess(_: void, lhs: f64, rhs: f64) bool {
    return lhs < rhs;
}

fn labelLess(_: void, lhs: Label, rhs: Label) bool {
    const name_order = std.mem.order(u8, lhs.name, rhs.name);
    if (name_order != .eq) return name_order == .lt;
    return std.mem.order(u8, lhs.value, rhs.value) == .lt;
}

fn entryLess(_: void, lhs: *const MetricEntry, rhs: *const MetricEntry) bool {
    const name_order = std.mem.order(u8, lhs.name, rhs.name);
    if (name_order != .eq) return name_order == .lt;

    const lhs_kind = @tagName(lhs.metric.kind());
    const rhs_kind = @tagName(rhs.metric.kind());
    const kind_order = std.mem.order(u8, lhs_kind, rhs_kind);
    if (kind_order != .eq) return kind_order == .lt;

    return labelsLess(lhs.labels, rhs.labels);
}

fn labelsLess(lhs: []const Label, rhs: []const Label) bool {
    const common = @min(lhs.len, rhs.len);
    for (0..common) |i| {
        const name_order = std.mem.order(u8, lhs[i].name, rhs[i].name);
        if (name_order != .eq) return name_order == .lt;
        const value_order = std.mem.order(u8, lhs[i].value, rhs[i].value);
        if (value_order != .eq) return value_order == .lt;
    }
    return lhs.len < rhs.len;
}

fn labelsEqual(lhs: []const Label, rhs: []const Label) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |left, right| {
        if (!std.mem.eql(u8, left.name, right.name)) return false;
        if (!std.mem.eql(u8, left.value, right.value)) return false;
    }
    return true;
}

fn copyAndSortLabels(allocator: Allocator, labels: []const Label) ![]Label {
    const copied = try allocator.alloc(Label, labels.len);
    errdefer allocator.free(copied);

    var filled: usize = 0;
    errdefer {
        for (copied[0..filled]) |label| {
            allocator.free(label.name);
            allocator.free(label.value);
        }
    }

    for (labels, 0..) |label, i| {
        const name = try allocator.dupe(u8, label.name);
        const value = allocator.dupe(u8, label.value) catch |err| {
            allocator.free(name);
            return err;
        };
        copied[i] = .{ .name = name, .value = value };
        filled += 1;
    }

    std.mem.sort(Label, copied, {}, labelLess);
    for (copied, 0..) |label, i| {
        if (i != 0 and std.mem.eql(u8, label.name, copied[i - 1].name)) {
            return error.DuplicateLabelName;
        }
    }

    return copied;
}

fn freeLabels(allocator: Allocator, labels: []Label) void {
    for (labels) |label| {
        allocator.free(label.name);
        allocator.free(label.value);
    }
    allocator.free(labels);
}

fn writeSample(
    out: *std.ArrayList(u8),
    allocator: Allocator,
    name: []const u8,
    labels: []const Label,
    extra_label: ?Label,
    value: f64,
) !void {
    try writeSampleWithSuffix(out, allocator, name, "", labels, extra_label, value);
}

fn writeSampleWithSuffix(
    out: *std.ArrayList(u8),
    allocator: Allocator,
    name: []const u8,
    suffix: []const u8,
    labels: []const Label,
    extra_label: ?Label,
    value: f64,
) !void {
    try writeNameAndLabels(out, allocator, name, suffix, labels, extra_label);
    try out.print(allocator, " {d}\n", .{value});
}

fn writeCountSample(
    out: *std.ArrayList(u8),
    allocator: Allocator,
    name: []const u8,
    suffix: []const u8,
    labels: []const Label,
    extra_label: ?Label,
    value: u64,
) !void {
    try writeNameAndLabels(out, allocator, name, suffix, labels, extra_label);
    try out.print(allocator, " {d}\n", .{value});
}

fn writeNameAndLabels(
    out: *std.ArrayList(u8),
    allocator: Allocator,
    name: []const u8,
    suffix: []const u8,
    labels: []const Label,
    extra_label: ?Label,
) !void {
    try out.print(allocator, "{s}{s}", .{ name, suffix });
    if (labels.len == 0 and extra_label == null) return;

    try out.append(allocator, '{');
    for (labels, 0..) |label, i| {
        if (i != 0) try out.append(allocator, ',');
        try writeLabel(out, allocator, label);
    }
    if (extra_label) |label| {
        if (labels.len != 0) try out.append(allocator, ',');
        try writeLabel(out, allocator, label);
    }
    try out.append(allocator, '}');
}

fn writeLabel(out: *std.ArrayList(u8), allocator: Allocator, label: Label) !void {
    try out.print(allocator, "{s}=\"", .{label.name});
    try writeEscapedLabelValue(out, allocator, label.value);
    try out.append(allocator, '"');
}

fn writeEscapedHelp(out: *std.ArrayList(u8), allocator: Allocator, text: []const u8) !void {
    for (text) |byte| {
        switch (byte) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            else => try out.append(allocator, byte),
        }
    }
}

fn writeEscapedLabelValue(out: *std.ArrayList(u8), allocator: Allocator, text: []const u8) !void {
    for (text) |byte| {
        switch (byte) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            else => try out.append(allocator, byte),
        }
    }
}

fn formatFloatLabel(allocator: Allocator, value: f64) !std.ArrayList(u8) {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.print(allocator, "{d}", .{value});
    return out;
}

test "counter and gauge values" {
    var counter = Counter.init();
    try std.testing.expectEqual(@as(f64, 0), counter.value());
    try counter.inc(2);
    try counter.inc(0.5);
    try std.testing.expectEqual(@as(f64, 2.5), counter.value());
    try std.testing.expectError(error.NegativeIncrement, counter.inc(-1));

    var gauge = Gauge.init();
    gauge.set(10);
    gauge.inc(2.25);
    gauge.dec(4);
    try std.testing.expectEqual(@as(f64, 8.25), gauge.value());
}

test "histogram bucketing sum and count" {
    const allocator = std.testing.allocator;
    var histogram = try Histogram.init(allocator, &.{ 1, 0.1, 0.5 });
    defer histogram.deinit(allocator);

    const samples = [_]f64{ 0.05, 0.2, 0.5, 0.75, 2.0 };
    for (&samples) |sample| try histogram.observe(sample);

    try std.testing.expectEqual(@as(f64, 3.5), histogram.sum());
    try std.testing.expectEqual(@as(u64, 5), histogram.count());
    try std.testing.expectEqual(@as(f64, 0.1), histogram.buckets[0]);
    try std.testing.expectEqual(@as(f64, 0.5), histogram.buckets[1]);
    try std.testing.expectEqual(@as(f64, 1), histogram.buckets[2]);
    try std.testing.expectEqual(@as(u64, 1), histogram.cumulativeCount(0));
    try std.testing.expectEqual(@as(u64, 3), histogram.cumulativeCount(1));
    try std.testing.expectEqual(@as(u64, 4), histogram.cumulativeCount(2));
}

test "label rendering and escaping" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    var gauge = Gauge.init();
    gauge.set(1);
    try registry.registerGauge("escaped_metric", "slash\\newline\nhelp", &.{
        .{ .name = "z", .value = "quote\"slash\\newline\n" },
        .{ .name = "a", .value = "first" },
    }, gauge);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try registry.writePrometheus(&out);

    try std.testing.expectEqualStrings(
        "# HELP escaped_metric slash\\\\newline\\nhelp\n" ++
            "# TYPE escaped_metric gauge\n" ++
            "escaped_metric{a=\"first\",z=\"quote\\\"slash\\\\newline\\n\"} 1\n",
        out.items,
    );
}

test "registry serializes deterministically with golden text" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    var histogram = try Histogram.init(allocator, &.{ 1, 0.5, 0.1 });
    defer histogram.deinit(allocator);
    const samples = [_]f64{ 0.05, 0.2, 0.7, 2.0 };
    for (&samples) |sample| try histogram.observe(sample);

    var gauge = Gauge.init();
    gauge.set(-1.5);
    try registry.registerGauge("inflight", "In-flight work", &.{
        .{ .name = "worker", .value = "b" },
    }, gauge);

    try registry.registerHistogram("request_duration_seconds", "Request duration", &.{
        .{ .name = "method", .value = "GET" },
    }, histogram);

    var post = Counter.init();
    try post.inc(3);
    try registry.registerCounter("requests_total", "Total requests", &.{
        .{ .name = "method", .value = "POST" },
    }, post);

    var get = Counter.init();
    try get.inc(2);
    try registry.registerCounter("requests_total", "Total requests", &.{
        .{ .name = "method", .value = "GET" },
    }, get);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try registry.writePrometheus(&out);

    try std.testing.expectEqualStrings(
        "# HELP inflight In-flight work\n" ++
            "# TYPE inflight gauge\n" ++
            "inflight{worker=\"b\"} -1.5\n" ++
            "# HELP request_duration_seconds Request duration\n" ++
            "# TYPE request_duration_seconds histogram\n" ++
            "request_duration_seconds_bucket{method=\"GET\",le=\"0.1\"} 1\n" ++
            "request_duration_seconds_bucket{method=\"GET\",le=\"0.5\"} 2\n" ++
            "request_duration_seconds_bucket{method=\"GET\",le=\"1\"} 3\n" ++
            "request_duration_seconds_bucket{method=\"GET\",le=\"+Inf\"} 4\n" ++
            "request_duration_seconds_sum{method=\"GET\"} 2.95\n" ++
            "request_duration_seconds_count{method=\"GET\"} 4\n" ++
            "# HELP requests_total Total requests\n" ++
            "# TYPE requests_total counter\n" ++
            "requests_total{method=\"GET\"} 2\n" ++
            "requests_total{method=\"POST\"} 3\n",
        out.items,
    );
}

test "duplicate-name handling" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    var counter = Counter.init();
    try counter.inc(1);
    try registry.registerCounter("same_total", "Same", &.{
        .{ .name = "kind", .value = "a" },
    }, counter);

    try std.testing.expectError(error.DuplicateMetric, registry.registerCounter("same_total", "Same", &.{
        .{ .name = "kind", .value = "a" },
    }, counter));

    try registry.registerCounter("same_total", "Same", &.{
        .{ .name = "kind", .value = "b" },
    }, counter);

    var gauge = Gauge.init();
    gauge.set(1);
    try std.testing.expectError(error.ConflictingMetricFamily, registry.registerGauge("same_total", "Same", &.{
        .{ .name = "kind", .value = "c" },
    }, gauge));
    try std.testing.expectError(error.ConflictingMetricFamily, registry.registerCounter("same_total", "Other help", &.{
        .{ .name = "kind", .value = "c" },
    }, counter));
}

test "ordering stable independent of insertion order and label order" {
    const allocator = std.testing.allocator;

    var left = Registry.init(allocator);
    defer left.deinit();
    var right = Registry.init(allocator);
    defer right.deinit();

    var a = Counter.init();
    try a.inc(1);
    var b = Counter.init();
    try b.inc(2);

    try left.registerCounter("z_total", "Zed", &.{
        .{ .name = "b", .value = "2" },
        .{ .name = "a", .value = "1" },
    }, a);
    try left.registerCounter("a_total", "Aye", &.{}, b);

    try right.registerCounter("a_total", "Aye", &.{}, b);
    try right.registerCounter("z_total", "Zed", &.{
        .{ .name = "a", .value = "1" },
        .{ .name = "b", .value = "2" },
    }, a);

    var left_out: std.ArrayList(u8) = .empty;
    defer left_out.deinit(allocator);
    var right_out: std.ArrayList(u8) = .empty;
    defer right_out.deinit(allocator);

    try left.writePrometheus(&left_out);
    try right.writePrometheus(&right_out);
    try std.testing.expectEqualStrings(left_out.items, right_out.items);
}

test "invalid histogram buckets and duplicate labels are rejected" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.DuplicateBucket, Histogram.init(allocator, &.{ 1, 0.5, 1 }));
    try std.testing.expectError(error.InvalidBucket, Histogram.init(allocator, &.{std.math.inf(f64)}));

    var registry = Registry.init(allocator);
    defer registry.deinit();
    const gauge = Gauge.init();
    try std.testing.expectError(error.DuplicateLabelName, registry.registerGauge("bad", "Bad", &.{
        .{ .name = "dup", .value = "a" },
        .{ .name = "dup", .value = "b" },
    }, gauge));
}
