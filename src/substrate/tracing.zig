// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed tracing spans — OpenTelemetry-style, deterministic.
//!
//! Callers supply wall-clock timestamps (microseconds) and IDs; no real
//! time or random number calls are made inside this module.  Context is
//! explicit — there are no thread-locals.
//!
//! Sampling is performed by a deterministic ratio sampler keyed on the
//! upper 64 bits of the TraceId, so a given trace is either always
//! sampled or always dropped, regardless of span count.
//!
//! Finished spans can be serialised to NDJSON with `Tracer.export`.
const std = @import("std");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// 128-bit trace identifier (matches OTel W3C trace-id width).
pub const TraceId = [16]u8;

/// 64-bit span identifier (matches OTel span-id width).
pub const SpanId = [8]u8;

/// Convenience zero values used for "no parent".
pub const null_span_id: SpanId = [_]u8{0} ** 8;
pub const null_trace_id: TraceId = [_]u8{0} ** 16;

// ---------------------------------------------------------------------------
// Attribute value
// ---------------------------------------------------------------------------

pub const AttributeValue = union(enum) {
    str: []const u8,
    int: i64,
    bool: bool,
    float: f64,
};

pub const Attribute = struct {
    key: []const u8,
    value: AttributeValue,
};

// ---------------------------------------------------------------------------
// Span event
// ---------------------------------------------------------------------------

pub const SpanEvent = struct {
    timestamp_us: u64,
    name: []const u8,
};

// ---------------------------------------------------------------------------
// Span status
// ---------------------------------------------------------------------------

pub const StatusCode = enum {
    unset,
    ok,
    err,
};

pub const Status = struct {
    code: StatusCode = .unset,
    message: []const u8 = "",
};

// ---------------------------------------------------------------------------
// Span
// ---------------------------------------------------------------------------

/// A completed or in-flight tracing span.
///
/// Memory for `name`, attribute keys/values, and event names is NOT owned
/// by the Span; callers must ensure string lifetimes exceed the span's.
/// The `attributes` and `events` ArrayLists ARE owned and must be freed via
/// `deinit`.
pub const Span = struct {
    trace_id: TraceId,
    span_id: SpanId,
    parent_span_id: SpanId,
    name: []const u8,
    start_us: u64,
    end_us: u64, // 0 while in-flight
    attributes: std.ArrayListUnmanaged(Attribute),
    events: std.ArrayListUnmanaged(SpanEvent),
    status: Status,
    sampled: bool,

    const Self = @This();

    pub fn deinit(self: *Self, alloc: Allocator) void {
        self.attributes.deinit(alloc);
        self.events.deinit(alloc);
    }

    /// Duration in microseconds.  Returns 0 if the span has not ended.
    pub fn durationUs(self: Self) u64 {
        if (self.end_us == 0) return 0;
        return self.end_us -| self.start_us;
    }

    /// Append an attribute.  Returns error.OutOfMemory on allocation failure.
    pub fn addAttribute(self: *Self, alloc: Allocator, key: []const u8, value: AttributeValue) !void {
        try self.attributes.append(alloc, .{ .key = key, .value = value });
    }

    /// Append a timed event.
    pub fn addEvent(self: *Self, alloc: Allocator, timestamp_us: u64, name: []const u8) !void {
        try self.events.append(alloc, .{ .timestamp_us = timestamp_us, .name = name });
    }

    /// Mark the span as ended at `now_us`.  Idempotent (first call wins).
    pub fn end(self: *Self, now_us: u64) void {
        if (self.end_us == 0) self.end_us = now_us;
    }

    /// Write a single NDJSON line to `writer`.
    ///
    /// Format is deterministic given fixed inputs — no timestamps beyond
    /// the ones stored in the span.
    pub fn writeNdjson(self: Self, writer: anytype) !void {
        try writer.writeAll("{");

        // trace_id
        try writer.writeAll("\"trace_id\":\"");
        try writeHex(writer, &self.trace_id);
        try writer.writeAll("\",");

        // span_id
        try writer.writeAll("\"span_id\":\"");
        try writeHex(writer, &self.span_id);
        try writer.writeAll("\",");

        // parent_span_id
        try writer.writeAll("\"parent_span_id\":\"");
        try writeHex(writer, &self.parent_span_id);
        try writer.writeAll("\",");

        // name
        try writer.writeAll("\"name\":");
        try writeJsonString(writer, self.name);
        try writer.writeByte(',');

        // start / end / duration
        try writer.print("\"start_us\":{d},\"end_us\":{d},\"duration_us\":{d},", .{
            self.start_us, self.end_us, self.durationUs(),
        });

        // sampled
        try writer.print("\"sampled\":{},", .{self.sampled});

        // status
        try writer.writeAll("\"status\":{\"code\":\"");
        try writer.writeAll(switch (self.status.code) {
            .unset => "unset",
            .ok => "ok",
            .err => "err",
        });
        try writer.writeAll("\",\"message\":");
        try writeJsonString(writer, self.status.message);
        try writer.writeAll("},");

        // attributes
        try writer.writeAll("\"attributes\":[");
        for (self.attributes.items, 0..) |attr, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"key\":");
            try writeJsonString(writer, attr.key);
            try writer.writeAll(",\"value\":");
            switch (attr.value) {
                .str => |s| try writeJsonString(writer, s),
                .int => |n| try writer.print("{d}", .{n}),
                .bool => |b| try writer.writeAll(if (b) "true" else "false"),
                .float => |f| try writer.print("{d}", .{f}),
            }
            try writer.writeByte('}');
        }
        try writer.writeAll("],");

        // events
        try writer.writeAll("\"events\":[");
        for (self.events.items, 0..) |ev, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.print("{{\"timestamp_us\":{d},\"name\":", .{ev.timestamp_us});
            try writeJsonString(writer, ev.name);
            try writer.writeByte('}');
        }
        try writer.writeAll("]}\n");
    }
};

// ---------------------------------------------------------------------------
// Tracing context  (explicit — no thread-locals)
// ---------------------------------------------------------------------------

/// Lightweight value passed between callers to propagate the active span.
pub const Context = struct {
    trace_id: TraceId = null_trace_id,
    span_id: SpanId = null_span_id,
};

// ---------------------------------------------------------------------------
// Deterministic ratio sampler
// ---------------------------------------------------------------------------

/// Samples traces deterministically.
///
/// `ratio` must be in [0.0, 1.0].  A ratio of 1.0 samples all traces;
/// 0.0 drops all.  The decision is based solely on the upper 64 bits of
/// the trace ID so every span within a trace gets the same decision.
pub const RatioSampler = struct {
    /// Threshold in u64 space: a trace is sampled when its key < threshold.
    threshold: u64,

    pub fn init(ratio: f64) RatioSampler {
        const clamped = std.math.clamp(ratio, 0.0, 1.0);
        // Map [0,1] → [0, maxInt+1]; saturating cast handles 1.0 exactly.
        const threshold: u64 = if (clamped >= 1.0)
            std.math.maxInt(u64)
        else
            @intFromFloat(clamped * @as(f64, @floatFromInt(std.math.maxInt(u64))));
        return .{ .threshold = threshold };
    }

    pub fn shouldSample(self: RatioSampler, trace_id: TraceId) bool {
        if (self.threshold == std.math.maxInt(u64)) return true;
        // Read the first 8 bytes as big-endian u64.
        const key = std.mem.readInt(u64, trace_id[0..8], .big);
        return key < self.threshold;
    }
};

// ---------------------------------------------------------------------------
// Tracer
// ---------------------------------------------------------------------------

/// Owns all finished spans until `export` or `reset` is called.
pub const Tracer = struct {
    alloc: Allocator,
    sampler: RatioSampler,
    /// Finished spans (ended spans are moved here).
    finished: std.ArrayListUnmanaged(Span),

    const Self = @This();

    pub fn init(alloc: Allocator, sampler: RatioSampler) Self {
        return .{
            .alloc = alloc,
            .sampler = sampler,
            .finished = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.finished.items) |*s| s.deinit(self.alloc);
        self.finished.deinit(self.alloc);
    }

    /// Start a new span.
    ///
    /// `ctx` carries the parent trace/span; pass a zero Context for a root span
    /// (a new trace_id must be provided via `trace_id`).
    ///
    /// The caller is responsible for ensuring `name` outlives the span.
    pub fn startSpan(
        self: *Self,
        ctx: Context,
        trace_id: TraceId,
        span_id: SpanId,
        name: []const u8,
        now_us: u64,
    ) Span {
        const effective_trace_id: TraceId = if (std.mem.eql(u8, &ctx.trace_id, &null_trace_id))
            trace_id
        else
            ctx.trace_id;

        const sampled = self.sampler.shouldSample(effective_trace_id);

        return Span{
            .trace_id = effective_trace_id,
            .span_id = span_id,
            .parent_span_id = ctx.span_id,
            .name = name,
            .start_us = now_us,
            .end_us = 0,
            .attributes = .empty,
            .events = .empty,
            .status = .{},
            .sampled = sampled,
        };
    }

    /// Derive a child Context from an in-flight Span.
    pub fn contextFromSpan(span: Span) Context {
        return .{ .trace_id = span.trace_id, .span_id = span.span_id };
    }

    /// End a span and move it to the finished list if it is sampled.
    /// Always calls `span.end(now_us)`.  Unsampled spans are deinited here.
    pub fn endSpan(self: *Self, span: *Span, now_us: u64) !void {
        span.end(now_us);
        if (span.sampled) {
            try self.finished.append(self.alloc, span.*);
        } else {
            span.deinit(self.alloc);
        }
    }

    /// Write all finished spans as NDJSON lines to `writer`, in insertion order.
    pub fn exportNdjson(self: Self, writer: anytype) !void {
        for (self.finished.items) |span| {
            try span.writeNdjson(writer);
        }
    }

    /// Discard all finished spans, freeing their memory.
    pub fn reset(self: *Self) void {
        for (self.finished.items) |*s| s.deinit(self.alloc);
        self.finished.clearRetainingCapacity();
    }
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn writeHex(writer: anytype, bytes: []const u8) !void {
    const hex = "0123456789abcdef";
    for (bytes) |b| {
        try writer.writeByte(hex[b >> 4]);
        try writer.writeByte(hex[b & 0xf]);
    }
}

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            // Other C0 control characters excluding \n (0x0a), \r (0x0d), \t (0x09)
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try writer.print("\\u{x:0>4}", .{c}),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makeTraceId(v: u8) TraceId {
    var id: TraceId = undefined;
    @memset(&id, v);
    return id;
}

fn makeSpanId(v: u8) SpanId {
    var id: SpanId = undefined;
    @memset(&id, v);
    return id;
}

test "root span has null parent and correct trace_id" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    const tid = makeTraceId(0x01);
    const sid = makeSpanId(0xAA);

    var span = tracer.startSpan(.{}, tid, sid, "root", 1000);
    defer span.deinit(alloc); // deinit if not ended through tracer

    try testing.expectEqualSlices(u8, &tid, &span.trace_id);
    try testing.expectEqualSlices(u8, &sid, &span.span_id);
    try testing.expectEqualSlices(u8, &null_span_id, &span.parent_span_id);
}

test "parent/child linkage via context" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    const tid = makeTraceId(0x02);

    var parent = tracer.startSpan(.{}, tid, makeSpanId(0x01), "parent", 100);
    const child_ctx = Tracer.contextFromSpan(parent);

    var child = tracer.startSpan(child_ctx, tid, makeSpanId(0x02), "child", 200);

    // Both must share the same trace_id
    try testing.expectEqualSlices(u8, &parent.trace_id, &child.trace_id);
    // Child's parent_span_id == parent's span_id
    try testing.expectEqualSlices(u8, &parent.span_id, &child.parent_span_id);

    try tracer.endSpan(&child, 300);
    try tracer.endSpan(&parent, 400);

    try testing.expectEqual(@as(usize, 2), tracer.finished.items.len);
}

test "duration equals end minus start" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x03), makeSpanId(0x01), "timed", 5000);
    span.end(8000);
    try testing.expectEqual(@as(u64, 3000), span.durationUs());
    span.deinit(alloc);
}

test "in-flight span has zero duration" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x04), makeSpanId(0x01), "inflight", 1000);
    try testing.expectEqual(@as(u64, 0), span.durationUs());
    span.deinit(alloc);
}

test "attributes recorded correctly" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x05), makeSpanId(0x01), "attrs", 0);
    try span.addAttribute(alloc, "http.method", .{ .str = "GET" });
    try span.addAttribute(alloc, "http.status", .{ .int = 200 });
    try span.addAttribute(alloc, "error", .{ .bool = false });
    try span.addAttribute(alloc, "latency", .{ .float = 1.5 });

    try testing.expectEqual(@as(usize, 4), span.attributes.items.len);
    try testing.expectEqualStrings("http.method", span.attributes.items[0].key);
    try testing.expectEqualStrings("GET", span.attributes.items[0].value.str);
    try testing.expectEqual(@as(i64, 200), span.attributes.items[1].value.int);
    try testing.expectEqual(false, span.attributes.items[2].value.bool);
    try testing.expectEqual(@as(f64, 1.5), span.attributes.items[3].value.float);

    try tracer.endSpan(&span, 100);
}

test "events recorded correctly" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x06), makeSpanId(0x01), "events", 0);
    try span.addEvent(alloc, 50, "cache.miss");
    try span.addEvent(alloc, 75, "db.query.start");

    try testing.expectEqual(@as(usize, 2), span.events.items.len);
    try testing.expectEqual(@as(u64, 50), span.events.items[0].timestamp_us);
    try testing.expectEqualStrings("cache.miss", span.events.items[0].name);
    try testing.expectEqual(@as(u64, 75), span.events.items[1].timestamp_us);

    try tracer.endSpan(&span, 100);
}

test "sampler includes trace with ratio 1.0" {
    const sampler = RatioSampler.init(1.0);
    // All-zeros trace key is the smallest possible → always below threshold.
    try testing.expect(sampler.shouldSample(null_trace_id));
    // All-max bytes → still sampled at ratio 1.0.
    try testing.expect(sampler.shouldSample(makeTraceId(0xFF)));
}

test "sampler excludes trace with ratio 0.0" {
    const sampler = RatioSampler.init(0.0);
    try testing.expect(!sampler.shouldSample(null_trace_id));
    try testing.expect(!sampler.shouldSample(makeTraceId(0xFF)));
}

test "sampler deterministic: same trace_id always same decision" {
    const sampler = RatioSampler.init(0.5);
    const tid_a = makeTraceId(0x00); // key = 0x00…  → sampled (below 50% threshold)
    const tid_b = makeTraceId(0xFF); // key = 0xFF…  → NOT sampled (above threshold)

    // Call multiple times; the result must be stable.
    try testing.expect(sampler.shouldSample(tid_a));
    try testing.expect(sampler.shouldSample(tid_a));
    try testing.expect(!sampler.shouldSample(tid_b));
    try testing.expect(!sampler.shouldSample(tid_b));
}

test "unsampled spans are not stored" {
    const alloc = testing.allocator;
    // ratio=0.0 drops everything
    var tracer = Tracer.init(alloc, RatioSampler.init(0.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x07), makeSpanId(0x01), "dropped", 0);
    try span.addAttribute(alloc, "key", .{ .str = "val" });
    try tracer.endSpan(&span, 100);

    try testing.expectEqual(@as(usize, 0), tracer.finished.items.len);
}

test "NDJSON export golden compare — single span" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    // Deterministic IDs
    var tid: TraceId = [_]u8{0} ** 16;
    tid[0] = 0xDE;
    tid[1] = 0xAD;
    var sid: SpanId = [_]u8{0} ** 8;
    sid[0] = 0xBE;
    sid[1] = 0xEF;

    var span = tracer.startSpan(.{}, tid, sid, "hello", 1000);
    try span.addAttribute(alloc, "db", .{ .str = "postgres" });
    try span.addEvent(alloc, 1050, "query.start");
    span.status = .{ .code = .ok, .message = "" };
    try tracer.endSpan(&span, 2000);

    var aw = std.Io.Writer.Allocating.init(alloc);
    defer aw.deinit();
    try tracer.exportNdjson(&aw.writer);

    // trace_id: 16 bytes → 32 hex chars; span_id: 8 bytes → 16 hex chars
    const expected =
        ("{\"trace_id\":\"dead0000000000000000000000000000\"," ++ "\"span_id\":\"beef000000000000\"," ++ "\"parent_span_id\":\"0000000000000000\"," ++ "\"name\":\"hello\"," ++ "\"start_us\":1000,\"end_us\":2000,\"duration_us\":1000," ++ "\"sampled\":true," ++ "\"status\":{\"code\":\"ok\",\"message\":\"\"}," ++ "\"attributes\":[{\"key\":\"db\",\"value\":\"postgres\"}]," ++ "\"events\":[{\"timestamp_us\":1050,\"name\":\"query.start\"}]}\n");

    try testing.expectEqualStrings(expected, aw.writer.buffered());
}

test "NDJSON export — multiple spans ordered by insertion" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    const tid = makeTraceId(0x10);

    var s1 = tracer.startSpan(.{}, tid, makeSpanId(0x01), "first", 0);
    try tracer.endSpan(&s1, 10);

    var s2 = tracer.startSpan(.{}, tid, makeSpanId(0x02), "second", 20);
    try tracer.endSpan(&s2, 30);

    var aw = std.Io.Writer.Allocating.init(alloc);
    defer aw.deinit();
    try tracer.exportNdjson(&aw.writer);

    // Two lines expected.
    var lines = std.mem.splitScalar(u8, aw.writer.buffered(), '\n');
    const line1 = lines.next() orelse "";
    const line2 = lines.next() orelse "";
    const line3 = lines.next() orelse "";

    try testing.expect(std.mem.indexOf(u8, line1, "\"name\":\"first\"") != null);
    try testing.expect(std.mem.indexOf(u8, line2, "\"name\":\"second\"") != null);
    try testing.expectEqualStrings("", line3); // trailing newline yields empty final token
}

test "nested spans — grandchild inherits trace_id" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    const tid = makeTraceId(0x20);

    var root = tracer.startSpan(.{}, tid, makeSpanId(0x01), "root", 0);
    const ctx1 = Tracer.contextFromSpan(root);

    var child = tracer.startSpan(ctx1, tid, makeSpanId(0x02), "child", 10);
    const ctx2 = Tracer.contextFromSpan(child);

    var grand = tracer.startSpan(ctx2, tid, makeSpanId(0x03), "grandchild", 20);

    try testing.expectEqualSlices(u8, &root.trace_id, &grand.trace_id);
    try testing.expectEqualSlices(u8, &child.span_id, &grand.parent_span_id);

    try tracer.endSpan(&grand, 30);
    try tracer.endSpan(&child, 40);
    try tracer.endSpan(&root, 50);

    try testing.expectEqual(@as(usize, 3), tracer.finished.items.len);
}

test "reset clears finished spans" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x30), makeSpanId(0x01), "x", 0);
    try tracer.endSpan(&span, 1);
    try testing.expectEqual(@as(usize, 1), tracer.finished.items.len);

    tracer.reset();
    try testing.expectEqual(@as(usize, 0), tracer.finished.items.len);
}

test "endSpan is idempotent: end_us set by first call" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x40), makeSpanId(0x01), "once", 0);
    span.end(100);
    span.end(999); // second call must not overwrite
    try testing.expectEqual(@as(u64, 100), span.end_us);
    span.deinit(alloc);
}

test "JSON string escaping" {
    const alloc = testing.allocator;
    var tracer = Tracer.init(alloc, RatioSampler.init(1.0));
    defer tracer.deinit();

    var span = tracer.startSpan(.{}, makeTraceId(0x50), makeSpanId(0x01), "esc\"test\\n", 0);
    try tracer.endSpan(&span, 1);

    var aw = std.Io.Writer.Allocating.init(alloc);
    defer aw.deinit();
    try tracer.exportNdjson(&aw.writer);

    // The name field must appear escaped in the output.
    try testing.expect(std.mem.indexOf(u8, aw.writer.buffered(), "esc\\\"test\\\\n") != null);
}
