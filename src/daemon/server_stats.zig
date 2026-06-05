//! Allocation-free runtime counters for the daemon hot path.
//!
//! The hot path (accept/recv/send/line dispatch) must never allocate or take a
//! lock to record a metric, so this is a plain struct of plain integers bumped
//! inline. Rendering — Prometheus exposition text or an oper STATS dump — is a
//! cold path that snapshots the counters into a caller-provided buffer.
//!
//! These complement the structured `qlog`/`trace` flight recorder (which keeps
//! the last N *events*); this keeps monotonic *totals* and a couple of gauges.
const std = @import("std");

/// Monotonic counters (only ever increase) plus two gauges (active connections,
/// established S2S links) which move both ways. Copyable; the server embeds one.
pub const Stats = struct {
    // --- counters (monotonic) ---
    connections_total: u64 = 0,
    s2s_accepts_total: u64 = 0,
    messages_in_total: u64 = 0,
    bytes_in_total: u64 = 0,
    bytes_out_total: u64 = 0,
    errors_total: u64 = 0,
    quits_total: u64 = 0,

    // --- gauges (up/down) ---
    connections_active: i64 = 0,
    s2s_links_active: i64 = 0,

    pub fn onAccept(self: *Stats) void {
        self.connections_total += 1;
        self.connections_active += 1;
    }

    pub fn onS2sAccept(self: *Stats) void {
        self.s2s_accepts_total += 1;
        self.s2s_links_active += 1;
    }

    /// A connection closed. `was_s2s` decrements the S2S gauge instead of the
    /// client gauge so the two never cross-count.
    pub fn onClose(self: *Stats, was_s2s: bool) void {
        if (was_s2s) {
            if (self.s2s_links_active > 0) self.s2s_links_active -= 1;
        } else {
            if (self.connections_active > 0) self.connections_active -= 1;
        }
    }

    pub fn onBytesIn(self: *Stats, n: usize) void {
        self.bytes_in_total +%= n;
    }

    pub fn onBytesOut(self: *Stats, n: usize) void {
        self.bytes_out_total +%= n;
    }

    pub fn onLine(self: *Stats) void {
        self.messages_in_total += 1;
    }

    pub fn onError(self: *Stats) void {
        self.errors_total += 1;
    }

    pub fn onQuit(self: *Stats) void {
        self.quits_total += 1;
    }

    /// One metric's identity for rendering: Prometheus name, HELP text, type, and
    /// the live value. `prom` is the metric name; `irc` is the short token used
    /// in the oper STATS dump.
    const Row = struct {
        prom: []const u8,
        irc: []const u8,
        help: []const u8,
        kind: enum { counter, gauge },
        value: i128,
    };

    fn rows(self: *const Stats) [9]Row {
        return .{
            .{ .prom = "mizuchi_connections_total", .irc = "conns", .help = "Total client connections accepted", .kind = .counter, .value = self.connections_total },
            .{ .prom = "mizuchi_connections_active", .irc = "conns_active", .help = "Currently open client connections", .kind = .gauge, .value = self.connections_active },
            .{ .prom = "mizuchi_s2s_accepts_total", .irc = "s2s", .help = "Total server-to-server peers accepted", .kind = .counter, .value = self.s2s_accepts_total },
            .{ .prom = "mizuchi_s2s_links_active", .irc = "s2s_active", .help = "Currently established S2S links", .kind = .gauge, .value = self.s2s_links_active },
            .{ .prom = "mizuchi_messages_in_total", .irc = "msgs_in", .help = "Total complete protocol lines received", .kind = .counter, .value = self.messages_in_total },
            .{ .prom = "mizuchi_bytes_in_total", .irc = "bytes_in", .help = "Total bytes received from clients", .kind = .counter, .value = self.bytes_in_total },
            .{ .prom = "mizuchi_bytes_out_total", .irc = "bytes_out", .help = "Total bytes queued to clients", .kind = .counter, .value = self.bytes_out_total },
            .{ .prom = "mizuchi_quits_total", .irc = "quits", .help = "Total client disconnects", .kind = .counter, .value = self.quits_total },
            .{ .prom = "mizuchi_errors_total", .irc = "errors", .help = "Total recoverable hot-path errors", .kind = .counter, .value = self.errors_total },
        };
    }

    /// Append Prometheus exposition text (HELP/TYPE/sample per metric) to `out`.
    pub fn writePrometheus(self: *const Stats, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        for (self.rows()) |row| {
            try out.print(allocator, "# HELP {s} {s}\n", .{ row.prom, row.help });
            try out.print(allocator, "# TYPE {s} {s}\n", .{ row.prom, @tagName(row.kind) });
            try out.print(allocator, "{s} {d}\n", .{ row.prom, row.value });
        }
    }

    /// Emit one compact `token=value` line per metric via `sink` (e.g. an oper
    /// notice callback). Never allocates; formats into a small stack buffer.
    pub fn forEachLine(
        self: *const Stats,
        ctx: anytype,
        comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void,
    ) !void {
        var buf: [96]u8 = undefined;
        for (self.rows()) |row| {
            const line = std.fmt.bufPrint(&buf, "{s} = {d}", .{ row.irc, row.value }) catch continue;
            try emit(ctx, line);
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "counters and gauges move as expected" {
    var s = Stats{};
    s.onAccept();
    s.onAccept();
    s.onBytesIn(100);
    s.onLine();
    s.onClose(false);
    try testing.expectEqual(@as(u64, 2), s.connections_total);
    try testing.expectEqual(@as(i64, 1), s.connections_active);
    try testing.expectEqual(@as(u64, 100), s.bytes_in_total);
    try testing.expectEqual(@as(u64, 1), s.messages_in_total);
}

test "gauges never go negative on extra closes" {
    var s = Stats{};
    s.onClose(false);
    s.onClose(true);
    try testing.expectEqual(@as(i64, 0), s.connections_active);
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active);
}

test "s2s accept/close uses the s2s gauge only" {
    var s = Stats{};
    s.onS2sAccept();
    try testing.expectEqual(@as(i64, 1), s.s2s_links_active);
    try testing.expectEqual(@as(i64, 0), s.connections_active);
    s.onClose(true);
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active);
}

test "prometheus export carries HELP, TYPE, and samples" {
    const allocator = testing.allocator;
    var s = Stats{};
    s.onAccept();
    s.onBytesIn(42);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try s.writePrometheus(allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "# TYPE mizuchi_connections_total counter") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "mizuchi_bytes_in_total 42") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "mizuchi_connections_active 1") != null);
}

test "forEachLine emits one token line per metric" {
    var s = Stats{};
    s.onAccept();
    const Collector = struct {
        count: usize = 0,
        saw_conns: bool = false,
        fn emit(self: *@This(), line: []const u8) !void {
            self.count += 1;
            if (std.mem.startsWith(u8, line, "conns =")) self.saw_conns = true;
        }
    };
    var c = Collector{};
    try s.forEachLine(&c, Collector.emit);
    try testing.expectEqual(@as(usize, 9), c.count);
    try testing.expect(c.saw_conns);
}
