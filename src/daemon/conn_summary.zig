//! Bounded per-connection counters for operator diagnostics.
//!
//! This module tracks lightweight connection facts that aggregate server
//! counters cannot answer: per-client byte counts, message counts, JOIN counts,
//! and the original connection timestamp. Rendering uses caller-provided
//! buffers so STATS and WHO views can stay allocation-free on the cold path.

const std = @import("std");
const numeric = @import("../proto/numeric.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("connection summaries require a 64-bit target");
}

/// Numeric replies used by connection summary diagnostic views.
pub const ConnSummaryNumeric = enum(u16) {
    RPL_ENDOFSTATS = 219,
    RPL_STATSDEBUG = 249,
    RPL_ENDOFWHO = 315,
    RPL_WHOREPLY = 352,

    /// Convert the local mapping into the shared numeric enum.
    pub fn known(self: ConnSummaryNumeric) numeric.Numeric {
        return switch (self) {
            .RPL_ENDOFSTATS => .RPL_ENDOFSTATS,
            .RPL_STATSDEBUG => .RPL_STATSDEBUG,
            .RPL_ENDOFWHO => .RPL_ENDOFWHO,
            .RPL_WHOREPLY => .RPL_WHOREPLY,
        };
    }
};

/// Compile-time limits for a connection summary store.
pub const Params = struct {
    max_connections: usize = 4096,
    max_key_bytes: usize = 64,
    max_label_bytes: usize = 96,
    max_line_bytes: usize = 512,
};

/// Typed failures returned by the connection summary API.
pub const ConnSummaryError = std.mem.Allocator.Error || error{
    EmptyKey,
    KeyTooLong,
    InvalidKey,
    LabelTooLong,
    InvalidLabel,
    TooManyConnections,
    MissingConnection,
    OutputTooSmall,
};

/// Copyable raw counters for one connection.
pub const Counters = struct {
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    messages: u64 = 0,
    joins: u64 = 0,
    connect_ts: u64 = 0,
};

/// Borrowed snapshot suitable for formatting or sorting by a caller.
pub const Snapshot = struct {
    key: []const u8,
    label: []const u8,
    bytes_in: u64,
    bytes_out: u64,
    messages: u64,
    joins: u64,
    connect_ts: u64,
};

const Entry = struct {
    label: []u8,
    counters: Counters,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        self.* = undefined;
    }
};

/// Return a bounded, allocator-backed connection summary store type.
pub fn ConnSummary(comptime params: Params) type {
    comptime {
        if (params.max_connections == 0) @compileError("connection summaries need connection storage");
        if (params.max_key_bytes == 0) @compileError("connection summaries need key storage");
        if (params.max_label_bytes == 0) @compileError("connection summaries need label storage");
        if (params.max_line_bytes == 0) @compileError("connection summaries need line storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        connections: std.StringHashMap(Entry),

        /// Create an empty store using `allocator` for owned keys and labels.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .connections = std.StringHashMap(Entry).init(allocator),
            };
        }

        /// Free all owned keys, labels, and hash table storage.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.connections.deinit();
            self.* = undefined;
        }

        /// Remove every tracked connection while retaining hash table capacity.
        pub fn clear(self: *Self) void {
            var it = self.connections.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.connections.clearRetainingCapacity();
        }

        /// Return the number of currently tracked connections.
        pub fn count(self: *const Self) usize {
            return self.connections.count();
        }

        /// Add or reset one connection.
        ///
        /// Returns true for a new key and false when an existing key was reset.
        pub fn open(self: *Self, key: []const u8, label: []const u8, connect_ts: u64) ConnSummaryError!bool {
            try validateKey(params, key);
            try validateLabel(params, label);

            if (self.connections.getPtr(key)) |entry| {
                try self.replaceLabel(entry, label);
                entry.counters = .{ .connect_ts = connect_ts };
                return false;
            }

            if (self.connections.count() >= params.max_connections) return error.TooManyConnections;

            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);

            const owned_label = try self.allocator.dupe(u8, label);
            errdefer self.allocator.free(owned_label);

            try self.connections.putNoClobber(owned_key, .{
                .label = owned_label,
                .counters = .{ .connect_ts = connect_ts },
            });
            return true;
        }

        /// Replace the display label for an existing connection.
        pub fn updateLabel(self: *Self, key: []const u8, label: []const u8) ConnSummaryError!void {
            const entry = try self.entryFor(key);
            try validateLabel(params, label);
            try self.replaceLabel(entry, label);
        }

        /// Remove a connection and free its owned key and label.
        pub fn remove(self: *Self, key: []const u8) ConnSummaryError!bool {
            try validateKey(params, key);
            const removed = self.connections.fetchRemove(key) orelse return false;
            self.allocator.free(removed.key);
            var value = removed.value;
            value.deinit(self.allocator);
            return true;
        }

        /// Report whether a valid connection key is present.
        pub fn contains(self: *const Self, key: []const u8) ConnSummaryError!bool {
            try validateKey(params, key);
            return self.connections.contains(key);
        }

        /// Add received bytes to one connection's input counter.
        pub fn recordBytesIn(self: *Self, key: []const u8, n: usize) ConnSummaryError!void {
            const entry = try self.entryFor(key);
            entry.counters.bytes_in +%= sizeToU64(n);
        }

        /// Add sent bytes to one connection's output counter.
        pub fn recordBytesOut(self: *Self, key: []const u8, n: usize) ConnSummaryError!void {
            const entry = try self.entryFor(key);
            entry.counters.bytes_out +%= sizeToU64(n);
        }

        /// Increment the complete-message counter for one connection.
        pub fn recordMessage(self: *Self, key: []const u8) ConnSummaryError!void {
            const entry = try self.entryFor(key);
            entry.counters.messages +%= 1;
        }

        /// Increment the JOIN counter for one connection.
        pub fn recordJoin(self: *Self, key: []const u8) ConnSummaryError!void {
            const entry = try self.entryFor(key);
            entry.counters.joins +%= 1;
        }

        /// Return a borrowed snapshot for one connection.
        pub fn snapshot(self: *const Self, key: []const u8) ConnSummaryError!Snapshot {
            try validateKey(params, key);
            const entry = self.connections.getEntry(key) orelse return error.MissingConnection;
            return makeSnapshot(entry.key_ptr.*, entry.value_ptr.*);
        }

        /// Copy borrowed snapshots for all tracked connections into `out`.
        pub fn list(self: *const Self, out: []Snapshot) ConnSummaryError![]const Snapshot {
            if (out.len < self.connections.count()) return error.OutputTooSmall;

            var index: usize = 0;
            var it = self.connections.iterator();
            while (it.next()) |entry| {
                out[index] = makeSnapshot(entry.key_ptr.*, entry.value_ptr.*);
                index += 1;
            }
            return out[0..index];
        }

        fn entryFor(self: *Self, key: []const u8) ConnSummaryError!*Entry {
            try validateKey(params, key);
            return self.connections.getPtr(key) orelse error.MissingConnection;
        }

        fn replaceLabel(self: *Self, entry: *Entry, label: []const u8) ConnSummaryError!void {
            const owned_label = try self.allocator.dupe(u8, label);
            self.allocator.free(entry.label);
            entry.label = owned_label;
        }
    };
}

/// Default bounded connection summary store.
pub const DefaultSummary = ConnSummary(.{});

/// Format one STATS-style diagnostic line into `out`.
pub fn formatStatsLine(out: []u8, row: Snapshot, now_ts: u64) ConnSummaryError![]const u8 {
    const age = elapsedSeconds(row.connect_ts, now_ts);
    return std.fmt.bufPrint(
        out,
        "conn={s} label={s} bytes_in={d} bytes_out={d} msgs={d} joins={d} connect_ts={d} age={d}",
        .{ row.key, row.label, row.bytes_in, row.bytes_out, row.messages, row.joins, row.connect_ts, age },
    ) catch |err| switch (err) {
        error.NoSpaceLeft => error.OutputTooSmall,
    };
}

/// Format compact no-space fields suitable for appending to an oper WHO view.
pub fn formatWhoToken(out: []u8, row: Snapshot, now_ts: u64) ConnSummaryError![]const u8 {
    const age = elapsedSeconds(row.connect_ts, now_ts);
    return std.fmt.bufPrint(
        out,
        "conn={s};in={d};out={d};msgs={d};joins={d};age={d}",
        .{ row.key, row.bytes_in, row.bytes_out, row.messages, row.joins, age },
    ) catch |err| switch (err) {
        error.NoSpaceLeft => error.OutputTooSmall,
    };
}

fn makeSnapshot(key: []const u8, entry: Entry) Snapshot {
    return .{
        .key = key,
        .label = entry.label,
        .bytes_in = entry.counters.bytes_in,
        .bytes_out = entry.counters.bytes_out,
        .messages = entry.counters.messages,
        .joins = entry.counters.joins,
        .connect_ts = entry.counters.connect_ts,
    };
}

fn validateKey(comptime params: Params, key: []const u8) ConnSummaryError!void {
    if (key.len == 0) return error.EmptyKey;
    if (key.len > params.max_key_bytes) return error.KeyTooLong;

    for (key) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidKey;
    }
}

fn validateLabel(comptime params: Params, label: []const u8) ConnSummaryError!void {
    if (label.len > params.max_label_bytes) return error.LabelTooLong;

    for (label) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidLabel;
    }
}

fn elapsedSeconds(connect_ts: u64, now_ts: u64) u64 {
    if (now_ts <= connect_ts) return 0;
    return now_ts - connect_ts;
}

fn sizeToU64(n: usize) u64 {
    return @as(u64, @intCast(n));
}

const testing = std.testing;

test "open records one connection and formats stats output" {
    // Arrange.
    var summaries = DefaultSummary.init(testing.allocator);
    defer summaries.deinit();

    // Act.
    try testing.expect(try summaries.open("fd-7", "alice", 100));
    try summaries.recordBytesIn("fd-7", 128);
    try summaries.recordBytesOut("fd-7", 64);
    try summaries.recordMessage("fd-7");
    try summaries.recordMessage("fd-7");
    try summaries.recordJoin("fd-7");
    const row = try summaries.snapshot("fd-7");
    var out: [512]u8 = undefined;
    const line = try formatStatsLine(&out, row, 130);

    // Assert.
    try testing.expectEqualStrings("fd-7", row.key);
    try testing.expectEqualStrings("alice", row.label);
    try testing.expectEqual(@as(u64, 128), row.bytes_in);
    try testing.expectEqual(@as(u64, 64), row.bytes_out);
    try testing.expectEqual(@as(u64, 2), row.messages);
    try testing.expectEqual(@as(u64, 1), row.joins);
    try testing.expect(std.mem.indexOf(u8, line, "conn=fd-7") != null);
    try testing.expect(std.mem.indexOf(u8, line, "age=30") != null);
}

test "list returns borrowed snapshots for all tracked connections" {
    // Arrange.
    var summaries = DefaultSummary.init(testing.allocator);
    defer summaries.deinit();
    try testing.expect(try summaries.open("fd-1", "alice", 10));
    try testing.expect(try summaries.open("fd-2", "bob", 20));
    try summaries.recordBytesOut("fd-2", 512);

    // Act.
    var rows: [2]Snapshot = undefined;
    const listed = try summaries.list(&rows);

    // Assert.
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expect(containsKey(listed, "fd-1"));
    try testing.expect(containsKey(listed, "fd-2"));
}

test "open enforces configured capacity and key validation" {
    // Arrange.
    const TinySummary = ConnSummary(.{ .max_connections = 1, .max_key_bytes = 4, .max_label_bytes = 8 });
    var summaries = TinySummary.init(testing.allocator);
    defer summaries.deinit();

    // Act and assert.
    try testing.expectError(error.EmptyKey, summaries.open("", "ok", 0));
    try testing.expectError(error.KeyTooLong, summaries.open("abcde", "ok", 0));
    try testing.expectError(error.InvalidKey, summaries.open("a b", "ok", 0));
    try testing.expect(try summaries.open("one", "ok", 0));
    try testing.expectError(error.TooManyConnections, summaries.open("two", "ok", 0));
}

test "label validation and update replace owned labels" {
    // Arrange.
    const TinySummary = ConnSummary(.{ .max_connections = 2, .max_key_bytes = 8, .max_label_bytes = 5 });
    var summaries = TinySummary.init(testing.allocator);
    defer summaries.deinit();
    try testing.expect(try summaries.open("fd1", "alpha", 1));

    // Act.
    try testing.expectError(error.LabelTooLong, summaries.updateLabel("fd1", "longer"));
    try testing.expectError(error.InvalidLabel, summaries.updateLabel("fd1", "bad\n"));
    try summaries.updateLabel("fd1", "beta");
    const row = try summaries.snapshot("fd1");

    // Assert.
    try testing.expectEqualStrings("beta", row.label);
}

test "opening an existing key resets counters and timestamp" {
    // Arrange.
    var summaries = DefaultSummary.init(testing.allocator);
    defer summaries.deinit();
    try testing.expect(try summaries.open("fd-9", "old", 10));
    try summaries.recordBytesIn("fd-9", 900);
    try summaries.recordJoin("fd-9");

    // Act.
    try testing.expect(!(try summaries.open("fd-9", "new", 50)));
    const row = try summaries.snapshot("fd-9");

    // Assert.
    try testing.expectEqualStrings("new", row.label);
    try testing.expectEqual(@as(u64, 0), row.bytes_in);
    try testing.expectEqual(@as(u64, 0), row.joins);
    try testing.expectEqual(@as(u64, 50), row.connect_ts);
    try testing.expectEqual(@as(usize, 1), summaries.count());
}

test "remove and clear free owned entries and update presence" {
    // Arrange.
    var summaries = DefaultSummary.init(testing.allocator);
    defer summaries.deinit();
    try testing.expect(try summaries.open("fd-a", "alice", 1));
    try testing.expect(try summaries.open("fd-b", "bob", 2));

    // Act.
    try testing.expect(try summaries.remove("fd-a"));
    const still_has_a = try summaries.contains("fd-a");
    const still_has_b = try summaries.contains("fd-b");
    summaries.clear();

    // Assert.
    try testing.expect(!still_has_a);
    try testing.expect(still_has_b);
    try testing.expectEqual(@as(usize, 0), summaries.count());
    try testing.expect(!(try summaries.remove("fd-b")));
}

test "who token is compact and reports zero age for future timestamps" {
    // Arrange.
    var summaries = DefaultSummary.init(testing.allocator);
    defer summaries.deinit();
    try testing.expect(try summaries.open("fd-3", "carol", 200));
    try summaries.recordBytesIn("fd-3", 3);
    try summaries.recordBytesOut("fd-3", 5);
    try summaries.recordMessage("fd-3");
    const row = try summaries.snapshot("fd-3");

    // Act.
    var out: [128]u8 = undefined;
    const token = try formatWhoToken(&out, row, 199);

    // Assert.
    try testing.expectEqualStrings("conn=fd-3;in=3;out=5;msgs=1;joins=0;age=0", token);
    try testing.expectError(error.OutputTooSmall, formatWhoToken(out[0..8], row, 250));
}

test "numeric mapping returns shared numeric variants" {
    // Arrange.
    const stats_numeric = ConnSummaryNumeric.RPL_STATSDEBUG;
    const who_numeric = ConnSummaryNumeric.RPL_WHOREPLY;

    // Act.
    const stats_known = stats_numeric.known();
    const who_known = who_numeric.known();

    // Assert.
    try testing.expectEqual(numeric.Numeric.RPL_STATSDEBUG, stats_known);
    try testing.expectEqual(numeric.Numeric.RPL_WHOREPLY, who_known);
}

fn containsKey(rows: []const Snapshot, key: []const u8) bool {
    for (rows) |row| {
        if (std.mem.eql(u8, row.key, key)) return true;
    }
    return false;
}
