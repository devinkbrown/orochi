// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded, node-wide ring of recent Event Spine events, backing `EVENT REPLAY`
//! so an operator who just connected (or just subscribed) can see what they
//! missed. One shared instance per node, written from ANY reactor thread (a
//! connect/kill/ward can be raised on any shard) and from the mesh drain, so
//! every push/collect takes the internal mutex. Strings are copied into fixed
//! in-slot buffers (no external ownership), and the ring serializes to a small
//! snapshot file so history survives a USR2 hot-upgrade and a cold restart.
const std = @import("std");
const event_spine = @import("event_spine.zig");
const rwlock = @import("../substrate/rwlock.zig");

pub const max_origin_len: usize = 64;
pub const max_message_len: usize = 400;

/// One retained event. Byte layout is stable and little-endian on disk (see
/// `serializeInto`); `category`/`severity` are raw ordinals validated on read.
pub const StoredEvent = struct {
    category: u8,
    severity: u8,
    ts_unix_ms: i64,
    origin_buf: [max_origin_len]u8 = undefined,
    origin_len: u16 = 0,
    msg_buf: [max_message_len]u8 = undefined,
    msg_len: u16 = 0,

    pub fn origin(self: *const StoredEvent) []const u8 {
        return self.origin_buf[0..self.origin_len];
    }

    pub fn message(self: *const StoredEvent) []const u8 {
        return self.msg_buf[0..self.msg_len];
    }

    /// The category as an enum, or null if the stored ordinal is out of range
    /// (a forward-compat / corrupt-snapshot guard — callers skip such rows).
    pub fn categoryEnum(self: *const StoredEvent) ?event_spine.EventCategory {
        const n = @typeInfo(event_spine.EventCategory).@"enum".field_names.len;
        if (self.category >= n) return null;
        return @enumFromInt(self.category);
    }

    /// The severity as an enum, clamped to the top defined level.
    pub fn severityEnum(self: *const StoredEvent) event_spine.EventSeverity {
        const max = @as(u8, @typeInfo(event_spine.EventSeverity).@"enum".field_names.len - 1);
        return @enumFromInt(@min(self.severity, max));
    }

    fn set(cat: u8, sev: u8, ts: i64, origin_s: []const u8, message_s: []const u8) StoredEvent {
        var ev = StoredEvent{ .category = cat, .severity = sev, .ts_unix_ms = ts };
        const on = @min(origin_s.len, max_origin_len);
        @memcpy(ev.origin_buf[0..on], origin_s[0..on]);
        ev.origin_len = @intCast(on);
        const mn = @min(message_s.len, max_message_len);
        @memcpy(ev.msg_buf[0..mn], message_s[0..mn]);
        ev.msg_len = @intCast(mn);
        return ev;
    }
};

pub const category_count = @typeInfo(event_spine.EventCategory).@"enum".field_names.len;
pub const severity_count = @typeInfo(event_spine.EventSeverity).@"enum".field_names.len;

/// Lock-free per-category / per-severity Event Spine counters backing
/// `EVENT STATS`. Incremented from any reactor + the mesh drain (atomic adds),
/// read for the stats reply. Process-lifetime (not persisted — a running total
/// resets on restart, which is the useful semantics for "since this boot").
pub const EventStats = struct {
    by_category: [category_count]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),
    by_severity: [severity_count]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),
    total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn record(self: *EventStats, cat: u8, sev: u8) void {
        if (cat < category_count) _ = self.by_category[cat].fetchAdd(1, .monotonic);
        if (sev < severity_count) _ = self.by_severity[sev].fetchAdd(1, .monotonic);
        _ = self.total.fetchAdd(1, .monotonic);
    }

    pub fn categoryCount(self: *const EventStats, cat: usize) u64 {
        return self.by_category[cat].load(.monotonic);
    }
    pub fn severityCount(self: *const EventStats, sev: usize) u64 {
        return self.by_severity[sev].load(.monotonic);
    }
    pub fn totalCount(self: *const EventStats) u64 {
        return self.total.load(.monotonic);
    }
};

const snapshot_magic = "OEH1";
const snapshot_version: u8 = 1;

pub fn EventHistory(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        items: [capacity]StoredEvent = undefined,
        start: usize = 0,
        count: usize = 0,
        mu: rwlock.RwLock = .{},

        /// Append one event (thread-safe). Oldest is evicted when full.
        pub fn record(
            self: *Self,
            category: u8,
            severity: u8,
            ts_unix_ms: i64,
            origin_s: []const u8,
            message_s: []const u8,
        ) void {
            if (capacity == 0) return;
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            const slot = if (self.count < capacity) blk: {
                const i = (self.start + self.count) % capacity;
                self.count += 1;
                break :blk i;
            } else blk: {
                const i = self.start;
                self.start = (self.start + 1) % capacity;
                break :blk i;
            };
            self.items[slot] = StoredEvent.set(category, severity, ts_unix_ms, origin_s, message_s);
        }

        /// Copy up to `out.len` recent events into `out`, NEWEST FIRST, keeping
        /// only those matching `filter_category` (null = any) with severity ≥
        /// `min_severity` (raw ordinal). Returns the number written. Done under
        /// the lock into caller storage so rendering/delivery happens lock-free.
        pub fn collect(
            self: *Self,
            filter_category: ?u8,
            min_severity: u8,
            out: []StoredEvent,
        ) usize {
            if (out.len == 0) return 0;
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            var written: usize = 0;
            var scanned: usize = 0;
            // Walk newest→oldest: index count-1 down to 0 in ring order.
            while (scanned < self.count and written < out.len) : (scanned += 1) {
                const logical = self.count - 1 - scanned;
                const ev = self.items[(self.start + logical) % capacity];
                if (filter_category) |fc| {
                    if (ev.category != fc) continue;
                }
                if (ev.severity < min_severity) continue;
                out[written] = ev;
                written += 1;
            }
            return written;
        }

        pub fn len(self: *Self) usize {
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            return self.count;
        }

        /// Serialize the ring OLDEST-FIRST into `w`: magic, version, u32 count,
        /// then each event. Little-endian. Caller holds no lock expectations —
        /// this takes the lock so a concurrent record() can't tear a row.
        pub fn serializeInto(self: *Self, w: *std.Io.Writer) std.Io.Writer.Error!void {
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            try w.writeAll(snapshot_magic);
            try w.writeByte(snapshot_version);
            try putU32(w, @intCast(self.count));
            var i: usize = 0;
            while (i < self.count) : (i += 1) {
                const ev = self.items[(self.start + i) % capacity];
                try w.writeByte(ev.category);
                try w.writeByte(ev.severity);
                try putI64(w, ev.ts_unix_ms);
                try putBytes(w, ev.origin());
                try putBytes(w, ev.message());
            }
        }

        /// Load a snapshot produced by `serializeInto`, replacing the ring.
        /// Returns false (leaving the ring empty) on any magic/version/parse
        /// mismatch — history is best-effort, so a bad file just starts empty.
        pub fn load(self: *Self, data: []const u8) bool {
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            self.start = 0;
            self.count = 0;
            if (data.len < 5 or !std.mem.eql(u8, data[0..4], snapshot_magic)) return false;
            if (data[4] != snapshot_version) return false;
            var c = Cursor{ .b = data, .i = 5 };
            const n = c.readU32() orelse return false;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const cat = c.byte() orelse return false;
                const sev = c.byte() orelse return false;
                const ts = c.readI64() orelse return false;
                const origin_s = c.bytes() orelse return false;
                const message_s = c.bytes() orelse return false;
                if (self.count >= capacity) {
                    // A snapshot larger than this build's ring: keep the newest
                    // `capacity` by evicting oldest (mirrors record()).
                    self.items[self.start] = StoredEvent.set(cat, sev, ts, origin_s, message_s);
                    self.start = (self.start + 1) % capacity;
                } else {
                    self.items[self.count] = StoredEvent.set(cat, sev, ts, origin_s, message_s);
                    self.count += 1;
                }
            }
            return true;
        }
    };
}

fn putU32(w: *std.Io.Writer, v: u32) std.Io.Writer.Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try w.writeAll(&b);
}

fn putI64(w: *std.Io.Writer, v: i64) std.Io.Writer.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(i64, &b, v, .little);
    try w.writeAll(&b);
}

fn putBytes(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    const n: u16 = @intCast(@min(s.len, std.math.maxInt(u16)));
    try putU32(w, n);
    try w.writeAll(s[0..n]);
}

const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    fn byte(c: *Cursor) ?u8 {
        if (c.i + 1 > c.b.len) return null;
        const v = c.b[c.i];
        c.i += 1;
        return v;
    }
    fn readU32(c: *Cursor) ?u32 {
        if (c.i + 4 > c.b.len) return null;
        const v = std.mem.readInt(u32, c.b[c.i..][0..4], .little);
        c.i += 4;
        return v;
    }
    fn readI64(c: *Cursor) ?i64 {
        if (c.i + 8 > c.b.len) return null;
        const v = std.mem.readInt(i64, c.b[c.i..][0..8], .little);
        c.i += 8;
        return v;
    }
    fn bytes(c: *Cursor) ?[]const u8 {
        const n = c.readU32() orelse return null;
        if (c.i + n > c.b.len) return null;
        const s = c.b[c.i .. c.i + n];
        c.i += n;
        return s;
    }
};

test "EventStats counts per category, per severity, and total" {
    var s = EventStats{};
    s.record(7, 3); // category 7, severity 3
    s.record(7, 1); // category 7, severity 1
    s.record(3, 3); // category 3, severity 3
    try std.testing.expectEqual(@as(u64, 3), s.totalCount());
    try std.testing.expectEqual(@as(u64, 2), s.categoryCount(7));
    try std.testing.expectEqual(@as(u64, 1), s.categoryCount(3));
    try std.testing.expectEqual(@as(u64, 0), s.categoryCount(0));
    try std.testing.expectEqual(@as(u64, 2), s.severityCount(3));
    try std.testing.expectEqual(@as(u64, 1), s.severityCount(1));
    // Out-of-range ordinals still bump the total but no per-slot counter.
    s.record(250, 250);
    try std.testing.expectEqual(@as(u64, 4), s.totalCount());
}

test "records, evicts oldest, and collects newest-first" {
    var h = EventHistory(3){};
    h.record(0, 2, 100, "a.node", "one");
    h.record(1, 2, 200, "a.node", "two");
    h.record(2, 2, 300, "a.node", "three");
    h.record(3, 2, 400, "a.node", "four"); // evicts "one"

    var out: [8]StoredEvent = undefined;
    const n = h.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("four", out[0].message());
    try std.testing.expectEqualStrings("three", out[1].message());
    try std.testing.expectEqualStrings("two", out[2].message());
}

test "collect filters by category and minimum severity" {
    var h = EventHistory(8){};
    h.record(7, 1, 1, "n", "kill-info"); // category 7, severity 1 (info)
    h.record(7, 3, 2, "n", "kill-warn"); // category 7, severity 3 (warn)
    h.record(3, 3, 3, "n", "flood-warn"); // category 3

    var out: [8]StoredEvent = undefined;
    // Category 7 only, severity ≥ warn(3): just the warn kill.
    const n = h.collect(7, 3, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("kill-warn", out[0].message());

    // Category 7, any severity: both kills, newest first.
    const n2 = h.collect(7, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), n2);
    try std.testing.expectEqualStrings("kill-warn", out[0].message());
    try std.testing.expectEqualStrings("kill-info", out[1].message());
}

test "snapshot round-trips oldest-first and survives reload" {
    var h = EventHistory(4){};
    h.record(1, 2, 111, "eshmaki.me", "USER CONNECT n!u@h");
    h.record(7, 3, 222, "ircx.us", "k killed s (flood)");

    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    try h.serializeInto(&aw.writer);

    var restored = EventHistory(4){};
    try std.testing.expect(restored.load(aw.written()));
    var out: [8]StoredEvent = undefined;
    const n = restored.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("k killed s (flood)", out[0].message());
    try std.testing.expectEqual(@as(i64, 222), out[0].ts_unix_ms);
    try std.testing.expectEqual(@as(u8, 7), out[0].category);
    try std.testing.expectEqualStrings("ircx.us", out[0].origin());
    try std.testing.expectEqualStrings("USER CONNECT n!u@h", out[1].message());

    // A bad magic / version loads empty (best-effort).
    try std.testing.expect(!restored.load("XXXX\x01\x00\x00\x00\x00"));
    try std.testing.expect(!restored.load("OEH1\x02\x00\x00\x00\x00"));
    try std.testing.expectEqual(@as(usize, 0), restored.len());
}
