// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-command usage counters for `STATS m` (RPL_STATSCOMMANDS, 212).
//!
//! Records how many times each command verb has been dispatched plus the total
//! bytes those lines carried. The table is fixed-capacity and self-allocating:
//! the first time a verb is seen it claims a free slot; subsequent hits bump
//! atomic counters with no lock. Only the rare new-verb claim takes the mutex,
//! so the hot path (an already-seen verb) is lock-free.
//!
//! Command verbs are uppercased and capped at `MAX_NAME` bytes for a stable key.
//! Once the table fills, further unseen verbs are silently dropped (the common
//! commands are recorded first, which is what `STATS m` is for).
const std = @import("std");

/// Max distinct command verbs tracked. Comfortably above the live command set.
pub const MAX_COMMANDS: usize = 192;
/// Max stored verb length; longer verbs are truncated for the key.
pub const MAX_NAME: usize = 24;

const AtomicU64 = std.atomic.Value(u64);

const Slot = struct {
    /// Inline uppercased verb. `name_len == 0` means the slot is free.
    name: [MAX_NAME]u8 = @splat(0),
    name_len: usize = 0,
    count: AtomicU64 = .init(0),
    bytes: AtomicU64 = .init(0),

    fn nameSlice(self: *const Slot) []const u8 {
        return self.name[0..self.name_len];
    }
};

/// Fixed-capacity command-usage table. Embed one in the server.
pub const CommandUsage = struct {
    slots: [MAX_COMMANDS]Slot = @splat(.{}),
    /// Number of claimed slots. Read locklessly for iteration bounds; only
    /// advanced under `claim_lock`.
    used: AtomicU64 = .init(0),
    /// tryLock-only spinlock guarding the rare new-verb claim (codebase idiom).
    claim_lock: std.atomic.Mutex = .unlocked,

    /// Record one dispatch of `command` carrying `line_bytes`. Lock-free for an
    /// already-seen verb; takes the claim lock only to register a new verb.
    pub fn record(self: *CommandUsage, command: []const u8, line_bytes: usize) void {
        var key_buf: [MAX_NAME]u8 = undefined;
        const key = normalize(command, &key_buf);
        if (key.len == 0) return;

        const claimed = self.used.load(.acquire);
        // Fast path: bump an existing slot without locking.
        if (self.findIndex(key, claimed)) |idx| {
            _ = self.slots[idx].count.fetchAdd(1, .monotonic);
            _ = self.slots[idx].bytes.fetchAdd(@as(u64, line_bytes), .monotonic);
            return;
        }

        // Slow path: claim a fresh slot under the lock (re-check in case another
        // thread registered the same verb between the load and the lock).
        lockSpin(&self.claim_lock);
        defer self.claim_lock.unlock();
        const now_used = self.used.load(.acquire);
        if (self.findIndex(key, now_used)) |idx| {
            _ = self.slots[idx].count.fetchAdd(1, .monotonic);
            _ = self.slots[idx].bytes.fetchAdd(@as(u64, line_bytes), .monotonic);
            return;
        }
        if (now_used >= MAX_COMMANDS) return; // table full: drop the new verb
        const idx: usize = @intCast(now_used);
        @memcpy(self.slots[idx].name[0..key.len], key);
        self.slots[idx].name_len = key.len;
        self.slots[idx].count.store(1, .monotonic);
        self.slots[idx].bytes.store(@as(u64, line_bytes), .monotonic);
        // Publish the slot's name before bumping `used` so a concurrent reader
        // that observes the new count also sees a fully written name.
        self.used.store(now_used + 1, .release);
    }

    fn findIndex(self: *CommandUsage, key: []const u8, bound: u64) ?usize {
        var i: usize = 0;
        const n: usize = @intCast(bound);
        while (i < n) : (i += 1) {
            if (std.mem.eql(u8, self.slots[i].nameSlice(), key)) return i;
        }
        return null;
    }

    /// One reported command row.
    pub const Row = struct {
        name: []const u8,
        count: u64,
        bytes: u64,
    };

    /// Invoke `cb` once per recorded command (snapshot of current counters).
    pub fn forEach(self: *CommandUsage, ctx: anytype, comptime cb: fn (@TypeOf(ctx), Row) anyerror!void) anyerror!void {
        const n: usize = @intCast(self.used.load(.acquire));
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const slot = &self.slots[i];
            if (slot.name_len == 0) continue;
            try cb(ctx, .{
                .name = slot.nameSlice(),
                .count = slot.count.load(.monotonic),
                .bytes = slot.bytes.load(.monotonic),
            });
        }
    }
};

/// Blocking acquire on the tryLock-only `std.atomic.Mutex` (codebase idiom).
/// Only the rare new-verb registration contends, so spinning is fine.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

/// Uppercase + length-cap `command` into `buf`, returning the stable key. Rejects
/// empty input and any control/space bytes (which can never be a real verb).
fn normalize(command: []const u8, buf: []u8) []const u8 {
    var n: usize = 0;
    for (command) |ch| {
        if (n >= buf.len or n >= MAX_NAME) break;
        if (ch <= ' ' or ch == 0x7f) return buf[0..0];
        buf[n] = std.ascii.toUpper(ch);
        n += 1;
    }
    return buf[0..n];
}

test "records distinct verbs and accumulates counts and bytes" {
    var usage = CommandUsage{};
    usage.record("PRIVMSG", 30);
    usage.record("privmsg", 20); // case-insensitive: same verb
    usage.record("JOIN", 10);

    const Collector = struct {
        privmsg_count: u64 = 0,
        privmsg_bytes: u64 = 0,
        join_count: u64 = 0,
        rows: usize = 0,

        fn cb(self: *@This(), row: CommandUsage.Row) anyerror!void {
            self.rows += 1;
            if (std.mem.eql(u8, row.name, "PRIVMSG")) {
                self.privmsg_count = row.count;
                self.privmsg_bytes = row.bytes;
            } else if (std.mem.eql(u8, row.name, "JOIN")) {
                self.join_count = row.count;
            }
        }
    };
    var collector = Collector{};
    try usage.forEach(&collector, Collector.cb);

    try std.testing.expectEqual(@as(usize, 2), collector.rows);
    try std.testing.expectEqual(@as(u64, 2), collector.privmsg_count);
    try std.testing.expectEqual(@as(u64, 50), collector.privmsg_bytes);
    try std.testing.expectEqual(@as(u64, 1), collector.join_count);
}

test "rejects empty and control-laden verbs" {
    var usage = CommandUsage{};
    usage.record("", 10);
    usage.record("BAD\tVERB", 10);

    const Counter = struct {
        rows: usize = 0,
        fn cb(self: *@This(), _: CommandUsage.Row) anyerror!void {
            self.rows += 1;
        }
    };
    var counter = Counter{};
    try usage.forEach(&counter, Counter.cb);
    try std.testing.expectEqual(@as(usize, 0), counter.rows);
}

test "table saturates without overflow" {
    var usage = CommandUsage{};
    var i: usize = 0;
    var name_buf: [8]u8 = undefined;
    while (i < MAX_COMMANDS + 16) : (i += 1) {
        const name = std.fmt.bufPrint(&name_buf, "C{d}", .{i}) catch unreachable;
        usage.record(name, 1);
    }
    try std.testing.expectEqual(@as(u64, MAX_COMMANDS), usage.used.load(.acquire));
}
