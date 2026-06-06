//! Snooze: per-account "do-not-disturb until" tracking.
//!
//! Each account maps to a 64-bit Unix-millisecond timestamp. An account is
//! considered snoozed while the current time is strictly before that deadline.
//! Account keys are owned (duplicated) by the table; values are stored inline.

const std = @import("std");

/// Tracks a "do-not-disturb until" deadline per account name.
pub const Snooze = struct {
    allocator: std.mem.Allocator,
    deadlines: std.StringHashMap(i64),

    /// Create an empty Snooze table backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) Snooze {
        return .{
            .allocator = allocator,
            .deadlines = std.StringHashMap(i64).init(allocator),
        };
    }

    /// Release every owned key and the backing table.
    pub fn deinit(self: *Snooze) void {
        var it = self.deadlines.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.deadlines.deinit();
        self.* = undefined;
    }

    /// Set (or replace) the snooze deadline for `account` to `until_ms`.
    /// Re-uses the existing owned key when the account already exists.
    pub fn set(self: *Snooze, account: []const u8, until_ms: i64) !void {
        const gop = try self.deadlines.getOrPut(account);
        if (gop.found_existing) {
            gop.value_ptr.* = until_ms;
            return;
        }
        // New entry: duplicate the key so the table owns it. On failure we must
        // remove the half-inserted slot to avoid a dangling key pointer.
        const owned = self.allocator.dupe(u8, account) catch |err| {
            _ = self.deadlines.remove(account);
            return err;
        };
        gop.key_ptr.* = owned;
        gop.value_ptr.* = until_ms;
    }

    /// True when `account` has a deadline and `now_ms` is strictly before it.
    pub fn snoozed(self: *const Snooze, account: []const u8, now_ms: i64) bool {
        const deadline = self.deadlines.get(account) orelse return false;
        return now_ms < deadline;
    }

    /// Return the stored deadline for `account`, or null if none is set.
    pub fn until(self: *const Snooze, account: []const u8) ?i64 {
        return self.deadlines.get(account);
    }

    /// Remove any snooze for `account`. Returns true if an entry was removed.
    pub fn clear(self: *Snooze, account: []const u8) bool {
        if (self.deadlines.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }
};

test "set then snoozed true before deadline and false after" {
    var snooze = Snooze.init(std.testing.allocator);
    defer snooze.deinit();

    try snooze.set("alice", 10_000);

    try std.testing.expect(snooze.snoozed("alice", 5_000));
    try std.testing.expect(!snooze.snoozed("alice", 10_000)); // strict: now == until
    try std.testing.expect(!snooze.snoozed("alice", 15_000));

    // Unknown account is never snoozed.
    try std.testing.expect(!snooze.snoozed("nobody", 0));
}

test "until getter reflects set and replacement" {
    var snooze = Snooze.init(std.testing.allocator);
    defer snooze.deinit();

    try std.testing.expectEqual(@as(?i64, null), snooze.until("bob"));

    try snooze.set("bob", 42);
    try std.testing.expectEqual(@as(?i64, 42), snooze.until("bob"));

    // Replacing keeps a single owned key and updates the value.
    try snooze.set("bob", 9_000_000_000_000);
    try std.testing.expectEqual(@as(?i64, 9_000_000_000_000), snooze.until("bob"));
    try std.testing.expectEqual(@as(usize, 1), snooze.deadlines.count());
}

test "clear removes entry and reports presence" {
    var snooze = Snooze.init(std.testing.allocator);
    defer snooze.deinit();

    try snooze.set("carol", 1_000);
    try std.testing.expect(snooze.clear("carol"));
    try std.testing.expect(!snooze.clear("carol")); // already gone
    try std.testing.expectEqual(@as(?i64, null), snooze.until("carol"));
    try std.testing.expect(!snooze.snoozed("carol", 0));
}
