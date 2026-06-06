//! Per-account history opt-out registry.
//!
//! `HistoryOptOut` is a privacy control: when an account is present in the
//! registry, the daemon must not retain that account's messages in channel
//! history buffers. Presence in the set means "opted out"; absence means
//! the default (history retained).
//!
//! Account names are stored as owned copies so callers do not need to keep
//! their input strings alive. The map value is `void` since the key's mere
//! presence carries all the meaning.

const std = @import("std");

/// Registry of accounts that have opted out of channel history retention.
pub const HistoryOptOut = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(void),

    /// Create an empty registry. No allocations occur until the first opt-out.
    pub fn init(allocator: std.mem.Allocator) HistoryOptOut {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(void).init(allocator),
        };
    }

    /// Release all owned account keys and the backing map storage.
    pub fn deinit(self: *HistoryOptOut) void {
        var it = self.accounts.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    /// Mark `account` as opted out of history retention.
    ///
    /// Idempotent: opting out an already-opted-out account is a no-op and does
    /// not allocate a second copy of the key.
    pub fn optOut(self: *HistoryOptOut, account: []const u8) !void {
        if (self.accounts.contains(account)) return;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);

        try self.accounts.put(owned, {});
    }

    /// Remove `account` from the opt-out set, re-enabling history retention.
    ///
    /// Returns `true` if the account was present and has been removed, `false`
    /// if it was not opted out to begin with.
    pub fn optIn(self: *HistoryOptOut, account: []const u8) bool {
        if (self.accounts.fetchRemove(account)) |entry| {
            self.allocator.free(entry.key);
            return true;
        }
        return false;
    }

    /// Report whether `account` has opted out of history retention.
    pub fn isOptedOut(self: *const HistoryOptOut, account: []const u8) bool {
        return self.accounts.contains(account);
    }

    /// Number of accounts currently opted out.
    pub fn count(self: *const HistoryOptOut) usize {
        return self.accounts.count();
    }
};

test "optOut then isOptedOut and count" {
    var registry = HistoryOptOut.init(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expect(!registry.isOptedOut("alice"));
    try std.testing.expectEqual(@as(usize, 0), registry.count());

    try registry.optOut("alice");
    try registry.optOut("bob");

    try std.testing.expect(registry.isOptedOut("alice"));
    try std.testing.expect(registry.isOptedOut("bob"));
    try std.testing.expect(!registry.isOptedOut("carol"));
    try std.testing.expectEqual(@as(usize, 2), registry.count());
}

test "optOut is idempotent and does not double-count" {
    var registry = HistoryOptOut.init(std.testing.allocator);
    defer registry.deinit();

    try registry.optOut("dave");
    try registry.optOut("dave");
    try registry.optOut("dave");

    try std.testing.expect(registry.isOptedOut("dave"));
    try std.testing.expectEqual(@as(usize, 1), registry.count());
}

test "optIn removes account and reports prior membership" {
    var registry = HistoryOptOut.init(std.testing.allocator);
    defer registry.deinit();

    try registry.optOut("erin");
    try std.testing.expectEqual(@as(usize, 1), registry.count());

    // Removing a present account returns true.
    try std.testing.expect(registry.optIn("erin"));
    try std.testing.expect(!registry.isOptedOut("erin"));
    try std.testing.expectEqual(@as(usize, 0), registry.count());

    // Removing an absent account returns false.
    try std.testing.expect(!registry.optIn("erin"));
    try std.testing.expect(!registry.optIn("frank"));
}

test "keys are owned copies independent of caller buffer" {
    var registry = HistoryOptOut.init(std.testing.allocator);
    defer registry.deinit();

    var buf: [8]u8 = undefined;
    @memcpy(buf[0..5], "gwen\x00"[0..5]);
    try registry.optOut(buf[0..4]);

    // Mutate the caller's buffer; the registry must still match the original.
    @memcpy(buf[0..4], "ZZZZ");
    try std.testing.expect(registry.isOptedOut("gwen"));
    try std.testing.expect(!registry.isOptedOut("ZZZZ"));
}
