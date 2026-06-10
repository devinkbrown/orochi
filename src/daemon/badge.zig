//! Per-account badge-label registry for the Orochi IRC daemon.
//!
//! A `Badge` maps an account name to a small, bounded set of badge labels.
//! Both account names and badge labels are owned (heap-duplicated) by the
//! registry, so callers may pass transient slices freely. Everything is
//! released on `deinit`.

const std = @import("std");

/// Maximum number of distinct badges retained per account.
pub const max_badges_per_account: usize = 32;

/// Maximum byte length of a single badge label.
pub const max_badge_len: usize = 32;

/// Per-account badge-label set.
pub const Badge = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMapUnmanaged(BadgeSet) = .empty,

    /// A bounded, owned set of badge labels for one account.
    const BadgeSet = struct {
        labels: std.ArrayListUnmanaged([]u8) = .empty,

        fn deinit(self: *BadgeSet, allocator: std.mem.Allocator) void {
            for (self.labels.items) |label| allocator.free(label);
            self.labels.deinit(allocator);
        }

        fn indexOf(self: *const BadgeSet, badge: []const u8) ?usize {
            for (self.labels.items, 0..) |label, i| {
                if (std.mem.eql(u8, label, badge)) return i;
            }
            return null;
        }
    };

    pub fn init(allocator: std.mem.Allocator) Badge {
        return .{ .allocator = allocator };
    }

    /// Frees every owned account name and badge label. No leaks.
    pub fn deinit(self: *Badge) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit(self.allocator);
        self.* = undefined;
    }

    /// Grants `badge` to `account`. Returns `true` if newly added, `false` if
    /// the badge was already present or the per-account cap is reached.
    /// Returns an error only on allocation failure or an out-of-range badge.
    pub fn grant(self: *Badge, account: []const u8, badge: []const u8) !bool {
        if (badge.len == 0 or badge.len > max_badge_len) return error.InvalidBadge;

        const gop = try self.accounts.getOrPut(self.allocator, account);
        if (!gop.found_existing) {
            // Own the account key; roll back the slot if anything below fails.
            const owned_key = self.allocator.dupe(u8, account) catch |err| {
                self.accounts.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = .{ .labels = .empty };
        }

        const set = gop.value_ptr;
        if (set.indexOf(badge) != null) return false;
        if (set.labels.items.len >= max_badges_per_account) return false;

        const owned_badge = try self.allocator.dupe(u8, badge);
        errdefer self.allocator.free(owned_badge);
        try set.labels.append(self.allocator, owned_badge);
        return true;
    }

    /// Revokes `badge` from `account`. Returns `true` if it was present.
    pub fn revoke(self: *Badge, account: []const u8, badge: []const u8) bool {
        const set = self.accounts.getPtr(account) orelse return false;
        const idx = set.indexOf(badge) orelse return false;
        const removed = set.labels.swapRemove(idx);
        self.allocator.free(removed);
        return true;
    }

    /// Reports whether `account` holds `badge`.
    pub fn has(self: *Badge, account: []const u8, badge: []const u8) bool {
        const set = self.accounts.getPtr(account) orelse return false;
        return set.indexOf(badge) != null;
    }

    /// Returns the badges held by `account`. The returned slice and its items
    /// are owned by the registry and remain valid until the next mutation of
    /// this account or `deinit`. An unknown account yields an empty slice.
    pub fn list(self: *Badge, account: []const u8) []const []const u8 {
        const set = self.accounts.getPtr(account) orelse return &.{};
        return set.labels.items;
    }
};

test "grant, has, and revoke roundtrip" {
    const allocator = std.testing.allocator;
    var reg = Badge.init(allocator);
    defer reg.deinit();

    try std.testing.expect(!reg.has("alice", "founder"));

    try std.testing.expect(try reg.grant("alice", "founder"));
    try std.testing.expect(reg.has("alice", "founder"));
    try std.testing.expectEqual(@as(usize, 1), reg.list("alice").len);

    try std.testing.expect(reg.revoke("alice", "founder"));
    try std.testing.expect(!reg.has("alice", "founder"));
    try std.testing.expect(!reg.revoke("alice", "founder"));
    try std.testing.expectEqual(@as(usize, 0), reg.list("alice").len);
}

test "dedup and per-account cap" {
    const allocator = std.testing.allocator;
    var reg = Badge.init(allocator);
    defer reg.deinit();

    // Duplicate grant is a no-op returning false.
    try std.testing.expect(try reg.grant("bob", "verified"));
    try std.testing.expect(!try reg.grant("bob", "verified"));
    try std.testing.expectEqual(@as(usize, 1), reg.list("bob").len);

    // Fill to the cap with distinct labels.
    var buf: [max_badge_len]u8 = undefined;
    while (reg.list("bob").len < max_badges_per_account) {
        const n = reg.list("bob").len;
        const label = try std.fmt.bufPrint(&buf, "b{d}", .{n});
        try std.testing.expect(try reg.grant("bob", label));
    }
    try std.testing.expectEqual(max_badges_per_account, reg.list("bob").len);

    // Over the cap: a fresh distinct badge is rejected without error.
    try std.testing.expect(!try reg.grant("bob", "overflow"));
    try std.testing.expectEqual(max_badges_per_account, reg.list("bob").len);

    // Invalid badge lengths are rejected.
    try std.testing.expectError(error.InvalidBadge, reg.grant("bob", ""));
    const too_long = "x" ** (max_badge_len + 1);
    try std.testing.expectError(error.InvalidBadge, reg.grant("bob", too_long));
}

test "per-account independence" {
    const allocator = std.testing.allocator;
    var reg = Badge.init(allocator);
    defer reg.deinit();

    try std.testing.expect(try reg.grant("carol", "staff"));
    try std.testing.expect(try reg.grant("dave", "guest"));

    try std.testing.expect(reg.has("carol", "staff"));
    try std.testing.expect(!reg.has("carol", "guest"));
    try std.testing.expect(reg.has("dave", "guest"));
    try std.testing.expect(!reg.has("dave", "staff"));

    // Revoking from one account leaves the other untouched.
    try std.testing.expect(reg.revoke("carol", "staff"));
    try std.testing.expect(!reg.has("carol", "staff"));
    try std.testing.expect(reg.has("dave", "guest"));

    // Unknown account yields an empty list and false predicates.
    try std.testing.expectEqual(@as(usize, 0), reg.list("nobody").len);
    try std.testing.expect(!reg.has("nobody", "anything"));
    try std.testing.expect(!reg.revoke("nobody", "anything"));
}
