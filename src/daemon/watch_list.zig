//! Per-account watch lists for the Orochi IRC daemon.
//!
//! Each account may register a set of *target* accounts it wishes to be
//! notified about when those targets come online. This module only tracks the
//! membership relation (account -> set of targets); presence/notification
//! delivery is handled elsewhere.
//!
//! Ownership: every account key and every target string stored here is owned
//! by the WatchList and duplicated on insertion. `deinit` frees everything.

const std = @import("std");

/// Maximum number of targets a single account may watch.
pub const max_targets_per_account: usize = 128;

/// A set of owned target strings, keyed by the target name.
const TargetSet = std.StringHashMapUnmanaged(void);

pub const WatchList = struct {
    allocator: std.mem.Allocator,
    /// Owned account key -> owned target set.
    accounts: std.StringHashMapUnmanaged(TargetSet),

    pub fn init(allocator: std.mem.Allocator) WatchList {
        return .{
            .allocator = allocator,
            .accounts = .{},
        };
    }

    /// Free all owned keys, target strings, and backing storage.
    pub fn deinit(self: *WatchList) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.freeTargetSet(entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.accounts.deinit(self.allocator);
        self.* = undefined;
    }

    /// Register `target` under `account`.
    ///
    /// Returns `true` if the target was newly added. Returns `false` if the
    /// target was already present (duplicate) or the account is already at the
    /// per-account cap.
    pub fn watch(self: *WatchList, account: []const u8, target: []const u8) !bool {
        const gop = try self.accounts.getOrPut(self.allocator, account);
        if (!gop.found_existing) {
            // Replace the borrowed key with an owned copy; initialize the set.
            const owned_account = self.allocator.dupe(u8, account) catch |err| {
                self.accounts.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = owned_account;
            gop.value_ptr.* = .{};
        }

        const set = gop.value_ptr;

        if (set.contains(target)) return false;
        if (set.count() >= max_targets_per_account) return false;

        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);
        try set.put(self.allocator, owned_target, {});
        return true;
    }

    /// Remove `target` from `account`. Returns `true` if it was present.
    ///
    /// If this empties the account's set, the account entry is removed too.
    pub fn unwatch(self: *WatchList, account: []const u8, target: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const set = entry.value_ptr;

        if (set.fetchRemove(target)) |removed| {
            self.allocator.free(removed.key);
        } else {
            return false;
        }

        if (set.count() == 0) {
            set.deinit(self.allocator);
            const owned_account = entry.key_ptr.*;
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_account);
        }
        return true;
    }

    /// Whether `account` is currently watching `target`.
    pub fn isWatching(self: *const WatchList, account: []const u8, target: []const u8) bool {
        const set = self.accounts.getPtr(account) orelse return false;
        return set.contains(target);
    }

    /// Return the targets watched by `account` as a freshly allocated slice.
    ///
    /// The returned slice and its underlying array are owned by the caller and
    /// must be freed with `allocator.free`. The individual strings remain owned
    /// by the WatchList and are valid until the corresponding target is
    /// unwatched or the WatchList is deinitialized. Returns an empty slice for
    /// an unknown account.
    pub fn list(self: *const WatchList, allocator: std.mem.Allocator, account: []const u8) ![]const []const u8 {
        const set = self.accounts.getPtr(account) orelse return &.{};

        var out = try allocator.alloc([]const u8, set.count());
        errdefer allocator.free(out);

        var i: usize = 0;
        var it = set.keyIterator();
        while (it.next()) |key_ptr| : (i += 1) {
            out[i] = key_ptr.*;
        }
        return out;
    }

    fn freeTargetSet(self: *WatchList, set: *TargetSet) void {
        var it = set.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        set.deinit(self.allocator);
    }
};

test "watch adds targets, rejects duplicates, and reports membership" {
    const allocator = std.testing.allocator;
    var wl = WatchList.init(allocator);
    defer wl.deinit();

    try std.testing.expect(try wl.watch("alice", "bob"));
    try std.testing.expect(try wl.watch("alice", "carol"));

    // Duplicate target is rejected.
    try std.testing.expect(!try wl.watch("alice", "bob"));

    try std.testing.expect(wl.isWatching("alice", "bob"));
    try std.testing.expect(wl.isWatching("alice", "carol"));
    try std.testing.expect(!wl.isWatching("alice", "dave"));
    try std.testing.expect(!wl.isWatching("nobody", "bob"));
}

test "unwatch removes targets and prunes empty accounts" {
    const allocator = std.testing.allocator;
    var wl = WatchList.init(allocator);
    defer wl.deinit();

    try std.testing.expect(try wl.watch("alice", "bob"));

    // Removing an absent target/account returns false.
    try std.testing.expect(!wl.unwatch("alice", "ghost"));
    try std.testing.expect(!wl.unwatch("missing", "bob"));

    try std.testing.expect(wl.unwatch("alice", "bob"));
    try std.testing.expect(!wl.isWatching("alice", "bob"));

    // The now-empty account should be gone; re-watching still works.
    try std.testing.expect(try wl.watch("alice", "eve"));
    try std.testing.expect(wl.isWatching("alice", "eve"));
}

test "list returns all targets for an account" {
    const allocator = std.testing.allocator;
    var wl = WatchList.init(allocator);
    defer wl.deinit();

    try std.testing.expect(try wl.watch("alice", "bob"));
    try std.testing.expect(try wl.watch("alice", "carol"));
    try std.testing.expect(try wl.watch("alice", "dave"));

    const targets = try wl.list(allocator, "alice");
    defer allocator.free(targets);
    try std.testing.expectEqual(@as(usize, 3), targets.len);

    var saw_bob = false;
    var saw_carol = false;
    var saw_dave = false;
    for (targets) |t| {
        if (std.mem.eql(u8, t, "bob")) saw_bob = true;
        if (std.mem.eql(u8, t, "carol")) saw_carol = true;
        if (std.mem.eql(u8, t, "dave")) saw_dave = true;
    }
    try std.testing.expect(saw_bob and saw_carol and saw_dave);

    // Unknown account yields an empty slice (no allocation to free).
    const empty = try wl.list(allocator, "stranger");
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "watch enforces the per-account target cap" {
    const allocator = std.testing.allocator;
    var wl = WatchList.init(allocator);
    defer wl.deinit();

    var buf: [32]u8 = undefined;
    var n: usize = 0;
    while (n < max_targets_per_account) : (n += 1) {
        const name = try std.fmt.bufPrint(&buf, "t{d}", .{n});
        try std.testing.expect(try wl.watch("alice", name));
    }

    // One past the cap is rejected.
    try std.testing.expect(!try wl.watch("alice", "overflow"));

    const targets = try wl.list(allocator, "alice");
    defer allocator.free(targets);
    try std.testing.expectEqual(max_targets_per_account, targets.len);
}
