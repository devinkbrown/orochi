//! privacy_pref.zig — Per-account privacy preference store for the Orochi daemon.
//!
//! Each account may opt in or out of a small set of privacy-affecting behaviors.
//! Preferences are kept in memory keyed by account name. Accounts that have never
//! set a preference report the documented defaults.
//!
//! Clean-room implementation: depends only on the Zig standard library.

const std = @import("std");

/// Per-account privacy toggles.
///
/// Packed into a single byte so a whole preference set is one cheap value to
/// copy, store, or compare. Defaults are chosen to be friendly-but-private:
/// the account is reachable and visible by default, but read receipts stay off.
pub const Toggles = packed struct {
    /// Accept direct messages from accounts the user shares no channel/contact with.
    allow_dms_from_strangers: bool = true,
    /// Expose presence (online/away/idle) to other users.
    show_online_status: bool = true,
    /// Permit other users to send channel invites to this account.
    allow_invites: bool = true,
    /// Report message read receipts back to senders.
    show_read_receipts: bool = false,
    /// Appear in user search / discovery listings.
    discoverable: bool = true,
    /// Reserved padding so the struct occupies a stable, addressable byte.
    _reserved: u3 = 0,
};

comptime {
    // Guard the on-the-wire/in-memory size and a 64-bit target assumption.
    std.debug.assert(@bitSizeOf(Toggles) == 8);
    std.debug.assert(@bitSizeOf(usize) == 64);
}

/// In-memory privacy preference store. Owns the account-name keys it stores.
pub const PrivacyPref = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(Toggles),

    /// The defaults returned for any account without an explicit entry.
    pub const default_toggles: Toggles = .{};

    pub fn init(allocator: std.mem.Allocator) PrivacyPref {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Toggles).init(allocator),
        };
    }

    /// Releases all owned key memory and the backing map.
    pub fn deinit(self: *PrivacyPref) void {
        var it = self.entries.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Sets (or replaces) the toggles for `account`.
    ///
    /// The key is duplicated and owned by the store. Replacing an existing entry
    /// keeps the original key allocation and only updates the value, so no churn
    /// occurs on repeated updates of the same account.
    pub fn set(self: *PrivacyPref, account: []const u8, toggles: Toggles) !void {
        const gop = try self.entries.getOrPut(account);
        if (gop.found_existing) {
            gop.value_ptr.* = toggles;
            return;
        }
        // New entry: own a stable copy of the key. On failure, undo the slot so
        // the map never holds a dangling/borrowed key.
        const owned_key = self.allocator.dupe(u8, account) catch |err| {
            _ = self.entries.remove(account);
            return err;
        };
        gop.key_ptr.* = owned_key;
        gop.value_ptr.* = toggles;
    }

    /// Returns the toggles for `account`, or the defaults if none were set.
    pub fn get(self: *const PrivacyPref, account: []const u8) Toggles {
        return self.entries.get(account) orelse default_toggles;
    }

    /// Removes any explicit entry for `account`.
    ///
    /// Returns true if an entry existed and was removed, false otherwise.
    pub fn clear(self: *PrivacyPref, account: []const u8) bool {
        if (self.entries.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }
};

test "unset accounts report defaults" {
    var store = PrivacyPref.init(std.testing.allocator);
    defer store.deinit();

    const t = store.get("nobody");
    try std.testing.expectEqual(true, t.allow_dms_from_strangers);
    try std.testing.expectEqual(true, t.show_online_status);
    try std.testing.expectEqual(true, t.allow_invites);
    try std.testing.expectEqual(false, t.show_read_receipts);
    try std.testing.expectEqual(true, t.discoverable);
}

test "set then get round-trips and replaces in place" {
    var store = PrivacyPref.init(std.testing.allocator);
    defer store.deinit();

    try store.set("kappa", .{
        .allow_dms_from_strangers = false,
        .show_online_status = false,
        .allow_invites = false,
        .show_read_receipts = true,
        .discoverable = false,
    });

    var got = store.get("kappa");
    try std.testing.expectEqual(false, got.allow_dms_from_strangers);
    try std.testing.expectEqual(true, got.show_read_receipts);
    try std.testing.expectEqual(false, got.discoverable);

    // Re-setting the same account replaces the value without leaking the key.
    try store.set("kappa", .{ .discoverable = true });
    got = store.get("kappa");
    try std.testing.expectEqual(true, got.discoverable);
    try std.testing.expectEqual(true, got.allow_dms_from_strangers); // back to default

    try std.testing.expectEqual(@as(usize, 1), store.entries.count());
}

test "clear removes entries and reports presence" {
    var store = PrivacyPref.init(std.testing.allocator);
    defer store.deinit();

    try store.set("suijin", .{ .show_read_receipts = true });
    try std.testing.expectEqual(true, store.clear("suijin"));
    try std.testing.expectEqual(false, store.clear("suijin"));

    // After clearing, the account falls back to defaults.
    try std.testing.expectEqual(false, store.get("suijin").show_read_receipts);
    try std.testing.expectEqual(@as(usize, 0), store.entries.count());
}

test "many distinct accounts coexist without leaks" {
    var store = PrivacyPref.init(std.testing.allocator);
    defer store.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const name = try std.fmt.bufPrint(&buf, "acct-{d}", .{i});
        try store.set(name, .{ .discoverable = (i % 2 == 0) });
    }
    try std.testing.expectEqual(@as(usize, 64), store.entries.count());

    const seven = try std.fmt.bufPrint(&buf, "acct-{d}", .{7});
    try std.testing.expectEqual(false, store.get(seven).discoverable);
    const eight = try std.fmt.bufPrint(&buf, "acct-{d}", .{8});
    try std.testing.expectEqual(true, store.get(eight).discoverable);
}
