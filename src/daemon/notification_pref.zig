//! Per-account notification preference storage for the Mizuchi daemon.
//!
//! Each account maps to a small set of notification flags. Flags are packed
//! into a single byte so the table stays compact even with many accounts.
//! Pure standard library; no external dependencies.

const std = @import("std");

/// Notification flag set for a single account.
///
/// Packed into one byte. Each field toggles delivery of one notification
/// category. The padding bits are reserved for future categories.
pub const Flags = packed struct {
    /// Notify when the account's nick is mentioned.
    mentions: bool = false,
    /// Notify on direct (private) messages.
    dms: bool = false,
    /// Notify on activity in joined channels.
    channels: bool = false,
    /// Notify on incoming call invitations.
    calls: bool = false,
    /// Play an audible cue alongside notifications.
    sounds: bool = false,
    /// Reserved padding so the struct occupies exactly one byte.
    _reserved: u3 = 0,

    /// Sensible out-of-the-box defaults: mentions, DMs, and calls on.
    pub const default: Flags = .{
        .mentions = true,
        .dms = true,
        .channels = false,
        .calls = true,
        .sounds = false,
    };

    comptime {
        // Lock the on-wire/in-memory size at one byte (64-bit target safe).
        std.debug.assert(@bitSizeOf(Flags) == 8);
    }
};

/// Owns the account -> Flags mapping. Keys are heap-duplicated and freed on
/// removal and on deinit; values are stored inline.
pub const NotificationPref = struct {
    allocator: std.mem.Allocator,
    table: std.StringHashMap(Flags),

    /// Create an empty preference store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) NotificationPref {
        return .{
            .allocator = allocator,
            .table = std.StringHashMap(Flags).init(allocator),
        };
    }

    /// Release every owned key and the backing table.
    pub fn deinit(self: *NotificationPref) void {
        var it = self.table.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.table.deinit();
        self.* = undefined;
    }

    /// Store `flags` for `account`. Overwrites any existing entry without
    /// leaking the previously owned key.
    pub fn set(self: *NotificationPref, account: []const u8, flags: Flags) !void {
        const gop = try self.table.getOrPut(account);
        if (!gop.found_existing) {
            // New entry: own a private copy of the key. On failure, roll back
            // the partial insertion so the table stays consistent.
            const key_copy = self.allocator.dupe(u8, account) catch |err| {
                _ = self.table.remove(account);
                return err;
            };
            gop.key_ptr.* = key_copy;
        }
        gop.value_ptr.* = flags;
    }

    /// Return the flags for `account`, or `Flags.default` when unset.
    pub fn get(self: *const NotificationPref, account: []const u8) Flags {
        return self.table.get(account) orelse Flags.default;
    }

    /// Remove `account`'s entry, freeing its owned key. Returns true if an
    /// entry was present and removed.
    pub fn clear(self: *NotificationPref, account: []const u8) bool {
        if (self.table.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }
};

test "set then get returns stored flags" {
    var prefs = NotificationPref.init(std.testing.allocator);
    defer prefs.deinit();

    const custom: Flags = .{
        .mentions = false,
        .dms = true,
        .channels = true,
        .calls = false,
        .sounds = true,
    };

    try prefs.set("aria", custom);
    const got = prefs.get("aria");

    try std.testing.expectEqual(custom.mentions, got.mentions);
    try std.testing.expectEqual(custom.dms, got.dms);
    try std.testing.expectEqual(custom.channels, got.channels);
    try std.testing.expectEqual(custom.calls, got.calls);
    try std.testing.expectEqual(custom.sounds, got.sounds);
}

test "get returns default when account is unset" {
    var prefs = NotificationPref.init(std.testing.allocator);
    defer prefs.deinit();

    const got = prefs.get("nobody");
    try std.testing.expectEqual(Flags.default, got);
    try std.testing.expect(got.mentions);
    try std.testing.expect(got.dms);
    try std.testing.expect(got.calls);
    try std.testing.expect(!got.channels);
    try std.testing.expect(!got.sounds);
}

test "clear removes entry and reports presence" {
    var prefs = NotificationPref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("kobo", Flags.default);
    try std.testing.expect(prefs.clear("kobo"));
    // After clearing, the account falls back to defaults again.
    try std.testing.expectEqual(Flags.default, prefs.get("kobo"));
    // Clearing a missing account reports false.
    try std.testing.expect(!prefs.clear("kobo"));
    try std.testing.expect(!prefs.clear("ghost"));
}

test "set overwrites existing entry without leaking key" {
    var prefs = NotificationPref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("mizu", Flags.default);
    const replacement: Flags = .{ .mentions = false, .dms = false, .channels = true };
    try prefs.set("mizu", replacement);

    const got = prefs.get("mizu");
    try std.testing.expect(!got.mentions);
    try std.testing.expect(got.channels);
    try std.testing.expectEqual(@as(u32, 1), prefs.table.count());
}
