//! Per-account accessibility preferences for the Mizuchi IRC daemon.
//!
//! Stores a small set of per-account accessibility toggles. Unset accounts
//! resolve to an all-false default, so callers can query freely without first
//! checking for membership.
//!
//! Clean-room: this module depends on `std` only and shares no code or naming
//! with any prior server implementation.

const std = @import("std");

/// Compact set of per-account accessibility toggles.
///
/// Backed by a single 64-bit word so it copies cheaply by value and never
/// requires heap allocation of its own. All toggles default to `false`.
pub const A11y = packed struct(u64) {
    /// Prefer reduced/eliminated motion in client-rendered UI.
    reduce_motion: bool = false,
    /// Prefer a high-contrast presentation.
    high_contrast: bool = false,
    /// Emit extra hints intended for screen readers.
    screen_reader_hints: bool = false,
    /// Prefer enlarged text rendering.
    large_text: bool = false,
    /// Enable captions by default where applicable.
    captions_default_on: bool = false,
    /// Reserved padding to fill the 64-bit backing word.
    _reserved: u59 = 0,

    /// The all-false default used for accounts with no stored preferences.
    pub const default: A11y = .{};
};

/// Owns a map of account name -> `A11y` preferences.
///
/// Account-name keys are duplicated and owned by this structure; callers retain
/// ownership of the strings they pass in.
pub const AccessibilityPref = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(A11y),

    /// Create an empty preference store.
    pub fn init(allocator: std.mem.Allocator) AccessibilityPref {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(A11y).init(allocator),
        };
    }

    /// Release all owned keys and the backing map.
    pub fn deinit(self: *AccessibilityPref) void {
        var it = self.map.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.map.deinit();
        self.* = undefined;
    }

    /// Store (or replace) the preferences for `account`.
    ///
    /// The first time an account is seen its name is duplicated and owned by the
    /// store; subsequent sets reuse the existing key and only overwrite the value.
    pub fn set(self: *AccessibilityPref, account: []const u8, prefs: A11y) !void {
        const gop = try self.map.getOrPut(account);
        if (!gop.found_existing) {
            const owned = self.allocator.dupe(u8, account) catch |err| {
                // Roll back the reserved slot so the map stays consistent.
                self.map.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = owned;
        }
        gop.value_ptr.* = prefs;
    }

    /// Return the preferences for `account`, or the all-false default if unset.
    pub fn get(self: *const AccessibilityPref, account: []const u8) A11y {
        return self.map.get(account) orelse A11y.default;
    }

    /// Remove any stored preferences for `account`.
    ///
    /// Returns `true` if an entry existed and was removed, `false` otherwise.
    pub fn clear(self: *AccessibilityPref, account: []const u8) bool {
        if (self.map.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }
};

test "get returns all-false default for unknown account" {
    var prefs = AccessibilityPref.init(std.testing.allocator);
    defer prefs.deinit();

    const got = prefs.get("ghost");
    try std.testing.expectEqual(A11y.default, got);
    try std.testing.expectEqual(false, got.reduce_motion);
    try std.testing.expectEqual(false, got.high_contrast);
    try std.testing.expectEqual(false, got.screen_reader_hints);
    try std.testing.expectEqual(false, got.large_text);
    try std.testing.expectEqual(false, got.captions_default_on);
}

test "set then get round-trips toggles and overwrites" {
    var prefs = AccessibilityPref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("alice", .{ .reduce_motion = true, .large_text = true });
    var got = prefs.get("alice");
    try std.testing.expectEqual(true, got.reduce_motion);
    try std.testing.expectEqual(true, got.large_text);
    try std.testing.expectEqual(false, got.high_contrast);

    // Overwriting reuses the existing key and replaces the value wholesale.
    try prefs.set("alice", .{ .high_contrast = true });
    got = prefs.get("alice");
    try std.testing.expectEqual(false, got.reduce_motion);
    try std.testing.expectEqual(false, got.large_text);
    try std.testing.expectEqual(true, got.high_contrast);
}

test "clear removes existing entry and reports prior presence" {
    var prefs = AccessibilityPref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("bob", .{ .captions_default_on = true });
    try std.testing.expectEqual(true, prefs.get("bob").captions_default_on);

    try std.testing.expectEqual(true, prefs.clear("bob"));
    try std.testing.expectEqual(false, prefs.clear("bob"));
    // After clearing, the account resolves to the default again.
    try std.testing.expectEqual(A11y.default, prefs.get("bob"));
}

test "A11y is a 64-bit packed struct" {
    try std.testing.expectEqual(@as(usize, 64), @bitSizeOf(A11y));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(A11y));
}

test "keys are owned independently of caller buffers" {
    var prefs = AccessibilityPref.init(std.testing.allocator);
    defer prefs.deinit();

    var buf: [8]u8 = undefined;
    @memcpy(buf[0..5], "carol");
    try prefs.set(buf[0..5], .{ .screen_reader_hints = true });

    // Mutate the caller buffer; stored key must remain valid and findable.
    @memcpy(buf[0..5], "xxxxx");
    try std.testing.expectEqual(true, prefs.get("carol").screen_reader_hints);
}
