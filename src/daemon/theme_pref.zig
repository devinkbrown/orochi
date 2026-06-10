//! theme_pref.zig — Per-account UI theme preference store for the Orochi daemon.
//!
//! Each account may pin a single theme name (a short identifier such as
//! "abyss" or "shoal"). Names are bounded to keep memory predictable across a
//! large account population. The store owns both keys and values: callers may
//! free or reuse their input slices immediately after a call returns.
//!
//! Pure std only. Builds and tests standalone:
//!     zig test src/daemon/theme_pref.zig

const std = @import("std");

/// Maximum byte length of a stored theme name. Names longer than this are
/// rejected so a single account cannot pin an unbounded blob.
pub const max_theme_len: usize = 32;

/// Errors surfaced by `set`.
pub const ThemeError = error{
    /// The theme name was empty or exceeded `max_theme_len`.
    InvalidTheme,
};

/// Owning map from account identifier to chosen theme name.
///
/// Both the account key and the theme value are heap-duplicated on insert and
/// freed on overwrite, removal, or `deinit`.
pub const ThemePref = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap([]u8),

    /// Create an empty preference store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ThemePref {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Free every owned key and value, then the map itself.
    pub fn deinit(self: *ThemePref) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Pin `theme` to `account`, overwriting any existing choice.
    ///
    /// Returns `error.InvalidTheme` if `theme` is empty or longer than
    /// `max_theme_len`. On overwrite the previous theme value is freed; the
    /// existing account key is retained to avoid a needless re-allocation.
    pub fn set(self: *ThemePref, account: []const u8, theme: []const u8) !void {
        if (theme.len == 0 or theme.len > max_theme_len) {
            return ThemeError.InvalidTheme;
        }

        const owned_theme = try self.allocator.dupe(u8, theme);
        errdefer self.allocator.free(owned_theme);

        if (self.entries.getEntry(account)) |existing| {
            // Overwrite: drop the stale value, keep the established key.
            self.allocator.free(existing.value_ptr.*);
            existing.value_ptr.* = owned_theme;
            return;
        }

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);

        try self.entries.put(owned_account, owned_theme);
    }

    /// Return the theme pinned to `account`, or null if none is set.
    ///
    /// The returned slice is owned by the store and stays valid until the next
    /// mutating call touching this account (`set`/`clear`) or `deinit`.
    pub fn get(self: *const ThemePref, account: []const u8) ?[]const u8 {
        if (self.entries.get(account)) |theme| {
            return theme;
        }
        return null;
    }

    /// Remove `account`'s preference, freeing its key and value.
    ///
    /// Returns true if an entry was removed, false if none existed.
    pub fn clear(self: *ThemePref, account: []const u8) bool {
        if (self.entries.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }
};

test "set then get returns the pinned theme" {
    var prefs = ThemePref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("nizuka", "abyss");

    const got = prefs.get("nizuka") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("abyss", got);
    try std.testing.expect(prefs.get("unknown") == null);
}

test "set overwrites without leaking the prior value" {
    var prefs = ThemePref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("kaito", "shoal");
    try prefs.set("kaito", "current");

    try std.testing.expectEqualStrings("current", prefs.get("kaito").?);
    // Only one account is tracked despite two writes.
    try std.testing.expectEqual(@as(u32, 1), prefs.entries.count());
}

test "set rejects empty and oversize theme names" {
    var prefs = ThemePref.init(std.testing.allocator);
    defer prefs.deinit();

    try std.testing.expectError(ThemeError.InvalidTheme, prefs.set("ren", ""));

    const too_long = "x" ** (max_theme_len + 1);
    try std.testing.expectError(ThemeError.InvalidTheme, prefs.set("ren", too_long));

    // A name at exactly the limit is accepted.
    const at_limit = "y" ** max_theme_len;
    try prefs.set("ren", at_limit);
    try std.testing.expectEqualStrings(at_limit, prefs.get("ren").?);

    // Rejected writes left no entry behind for an otherwise-empty account.
    try std.testing.expect(prefs.get("nobody") == null);
}

test "clear removes an entry and reports presence" {
    var prefs = ThemePref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("suzuki", "tide");
    try std.testing.expect(prefs.clear("suzuki"));
    try std.testing.expect(prefs.get("suzuki") == null);
    // Clearing a missing account is a no-op returning false.
    try std.testing.expect(!prefs.clear("suzuki"));
}

comptime {
    // 64-bit target assumption for the daemon build.
    std.debug.assert(@bitSizeOf(usize) == 64);
}
