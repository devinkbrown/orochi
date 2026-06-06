//! Per-account locale preferences for the Mizuchi IRC daemon.
//!
//! Stores a short locale string (for example "en-US") for each account name.
//! Both the account key and the locale value are owned heap copies, so callers
//! may pass transient slices without worrying about lifetimes.

const std = @import("std");

/// Maximum byte length of a locale string ("en-US", "pt-BR", ...).
const max_locale_len: usize = 16;

/// Error returned when a supplied locale is empty or exceeds the size limit.
pub const LocaleError = error{InvalidLocale};

/// Maps owned account names to owned locale strings.
pub const LanguagePref = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap([]u8),

    /// Create an empty preference table backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) LanguagePref {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Free every owned key and value plus the backing map.
    pub fn deinit(self: *LanguagePref) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
        self.* = undefined;
    }

    /// Assign `locale` to `account`, overwriting any prior value.
    ///
    /// Returns `error.InvalidLocale` when `locale` is empty or longer than
    /// `max_locale_len` bytes. On overwrite the previous locale is freed and
    /// the existing account key is reused. On allocation failure the table is
    /// left unchanged.
    pub fn set(self: *LanguagePref, account: []const u8, locale: []const u8) (LocaleError || std.mem.Allocator.Error)!void {
        if (locale.len == 0 or locale.len > max_locale_len) {
            return LocaleError.InvalidLocale;
        }

        const locale_copy = try self.allocator.dupe(u8, locale);
        errdefer self.allocator.free(locale_copy);

        if (self.map.getEntry(account)) |entry| {
            // Account already present: swap in the new value, free the old one.
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = locale_copy;
            return;
        }

        const account_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(account_copy);

        try self.map.put(account_copy, locale_copy);
    }

    /// Return the stored locale for `account`, or null if none is set.
    /// The returned slice is owned by the table and stays valid until the
    /// entry is overwritten, cleared, or the table is deinitialized.
    pub fn get(self: *const LanguagePref, account: []const u8) ?[]const u8 {
        if (self.map.get(account)) |locale| {
            return locale;
        }
        return null;
    }

    /// Remove `account`'s preference, freeing its key and value.
    /// Returns true if an entry was removed, false if none existed.
    pub fn clear(self: *LanguagePref, account: []const u8) bool {
        if (self.map.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }
};

test "set then get round-trips a locale" {
    const allocator = std.testing.allocator;
    var prefs = LanguagePref.init(allocator);
    defer prefs.deinit();

    try prefs.set("alice", "en-US");

    const got = prefs.get("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("en-US", got);
    try std.testing.expect(prefs.get("bob") == null);
}

test "set overwrites and frees the previous locale" {
    const allocator = std.testing.allocator;
    var prefs = LanguagePref.init(allocator);
    defer prefs.deinit();

    try prefs.set("carol", "en-US");
    try prefs.set("carol", "pt-BR");

    const got = prefs.get("carol") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("pt-BR", got);
    try std.testing.expectEqual(@as(usize, 1), prefs.map.count());
}

test "set rejects empty and oversize locales" {
    const allocator = std.testing.allocator;
    var prefs = LanguagePref.init(allocator);
    defer prefs.deinit();

    try std.testing.expectError(LocaleError.InvalidLocale, prefs.set("dave", ""));

    const too_long = "x" ** (max_locale_len + 1);
    try std.testing.expectError(LocaleError.InvalidLocale, prefs.set("dave", too_long));

    // A locale exactly at the limit is accepted.
    const at_limit = "y" ** max_locale_len;
    try prefs.set("dave", at_limit);
    try std.testing.expectEqualStrings(at_limit, prefs.get("dave").?);
}

test "clear removes an entry and reports presence" {
    const allocator = std.testing.allocator;
    var prefs = LanguagePref.init(allocator);
    defer prefs.deinit();

    try prefs.set("erin", "fr-FR");

    try std.testing.expect(prefs.clear("erin"));
    try std.testing.expect(prefs.get("erin") == null);
    try std.testing.expect(!prefs.clear("erin"));
}

test "64-bit target assumption holds" {
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(usize));
}
