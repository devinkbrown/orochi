//! Per-account font preference store for the Orochi IRC daemon.
//!
//! Tracks a display font family name and point size for each account. Both the
//! map keys (account names) and the family strings are heap-owned, so callers
//! may pass transient slices safely. Standalone module: imports only `std`.

const std = @import("std");

/// Hard limits on stored font preferences.
const MAX_FAMILY_LEN: usize = 48;
const MIN_SIZE_PT: u8 = 6;
const MAX_SIZE_PT: u8 = 72;

/// A resolved font preference. `family` is owned by the enclosing `FontPref`.
pub const Entry = struct {
    family: []const u8,
    size_pt: u8,
};

/// Errors surfaced by `set`.
pub const FontError = error{
    /// Family was empty or exceeded `MAX_FAMILY_LEN`.
    InvalidFont,
} || std.mem.Allocator.Error;

/// Account-keyed font preference table.
pub const FontPref = struct {
    allocator: std.mem.Allocator,
    table: std.StringHashMap(Entry),

    pub fn init(allocator: std.mem.Allocator) FontPref {
        return .{
            .allocator = allocator,
            .table = std.StringHashMap(Entry).init(allocator),
        };
    }

    /// Release every owned key and family slice, then the table itself.
    pub fn deinit(self: *FontPref) void {
        var it = self.table.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            self.allocator.free(kv.value_ptr.family);
        }
        self.table.deinit();
        self.* = undefined;
    }

    /// Store (or overwrite) the preference for `account`.
    ///
    /// `family` must be non-empty and at most `MAX_FAMILY_LEN` bytes, otherwise
    /// `error.InvalidFont` is returned. `size_pt` is clamped to
    /// `MIN_SIZE_PT..MAX_SIZE_PT` inclusive. On overwrite, the previous family
    /// allocation is freed and the existing key is reused.
    pub fn set(self: *FontPref, account: []const u8, family: []const u8, size_pt: u8) FontError!void {
        if (family.len == 0 or family.len > MAX_FAMILY_LEN) return error.InvalidFont;

        const clamped = std.math.clamp(size_pt, MIN_SIZE_PT, MAX_SIZE_PT);
        const family_copy = try self.allocator.dupe(u8, family);
        errdefer self.allocator.free(family_copy);

        if (self.table.getEntry(account)) |existing| {
            self.allocator.free(existing.value_ptr.family);
            existing.value_ptr.* = .{ .family = family_copy, .size_pt = clamped };
            return;
        }

        const key_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key_copy);
        try self.table.put(key_copy, .{ .family = family_copy, .size_pt = clamped });
    }

    /// Return the current preference for `account`, or null if unset. The
    /// returned `family` slice remains owned by this `FontPref`.
    pub fn get(self: *const FontPref, account: []const u8) ?Entry {
        return self.table.get(account);
    }

    /// Remove the preference for `account`, freeing its key and family.
    /// Returns true if an entry was removed.
    pub fn clear(self: *FontPref, account: []const u8) bool {
        if (self.table.fetchRemove(account)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value.family);
            return true;
        }
        return false;
    }
};

test "set then get round-trips and clamps size" {
    var prefs = FontPref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("aki", "Iosevka", 3); // below floor -> clamped to 6
    const lo = prefs.get("aki").?;
    try std.testing.expectEqualStrings("Iosevka", lo.family);
    try std.testing.expectEqual(@as(u8, MIN_SIZE_PT), lo.size_pt);

    try prefs.set("aki", "Berkeley Mono", 200); // above ceiling -> clamped to 72
    const hi = prefs.get("aki").?;
    try std.testing.expectEqualStrings("Berkeley Mono", hi.family);
    try std.testing.expectEqual(@as(u8, MAX_SIZE_PT), hi.size_pt);

    try std.testing.expect(prefs.get("missing") == null);
}

test "invalid families are rejected without mutating state" {
    var prefs = FontPref.init(std.testing.allocator);
    defer prefs.deinit();

    try std.testing.expectError(error.InvalidFont, prefs.set("kai", "", 12));

    const too_long = "x" ** (MAX_FAMILY_LEN + 1);
    try std.testing.expectError(error.InvalidFont, prefs.set("kai", too_long, 12));

    try std.testing.expect(prefs.get("kai") == null);

    // Boundary length is accepted.
    const exact = "y" ** MAX_FAMILY_LEN;
    try prefs.set("kai", exact, 14);
    try std.testing.expectEqual(@as(usize, MAX_FAMILY_LEN), prefs.get("kai").?.family.len);
}

test "clear removes entries and reports presence" {
    var prefs = FontPref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("rei", "Comic Mono", 11);
    try std.testing.expect(prefs.clear("rei"));
    try std.testing.expect(prefs.get("rei") == null);
    try std.testing.expect(!prefs.clear("rei"));
}

test "overwrite frees old family without leaking" {
    var prefs = FontPref.init(std.testing.allocator);
    defer prefs.deinit();

    try prefs.set("sora", "First Family", 10);
    try prefs.set("sora", "Second Family", 20);

    const e = prefs.get("sora").?;
    try std.testing.expectEqualStrings("Second Family", e.family);
    try std.testing.expectEqual(@as(u8, 20), e.size_pt);
    try std.testing.expectEqual(@as(u32, 1), prefs.table.count());
}
