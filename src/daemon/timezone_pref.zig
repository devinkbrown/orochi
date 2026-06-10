//! Per-account timezone preferences for the Orochi IRC daemon.
//!
//! Each account may associate a single timezone identifier (IANA-style, e.g.
//! "America/New_York") together with a cached UTC offset in minutes. Storage is
//! a hash map keyed by owned account strings; both keys and timezone names are
//! owned by this structure and freed on removal or teardown.

const std = @import("std");

/// Maximum permitted length (in bytes) of a timezone identifier.
pub const max_name_len: usize = 48;

/// Returned when a supplied timezone name is empty or exceeds `max_name_len`.
pub const TimezoneError = error{InvalidTimezone};

/// A single stored timezone preference. `name` is owned by the `TimezonePref`
/// that produced it; callers must not free or retain it past a mutating call.
pub const Entry = struct {
    name: []const u8,
    offset_min: i32,
};

/// Mutable, owning entry stored internally in the map.
const StoredEntry = struct {
    name: []u8,
    offset_min: i32,
};

/// Owns a set of per-account timezone preferences.
pub const TimezonePref = struct {
    allocator: std.mem.Allocator,
    table: std.StringHashMap(StoredEntry),

    /// Create an empty preference store.
    pub fn init(allocator: std.mem.Allocator) TimezonePref {
        return .{
            .allocator = allocator,
            .table = std.StringHashMap(StoredEntry).init(allocator),
        };
    }

    /// Release every owned key and timezone name, then the table itself.
    pub fn deinit(self: *TimezonePref) void {
        var it = self.table.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            self.allocator.free(kv.value_ptr.name);
        }
        self.table.deinit();
        self.* = undefined;
    }

    /// Validate a candidate timezone name.
    fn validateName(name: []const u8) TimezoneError!void {
        if (name.len == 0 or name.len > max_name_len) return TimezoneError.InvalidTimezone;
    }

    /// Associate `name`/`offset_min` with `account`.
    ///
    /// Rejects empty or oversize names with `error.InvalidTimezone`. On an
    /// overwrite, the previous timezone name is freed and the existing account
    /// key is reused. New accounts duplicate both the account key and the name.
    pub fn set(self: *TimezonePref, account: []const u8, name: []const u8, offset_min: i32) !void {
        try validateName(name);

        if (self.table.getPtr(account)) |existing| {
            const dup_name = try self.allocator.dupe(u8, name);
            self.allocator.free(existing.name);
            existing.name = dup_name;
            existing.offset_min = offset_min;
            return;
        }

        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);

        const dup_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(dup_name);

        try self.table.put(key, .{ .name = dup_name, .offset_min = offset_min });
    }

    /// Look up the timezone preference for `account`, if any. The returned
    /// `Entry.name` borrows internal storage and is invalidated by any later
    /// mutation of the same account.
    pub fn get(self: *const TimezonePref, account: []const u8) ?Entry {
        const stored = self.table.get(account) orelse return null;
        return .{ .name = stored.name, .offset_min = stored.offset_min };
    }

    /// Remove the preference for `account`, freeing its key and name. Returns
    /// true if an entry was removed, false if no such account existed.
    pub fn clear(self: *TimezonePref, account: []const u8) bool {
        const kv = self.table.fetchRemove(account) orelse return false;
        self.allocator.free(kv.key);
        self.allocator.free(kv.value.name);
        return true;
    }
};

test "set and get round-trips a timezone preference" {
    const allocator = std.testing.allocator;
    var prefs = TimezonePref.init(allocator);
    defer prefs.deinit();

    try prefs.set("alice", "America/New_York", -240);

    const entry = prefs.get("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("America/New_York", entry.name);
    try std.testing.expectEqual(@as(i32, -240), entry.offset_min);

    try std.testing.expect(prefs.get("nobody") == null);
}

test "set overwrites an existing account and frees the old name" {
    const allocator = std.testing.allocator;
    var prefs = TimezonePref.init(allocator);
    defer prefs.deinit();

    try prefs.set("bob", "Europe/London", 0);
    try prefs.set("bob", "Asia/Tokyo", 540);

    const entry = prefs.get("bob") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Asia/Tokyo", entry.name);
    try std.testing.expectEqual(@as(i32, 540), entry.offset_min);
    try std.testing.expectEqual(@as(usize, 1), prefs.table.count());
}

test "clear removes an entry and reports presence" {
    const allocator = std.testing.allocator;
    var prefs = TimezonePref.init(allocator);
    defer prefs.deinit();

    try prefs.set("carol", "UTC", 0);
    try std.testing.expect(prefs.clear("carol"));
    try std.testing.expect(prefs.get("carol") == null);
    try std.testing.expect(!prefs.clear("carol"));
}

test "set rejects empty and oversize timezone names" {
    const allocator = std.testing.allocator;
    var prefs = TimezonePref.init(allocator);
    defer prefs.deinit();

    try std.testing.expectError(TimezoneError.InvalidTimezone, prefs.set("dave", "", 0));

    const oversize = "X" ** (max_name_len + 1);
    try std.testing.expectError(TimezoneError.InvalidTimezone, prefs.set("dave", oversize, 0));

    try std.testing.expect(prefs.get("dave") == null);

    // Exactly at the limit is accepted.
    const at_limit = "Y" ** max_name_len;
    try prefs.set("dave", at_limit, 60);
    const entry = prefs.get("dave") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, max_name_len), entry.name.len);
}
