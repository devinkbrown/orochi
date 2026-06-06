//! Per-account birthday tracking for the Mizuchi IRC daemon.
//!
//! Stores an optional birthday (month + day) per account. The year is
//! deliberately omitted to preserve member privacy; only the calendar date
//! is retained so the daemon can recognize when "today" matches a member's
//! birthday without ever learning their age.

const std = @import("std");

/// A privacy-preserving calendar date: month and day only, no year.
pub const Date = struct {
    /// Month of the year, 1 (January) through 12 (December).
    month: u8,
    /// Day of the month, 1 through 31.
    day: u8,
};

/// Returned when a supplied month/day pair falls outside the accepted range.
pub const SetError = error{InvalidDate} || std.mem.Allocator.Error;

/// Tracks one birthday per account name.
pub const Birthday = struct {
    allocator: std.mem.Allocator,
    /// Owns its account-name keys; `Date` values are stored inline.
    entries: std.StringHashMap(Date),

    const Self = @This();

    /// Smallest accepted month value (January).
    const month_min: u8 = 1;
    /// Largest accepted month value (December).
    const month_max: u8 = 12;
    /// Smallest accepted day value.
    const day_min: u8 = 1;
    /// Largest accepted day value (coarse upper bound; per-month length is
    /// not enforced so that Feb 29 and similar dates remain expressible).
    const day_max: u8 = 31;

    /// Create an empty tracker backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Date).init(allocator),
        };
    }

    /// Release every owned key and the backing map. Safe to call once.
    pub fn deinit(self: *Self) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Validate that `month`/`day` lie within the accepted ranges.
    fn validate(month: u8, day: u8) error{InvalidDate}!void {
        if (month < month_min or month > month_max) return error.InvalidDate;
        if (day < day_min or day > day_max) return error.InvalidDate;
    }

    /// Record `account`'s birthday as `month`/`day`.
    ///
    /// Rejects out-of-range dates with `error.InvalidDate`. Updating an
    /// existing account reuses its stored key and never leaks memory.
    pub fn set(self: *Self, account: []const u8, month: u8, day: u8) SetError!void {
        try validate(month, day);

        const date = Date{ .month = month, .day = day };

        if (self.entries.getPtr(account)) |existing| {
            existing.* = date;
            return;
        }

        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);
        try self.entries.put(key, date);
    }

    /// Return `account`'s stored birthday, or `null` if none is recorded.
    pub fn get(self: *Self, account: []const u8) ?Date {
        return self.entries.get(account);
    }

    /// Remove `account`'s birthday, freeing its key.
    /// Returns true if an entry was removed, false if none existed.
    pub fn clear(self: *Self, account: []const u8) bool {
        if (self.entries.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }

    /// Report whether `account`'s recorded birthday equals `month`/`day`.
    /// Returns false when the account has no recorded birthday.
    pub fn isToday(self: *Self, account: []const u8, month: u8, day: u8) bool {
        const date = self.get(account) orelse return false;
        return date.month == month and date.day == day;
    }
};

test "set and get round-trips a birthday" {
    const allocator = std.testing.allocator;
    var birthdays = Birthday.init(allocator);
    defer birthdays.deinit();

    try birthdays.set("amaterasu", 3, 14);

    const stored = birthdays.get("amaterasu") orelse
        return error.TestExpectedStoredDate;
    try std.testing.expectEqual(@as(u8, 3), stored.month);
    try std.testing.expectEqual(@as(u8, 14), stored.day);

    try std.testing.expect(birthdays.get("unknown") == null);
}

test "set rejects invalid dates" {
    const allocator = std.testing.allocator;
    var birthdays = Birthday.init(allocator);
    defer birthdays.deinit();

    try std.testing.expectError(error.InvalidDate, birthdays.set("susanoo", 0, 10));
    try std.testing.expectError(error.InvalidDate, birthdays.set("susanoo", 13, 10));
    try std.testing.expectError(error.InvalidDate, birthdays.set("susanoo", 6, 0));
    try std.testing.expectError(error.InvalidDate, birthdays.set("susanoo", 6, 32));

    // Nothing should have been stored for the rejected account.
    try std.testing.expect(birthdays.get("susanoo") == null);
}

test "isToday matches only the recorded date" {
    const allocator = std.testing.allocator;
    var birthdays = Birthday.init(allocator);
    defer birthdays.deinit();

    try birthdays.set("tsukuyomi", 12, 25);

    try std.testing.expect(birthdays.isToday("tsukuyomi", 12, 25));
    try std.testing.expect(!birthdays.isToday("tsukuyomi", 12, 24));
    try std.testing.expect(!birthdays.isToday("tsukuyomi", 1, 25));
    // Accounts without a recorded birthday never match.
    try std.testing.expect(!birthdays.isToday("nobody", 12, 25));
}

test "update reuses key and clear removes it" {
    const allocator = std.testing.allocator;
    var birthdays = Birthday.init(allocator);
    defer birthdays.deinit();

    try birthdays.set("inari", 1, 1);
    try birthdays.set("inari", 7, 7); // update in place

    const updated = birthdays.get("inari") orelse
        return error.TestExpectedStoredDate;
    try std.testing.expectEqual(@as(u8, 7), updated.month);
    try std.testing.expectEqual(@as(u8, 7), updated.day);

    try std.testing.expect(birthdays.clear("inari"));
    try std.testing.expect(!birthdays.clear("inari"));
    try std.testing.expect(birthdays.get("inari") == null);
}
