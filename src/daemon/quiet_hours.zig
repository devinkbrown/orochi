//! quiet_hours.zig — per-account daily do-not-disturb windows for the Orochi daemon.
//!
//! Each account may register a single recurring "quiet" window expressed in
//! minutes-of-day (0..=1439). A window where `start_min > end_min` wraps past
//! midnight (e.g. 22:00 -> 07:00). Membership tests are inclusive of both
//! endpoints.

const std = @import("std");

/// Largest valid minute-of-day value (23:59).
const minute_max: u16 = 1439;

/// A daily do-not-disturb window stored inline in the map.
pub const Window = struct {
    start_min: u16,
    end_min: u16,
};

/// Tracks per-account quiet windows. Owns its account-name keys.
pub const QuietHours = struct {
    allocator: std.mem.Allocator,
    windows: std.StringHashMap(Window),

    /// Construct an empty registry bound to `allocator`.
    pub fn init(allocator: std.mem.Allocator) QuietHours {
        return .{
            .allocator = allocator,
            .windows = std.StringHashMap(Window).init(allocator),
        };
    }

    /// Release all owned keys and the backing map.
    pub fn deinit(self: *QuietHours) void {
        var it = self.windows.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.windows.deinit();
    }

    /// Set (or replace) the quiet window for `account`.
    /// Returns `error.InvalidWindow` if either bound is out of range.
    pub fn set(self: *QuietHours, account: []const u8, start_min: u16, end_min: u16) !void {
        if (start_min > minute_max or end_min > minute_max) return error.InvalidWindow;

        const win = Window{ .start_min = start_min, .end_min = end_min };

        // Reuse the existing key when the account is already present so we never
        // leak or double-own the key string.
        if (self.windows.getEntry(account)) |entry| {
            entry.value_ptr.* = win;
            return;
        }

        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);
        try self.windows.put(key, win);
    }

    /// Fetch the window for `account`, if any.
    pub fn get(self: *const QuietHours, account: []const u8) ?Window {
        return self.windows.get(account);
    }

    /// Report whether `minute_of_day` falls inside the account's quiet window.
    /// Accounts without a window are never quiet. Handles midnight wrap.
    pub fn isQuiet(self: *const QuietHours, account: []const u8, minute_of_day: u16) bool {
        const win = self.windows.get(account) orelse return false;
        if (win.start_min <= win.end_min) {
            // Same-day window: [start, end] inclusive.
            return minute_of_day >= win.start_min and minute_of_day <= win.end_min;
        }
        // Wrapping window: quiet from start..midnight and midnight..end.
        return minute_of_day >= win.start_min or minute_of_day <= win.end_min;
    }

    /// Remove the window for `account`. Returns true if one existed.
    pub fn clear(self: *QuietHours, account: []const u8) bool {
        if (self.windows.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }
};

test "set, get, and validation reject out-of-range bounds" {
    var qh = QuietHours.init(std.testing.allocator);
    defer qh.deinit();

    try qh.set("ayame", 540, 1020); // 09:00 -> 17:00
    const win = qh.get("ayame").?;
    try std.testing.expectEqual(@as(u16, 540), win.start_min);
    try std.testing.expectEqual(@as(u16, 1020), win.end_min);

    try std.testing.expect(qh.get("unknown") == null);

    try std.testing.expectError(error.InvalidWindow, qh.set("ayame", 1440, 100));
    try std.testing.expectError(error.InvalidWindow, qh.set("ayame", 0, 9999));
}

test "isQuiet for a same-day window respects inclusive endpoints" {
    var qh = QuietHours.init(std.testing.allocator);
    defer qh.deinit();

    try qh.set("kasumi", 540, 1020); // 09:00 -> 17:00

    try std.testing.expect(qh.isQuiet("kasumi", 540)); // start edge
    try std.testing.expect(qh.isQuiet("kasumi", 1020)); // end edge
    try std.testing.expect(qh.isQuiet("kasumi", 700)); // middle
    try std.testing.expect(!qh.isQuiet("kasumi", 539)); // just before
    try std.testing.expect(!qh.isQuiet("kasumi", 1021)); // just after
    try std.testing.expect(!qh.isQuiet("nobody", 700)); // no window
}

test "isQuiet wraps past midnight" {
    var qh = QuietHours.init(std.testing.allocator);
    defer qh.deinit();

    try qh.set("yoru", 1320, 420); // 22:00 -> 07:00, wraps midnight

    try std.testing.expect(qh.isQuiet("yoru", 1320)); // 22:00 start edge
    try std.testing.expect(qh.isQuiet("yoru", 1439)); // 23:59 before midnight
    try std.testing.expect(qh.isQuiet("yoru", 0)); // 00:00 after midnight
    try std.testing.expect(qh.isQuiet("yoru", 420)); // 07:00 end edge
    try std.testing.expect(!qh.isQuiet("yoru", 421)); // 07:01 just outside
    try std.testing.expect(!qh.isQuiet("yoru", 700)); // mid-day, awake
}

test "set replaces existing window without leaking keys, clear removes it" {
    var qh = QuietHours.init(std.testing.allocator);
    defer qh.deinit();

    try qh.set("midori", 100, 200);
    try qh.set("midori", 300, 400); // replace; must reuse key
    try std.testing.expectEqual(@as(u16, 300), qh.get("midori").?.start_min);

    try std.testing.expect(qh.clear("midori"));
    try std.testing.expect(!qh.clear("midori")); // already gone
    try std.testing.expect(qh.get("midori") == null);
}
