//! Per-account UI accent color preferences for the Orochi daemon.
//!
//! Each account may store a single accent color expressed as a short string
//! (for example "#aabbccff"). Colors are validated to be non-empty and at most
//! `max_color_len` bytes. Keys (account names) and values (color strings) are
//! owned by the store and freed on overwrite, clear, and deinit.

const std = @import("std");

/// Maximum byte length of a stored color string (e.g. "#aabbccff").
const max_color_len: usize = 9;

/// Errors returned when validating a candidate color string.
pub const ColorError = error{InvalidColor};

/// A store mapping owned account names to owned accent color strings.
pub const ColorPref = struct {
    allocator: std.mem.Allocator,
    table: std.StringHashMap([]u8),

    /// Initialize an empty preference store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ColorPref {
        return .{
            .allocator = allocator,
            .table = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Release every owned key and value, then the table itself.
    pub fn deinit(self: *ColorPref) void {
        var it = self.table.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.table.deinit();
    }

    /// Set (or overwrite) the accent color for `account`.
    ///
    /// Rejects empty colors and colors longer than `max_color_len` bytes with
    /// `error.InvalidColor`. On overwrite the previous color is freed while the
    /// existing key is retained.
    pub fn set(self: *ColorPref, account: []const u8, color: []const u8) !void {
        if (color.len == 0 or color.len > max_color_len) {
            return ColorError.InvalidColor;
        }

        const new_color = try self.allocator.dupe(u8, color);
        errdefer self.allocator.free(new_color);

        if (self.table.getEntry(account)) |entry| {
            // Overwrite: free old value, reuse existing key allocation.
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = new_color;
            return;
        }

        const new_key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(new_key);

        try self.table.put(new_key, new_color);
    }

    /// Return the stored color for `account`, or null if none is set.
    pub fn get(self: *ColorPref, account: []const u8) ?[]const u8 {
        return self.table.get(account);
    }

    /// Remove the entry for `account`, freeing its key and value.
    /// Returns true if an entry was removed, false otherwise.
    pub fn clear(self: *ColorPref, account: []const u8) bool {
        if (self.table.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }
};

test "set/get/overwrite" {
    const allocator = std.testing.allocator;
    var prefs = ColorPref.init(allocator);
    defer prefs.deinit();

    try prefs.set("alice", "#aabbccff");
    try std.testing.expectEqualStrings("#aabbccff", prefs.get("alice").?);

    // Overwrite frees the old value and stores the new one.
    try prefs.set("alice", "#11223344");
    try std.testing.expectEqualStrings("#11223344", prefs.get("alice").?);

    // Unknown account returns null.
    try std.testing.expect(prefs.get("nobody") == null);
}

test "clear removes entry" {
    const allocator = std.testing.allocator;
    var prefs = ColorPref.init(allocator);
    defer prefs.deinit();

    try prefs.set("bob", "#ff0000");
    try std.testing.expect(prefs.get("bob") != null);

    try std.testing.expect(prefs.clear("bob"));
    try std.testing.expect(prefs.get("bob") == null);

    // Clearing a missing account reports false.
    try std.testing.expect(!prefs.clear("bob"));
}

test "set rejects invalid colors" {
    const allocator = std.testing.allocator;
    var prefs = ColorPref.init(allocator);
    defer prefs.deinit();

    try std.testing.expectError(ColorError.InvalidColor, prefs.set("carol", ""));
    try std.testing.expectError(ColorError.InvalidColor, prefs.set("carol", "#aabbccffx"));

    // A rejected set leaves no entry behind.
    try std.testing.expect(prefs.get("carol") == null);
}
