//! Per-account auto-reply text for the Orochi IRC daemon.
//!
//! Holds an optional auto-response message per account, used when a client is
//! marked away or busy. Each entry pairs an `enabled` flag with the stored text.
//! The map owns every account key and every text buffer it stores.

const std = @import("std");

/// Maximum length, in bytes, of a stored auto-response message.
pub const max_response_len: usize = 300;

/// Returned when a supplied response text is empty or exceeds `max_response_len`.
pub const Error = error{InvalidResponse};

const Entry = struct {
    enabled: bool,
    text: []u8,
};

/// Stores per-account auto-reply text keyed by owned account-name strings.
pub const AutoResponse = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(Entry),

    /// Creates an empty store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) AutoResponse {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Entry).init(allocator),
        };
    }

    /// Frees every owned account key and text buffer, then the map itself.
    pub fn deinit(self: *AutoResponse) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            self.allocator.free(kv.value_ptr.text);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Sets (or overwrites) the auto-response for `account` and enables it.
    ///
    /// Returns `Error.InvalidResponse` when `text` is empty or longer than
    /// `max_response_len`. On overwrite the previous text buffer is freed; the
    /// account key is reused. On any failure the store is left unchanged.
    pub fn set(self: *AutoResponse, account: []const u8, text: []const u8) !void {
        if (text.len == 0 or text.len > max_response_len) return Error.InvalidResponse;

        const text_copy = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_copy);

        if (self.entries.getPtr(account)) |entry| {
            self.allocator.free(entry.text);
            entry.text = text_copy;
            entry.enabled = true;
            return;
        }

        const key_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key_copy);

        try self.entries.put(key_copy, .{ .enabled = true, .text = text_copy });
    }

    /// Disables the auto-response for `account` without discarding its text.
    ///
    /// Returns `true` if an entry existed and was enabled, `false` otherwise.
    pub fn disable(self: *AutoResponse, account: []const u8) bool {
        if (self.entries.getPtr(account)) |entry| {
            const was_enabled = entry.enabled;
            entry.enabled = false;
            return was_enabled;
        }
        return false;
    }

    /// Returns the stored text for `account` only when it is enabled.
    pub fn get(self: *AutoResponse, account: []const u8) ?[]const u8 {
        if (self.entries.getPtr(account)) |entry| {
            if (entry.enabled) return entry.text;
        }
        return null;
    }
};

test "set then get returns enabled text and rejects bad input" {
    var ar = AutoResponse.init(std.testing.allocator);
    defer ar.deinit();

    try ar.set("kraken", "Away diving the trench.");
    try std.testing.expectEqualStrings("Away diving the trench.", ar.get("kraken").?);

    try std.testing.expectEqual(@as(?[]const u8, null), ar.get("nobody"));

    try std.testing.expectError(Error.InvalidResponse, ar.set("kraken", ""));
    const oversize = "x" ** (max_response_len + 1);
    try std.testing.expectError(Error.InvalidResponse, ar.set("kraken", oversize));

    // Failed set must leave the prior value intact.
    try std.testing.expectEqualStrings("Away diving the trench.", ar.get("kraken").?);
}

test "overwrite frees old text and re-enables" {
    var ar = AutoResponse.init(std.testing.allocator);
    defer ar.deinit();

    try ar.set("naga", "first");
    try ar.set("naga", "second");
    try std.testing.expectEqualStrings("second", ar.get("naga").?);

    // Disable, then overwrite should re-enable.
    _ = ar.disable("naga");
    try std.testing.expectEqual(@as(?[]const u8, null), ar.get("naga"));
    try ar.set("naga", "third");
    try std.testing.expectEqualStrings("third", ar.get("naga").?);
}

test "disable hides text but preserves storage" {
    var ar = AutoResponse.init(std.testing.allocator);
    defer ar.deinit();

    try std.testing.expectEqual(false, ar.disable("ghost"));

    try ar.set("ryujin", "On a call.");
    try std.testing.expectEqual(true, ar.disable("ryujin"));
    try std.testing.expectEqual(false, ar.disable("ryujin"));
    try std.testing.expectEqual(@as(?[]const u8, null), ar.get("ryujin"));

    // Boundary: exactly max length is accepted.
    const exact = "y" ** max_response_len;
    try ar.set("ryujin", exact);
    try std.testing.expectEqual(@as(usize, max_response_len), ar.get("ryujin").?.len);
}
