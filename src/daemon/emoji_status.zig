//! Per-account short status text/emoji store for the Mizuchi IRC daemon.
//!
//! Each account may carry a tiny presence string (an emoji, a mood, a brief
//! "away" blurb). Status values are capped at MAX_STATUS_BYTES to keep them
//! cheap to broadcast across the mesh and trivial to render in clients.
//!
//! Ownership model: this map owns every key (account name) and every value
//! (status string). Both are duplicated on insert and freed on removal or
//! overwrite, so callers retain ownership of whatever slices they pass in.

const std = @import("std");

/// Hard upper bound on a status payload, in bytes.
pub const MAX_STATUS_BYTES: usize = 16;

/// Errors produced when a status value fails validation.
pub const StatusError = error{
    /// Status was empty or exceeded MAX_STATUS_BYTES.
    InvalidStatus,
};

/// Owned account -> owned status string map.
pub const EmojiStatus = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap([]u8),

    /// Create an empty status store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) EmojiStatus {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Free every owned key and value, then the map itself.
    pub fn deinit(self: *EmojiStatus) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
        self.* = undefined;
    }

    /// Set (or overwrite) the status for `account`.
    ///
    /// Rejects empty status and any status longer than MAX_STATUS_BYTES with
    /// StatusError.InvalidStatus. On overwrite, the previous value is freed
    /// while the existing key is reused (no churn on the key allocation).
    pub fn set(self: *EmojiStatus, account: []const u8, status: []const u8) StatusError!void {
        if (status.len == 0 or status.len > MAX_STATUS_BYTES) {
            return StatusError.InvalidStatus;
        }

        const new_value = self.allocator.dupe(u8, status) catch return StatusError.InvalidStatus;
        errdefer self.allocator.free(new_value);

        if (self.map.getEntry(account)) |entry| {
            // Overwrite: reuse the owned key, swap and free the old value.
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = new_value;
            return;
        }

        const owned_key = self.allocator.dupe(u8, account) catch return StatusError.InvalidStatus;
        errdefer self.allocator.free(owned_key);

        self.map.put(owned_key, new_value) catch return StatusError.InvalidStatus;
    }

    /// Return the current status for `account`, or null if none is set.
    /// The returned slice is owned by the store and valid until the entry is
    /// overwritten, cleared, or the store is deinitialized.
    pub fn get(self: *const EmojiStatus, account: []const u8) ?[]const u8 {
        if (self.map.get(account)) |value| {
            return value;
        }
        return null;
    }

    /// Remove the status for `account`, freeing its key and value.
    /// Returns true if an entry was removed, false if none existed.
    pub fn clear(self: *EmojiStatus, account: []const u8) bool {
        if (self.map.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }
};

test "set/get/overwrite" {
    const allocator = std.testing.allocator;
    var store = EmojiStatus.init(allocator);
    defer store.deinit();

    try store.set("akira", "🐉");
    try std.testing.expectEqualStrings("🐉", store.get("akira").?);

    // Unknown account returns null.
    try std.testing.expect(store.get("mizuki") == null);

    // Overwrite frees the old value and exposes the new one.
    try store.set("akira", "afk");
    try std.testing.expectEqualStrings("afk", store.get("akira").?);

    // A second account coexists.
    try store.set("mizuki", "online");
    try std.testing.expectEqualStrings("online", store.get("mizuki").?);
    try std.testing.expectEqualStrings("afk", store.get("akira").?);
}

test "clear" {
    const allocator = std.testing.allocator;
    var store = EmojiStatus.init(allocator);
    defer store.deinit();

    try store.set("haru", "🌊");
    try std.testing.expect(store.clear("haru"));
    try std.testing.expect(store.get("haru") == null);

    // Clearing a missing account is a no-op returning false.
    try std.testing.expect(!store.clear("haru"));
    try std.testing.expect(!store.clear("nobody"));
}

test "reject empty/oversize" {
    const allocator = std.testing.allocator;
    var store = EmojiStatus.init(allocator);
    defer store.deinit();

    // Empty is rejected.
    try std.testing.expectError(StatusError.InvalidStatus, store.set("ren", ""));

    // Exactly MAX_STATUS_BYTES is accepted.
    const exact = "0123456789abcdef"; // 16 bytes
    try std.testing.expectEqual(@as(usize, MAX_STATUS_BYTES), exact.len);
    try store.set("ren", exact);
    try std.testing.expectEqualStrings(exact, store.get("ren").?);

    // One byte over the limit is rejected, and a failed set must not mutate
    // the existing value.
    const oversize = "0123456789abcdefg"; // 17 bytes
    try std.testing.expectError(StatusError.InvalidStatus, store.set("ren", oversize));
    try std.testing.expectEqualStrings(exact, store.get("ren").?);
}
