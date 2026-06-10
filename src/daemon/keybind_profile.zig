//! Per-account opaque client keybind blobs for the Orochi IRC daemon.
//!
//! Clients may stash a small, server-opaque blob of keybind configuration
//! keyed by account name. The daemon never interprets the contents; it only
//! enforces a size ceiling and owns the backing memory.

const std = @import("std");

/// Maximum size, in bytes, of a single stored keybind blob.
pub const max_blob_bytes: usize = 2048;

/// Errors produced when storing a keybind blob.
pub const KeybindError = error{
    /// The blob was empty or exceeded `max_blob_bytes`.
    InvalidBlob,
};

/// Owns a mapping of account name -> opaque keybind blob.
///
/// Both the account-name keys and the blob values are duplicated into
/// allocator-owned memory. `deinit` releases everything.
pub const KeybindProfile = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap([]u8),

    /// Create an empty profile store.
    pub fn init(allocator: std.mem.Allocator) KeybindProfile {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Release every stored key and blob, then the map itself.
    pub fn deinit(self: *KeybindProfile) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Store `blob` for `account`, replacing any existing blob.
    ///
    /// Rejects empty blobs and blobs larger than `max_blob_bytes` with
    /// `error.InvalidBlob`. An existing blob for the account is freed and
    /// overwritten; the account key is reused in that case.
    pub fn set(self: *KeybindProfile, account: []const u8, blob: []const u8) !void {
        if (blob.len == 0 or blob.len > max_blob_bytes) return KeybindError.InvalidBlob;

        const blob_copy = try self.allocator.dupe(u8, blob);
        errdefer self.allocator.free(blob_copy);

        if (self.entries.getEntry(account)) |existing| {
            self.allocator.free(existing.value_ptr.*);
            existing.value_ptr.* = blob_copy;
            return;
        }

        const key_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key_copy);

        try self.entries.put(key_copy, blob_copy);
    }

    /// Return the stored blob for `account`, or null if none exists.
    ///
    /// The returned slice is owned by the store and is invalidated by a
    /// subsequent `set`, `clear`, or `deinit` on the same account.
    pub fn get(self: *const KeybindProfile, account: []const u8) ?[]const u8 {
        if (self.entries.get(account)) |blob| return blob;
        return null;
    }

    /// Remove and free the blob for `account`.
    ///
    /// Returns true if an entry was removed, false if none existed.
    pub fn clear(self: *KeybindProfile, account: []const u8) bool {
        if (self.entries.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }
};

test "set then get returns stored blob" {
    var profile = KeybindProfile.init(std.testing.allocator);
    defer profile.deinit();

    const blob = "bind:ctrl-k=clear";
    try profile.set("nullptr", blob);

    const fetched = profile.get("nullptr") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(blob, fetched);
    try std.testing.expect(profile.get("ghost") == null);
}

test "set overwrites existing blob and frees old" {
    var profile = KeybindProfile.init(std.testing.allocator);
    defer profile.deinit();

    try profile.set("seabright", "first-config");
    try profile.set("seabright", "second-config-which-is-longer");

    const fetched = profile.get("seabright") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("second-config-which-is-longer", fetched);
    try std.testing.expectEqual(@as(usize, 1), profile.entries.count());
}

test "clear removes entry and reports presence" {
    var profile = KeybindProfile.init(std.testing.allocator);
    defer profile.deinit();

    try profile.set("driftwood", "x");
    try std.testing.expect(profile.clear("driftwood"));
    try std.testing.expect(profile.get("driftwood") == null);
    try std.testing.expect(!profile.clear("driftwood"));
    try std.testing.expect(!profile.clear("never-existed"));
}

test "set rejects empty and oversize blobs" {
    var profile = KeybindProfile.init(std.testing.allocator);
    defer profile.deinit();

    try std.testing.expectError(KeybindError.InvalidBlob, profile.set("acct", ""));

    const oversize = [_]u8{'a'} ** (max_blob_bytes + 1);
    try std.testing.expectError(KeybindError.InvalidBlob, profile.set("acct", &oversize));

    // Exactly at the limit must succeed.
    const at_limit = [_]u8{'b'} ** max_blob_bytes;
    try profile.set("acct", &at_limit);
    try std.testing.expectEqual(@as(usize, max_blob_bytes), (profile.get("acct").?).len);
}
