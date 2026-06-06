//! ComposeDraft: per-(account, target) saved draft message text for the
//! Mizuchi IRC daemon.
//!
//! Each draft is keyed by a composite "account\x00target" string and maps to
//! an owned copy of the draft text. Drafts are capped at `max_draft_bytes`
//! and may not be empty. This module is self-contained: it imports only the
//! standard library and owns all key/value memory it allocates.

const std = @import("std");

/// Maximum allowed length, in bytes, of a single draft's text.
pub const max_draft_bytes: usize = 2048;

/// Separator byte joining the account and target portions of a composite key.
/// A NUL byte is used because it cannot appear in an account name or IRC
/// target, so it is an unambiguous delimiter.
const key_sep: u8 = 0;

/// Error set surfaced by `save`.
pub const DraftError = error{
    /// The draft text was empty or exceeded `max_draft_bytes`.
    InvalidDraft,
};

pub const ComposeDraft = struct {
    allocator: std.mem.Allocator,
    drafts: std.StringHashMap([]u8),

    /// Create an empty draft store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ComposeDraft {
        return .{
            .allocator = allocator,
            .drafts = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Release every owned key and value, then the map itself.
    pub fn deinit(self: *ComposeDraft) void {
        var it = self.drafts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.drafts.deinit();
        self.* = undefined;
    }

    /// Build a freshly-allocated composite key "account\x00target".
    /// Caller owns the returned slice.
    fn makeKey(self: *ComposeDraft, account: []const u8, target: []const u8) ![]u8 {
        const key = try self.allocator.alloc(u8, account.len + 1 + target.len);
        @memcpy(key[0..account.len], account);
        key[account.len] = key_sep;
        @memcpy(key[account.len + 1 ..], target);
        return key;
    }

    /// Save (or overwrite) the draft text for the given account/target pair.
    ///
    /// Rejects empty or oversize text with `DraftError.InvalidDraft`. On
    /// overwrite, the previous value is freed and the existing key is reused.
    pub fn save(
        self: *ComposeDraft,
        account: []const u8,
        target: []const u8,
        text: []const u8,
    ) !void {
        if (text.len == 0 or text.len > max_draft_bytes) {
            return DraftError.InvalidDraft;
        }

        const lookup_key = try self.makeKey(account, target);
        // Whether `lookup_key` ends up owned by the map or must be freed here
        // is decided below; default to freeing it.
        var release_lookup = true;
        defer if (release_lookup) self.allocator.free(lookup_key);

        const value = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(value);

        if (self.drafts.getEntry(lookup_key)) |entry| {
            // Existing key: free old value, keep the stored key, swap in new.
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = value;
            return;
        }

        // New key: the map takes ownership of `lookup_key`.
        try self.drafts.put(lookup_key, value);
        release_lookup = false;
    }

    /// Return the saved draft text for the pair, or null if none exists.
    /// The returned slice is owned by the store and valid until the entry is
    /// overwritten or cleared.
    pub fn get(self: *ComposeDraft, account: []const u8, target: []const u8) ?[]const u8 {
        const lookup_key = self.makeKey(account, target) catch return null;
        defer self.allocator.free(lookup_key);
        return self.drafts.get(lookup_key);
    }

    /// Remove the draft for a single account/target pair.
    /// Returns true if a draft was removed, false if none existed.
    pub fn clearTarget(self: *ComposeDraft, account: []const u8, target: []const u8) bool {
        const lookup_key = self.makeKey(account, target) catch return false;
        defer self.allocator.free(lookup_key);

        if (self.drafts.fetchRemove(lookup_key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    /// Remove every draft belonging to `account` (keys beginning with
    /// "account\x00"). Returns the number of drafts removed.
    ///
    /// The prefix includes the NUL separator so that an account such as
    /// "bob" does not match a prefix-confusable account such as "bobby".
    pub fn clearAccount(self: *ComposeDraft, account: []const u8) usize {
        // Build the exact prefix "account\x00".
        const prefix = self.allocator.alloc(u8, account.len + 1) catch return 0;
        defer self.allocator.free(prefix);
        @memcpy(prefix[0..account.len], account);
        prefix[account.len] = key_sep;

        // Collect matching keys first; mutating the map while iterating it is
        // not safe, so we gather references then remove in a second pass.
        var doomed: std.ArrayList([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.drafts.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (std.mem.startsWith(u8, key, prefix)) {
                doomed.append(self.allocator, key) catch {
                    // Out of memory while collecting: stop gathering but still
                    // remove whatever we already queued.
                    break;
                };
            }
        }

        var removed: usize = 0;
        for (doomed.items) |key| {
            if (self.drafts.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                removed += 1;
            }
        }
        return removed;
    }
};

test "save/get/overwrite round-trips and replaces text" {
    const allocator = std.testing.allocator;
    var store = ComposeDraft.init(allocator);
    defer store.deinit();

    // Missing entries return null.
    try std.testing.expect(store.get("alice", "#zig") == null);

    // Save then read back.
    try store.save("alice", "#zig", "hello world");
    try std.testing.expectEqualStrings("hello world", store.get("alice", "#zig").?);

    // Overwrite replaces the value and frees the old one (no leak).
    try store.save("alice", "#zig", "edited message");
    try std.testing.expectEqualStrings("edited message", store.get("alice", "#zig").?);

    // Distinct target is independent.
    try store.save("alice", "bob", "dm draft");
    try std.testing.expectEqualStrings("dm draft", store.get("alice", "bob").?);
    try std.testing.expectEqualStrings("edited message", store.get("alice", "#zig").?);

    // Empty and oversize drafts are rejected.
    try std.testing.expectError(DraftError.InvalidDraft, store.save("alice", "#zig", ""));
    const huge = [_]u8{'x'} ** (max_draft_bytes + 1);
    try std.testing.expectError(DraftError.InvalidDraft, store.save("alice", "#zig", &huge));
    // A rejected save must not disturb the existing draft.
    try std.testing.expectEqualStrings("edited message", store.get("alice", "#zig").?);

    // Exactly at the cap is accepted.
    const exact = [_]u8{'y'} ** max_draft_bytes;
    try store.save("alice", "#zig", &exact);
    try std.testing.expectEqual(@as(usize, max_draft_bytes), store.get("alice", "#zig").?.len);
}

test "clearTarget removes one pair and reports presence" {
    const allocator = std.testing.allocator;
    var store = ComposeDraft.init(allocator);
    defer store.deinit();

    try store.save("carol", "#one", "draft one");
    try store.save("carol", "#two", "draft two");

    // Removing a non-existent pair returns false.
    try std.testing.expect(store.clearTarget("carol", "#missing") == false);

    // Removing an existing pair returns true and the draft disappears.
    try std.testing.expect(store.clearTarget("carol", "#one") == true);
    try std.testing.expect(store.get("carol", "#one") == null);

    // The sibling draft is untouched.
    try std.testing.expectEqualStrings("draft two", store.get("carol", "#two").?);

    // Double-clear returns false.
    try std.testing.expect(store.clearTarget("carol", "#one") == false);
}

test "clearAccount scopes to exact account, not prefix-confusable ones" {
    const allocator = std.testing.allocator;
    var store = ComposeDraft.init(allocator);
    defer store.deinit();

    // "bob" and "bobby" share a prefix; only "bob\x00..." keys must match.
    try store.save("bob", "#chan", "bob chan");
    try store.save("bob", "ann", "bob dm");
    try store.save("bobby", "#chan", "bobby chan");
    try store.save("bobby", "carl", "bobby dm");

    const removed = store.clearAccount("bob");
    try std.testing.expectEqual(@as(usize, 2), removed);

    // bob's drafts are gone.
    try std.testing.expect(store.get("bob", "#chan") == null);
    try std.testing.expect(store.get("bob", "ann") == null);

    // bobby's drafts survive untouched.
    try std.testing.expectEqualStrings("bobby chan", store.get("bobby", "#chan").?);
    try std.testing.expectEqualStrings("bobby dm", store.get("bobby", "carl").?);

    // Clearing an account with no drafts removes nothing.
    try std.testing.expectEqual(@as(usize, 0), store.clearAccount("nobody"));

    // Clearing bobby now empties the store.
    try std.testing.expectEqual(@as(usize, 2), store.clearAccount("bobby"));
    try std.testing.expect(store.get("bobby", "#chan") == null);
}
