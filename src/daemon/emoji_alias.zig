//! Per-account custom emoji shortcode aliases for the Orochi IRC daemon.
//!
//! Each account may register its own shortcode -> replacement mappings, e.g.
//! ":shrug:" -> "¯\\_(ツ)_/¯". Lookups are scoped per account so two accounts
//! can define the same shortcode independently.
//!
//! Storage uses a composite key of the form "account\x00shortcode" mapping to
//! an owned replacement string. Both keys and values are heap-allocated and
//! owned by the table; deinit frees all of them.

const std = @import("std");

/// Maximum number of aliases retained across all accounts.
pub const max_aliases: usize = 256;

/// Maximum length (in bytes) of a shortcode.
pub const max_shortcode_len: usize = 32;

/// Maximum length (in bytes) of a replacement string.
pub const max_replacement_len: usize = 64;

/// Byte used to separate the account from the shortcode in composite keys.
const key_sep: u8 = 0x00;

/// Errors produced when validating alias input.
pub const AliasError = error{
    /// Shortcode or replacement was empty, oversize, or otherwise rejected.
    InvalidAlias,
} || std.mem.Allocator.Error;

/// Per-account custom shortcode -> replacement alias store.
pub const EmojiAlias = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMapUnmanaged([]u8),

    /// Initialize an empty alias store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) EmojiAlias {
        return .{
            .allocator = allocator,
            .map = .{},
        };
    }

    /// Free every owned key and value, then the backing map.
    pub fn deinit(self: *EmojiAlias) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit(self.allocator);
        self.* = undefined;
    }

    /// Build a composite "account\x00shortcode" key owned by the caller.
    fn buildKey(self: *EmojiAlias, account: []const u8, shortcode: []const u8) AliasError![]u8 {
        const total = account.len + 1 + shortcode.len;
        const buf = try self.allocator.alloc(u8, total);
        @memcpy(buf[0..account.len], account);
        buf[account.len] = key_sep;
        @memcpy(buf[account.len + 1 ..], shortcode);
        return buf;
    }

    /// Register or overwrite an alias for `account`.
    ///
    /// Rejects empty or oversize shortcode/replacement with error.InvalidAlias.
    /// Overwriting an existing shortcode frees the prior replacement.
    /// Adding a new shortcode when already at `max_aliases` is rejected.
    pub fn set(
        self: *EmojiAlias,
        account: []const u8,
        shortcode: []const u8,
        replacement: []const u8,
    ) AliasError!void {
        if (shortcode.len == 0 or shortcode.len > max_shortcode_len) return error.InvalidAlias;
        if (replacement.len == 0 or replacement.len > max_replacement_len) return error.InvalidAlias;
        if (account.len == 0) return error.InvalidAlias;
        // Embedded NUL in inputs would corrupt key scoping.
        if (std.mem.indexOfScalar(u8, account, key_sep) != null) return error.InvalidAlias;
        if (std.mem.indexOfScalar(u8, shortcode, key_sep) != null) return error.InvalidAlias;

        const key = try self.buildKey(account, shortcode);
        errdefer self.allocator.free(key);

        if (self.map.getEntry(key)) |entry| {
            // Overwrite: keep existing key, replace owned value.
            const new_val = try self.allocator.dupe(u8, replacement);
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = new_val;
            self.allocator.free(key);
            return;
        }

        if (self.map.count() >= max_aliases) {
            self.allocator.free(key);
            return error.InvalidAlias;
        }

        const value = try self.allocator.dupe(u8, replacement);
        errdefer self.allocator.free(value);
        try self.map.putNoClobber(self.allocator, key, value);
    }

    /// Look up the replacement for `account`'s `shortcode`, if any.
    /// The returned slice is owned by the store and valid until mutated.
    pub fn get(self: *EmojiAlias, account: []const u8, shortcode: []const u8) ?[]const u8 {
        if (shortcode.len == 0 or shortcode.len > max_shortcode_len) return null;
        if (account.len == 0) return null;

        var key_buf: [max_shortcode_len + 1 + 256]u8 = undefined;
        const total = account.len + 1 + shortcode.len;
        if (total > key_buf.len) {
            // Fall back to a heap key for unusually long account names.
            const key = self.buildKey(account, shortcode) catch return null;
            defer self.allocator.free(key);
            return self.map.get(key);
        }
        @memcpy(key_buf[0..account.len], account);
        key_buf[account.len] = key_sep;
        @memcpy(key_buf[account.len + 1 .. total], shortcode);
        return self.map.get(key_buf[0..total]);
    }

    /// Remove `account`'s `shortcode`. Returns true if an entry was removed.
    pub fn remove(self: *EmojiAlias, account: []const u8, shortcode: []const u8) bool {
        if (shortcode.len == 0 or account.len == 0) return false;
        const key = self.buildKey(account, shortcode) catch return false;
        defer self.allocator.free(key);

        if (self.map.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    /// Remove every alias belonging to `account`. Returns the count removed.
    ///
    /// Scoping matches only keys that begin with the exact prefix
    /// "account\x00", so an account name that is a prefix of another
    /// (e.g. "bob" vs "bobby") is never confused.
    pub fn clearAccount(self: *EmojiAlias, account: []const u8) usize {
        if (account.len == 0) return 0;

        const prefix = self.buildKey(account, "") catch return 0;
        defer self.allocator.free(prefix);

        // Collect matching keys first; mutating during iteration is unsafe.
        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.map.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            if (std.mem.startsWith(u8, k, prefix)) {
                doomed.append(self.allocator, k) catch return doomed.items.len;
            }
        }

        var removed: usize = 0;
        for (doomed.items) |k| {
            if (self.map.fetchRemove(k)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                removed += 1;
            }
        }
        return removed;
    }
};

test "set, get, and overwrite an alias" {
    const allocator = std.testing.allocator;
    var aliases = EmojiAlias.init(allocator);
    defer aliases.deinit();

    try aliases.set("alice", ":shrug:", "shrug-text");
    try std.testing.expectEqualStrings("shrug-text", aliases.get("alice", ":shrug:").?);

    // Overwrite frees the old value and stores the new one.
    try aliases.set("alice", ":shrug:", "new-shrug");
    try std.testing.expectEqualStrings("new-shrug", aliases.get("alice", ":shrug:").?);

    // Unknown shortcode and wrong account return null.
    try std.testing.expect(aliases.get("alice", ":missing:") == null);
    try std.testing.expect(aliases.get("bob", ":shrug:") == null);

    // Validation rejects empty and oversize input.
    try std.testing.expectError(error.InvalidAlias, aliases.set("alice", "", "x"));
    try std.testing.expectError(error.InvalidAlias, aliases.set("alice", ":x:", ""));
    const long_sc = "x" ** (max_shortcode_len + 1);
    try std.testing.expectError(error.InvalidAlias, aliases.set("alice", long_sc, "y"));
    const long_rp = "y" ** (max_replacement_len + 1);
    try std.testing.expectError(error.InvalidAlias, aliases.set("alice", ":z:", long_rp));
}

test "remove returns whether an entry existed" {
    const allocator = std.testing.allocator;
    var aliases = EmojiAlias.init(allocator);
    defer aliases.deinit();

    try aliases.set("carol", ":wave:", "o/");
    try std.testing.expect(aliases.get("carol", ":wave:") != null);

    try std.testing.expect(aliases.remove("carol", ":wave:"));
    try std.testing.expect(aliases.get("carol", ":wave:") == null);

    // Removing again, or removing a never-set shortcode, returns false.
    try std.testing.expect(!aliases.remove("carol", ":wave:"));
    try std.testing.expect(!aliases.remove("carol", ":never:"));
}

test "clearAccount scopes to exact account with prefix-confusable names" {
    const allocator = std.testing.allocator;
    var aliases = EmojiAlias.init(allocator);
    defer aliases.deinit();

    // "bob" is a prefix of "bobby"; ensure clearing one leaves the other.
    try aliases.set("bob", ":a:", "1");
    try aliases.set("bob", ":b:", "2");
    try aliases.set("bobby", ":a:", "3");
    try aliases.set("bobby", ":c:", "4");

    const removed = aliases.clearAccount("bob");
    try std.testing.expectEqual(@as(usize, 2), removed);

    // bob's aliases are gone.
    try std.testing.expect(aliases.get("bob", ":a:") == null);
    try std.testing.expect(aliases.get("bob", ":b:") == null);

    // bobby's aliases survive untouched.
    try std.testing.expectEqualStrings("3", aliases.get("bobby", ":a:").?);
    try std.testing.expectEqualStrings("4", aliases.get("bobby", ":c:").?);

    // Clearing an account with no aliases removes nothing.
    try std.testing.expectEqual(@as(usize, 0), aliases.clearAccount("nobody"));
}
