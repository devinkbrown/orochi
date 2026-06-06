//! Per-account personal channel aliases for the Mizuchi IRC daemon.
//!
//! Each account may register short, private aliases that resolve to a full
//! channel name. Aliases are scoped to the owning account: two accounts may
//! independently use the same alias spelling without collision.
//!
//! Storage uses a flat map keyed by a composite "account\x00alias" string so
//! that all of an account's aliases share a common, scannable prefix. The map
//! owns every key and value; all bytes are duplicated on insert and freed on
//! removal or teardown.

const std = @import("std");

/// Separator byte joining the account segment and the alias segment inside a
/// composite key. NUL can never appear inside an IRC account name or alias, so
/// it is an unambiguous delimiter.
const KEY_SEP: u8 = 0;

/// Maximum permitted alias length, in bytes.
const MAX_ALIAS_LEN: usize = 32;

/// Maximum permitted channel-name length, in bytes.
const MAX_CHANNEL_LEN: usize = 64;

/// Errors surfaced when registering an alias.
pub const AliasError = error{
    /// The alias was empty, the channel was empty, the alias exceeded
    /// MAX_ALIAS_LEN, or the channel exceeded MAX_CHANNEL_LEN.
    InvalidAlias,
};

/// A registry of per-account personal channel aliases.
pub const ChannelAlias = struct {
    allocator: std.mem.Allocator,
    /// Maps "account\x00alias" -> channel name. Both keys and values are owned.
    entries: std.StringHashMapUnmanaged([]const u8),

    /// Create an empty registry backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ChannelAlias {
        return .{
            .allocator = allocator,
            .entries = .empty,
        };
    }

    /// Free every owned key and value, then the backing table. The registry
    /// must not be used after this call.
    pub fn deinit(self: *ChannelAlias) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Build the composite "account\x00alias" lookup key. Caller owns the
    /// returned slice.
    fn makeKey(self: *ChannelAlias, account: []const u8, alias: []const u8) ![]u8 {
        const key = try self.allocator.alloc(u8, account.len + 1 + alias.len);
        @memcpy(key[0..account.len], account);
        key[account.len] = KEY_SEP;
        @memcpy(key[account.len + 1 ..], alias);
        return key;
    }

    /// Register `alias` for `account`, resolving to `channel`. Overwriting an
    /// existing alias frees the prior channel value. Rejects an empty or
    /// oversize alias/channel with `error.InvalidAlias`.
    pub fn set(
        self: *ChannelAlias,
        account: []const u8,
        alias: []const u8,
        channel: []const u8,
    ) AliasError!void {
        if (alias.len == 0 or alias.len > MAX_ALIAS_LEN) return error.InvalidAlias;
        if (channel.len == 0 or channel.len > MAX_CHANNEL_LEN) return error.InvalidAlias;

        // Duplicate the value up front; on any failure nothing is mutated.
        const value = self.allocator.dupe(u8, channel) catch return error.InvalidAlias;
        errdefer self.allocator.free(value);

        // Build the composite key once; reuse it for both the existence check
        // and, if needed, the insert. It is freed here only when an entry
        // already exists (the map keeps its own owned key in that case).
        const key = self.makeKey(account, alias) catch return error.InvalidAlias;
        errdefer self.allocator.free(key);

        if (self.entries.getEntry(key)) |existing| {
            // Existing key stays in the map; only swap the owned value and
            // discard the freshly built lookup key.
            self.allocator.free(key);
            self.allocator.free(existing.value_ptr.*);
            existing.value_ptr.* = value;
            return;
        }

        self.entries.put(self.allocator, key, value) catch return error.InvalidAlias;
    }

    /// Resolve `alias` for `account` to its channel name, or null if unset.
    /// The returned slice is owned by the registry and remains valid until the
    /// alias is overwritten, removed, or the registry is deinitialized.
    pub fn resolve(self: *ChannelAlias, account: []const u8, alias: []const u8) ?[]const u8 {
        const key = self.makeKey(account, alias) catch return null;
        defer self.allocator.free(key);
        return self.entries.get(key);
    }

    /// Remove `alias` for `account`. Returns true if an entry was removed.
    pub fn remove(self: *ChannelAlias, account: []const u8, alias: []const u8) bool {
        const key = self.makeKey(account, alias) catch return false;
        defer self.allocator.free(key);

        if (self.entries.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    /// Remove every alias owned by `account`. Returns the number of aliases
    /// removed. Only keys whose account segment exactly matches `account`
    /// (i.e. begin with "account\x00") are affected, so a different account
    /// whose name shares a prefix is never touched.
    pub fn clearAccount(self: *ChannelAlias, account: []const u8) usize {
        const prefix = self.allocator.alloc(u8, account.len + 1) catch return 0;
        defer self.allocator.free(prefix);
        @memcpy(prefix[0..account.len], account);
        prefix[account.len] = KEY_SEP;

        // Collect matching keys first; mutating the map while iterating is
        // unsafe, so we gather then delete.
        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            if (std.mem.startsWith(u8, k, prefix)) {
                doomed.append(self.allocator, k) catch continue;
            }
        }

        var removed: usize = 0;
        for (doomed.items) |k| {
            if (self.entries.fetchRemove(k)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                removed += 1;
            }
        }
        return removed;
    }
};

test "set, resolve, and overwrite" {
    const a = std.testing.allocator;
    var reg = ChannelAlias.init(a);
    defer reg.deinit();

    try reg.set("alice", "dev", "#development");
    try std.testing.expectEqualStrings("#development", reg.resolve("alice", "dev").?);

    // Overwrite frees the old value and stores the new one.
    try reg.set("alice", "dev", "#dev-team");
    try std.testing.expectEqualStrings("#dev-team", reg.resolve("alice", "dev").?);

    // Missing alias resolves to null.
    try std.testing.expect(reg.resolve("alice", "nope") == null);

    // Validation: empty and oversize inputs are rejected.
    try std.testing.expectError(error.InvalidAlias, reg.set("alice", "", "#x"));
    try std.testing.expectError(error.InvalidAlias, reg.set("alice", "x", ""));
    try std.testing.expectError(error.InvalidAlias, reg.set("alice", "a" ** 33, "#x"));
    try std.testing.expectError(error.InvalidAlias, reg.set("alice", "x", "#" ++ "c" ** 64));
}

test "remove returns whether an entry existed" {
    const a = std.testing.allocator;
    var reg = ChannelAlias.init(a);
    defer reg.deinit();

    try reg.set("bob", "home", "#bob-lounge");
    try std.testing.expect(reg.remove("bob", "home"));
    try std.testing.expect(reg.resolve("bob", "home") == null);

    // Removing again, or removing an unknown alias, returns false.
    try std.testing.expect(!reg.remove("bob", "home"));
    try std.testing.expect(!reg.remove("bob", "ghost"));
}

test "clearAccount is prefix-confusable-safe" {
    const a = std.testing.allocator;
    var reg = ChannelAlias.init(a);
    defer reg.deinit();

    // "carol" and "carolyn" share the textual prefix "carol" but must remain
    // independently scoped thanks to the NUL delimiter.
    try reg.set("carol", "a", "#carol-a");
    try reg.set("carol", "b", "#carol-b");
    try reg.set("carolyn", "a", "#carolyn-a");

    const removed = reg.clearAccount("carol");
    try std.testing.expectEqual(@as(usize, 2), removed);

    // carol fully cleared.
    try std.testing.expect(reg.resolve("carol", "a") == null);
    try std.testing.expect(reg.resolve("carol", "b") == null);

    // carolyn untouched.
    try std.testing.expectEqualStrings("#carolyn-a", reg.resolve("carolyn", "a").?);

    // Clearing an account with no aliases removes nothing.
    try std.testing.expectEqual(@as(usize, 0), reg.clearAccount("dave"));
}
