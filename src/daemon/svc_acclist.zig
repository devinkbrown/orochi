//! Per-account login access list (account-side recognition).
//!
//! Each registered account owns a list of allowed hostmasks. When a connection
//! identifies to an account, the server can auto-recognize it if its live
//! `nick!user@host` matches one of the account's owned masks. This is the
//! NickServ-ACCESS-style "recognition" concept, expressed as a real account
//! property — NOT a pseudo-client and NOT the channel/server/network ACCESS
//! list (`scoped_access.zig`). The two are deliberately separate: channel
//! ACCESS gates membership/privilege on a channel; this list gates whether a
//! connection is considered to belong to the account holder.
//!
//! Storage model: a single store maps account name -> owned mask list. Masks
//! are glob patterns over the full `nick!user@host` form, supporting `*`
//! (any run, including empty) and `?` (exactly one character), matched
//! case-insensitively over ASCII. The store owns all account-name and mask
//! bytes; every mutating operation takes an allocator.

const std = @import("std");

/// Maximum owned masks per account. Keeps a single account from exhausting
/// memory and bounds the per-identify match scan.
pub const default_max_masks: usize = 32;

/// Maximum account-name length accepted as a key. IRC account names are well
/// under this; over-long names are rejected rather than silently truncated.
pub const max_account_len: usize = 128;

/// Account-name is too long to be used as a key.
pub const Error = error{AccountNameTooLong};

/// Outcome of an attempt to add a mask to an account.
pub const AddResult = enum {
    /// The mask was stored as a new entry.
    added,
    /// An equal (case-insensitive) mask already existed; nothing changed.
    duplicate,
    /// The account already holds `max_masks` entries; nothing changed.
    full,
};

/// Owned list of recognition masks for a single account.
const MaskList = struct {
    masks: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *MaskList, allocator: std.mem.Allocator) void {
        for (self.masks.items) |mask| allocator.free(mask);
        self.masks.deinit(allocator);
        self.* = .{};
    }

    fn indexOf(self: *const MaskList, mask: []const u8) ?usize {
        for (self.masks.items, 0..) |existing, index| {
            if (asciiEqualSlice(existing, mask)) return index;
        }
        return null;
    }
};

/// Account-keyed store of recognition mask lists.
pub const AccountAccess = struct {
    /// owned lower-cased account name -> owned mask list. All lookups normalize
    /// the caller's account name to lower-case, so keying is case-insensitive.
    accounts: std.StringHashMapUnmanaged(MaskList) = .empty,
    max_masks: usize = default_max_masks,

    const Self = @This();

    pub fn init(max_masks: usize) Self {
        return .{ .accounts = .empty, .max_masks = max_masks };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.accounts.deinit(allocator);
        self.* = .{};
    }

    /// Number of accounts that currently own at least one mask.
    pub fn accountCount(self: *const Self) usize {
        return self.accounts.count();
    }

    /// Number of masks owned by `account`. Zero if the account is unknown or its
    /// name is over-long.
    pub fn maskCount(self: *const Self, account: []const u8) usize {
        var buf: [max_account_len]u8 = undefined;
        const key = normalize(&buf, account) orelse return 0;
        const ml = self.accounts.getPtr(key) orelse return 0;
        return ml.masks.items.len;
    }

    /// Add `mask` to `account`'s recognition list.
    ///
    /// Returns `.duplicate` if an equal mask (ASCII case-insensitive) is already
    /// present, `.full` if the account is at `max_masks`, or `.added` on success.
    /// Account-name keying is ASCII case-insensitive.
    pub fn add(
        self: *Self,
        allocator: std.mem.Allocator,
        account: []const u8,
        mask: []const u8,
    ) (std.mem.Allocator.Error || Error)!AddResult {
        var buf: [max_account_len]u8 = undefined;
        const key = normalize(&buf, account) orelse return Error.AccountNameTooLong;

        const gop = try self.accounts.getOrPut(allocator, key);
        if (!gop.found_existing) {
            // Own the key; on any failure below, undo the slot insertion.
            const owned_key = allocator.dupe(u8, key) catch |err| {
                std.debug.assert(self.accounts.remove(key));
                return err;
            };
            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = .{};
        }

        const fresh = !gop.found_existing;
        const ml = gop.value_ptr;

        if (ml.indexOf(mask) != null) {
            if (fresh) self.dropFresh(allocator, key);
            return .duplicate;
        }
        if (ml.masks.items.len >= self.max_masks) {
            if (fresh) self.dropFresh(allocator, key);
            return .full;
        }

        const owned = try allocator.dupe(u8, mask);
        errdefer allocator.free(owned);
        ml.masks.append(allocator, owned) catch |err| {
            if (fresh) self.dropFresh(allocator, key);
            return err;
        };
        return .added;
    }

    /// Remove a mask (ASCII case-insensitive) from `account`. Returns true if a
    /// mask was removed. When the last mask is removed, the account slot is
    /// dropped so empty accounts never linger.
    pub fn remove(
        self: *Self,
        allocator: std.mem.Allocator,
        account: []const u8,
        mask: []const u8,
    ) bool {
        var buf: [max_account_len]u8 = undefined;
        const key = normalize(&buf, account) orelse return false;
        const entry = self.accounts.getEntry(key) orelse return false;
        const ml = entry.value_ptr;
        const index = ml.indexOf(mask) orelse return false;

        allocator.free(ml.masks.orderedRemove(index));

        if (ml.masks.items.len == 0) {
            const stored_key = entry.key_ptr.*;
            ml.deinit(allocator);
            std.debug.assert(self.accounts.remove(stored_key));
            allocator.free(stored_key);
        }
        return true;
    }

    /// Drop every mask owned by `account`. Returns true if the account existed.
    pub fn removeAccount(
        self: *Self,
        allocator: std.mem.Allocator,
        account: []const u8,
    ) bool {
        var buf: [max_account_len]u8 = undefined;
        const key = normalize(&buf, account) orelse return false;
        const entry = self.accounts.getEntry(key) orelse return false;
        const stored_key = entry.key_ptr.*;
        entry.value_ptr.deinit(allocator);
        std.debug.assert(self.accounts.remove(stored_key));
        allocator.free(stored_key);
        return true;
    }

    /// Borrowed view of an account's masks (valid until the next mutation).
    /// Returns an empty slice for unknown or over-long accounts.
    pub fn list(self: *const Self, account: []const u8) []const []const u8 {
        var buf: [max_account_len]u8 = undefined;
        const key = normalize(&buf, account) orelse return &.{};
        const ml = self.accounts.getPtr(key) orelse return &.{};
        return ml.masks.items;
    }

    /// True if `hostmask` (a full `nick!user@host`) matches any mask owned by
    /// `account`. This is the account-side recognition test.
    pub fn matches(self: *const Self, account: []const u8, hostmask: []const u8) bool {
        var buf: [max_account_len]u8 = undefined;
        const key = normalize(&buf, account) orelse return false;
        const ml = self.accounts.getPtr(key) orelse return false;
        for (ml.masks.items) |mask| {
            if (globMatch(mask, hostmask)) return true;
        }
        return false;
    }

    /// Remove an account slot that was just created in this `add` call before any
    /// mask was stored, so a rejected first add leaves no empty account behind.
    fn dropFresh(self: *Self, allocator: std.mem.Allocator, key: []const u8) void {
        const entry = self.accounts.getEntry(key) orelse return;
        const stored_key = entry.key_ptr.*;
        entry.value_ptr.deinit(allocator);
        std.debug.assert(self.accounts.remove(stored_key));
        allocator.free(stored_key);
    }
};

/// Iterative `*`/`?` glob matcher with ASCII case folding and no recursion.
/// `*` matches any run (including empty); `?` matches exactly one character.
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var retry_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len and pattern[pattern_index] == '*') {
            star_index = pattern_index;
            pattern_index += 1;
            retry_text_index = text_index;
            continue;
        }

        if (pattern_index < pattern.len and
            (pattern[pattern_index] == '?' or asciiEqual(pattern[pattern_index], text[text_index])))
        {
            pattern_index += 1;
            text_index += 1;
            continue;
        }

        if (star_index) |star| {
            pattern_index = star + 1;
            retry_text_index += 1;
            text_index = retry_text_index;
            continue;
        }

        return false;
    }

    while (pattern_index < pattern.len and pattern[pattern_index] == '*') {
        pattern_index += 1;
    }

    return pattern_index == pattern.len;
}

fn asciiEqual(a: u8, b: u8) bool {
    return asciiLower(a) == asciiLower(b);
}

fn asciiEqualSlice(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (asciiLower(x) != asciiLower(y)) return false;
    }
    return true;
}

fn asciiLower(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        else => byte,
    };
}

/// Lower-case `account` into `buf` and return the slice. Returns null if the
/// name exceeds `max_account_len`, so callers treat over-long names as misses.
fn normalize(buf: []u8, account: []const u8) ?[]const u8 {
    if (account.len > buf.len) return null;
    for (account, 0..) |byte, index| buf[index] = asciiLower(byte);
    return buf[0..account.len];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "globMatch supports star, question mark, and ascii case folding" {
    try std.testing.expect(globMatch("*", "anything"));
    try std.testing.expect(globMatch("*!*@*", "Bob!~b@host.example"));
    try std.testing.expect(globMatch("BOB!*@*", "bob!~x@1.2.3.4"));
    try std.testing.expect(globMatch("a?c", "abc"));
    try std.testing.expect(globMatch("a?c", "AbC"));
    try std.testing.expect(globMatch("nick!user@*.example", "nick!user@edge.EXAMPLE"));

    try std.testing.expect(!globMatch("a?c", "ac"));
    try std.testing.expect(!globMatch("alice!*@*", "bob!~x@1.2.3.4"));
    try std.testing.expect(!globMatch("*@trusted.test", "n!u@other.test"));
    try std.testing.expect(!globMatch("", "x"));
    try std.testing.expect(globMatch("", ""));
}

test "globMatch handles trailing stars and exact tails" {
    try std.testing.expect(globMatch("foo*", "foo"));
    try std.testing.expect(globMatch("foo*", "foobar"));
    try std.testing.expect(globMatch("*bar", "foobar"));
    try std.testing.expect(globMatch("f*o*bar", "fooobar"));
    try std.testing.expect(!globMatch("foo*x", "foobar"));
}

test "add stores masks and recognizes matching hostmasks" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "ivy", "ivy!*@garden.test"));
    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "ivy", "*!*@trusted.test"));

    try std.testing.expectEqual(@as(usize, 1), store.accountCount());
    try std.testing.expectEqual(@as(usize, 2), store.maskCount("ivy"));

    // Recognition: account-side match against live nick!user@host.
    try std.testing.expect(store.matches("ivy", "Ivy!id@garden.test"));
    try std.testing.expect(store.matches("ivy", "anyone!u@trusted.test"));
    try std.testing.expect(!store.matches("ivy", "ivy!u@evil.test"));
    // Unknown account never matches.
    try std.testing.expect(!store.matches("ghost", "ivy!id@garden.test"));
}

test "account key is matched case-insensitively" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "Ren", "ren!*@home.test"));
    // Same account, different case: must collapse onto one slot.
    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "REN", "ren!*@work.test"));

    try std.testing.expectEqual(@as(usize, 1), store.accountCount());
    try std.testing.expectEqual(@as(usize, 2), store.maskCount("ren"));
    try std.testing.expect(store.matches("rEn", "ren!u@work.test"));
}

test "duplicate masks collapse case-insensitively without growing the list" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "sam", "sam!*@host.test"));
    try std.testing.expectEqual(AddResult.duplicate, try store.add(allocator, "sam", "sam!*@host.test"));
    try std.testing.expectEqual(AddResult.duplicate, try store.add(allocator, "sam", "SAM!*@HOST.TEST"));

    try std.testing.expectEqual(@as(usize, 1), store.maskCount("sam"));
}

test "rejected first add on a fresh account leaves no empty slot" {
    const allocator = std.testing.allocator;

    // max_masks == 0: the very first add is rejected as .full and must not
    // leave a lingering empty account behind.
    var tiny = AccountAccess.init(0);
    defer tiny.deinit(allocator);
    try std.testing.expectEqual(AddResult.full, try tiny.add(allocator, "newbie", "n!*@host"));
    try std.testing.expectEqual(@as(usize, 0), tiny.accountCount());
    try std.testing.expectEqual(@as(usize, 0), tiny.maskCount("newbie"));
}

test "over-long account names are rejected and never match" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    const long = "a" ** (max_account_len + 1);
    try std.testing.expectError(Error.AccountNameTooLong, store.add(allocator, long, "x!*@host"));
    try std.testing.expectEqual(@as(usize, 0), store.accountCount());
    try std.testing.expect(!store.matches(long, "x!u@host"));
    try std.testing.expect(!store.remove(allocator, long, "x!*@host"));
}

test "max_masks bound is enforced per account" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(2);
    defer store.deinit(allocator);

    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "cap", "a!*@1.test"));
    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "cap", "b!*@2.test"));
    try std.testing.expectEqual(AddResult.full, try store.add(allocator, "cap", "c!*@3.test"));

    try std.testing.expectEqual(@as(usize, 2), store.maskCount("cap"));
    // Bound is per-account: a different account starts fresh.
    try std.testing.expectEqual(AddResult.added, try store.add(allocator, "other", "x!*@9.test"));
}

test "list returns owned masks and empty slice for unknown account" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), store.list("nobody").len);

    _ = try store.add(allocator, "leah", "leah!*@a.test");
    _ = try store.add(allocator, "leah", "leah!*@b.test");

    const masks = store.list("leah");
    try std.testing.expectEqual(@as(usize, 2), masks.len);
    try std.testing.expectEqualStrings("leah!*@a.test", masks[0]);
    try std.testing.expectEqualStrings("leah!*@b.test", masks[1]);
}

test "remove deletes one mask and drops the account when empty" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    _ = try store.add(allocator, "max", "max!*@a.test");
    _ = try store.add(allocator, "max", "max!*@b.test");

    // Case-insensitive removal of one mask.
    try std.testing.expect(store.remove(allocator, "max", "MAX!*@A.TEST"));
    try std.testing.expectEqual(@as(usize, 1), store.maskCount("max"));
    try std.testing.expect(!store.matches("max", "max!u@a.test"));
    try std.testing.expect(store.matches("max", "max!u@b.test"));

    // Removing a non-existent mask is a no-op false.
    try std.testing.expect(!store.remove(allocator, "max", "max!*@nope.test"));

    // Removing the last mask drops the account slot entirely.
    try std.testing.expect(store.remove(allocator, "max", "max!*@b.test"));
    try std.testing.expectEqual(@as(usize, 0), store.maskCount("max"));
    try std.testing.expectEqual(@as(usize, 0), store.accountCount());

    // Removing from an unknown account is false.
    try std.testing.expect(!store.remove(allocator, "max", "max!*@a.test"));
}

test "removeAccount clears every mask for an account" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    _ = try store.add(allocator, "kit", "kit!*@1.test");
    _ = try store.add(allocator, "kit", "kit!*@2.test");
    _ = try store.add(allocator, "zed", "zed!*@3.test");

    try std.testing.expect(store.removeAccount(allocator, "kit"));
    try std.testing.expectEqual(@as(usize, 0), store.maskCount("kit"));
    try std.testing.expectEqual(@as(usize, 1), store.accountCount());
    try std.testing.expect(store.matches("zed", "zed!u@3.test"));

    try std.testing.expect(!store.removeAccount(allocator, "kit"));
}

test "no leaks across many accounts and masks" {
    const allocator = std.testing.allocator;
    var store = AccountAccess.init(default_max_masks);
    defer store.deinit(allocator);

    var account_buf: [32]u8 = undefined;
    var mask_buf: [64]u8 = undefined;
    var a: usize = 0;
    while (a < 8) : (a += 1) {
        const account = try std.fmt.bufPrint(&account_buf, "acct{d}", .{a});
        var m: usize = 0;
        while (m < 4) : (m += 1) {
            const mask = try std.fmt.bufPrint(&mask_buf, "n{d}!*@host{d}.test", .{ m, m });
            try std.testing.expectEqual(AddResult.added, try store.add(allocator, account, mask));
        }
    }
    try std.testing.expectEqual(@as(usize, 8), store.accountCount());
    // deinit (via defer) must release every account key, mask list, and mask.
}
