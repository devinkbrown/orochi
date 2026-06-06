//! Account to client-certificate fingerprint bindings for SASL EXTERNAL.
//!
//! The store accepts caller-supplied SHA-256 hex certificate fingerprints and
//! keeps normalized lowercase account and fingerprint keys. It does not parse
//! certificates, recompute fingerprints, or own any transport state.
const std = @import("std");

/// Runtime limits for `CertStore`.
pub const Params = struct {
    /// Maximum number of accounts that may have at least one fingerprint.
    max_accounts: usize = 65536,
    /// Maximum number of fingerprints retained for one account.
    max_fps_per_account: usize = 16,
    /// Expected hex fingerprint length; SHA-256 hex is 64 bytes.
    fp_len: usize = 64,
    /// Maximum account name length in bytes.
    max_account_bytes: usize = 64,
};

/// Errors returned by `CertStore` operations.
pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    InvalidFingerprint,
    TooManyAccounts,
    TooManyFingerprints,
    FingerprintInUse,
    OutputTooSmall,
};

const FingerprintList = struct {
    items: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *FingerprintList, allocator: std.mem.Allocator) void {
        self.items.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const FingerprintList, fingerprint: []const u8) ?usize {
        for (self.items.items, 0..) |item, idx| {
            if (eqlIgnoreCase(item, fingerprint)) return idx;
        }
        return null;
    }
};

const EnsuredAccount = struct {
    entry: std.StringHashMap(FingerprintList).Entry,
    created: bool,
};

/// Owns account to certificate-fingerprint bindings plus a reverse index.
pub const CertStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    accounts: std.StringHashMap(FingerprintList),
    reverse: std.StringHashMap([]const u8),

    /// Initialize an empty certificate binding store.
    pub fn init(allocator: std.mem.Allocator, params: Params) CertStore {
        return .{
            .allocator = allocator,
            .params = params,
            .accounts = std.StringHashMap(FingerprintList).init(allocator),
            .reverse = std.StringHashMap([]const u8).init(allocator),
        };
    }

    /// Free every owned account key, fingerprint key, and list allocation.
    pub fn deinit(self: *CertStore) void {
        var rev_it = self.reverse.iterator();
        while (rev_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.reverse.deinit();

        var account_it = self.accounts.iterator();
        while (account_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    /// Add `fingerprint` as an allowed SASL EXTERNAL credential for `account`.
    pub fn add(self: *CertStore, account: []const u8, fingerprint: []const u8) Error!void {
        try self.validateAccount(account);
        try self.validateFingerprint(fingerprint);

        if (self.findReverseEntry(fingerprint)) |reverse_entry| {
            if (eqlIgnoreCase(reverse_entry.value_ptr.*, account)) return;
            return error.FingerprintInUse;
        }

        const ensured = try self.ensureAccount(account);
        const account_entry = ensured.entry;
        errdefer if (ensured.created and account_entry.value_ptr.items.items.len == 0) {
            self.dropAccount(account_entry);
        };
        if (account_entry.value_ptr.items.items.len >= self.params.max_fps_per_account) {
            return error.TooManyFingerprints;
        }

        const owned_fp = try self.dupeLower(fingerprint);
        errdefer self.allocator.free(owned_fp);

        try account_entry.value_ptr.items.append(self.allocator, owned_fp);
        errdefer _ = account_entry.value_ptr.items.orderedRemove(account_entry.value_ptr.items.items.len - 1);

        try self.reverse.putNoClobber(owned_fp, account_entry.key_ptr.*);
    }

    /// Remove `fingerprint` from `account`, returning whether a binding existed.
    pub fn remove(self: *CertStore, account: []const u8, fingerprint: []const u8) bool {
        if (!self.accountLooksValid(account) or !self.fingerprintLooksValid(fingerprint)) return false;

        const account_entry = self.findAccountEntry(account) orelse return false;
        const idx = account_entry.value_ptr.indexOf(fingerprint) orelse return false;
        const removed_fp = account_entry.value_ptr.items.orderedRemove(idx);

        const removed_reverse = self.reverse.fetchRemove(removed_fp) orelse {
            self.allocator.free(removed_fp);
            if (account_entry.value_ptr.items.items.len == 0) self.dropAccount(account_entry);
            return true;
        };
        self.allocator.free(removed_reverse.key);

        if (account_entry.value_ptr.items.items.len == 0) self.dropAccount(account_entry);
        return true;
    }

    /// Copy the fingerprint list for `account` into `buf` and return the view.
    pub fn list(self: *const CertStore, account: []const u8, buf: [][]const u8) Error![]const []const u8 {
        try self.validateAccount(account);

        const list_entry = self.findAccountEntryConst(account) orelse return buf[0..0];
        if (buf.len < list_entry.value_ptr.items.items.len) return error.OutputTooSmall;

        for (list_entry.value_ptr.items.items, 0..) |fingerprint, idx| {
            buf[idx] = fingerprint;
        }
        return buf[0..list_entry.value_ptr.items.items.len];
    }

    /// Return the normalized account that owns `fingerprint`, if any.
    pub fn accountFor(self: *const CertStore, fingerprint: []const u8) ?[]const u8 {
        if (!self.fingerprintLooksValid(fingerprint)) return null;
        const reverse_entry = self.findReverseEntryConst(fingerprint) orelse return null;
        return reverse_entry.value_ptr.*;
    }

    /// Return true when `account` has `fingerprint`.
    pub fn has(self: *const CertStore, account: []const u8, fingerprint: []const u8) bool {
        if (!self.accountLooksValid(account) or !self.fingerprintLooksValid(fingerprint)) return false;
        const list_entry = self.findAccountEntryConst(account) orelse return false;
        return list_entry.value_ptr.indexOf(fingerprint) != null;
    }

    /// Return the number of fingerprints bound to `account`.
    pub fn count(self: *const CertStore, account: []const u8) usize {
        if (!self.accountLooksValid(account)) return 0;
        const list_entry = self.findAccountEntryConst(account) orelse return 0;
        return list_entry.value_ptr.items.items.len;
    }

    fn ensureAccount(self: *CertStore, account: []const u8) Error!EnsuredAccount {
        if (self.findAccountEntry(account)) |entry| return .{ .entry = entry, .created = false };
        if (self.accounts.count() >= self.params.max_accounts) return error.TooManyAccounts;

        const owned_account = try self.dupeLower(account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return .{ .entry = self.accounts.getEntry(owned_account).?, .created = true };
    }

    fn dropAccount(self: *CertStore, entry: std.StringHashMap(FingerprintList).Entry) void {
        const owned_account = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_account);
    }

    fn findAccountEntry(self: *CertStore, account: []const u8) ?std.StringHashMap(FingerprintList).Entry {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (eqlIgnoreCase(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }

    fn findAccountEntryConst(
        self: *const CertStore,
        account: []const u8,
    ) ?std.StringHashMap(FingerprintList).Entry {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (eqlIgnoreCase(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }

    fn findReverseEntry(self: *CertStore, fingerprint: []const u8) ?std.StringHashMap([]const u8).Entry {
        var it = self.reverse.iterator();
        while (it.next()) |entry| {
            if (eqlIgnoreCase(entry.key_ptr.*, fingerprint)) return entry;
        }
        return null;
    }

    fn findReverseEntryConst(
        self: *const CertStore,
        fingerprint: []const u8,
    ) ?std.StringHashMap([]const u8).Entry {
        var it = self.reverse.iterator();
        while (it.next()) |entry| {
            if (eqlIgnoreCase(entry.key_ptr.*, fingerprint)) return entry;
        }
        return null;
    }

    fn validateAccount(self: *const CertStore, account: []const u8) error{InvalidAccount}!void {
        if (!self.accountLooksValid(account)) return error.InvalidAccount;
    }

    fn validateFingerprint(self: *const CertStore, fingerprint: []const u8) error{InvalidFingerprint}!void {
        if (!self.fingerprintLooksValid(fingerprint)) return error.InvalidFingerprint;
    }

    fn accountLooksValid(self: *const CertStore, account: []const u8) bool {
        return account.len != 0 and account.len <= self.params.max_account_bytes;
    }

    fn fingerprintLooksValid(self: *const CertStore, fingerprint: []const u8) bool {
        if (fingerprint.len != self.params.fp_len) return false;
        for (fingerprint) |ch| {
            if (!isHex(ch)) return false;
        }
        return true;
    }

    fn dupeLower(self: *CertStore, input: []const u8) std.mem.Allocator.Error![]u8 {
        const out = try self.allocator.dupe(u8, input);
        for (out) |*ch| ch.* = std.ascii.toLower(ch.*);
        return out;
    }
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (std.ascii.toLower(left) != std.ascii.toLower(right)) return false;
    }
    return true;
}

fn isHex(ch: u8) bool {
    return switch (ch) {
        '0'...'9', 'a'...'f', 'A'...'F' => true,
        else => false,
    };
}

const testing = std.testing;

test "add list has and remove maintain account bindings" {
    // Arrange
    var store = CertStore.init(testing.allocator, .{});
    defer store.deinit();
    var out: [2][]const u8 = undefined;

    // Act
    try store.add("alice", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    try store.add("alice", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const listed = try store.list("alice", out[0..]);

    // Assert
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", listed[0]);
    try testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", listed[1]);

    // Act
    const removed = store.remove("alice", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    // Assert
    try testing.expect(removed);
    try testing.expect(!store.has("alice", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    try testing.expect(store.has("alice", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    try testing.expectEqual(@as(usize, 1), store.count("alice"));
    try testing.expect(!store.remove("alice", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

test "reverse accountFor reflects add and remove" {
    // Arrange
    var store = CertStore.init(testing.allocator, .{});
    defer store.deinit();
    const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // Act
    try store.add("Alice", fp);
    const account = store.accountFor(fp);

    // Assert
    try testing.expect(account != null);
    try testing.expectEqualStrings("alice", account.?);

    // Act
    const removed = store.remove("alice", fp);

    // Assert
    try testing.expect(removed);
    try testing.expect(store.accountFor(fp) == null);
    try testing.expectEqual(@as(usize, 0), store.count("alice"));
}

test "duplicate adds are no-ops and fingerprints cannot move accounts" {
    // Arrange
    var store = CertStore.init(testing.allocator, .{});
    defer store.deinit();
    var out: [2][]const u8 = undefined;
    const fp = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    // Act
    try store.add("ALICE", fp);
    try store.add("alice", fp);
    const listed = try store.list("Alice", out[0..]);

    // Assert
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings(fp, listed[0]);
    try testing.expectError(error.FingerprintInUse, store.add("bob", fp));
    try testing.expectEqualStrings("alice", store.accountFor(fp).?);
}

test "hex length and digits are validated" {
    // Arrange
    var store = CertStore.init(testing.allocator, .{});
    defer store.deinit();

    // Act and Assert
    try testing.expectError(error.InvalidFingerprint, store.add("alice", ""));
    try testing.expectError(
        error.InvalidFingerprint,
        store.add("alice", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"),
    );
    try testing.expectError(
        error.InvalidFingerprint,
        store.add("alice", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"),
    );
    try testing.expect(!store.has("alice", "short"));
    try testing.expect(store.accountFor("short") == null);
}

test "per-account and global account limits are enforced" {
    // Arrange
    var store = CertStore.init(testing.allocator, .{
        .max_accounts = 2,
        .max_fps_per_account = 2,
        .fp_len = 64,
        .max_account_bytes = 16,
    });
    defer store.deinit();

    // Act
    try store.add("alice", "1000000000000000000000000000000000000000000000000000000000000000");
    try store.add("alice", "2000000000000000000000000000000000000000000000000000000000000000");
    try store.add("bob", "3000000000000000000000000000000000000000000000000000000000000000");

    // Assert
    try testing.expectError(
        error.TooManyFingerprints,
        store.add("alice", "4000000000000000000000000000000000000000000000000000000000000000"),
    );
    try testing.expectError(
        error.TooManyAccounts,
        store.add("carol", "5000000000000000000000000000000000000000000000000000000000000000"),
    );

    try testing.expect(store.remove("bob", "3000000000000000000000000000000000000000000000000000000000000000"));
    try store.add("carol", "5000000000000000000000000000000000000000000000000000000000000000");
    try testing.expectEqualStrings(
        "carol",
        store.accountFor("5000000000000000000000000000000000000000000000000000000000000000").?,
    );
}

test "case-insensitive accounts and fingerprints are normalized" {
    // Arrange
    var store = CertStore.init(testing.allocator, .{});
    defer store.deinit();
    var out: [1][]const u8 = undefined;
    const mixed = "ABCDEFabcdefABCDEFabcdefABCDEFabcdefABCDEFabcdefABCDEFabcdef1234";
    const lower = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef1234";

    // Act
    try store.add("ALICE", mixed);
    const listed = try store.list("alice", out[0..]);

    // Assert
    try testing.expect(store.has("Alice", lower));
    try testing.expect(store.has("alice", mixed));
    try testing.expectEqualStrings("alice", store.accountFor(mixed).?);
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings(lower, listed[0]);
}

test "list validates accounts and output capacity" {
    // Arrange
    var store = CertStore.init(testing.allocator, .{ .max_account_bytes = 5 });
    defer store.deinit();
    var empty_out: [0][]const u8 = .{};
    var one_out: [1][]const u8 = undefined;

    // Act
    try store.add("alice", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    // Assert
    try testing.expectError(error.InvalidAccount, store.add("", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
    try testing.expectError(error.InvalidAccount, store.list("toolong", one_out[0..]));
    try testing.expectError(error.OutputTooSmall, store.list("alice", empty_out[0..]));
    try testing.expectEqual(@as(usize, 0), (try store.list("bob", one_out[0..])).len);
}

test {
    std.testing.refAllDecls(@This());
}
