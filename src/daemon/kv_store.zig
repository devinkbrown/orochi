const std = @import("std");

const max_accounts = 4096;
const max_account_len = 64;
const max_keys_per_account = 64;
const max_key_len = 64;
const max_value_len = 256;

pub const KvStoreError = error{
    AccountTooLong,
    KeyTooLong,
    ValueTooLong,
    TooManyAccounts,
    TooManyKeys,
};

pub const KvStore = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(AccountMap),

    pub fn init(allocator: std.mem.Allocator) KvStore {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(AccountMap).init(allocator),
        };
    }

    pub fn deinit(self: *KvStore) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn put(self: *KvStore, account: []const u8, key: []const u8, value: []const u8) !void {
        try checkAccount(account);
        try checkKey(key);
        if (value.len > max_value_len) return KvStoreError.ValueTooLong;

        if (!self.accounts.contains(account) and self.accounts.count() >= max_accounts) {
            return KvStoreError.TooManyAccounts;
        }

        if (self.accounts.getPtr(account)) |account_map| {
            try account_map.put(key, value);
            return;
        }

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);

        var account_map = AccountMap.init(self.allocator);
        errdefer account_map.deinit();
        try account_map.put(key, value);
        try self.accounts.put(owned_account, account_map);
    }

    pub fn get(self: *const KvStore, account: []const u8, key: []const u8) ?[]const u8 {
        if (!validAccount(account) or !validKey(key)) return null;
        const account_map = self.accounts.getPtr(account) orelse return null;
        return account_map.get(key);
    }

    pub fn del(self: *KvStore, account: []const u8, key: []const u8) bool {
        if (!validAccount(account) or !validKey(key)) return false;
        const entry = self.accounts.getEntry(account) orelse return false;
        const removed = entry.value_ptr.del(key);
        if (removed and entry.value_ptr.count() == 0) {
            var owned_map = entry.value_ptr.*;
            const owned_key = entry.key_ptr.*;
            self.accounts.removeByPtr(entry.key_ptr);
            owned_map.deinit();
            self.allocator.free(owned_key);
        }
        return removed;
    }
};

const AccountMap = struct {
    allocator: std.mem.Allocator,
    items: std.StringHashMap([]u8),

    fn init(allocator: std.mem.Allocator) AccountMap {
        return .{
            .allocator = allocator,
            .items = std.StringHashMap([]u8).init(allocator),
        };
    }

    fn deinit(self: *AccountMap) void {
        var it = self.items.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.items.deinit();
    }

    fn put(self: *AccountMap, key: []const u8, value: []const u8) !void {
        if (!self.items.contains(key) and self.items.count() >= max_keys_per_account) {
            return KvStoreError.TooManyKeys;
        }

        if (self.items.getPtr(key)) |stored_value| {
            const next_value = try self.allocator.dupe(u8, value);
            self.allocator.free(stored_value.*);
            stored_value.* = next_value;
            return;
        }

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);
        try self.items.put(owned_key, owned_value);
    }

    fn get(self: *const AccountMap, key: []const u8) ?[]const u8 {
        return self.items.get(key);
    }

    fn del(self: *AccountMap, key: []const u8) bool {
        if (self.items.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }

    fn count(self: *const AccountMap) usize {
        return self.items.count();
    }
};

fn checkAccount(account: []const u8) KvStoreError!void {
    if (!validAccount(account)) return KvStoreError.AccountTooLong;
}

fn checkKey(key: []const u8) KvStoreError!void {
    if (!validKey(key)) return KvStoreError.KeyTooLong;
}

fn validAccount(account: []const u8) bool {
    return account.len <= max_account_len;
}

fn validKey(key: []const u8) bool {
    return key.len <= max_key_len;
}

const testing = std.testing;

test "put and get values per account" {
    var store = KvStore.init(testing.allocator);
    defer store.deinit();

    try store.put("alice", "color", "blue");
    try store.put("bob", "color", "green");

    try testing.expectEqualStrings("blue", store.get("alice", "color").?);
    try testing.expectEqualStrings("green", store.get("bob", "color").?);
    try testing.expect(store.get("carol", "color") == null);
}

test "put replaces an existing value without changing other keys" {
    var store = KvStore.init(testing.allocator);
    defer store.deinit();

    try store.put("alice", "color", "blue");
    try store.put("alice", "status", "ready");
    try store.put("alice", "color", "red");

    try testing.expectEqualStrings("red", store.get("alice", "color").?);
    try testing.expectEqualStrings("ready", store.get("alice", "status").?);
}

test "delete removes only the selected key" {
    var store = KvStore.init(testing.allocator);
    defer store.deinit();

    try store.put("alice", "one", "1");
    try store.put("alice", "two", "2");

    try testing.expect(store.del("alice", "one"));
    try testing.expect(!store.del("alice", "one"));
    try testing.expect(store.get("alice", "one") == null);
    try testing.expectEqualStrings("2", store.get("alice", "two").?);
}

test "caps reject oversized values and too many keys" {
    var store = KvStore.init(testing.allocator);
    defer store.deinit();

    var value: [max_value_len + 1]u8 = undefined;
    @memset(&value, 'x');
    try testing.expectError(KvStoreError.ValueTooLong, store.put("alice", "large", &value));

    var key_buf: [8]u8 = undefined;
    for (0..max_keys_per_account) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "k{d}", .{i});
        try store.put("alice", key, "v");
    }
    try testing.expectError(KvStoreError.TooManyKeys, store.put("alice", "overflow", "v"));
}
