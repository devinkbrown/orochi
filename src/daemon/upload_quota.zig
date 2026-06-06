//! Bounded per-account upload byte accounting.
const std = @import("std");

pub const default_cap: u64 = 100 * 1024 * 1024;
pub const max_accounts: usize = 65536;
pub const max_account_len: usize = 128;

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    TooManyAccounts,
};

pub const UploadQuota = struct {
    allocator: std.mem.Allocator,
    totals: std.StringHashMap(u64),
    cap: u64,
    limit: usize,

    pub fn init(allocator: std.mem.Allocator) UploadQuota {
        return initWithCap(allocator, default_cap);
    }

    pub fn initWithCap(allocator: std.mem.Allocator, cap: u64) UploadQuota {
        return .{
            .allocator = allocator,
            .totals = std.StringHashMap(u64).init(allocator),
            .cap = cap,
            .limit = max_accounts,
        };
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, cap: u64, limit: usize) UploadQuota {
        return .{
            .allocator = allocator,
            .totals = std.StringHashMap(u64).init(allocator),
            .cap = cap,
            .limit = limit,
        };
    }

    pub fn deinit(self: *UploadQuota) void {
        var it = self.totals.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.totals.deinit();
        self.* = undefined;
    }

    pub fn add(self: *UploadQuota, account: []const u8, bytes: u64) Error!bool {
        try validateAccount(account);

        if (self.totals.getPtr(account)) |total| {
            if (bytes > self.cap - total.*) return false;
            total.* += bytes;
            return true;
        }

        if (bytes > self.cap) return false;
        if (self.totals.count() >= self.limit) return error.TooManyAccounts;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.totals.putNoClobber(owned, bytes);
        return true;
    }

    pub fn used(self: *const UploadQuota, account: []const u8) u64 {
        return self.totals.get(account) orelse 0;
    }

    pub fn reset(self: *UploadQuota, account: []const u8) bool {
        const kv = self.totals.fetchRemove(account) orelse return false;
        self.allocator.free(kv.key);
        return true;
    }

    pub fn count(self: *const UploadQuota) usize {
        return self.totals.count();
    }

    fn validateAccount(account: []const u8) Error!void {
        if (account.len == 0) return error.InvalidAccount;
        if (account.len > max_account_len) return error.AccountTooLong;
    }
};

const testing = std.testing;

test "add tracks used bytes per account" {
    var quota = UploadQuota.initWithCap(testing.allocator, 100);
    defer quota.deinit();

    try testing.expect(try quota.add("alice", 30));
    try testing.expect(try quota.add("alice", 25));
    try testing.expect(try quota.add("bob", 7));
    try testing.expectEqual(@as(u64, 55), quota.used("alice"));
    try testing.expectEqual(@as(u64, 7), quota.used("bob"));
    try testing.expectEqual(@as(u64, 0), quota.used("carol"));
}

test "add returns false when the cap would be exceeded" {
    var quota = UploadQuota.initWithCap(testing.allocator, 10);
    defer quota.deinit();

    try testing.expect(try quota.add("alice", 8));
    try testing.expect(!try quota.add("alice", 3));
    try testing.expect(!try quota.add("bob", 11));
    try testing.expectEqual(@as(u64, 8), quota.used("alice"));
    try testing.expectEqual(@as(u64, 0), quota.used("bob"));
}

test "reset removes an account total" {
    var quota = UploadQuota.initWithCap(testing.allocator, 100);
    defer quota.deinit();

    _ = try quota.add("alice", 5);
    try testing.expect(quota.reset("alice"));
    try testing.expect(!quota.reset("alice"));
    try testing.expectEqual(@as(u64, 0), quota.used("alice"));
}

test "account limit is enforced" {
    var quota = UploadQuota.initWithOptions(testing.allocator, 100, 1);
    defer quota.deinit();

    _ = try quota.add("alice", 1);
    try testing.expectError(error.TooManyAccounts, quota.add("bob", 1));
}
