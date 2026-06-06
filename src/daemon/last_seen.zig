//! Per-account last activity timestamps.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyAccount,
    AccountTooLong,
    TooManyAccounts,
};

pub const Config = struct {
    max_accounts: usize = 131_072,
    max_account_len: usize = 128,
};

pub const LastSeen = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    accounts: std.StringHashMap(i64),

    pub fn init(allocator: std.mem.Allocator) LastSeen {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) LastSeen {
        std.debug.assert(cfg.max_accounts > 0);
        std.debug.assert(cfg.max_account_len > 0);
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .accounts = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn deinit(self: *LastSeen) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn touch(self: *LastSeen, account: []const u8, now: i64) Error!void {
        try self.validateAccount(account);
        if (self.accounts.getPtr(account)) |seen_at| {
            seen_at.* = now;
            return;
        }
        if (self.accounts.count() >= self.cfg.max_accounts) return error.TooManyAccounts;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.accounts.putNoClobber(owned, now);
    }

    pub fn get(self: *const LastSeen, account: []const u8) ?i64 {
        return self.accounts.get(account);
    }

    pub fn idleMs(self: *const LastSeen, account: []const u8, now: i64) ?i64 {
        const last = self.get(account) orelse return null;
        const delta = @as(i128, now) - @as(i128, last);
        if (delta <= 0) return 0;
        if (delta > std.math.maxInt(i64)) return std.math.maxInt(i64);
        return @intCast(delta);
    }

    fn validateAccount(self: *const LastSeen, account: []const u8) Error!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > self.cfg.max_account_len) return error.AccountTooLong;
    }
};

const testing = std.testing;

test "touch records and updates last activity" {
    var seen = LastSeen.init(testing.allocator);
    defer seen.deinit();

    try seen.touch("alice", 10);
    try testing.expectEqual(@as(?i64, 10), seen.get("alice"));
    try seen.touch("alice", 25);
    try testing.expectEqual(@as(?i64, 25), seen.get("alice"));
}

test "idleMs reports elapsed milliseconds for known accounts" {
    var seen = LastSeen.init(testing.allocator);
    defer seen.deinit();

    try seen.touch("bob", 1000);
    try testing.expectEqual(@as(?i64, 250), seen.idleMs("bob", 1250));
    try testing.expectEqual(@as(?i64, 0), seen.idleMs("bob", 900));
    try testing.expectEqual(@as(?i64, null), seen.idleMs("missing", 1250));
}

test "account caps and validation are enforced" {
    var seen = LastSeen.initWithConfig(testing.allocator, .{
        .max_accounts = 1,
        .max_account_len = 4,
    });
    defer seen.deinit();

    try testing.expectError(error.EmptyAccount, seen.touch("", 1));
    try testing.expectError(error.AccountTooLong, seen.touch("abcde", 1));
    try seen.touch("abcd", 1);
    try testing.expectError(error.TooManyAccounts, seen.touch("wxyz", 2));
}
