const std = @import("std");

pub const CreditLedger = struct {
    const Self = @This();

    const max_accounts = 65536;
    const max_account_bytes = 128;

    allocator: std.mem.Allocator,
    by_account: std.StringHashMap(i64),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .by_account = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.by_account.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.by_account.deinit();
        self.* = undefined;
    }

    pub fn credit(self: *Self, account: []const u8, amt: u63) !i64 {
        try checkAccount(account);
        const amount: i64 = @intCast(amt);

        if (self.by_account.getPtr(account)) |value| {
            if (value.* > std.math.maxInt(i64) - amount) return error.Overflow;
            value.* += amount;
            return value.*;
        }

        if (self.by_account.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.by_account.put(owned_account, amount);
        return amount;
    }

    pub fn debit(self: *Self, account: []const u8, amt: u63) !i64 {
        try checkAccount(account);
        const amount: i64 = @intCast(amt);
        const current = self.balance(account);
        if (current < amount) return error.Insufficient;

        if (self.by_account.getPtr(account)) |value| {
            value.* = current - amount;
            return value.*;
        }

        return 0;
    }

    pub fn balance(self: *const Self, account: []const u8) i64 {
        return self.by_account.get(account) orelse 0;
    }

    fn checkAccount(account: []const u8) !void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > max_account_bytes) return error.AccountTooLong;
    }
};

test "credit creates and increments account balances" {
    var ledger = CreditLedger.init(std.testing.allocator);
    defer ledger.deinit();

    try std.testing.expectEqual(@as(i64, 10), try ledger.credit("alice", 10));
    try std.testing.expectEqual(@as(i64, 15), try ledger.credit("alice", 5));
    try std.testing.expectEqual(@as(i64, 7), try ledger.credit("bob", 7));
    try std.testing.expectEqual(@as(i64, 15), ledger.balance("alice"));
}

test "debit refuses insufficient balances" {
    var ledger = CreditLedger.init(std.testing.allocator);
    defer ledger.deinit();

    try std.testing.expectEqual(@as(i64, 12), try ledger.credit("alice", 12));
    try std.testing.expectEqual(@as(i64, 5), try ledger.debit("alice", 7));
    try std.testing.expectError(error.Insufficient, ledger.debit("alice", 6));
    try std.testing.expectError(error.Insufficient, ledger.debit("missing", 1));
}

test "zero debit on a missing account is a no-op" {
    var ledger = CreditLedger.init(std.testing.allocator);
    defer ledger.deinit();

    try std.testing.expectEqual(@as(i64, 0), try ledger.debit("alice", 0));
    try std.testing.expectEqual(@as(i64, 0), ledger.balance("alice"));
}

test "overflow and invalid account names are rejected" {
    var ledger = CreditLedger.init(std.testing.allocator);
    defer ledger.deinit();

    try std.testing.expectEqual(std.math.maxInt(i64), try ledger.credit("alice", std.math.maxInt(u63)));
    try std.testing.expectError(error.Overflow, ledger.credit("alice", 1));
    try std.testing.expectError(error.EmptyAccount, ledger.credit("", 1));

    var long: [129]u8 = undefined;
    @memset(&long, 'x');
    try std.testing.expectError(error.AccountTooLong, ledger.credit(&long, 1));
}
