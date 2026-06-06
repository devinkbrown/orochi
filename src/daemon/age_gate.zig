const std = @import("std");

pub const AgeGate = struct {
    pub const max_accounts: usize = 65536;
    pub const max_account_len: usize = 128;

    pub const Error = error{
        EmptyAccount,
        AccountTooLong,
        TooManyAccounts,
    } || std.mem.Allocator.Error;

    allocator: std.mem.Allocator,
    created: std.StringHashMap(i64),

    pub fn init(allocator: std.mem.Allocator) AgeGate {
        return .{
            .allocator = allocator,
            .created = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn deinit(self: *AgeGate) void {
        var it = self.created.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.created.deinit();
        self.* = undefined;
    }

    pub fn setCreated(self: *AgeGate, account: []const u8, ms: i64) Error!void {
        try validateAccount(account);

        if (self.created.getPtr(account)) |stored| {
            stored.* = ms;
            return;
        }

        if (self.created.count() >= max_accounts) return error.TooManyAccounts;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.created.put(owned, ms);
    }

    pub fn meetsAge(self: *const AgeGate, account: []const u8, now_ms: i64, min_ms: i64) bool {
        if (!validAccount(account)) return false;
        const created_ms = self.created.get(account) orelse return false;
        if (now_ms < created_ms) return false;
        if (min_ms <= 0) return true;

        const age = @as(i128, now_ms) - @as(i128, created_ms);
        return age >= @as(i128, min_ms);
    }

    pub fn createdOf(self: *const AgeGate, account: []const u8) ?i64 {
        if (!validAccount(account)) return null;
        return self.created.get(account);
    }

    pub fn accountCount(self: *const AgeGate) usize {
        return self.created.count();
    }

    fn validateAccount(account: []const u8) Error!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > max_account_len) return error.AccountTooLong;
    }

    fn validAccount(account: []const u8) bool {
        return account.len > 0 and account.len <= max_account_len;
    }
};

test "setCreated stores and returns account creation time" {
    var gate = AgeGate.init(std.testing.allocator);
    defer gate.deinit();

    try gate.setCreated("alice", 1000);
    try std.testing.expectEqual(@as(?i64, 1000), gate.createdOf("alice"));
    try std.testing.expectEqual(@as(usize, 1), gate.accountCount());
}

test "meetsAge is false for unknown or underage accounts" {
    var gate = AgeGate.init(std.testing.allocator);
    defer gate.deinit();

    try std.testing.expect(!gate.meetsAge("missing", 5000, 1000));
    try gate.setCreated("bob", 4000);
    try std.testing.expect(!gate.meetsAge("bob", 4500, 1000));
    try std.testing.expect(gate.meetsAge("bob", 5000, 1000));
}

test "future timestamps do not meet age checks" {
    var gate = AgeGate.init(std.testing.allocator);
    defer gate.deinit();

    try gate.setCreated("carol", 9000);
    try std.testing.expect(!gate.meetsAge("carol", 8000, 0));
    try std.testing.expect(gate.meetsAge("carol", 9000, 0));
}

test "setting an existing account updates the timestamp" {
    var gate = AgeGate.init(std.testing.allocator);
    defer gate.deinit();

    try gate.setCreated("delta", 100);
    try gate.setCreated("delta", 500);
    try std.testing.expectEqual(@as(?i64, 500), gate.createdOf("delta"));
    try std.testing.expect(!gate.meetsAge("delta", 1000, 600));
    try std.testing.expectEqual(@as(usize, 1), gate.accountCount());
}
