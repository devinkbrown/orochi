//! Bounded recent presence status history per account.
const std = @import("std");

pub const history_cap: usize = 20;
pub const max_status_len: usize = 64;

pub const Error = std.mem.Allocator.Error || error{
    EmptyAccount,
    AccountTooLong,
    StatusTooLong,
    TooManyAccounts,
};

pub const Config = struct {
    max_accounts: usize = 131_072,
    max_account_len: usize = 128,
};

pub const Status = struct {
    text: []const u8,
    at_ms: i64,
};

const AccountHistory = struct {
    items: std.ArrayList(Status) = .empty,

    fn deinit(self: *AccountHistory, allocator: std.mem.Allocator) void {
        for (self.items.items) |entry| allocator.free(entry.text);
        self.items.deinit(allocator);
        self.* = undefined;
    }

    fn push(self: *AccountHistory, allocator: std.mem.Allocator, text: []const u8, at_ms: i64) std.mem.Allocator.Error!void {
        const owned_text = try allocator.dupe(u8, text);
        errdefer allocator.free(owned_text);

        if (self.items.items.len == history_cap) {
            allocator.free(self.items.items[0].text);
            _ = self.items.orderedRemove(0);
        }
        try self.items.append(allocator, .{ .text = owned_text, .at_ms = at_ms });
    }
};

pub const PresenceHistory = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    accounts: std.StringHashMap(AccountHistory),

    pub fn init(allocator: std.mem.Allocator) PresenceHistory {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) PresenceHistory {
        std.debug.assert(cfg.max_accounts > 0);
        std.debug.assert(cfg.max_account_len > 0);
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .accounts = std.StringHashMap(AccountHistory).init(allocator),
        };
    }

    pub fn deinit(self: *PresenceHistory) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn push(self: *PresenceHistory, account: []const u8, text: []const u8, at_ms: i64) Error!void {
        try self.validateAccount(account);
        if (text.len > max_status_len) return error.StatusTooLong;

        if (self.accounts.getPtr(account)) |history| {
            try history.push(self.allocator, text, at_ms);
            return;
        }
        if (self.accounts.count() >= self.cfg.max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);

        var history: AccountHistory = .{};
        errdefer history.deinit(self.allocator);
        try history.push(self.allocator, text, at_ms);

        try self.accounts.putNoClobber(owned_account, history);
    }

    pub fn recent(self: *const PresenceHistory, account: []const u8) []const Status {
        const history = self.accounts.getPtr(account) orelse return &.{};
        return history.items.items;
    }

    pub fn clear(self: *PresenceHistory, account: []const u8) bool {
        const removed = self.accounts.fetchRemove(account) orelse return false;
        self.allocator.free(removed.key);
        var history = removed.value;
        history.deinit(self.allocator);
        return true;
    }

    fn validateAccount(self: *const PresenceHistory, account: []const u8) Error!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > self.cfg.max_account_len) return error.AccountTooLong;
    }
};

const testing = std.testing;

test "push stores recent status entries in order" {
    var history = PresenceHistory.init(testing.allocator);
    defer history.deinit();

    try history.push("alice", "online", 10);
    try history.push("alice", "away", 20);
    const recent = history.recent("alice");
    try testing.expectEqual(@as(usize, 2), recent.len);
    try testing.expectEqualStrings("online", recent[0].text);
    try testing.expectEqual(@as(i64, 20), recent[1].at_ms);
}

test "history keeps only the newest twenty entries" {
    var history = PresenceHistory.init(testing.allocator);
    defer history.deinit();

    var i: usize = 0;
    while (i < history_cap + 5) : (i += 1) {
        var buf: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "s{}", .{i});
        try history.push("alice", text, @intCast(i));
    }

    const recent = history.recent("alice");
    try testing.expectEqual(@as(usize, history_cap), recent.len);
    try testing.expectEqualStrings("s5", recent[0].text);
    try testing.expectEqualStrings("s24", recent[recent.len - 1].text);
}

test "clear removes one account history" {
    var history = PresenceHistory.init(testing.allocator);
    defer history.deinit();

    try history.push("alice", "online", 1);
    try history.push("bob", "away", 2);
    try testing.expect(history.clear("alice"));
    try testing.expect(!history.clear("alice"));
    try testing.expectEqual(@as(usize, 0), history.recent("alice").len);
    try testing.expectEqual(@as(usize, 1), history.recent("bob").len);
}

test "account and status bounds are enforced" {
    var history = PresenceHistory.initWithConfig(testing.allocator, .{
        .max_accounts = 1,
        .max_account_len = 4,
    });
    defer history.deinit();

    try testing.expectError(error.EmptyAccount, history.push("", "x", 1));
    try testing.expectError(error.AccountTooLong, history.push("abcde", "x", 1));
    try testing.expectError(error.StatusTooLong, history.push("abcd", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm", 1));
    try history.push("abcd", "ok", 1);
    try testing.expectError(error.TooManyAccounts, history.push("wxyz", "ok", 2));
}
