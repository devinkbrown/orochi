//! Per-account achievement unlock store.
const std = @import("std");

const IdList = struct {
    ids: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *IdList, allocator: std.mem.Allocator) void {
        for (self.ids.items) |id| {
            allocator.free(id);
        }
        self.ids.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const IdList, id: []const u8) ?usize {
        for (self.ids.items, 0..) |stored, idx| {
            if (std.mem.eql(u8, stored, id)) return idx;
        }
        return null;
    }
};

pub const Achievement = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(IdList),

    pub fn init(allocator: std.mem.Allocator) Achievement {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(IdList).init(allocator),
        };
    }

    pub fn deinit(self: *Achievement) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    /// Unlocks an id for an account. Returns true only for a new unlock.
    pub fn unlock(self: *Achievement, account: []const u8, id: []const u8) std.mem.Allocator.Error!bool {
        const ids = try self.ensureAccount(account);
        if (ids.indexOf(id) != null) return false;

        const owned = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(owned);
        try ids.ids.append(self.allocator, owned);
        return true;
    }

    pub fn has(self: *const Achievement, account: []const u8, id: []const u8) bool {
        const ids = self.accounts.getPtr(account) orelse return false;
        return ids.indexOf(id) != null;
    }

    /// Borrowed ids for account, valid until the next mutation of this store.
    pub fn list(self: *const Achievement, account: []const u8) []const []const u8 {
        const ids = self.accounts.getPtr(account) orelse return &.{};
        return ids.ids.items;
    }

    fn ensureAccount(self: *Achievement, account: []const u8) std.mem.Allocator.Error!*IdList {
        if (self.accounts.getPtr(account)) |ids| return ids;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.accounts.putNoClobber(owned, .{});
        return self.accounts.getPtr(account).?;
    }
};

const testing = std.testing;

test "unlock is idempotent per account" {
    var achievements = Achievement.init(testing.allocator);
    defer achievements.deinit();

    try testing.expect(try achievements.unlock("alice", "first-line"));
    try testing.expect(!try achievements.unlock("alice", "first-line"));
    try testing.expect(achievements.has("alice", "first-line"));
    try testing.expectEqual(@as(usize, 1), achievements.list("alice").len);
}

test "accounts keep independent unlock sets" {
    var achievements = Achievement.init(testing.allocator);
    defer achievements.deinit();

    _ = try achievements.unlock("alice", "builder");
    _ = try achievements.unlock("bob", "reader");
    try testing.expect(achievements.has("alice", "builder"));
    try testing.expect(!achievements.has("alice", "reader"));
    try testing.expect(achievements.has("bob", "reader"));
}

test "list returns unlocks in insertion order" {
    var achievements = Achievement.init(testing.allocator);
    defer achievements.deinit();

    _ = try achievements.unlock("alice", "a");
    _ = try achievements.unlock("alice", "b");
    const ids = achievements.list("alice");
    try testing.expectEqual(@as(usize, 2), ids.len);
    try testing.expectEqualStrings("a", ids[0]);
    try testing.expectEqualStrings("b", ids[1]);
}
