//! Orochi account contact lists.
//!
//! Stores owned account and friend names in bounded per-account lists. Returned
//! slices are borrowed and stay valid until the next mutation of this store.
const std = @import("std");

pub const max_accounts: usize = 65536;
pub const max_friends_per_account: usize = 256;
pub const max_name_bytes: usize = 64;

pub const Error = std.mem.Allocator.Error || error{
    InvalidName,
    TooManyAccounts,
    TooManyFriends,
};

const FriendSet = struct {
    items: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *FriendSet, allocator: std.mem.Allocator) void {
        for (self.items.items) |friend| allocator.free(friend);
        self.items.deinit(allocator);
    }

    fn indexOf(self: *const FriendSet, friend: []const u8) ?usize {
        for (self.items.items, 0..) |item, idx| {
            if (std.mem.eql(u8, item, friend)) return idx;
        }
        return null;
    }
};

pub const FriendList = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(FriendSet),

    pub fn init(allocator: std.mem.Allocator) FriendList {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(FriendSet).init(allocator),
        };
    }

    pub fn deinit(self: *FriendList) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn add(self: *FriendList, account: []const u8, friend: []const u8) Error!bool {
        try validateName(account);
        try validateName(friend);

        const set = try self.ensureAccount(account);
        if (set.indexOf(friend) != null) return false;
        if (set.items.items.len >= max_friends_per_account) return error.TooManyFriends;

        const owned_friend = try self.allocator.dupe(u8, friend);
        errdefer self.allocator.free(owned_friend);
        try set.items.append(self.allocator, owned_friend);
        return true;
    }

    pub fn remove(self: *FriendList, account: []const u8, friend: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOf(friend) orelse return false;
        const removed = entry.value_ptr.items.orderedRemove(idx);
        self.allocator.free(removed);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return true;
    }

    pub fn has(self: *const FriendList, account: []const u8, friend: []const u8) bool {
        const set = self.accounts.getPtr(account) orelse return false;
        return set.indexOf(friend) != null;
    }

    pub fn list(self: *const FriendList, account: []const u8) []const []const u8 {
        const set = self.accounts.getPtr(account) orelse return &.{};
        return set.items.items;
    }

    fn ensureAccount(self: *FriendList, account: []const u8) Error!*FriendSet {
        if (self.accounts.getPtr(account)) |set| return set;
        if (self.accounts.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }

    fn dropAccount(self: *FriendList, entry: std.StringHashMap(FriendSet).Entry) void {
        const owned_account = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_account);
    }
};

fn validateName(name: []const u8) error{InvalidName}!void {
    if (name.len == 0 or name.len > max_name_bytes) return error.InvalidName;
}

const testing = std.testing;

test "add is idempotent and has reflects membership" {
    var friends = FriendList.init(testing.allocator);
    defer friends.deinit();

    try testing.expect(try friends.add("alice", "bob"));
    try testing.expect(!try friends.add("alice", "bob"));
    try testing.expect(try friends.add("alice", "cara"));
    try testing.expect(friends.has("alice", "bob"));
    try testing.expect(!friends.has("alice", "drew"));
    try testing.expectEqual(@as(usize, 2), friends.list("alice").len);
}

test "remove prunes empty account lists" {
    var friends = FriendList.init(testing.allocator);
    defer friends.deinit();

    _ = try friends.add("alice", "bob");
    try testing.expect(friends.remove("alice", "bob"));
    try testing.expect(!friends.remove("alice", "bob"));
    try testing.expect(!friends.has("alice", "bob"));
    try testing.expectEqual(@as(usize, 0), friends.list("alice").len);
}

test "independent accounts keep separate contact sets" {
    var friends = FriendList.init(testing.allocator);
    defer friends.deinit();

    _ = try friends.add("alice", "bob");
    _ = try friends.add("zoe", "bob");
    _ = try friends.add("alice", "cara");
    try testing.expect(friends.has("alice", "cara"));
    try testing.expect(!friends.has("zoe", "cara"));
    try testing.expectEqualStrings("bob", friends.list("zoe")[0]);
}

test "invalid names and per-account cap are enforced" {
    var friends = FriendList.init(testing.allocator);
    defer friends.deinit();

    try testing.expectError(error.InvalidName, friends.add("", "bob"));

    var buf: [max_name_bytes]u8 = undefined;
    var idx: usize = 0;
    while (idx < max_friends_per_account) : (idx += 1) {
        const name = try std.fmt.bufPrint(&buf, "friend-{d}", .{idx});
        _ = try friends.add("alice", name);
    }
    try testing.expectError(error.TooManyFriends, friends.add("alice", "overflow"));
}
