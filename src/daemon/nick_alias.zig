//! Orochi account nickname aliases.
//!
//! Each account owns a bounded insertion-ordered alias list. Returned slices are
//! borrowed and stay valid until the next mutation of this store.
const std = @import("std");

pub const max_accounts: usize = 65536;
pub const max_aliases_per_account: usize = 16;
pub const max_name_bytes: usize = 64;

pub const Error = std.mem.Allocator.Error || error{
    InvalidName,
    TooManyAccounts,
    TooManyAliases,
};

const AliasSet = struct {
    items: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *AliasSet, allocator: std.mem.Allocator) void {
        for (self.items.items) |alias| allocator.free(alias);
        self.items.deinit(allocator);
    }

    fn indexOf(self: *const AliasSet, alias: []const u8) ?usize {
        for (self.items.items, 0..) |item, idx| {
            if (std.mem.eql(u8, item, alias)) return idx;
        }
        return null;
    }
};

pub const NickAlias = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(AliasSet),

    pub fn init(allocator: std.mem.Allocator) NickAlias {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(AliasSet).init(allocator),
        };
    }

    pub fn deinit(self: *NickAlias) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn add(self: *NickAlias, account: []const u8, alias: []const u8) Error!bool {
        try validateName(account);
        try validateName(alias);

        const set = try self.ensureAccount(account);
        if (set.indexOf(alias) != null) return false;
        if (set.items.items.len >= max_aliases_per_account) return error.TooManyAliases;

        const owned_alias = try self.allocator.dupe(u8, alias);
        errdefer self.allocator.free(owned_alias);
        try set.items.append(self.allocator, owned_alias);
        return true;
    }

    pub fn remove(self: *NickAlias, account: []const u8, alias: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOf(alias) orelse return false;
        const removed = entry.value_ptr.items.orderedRemove(idx);
        self.allocator.free(removed);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return true;
    }

    pub fn list(self: *const NickAlias, account: []const u8) []const []const u8 {
        const set = self.accounts.getPtr(account) orelse return &.{};
        return set.items.items;
    }

    fn ensureAccount(self: *NickAlias, account: []const u8) Error!*AliasSet {
        if (self.accounts.getPtr(account)) |set| return set;
        if (self.accounts.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }

    fn dropAccount(self: *NickAlias, entry: std.StringHashMap(AliasSet).Entry) void {
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

test "add is idempotent and list preserves insertion order" {
    var aliases = NickAlias.init(testing.allocator);
    defer aliases.deinit();

    try testing.expect(try aliases.add("alice", "ali"));
    try testing.expect(!try aliases.add("alice", "ali"));
    try testing.expect(try aliases.add("alice", "a_"));

    const list_view = aliases.list("alice");
    try testing.expectEqual(@as(usize, 2), list_view.len);
    try testing.expectEqualStrings("ali", list_view[0]);
    try testing.expectEqualStrings("a_", list_view[1]);
}

test "remove deletes aliases and prunes empty accounts" {
    var aliases = NickAlias.init(testing.allocator);
    defer aliases.deinit();

    _ = try aliases.add("alice", "ali");
    try testing.expect(aliases.remove("alice", "ali"));
    try testing.expect(!aliases.remove("alice", "ali"));
    try testing.expectEqual(@as(usize, 0), aliases.list("alice").len);
}

test "accounts maintain independent aliases" {
    var aliases = NickAlias.init(testing.allocator);
    defer aliases.deinit();

    _ = try aliases.add("alice", "ali");
    _ = try aliases.add("bob", "ali");
    _ = try aliases.add("alice", "alice_");
    try testing.expectEqual(@as(usize, 2), aliases.list("alice").len);
    try testing.expectEqual(@as(usize, 1), aliases.list("bob").len);
    try testing.expectEqualStrings("alice_", aliases.list("alice")[1]);
}

test "invalid names and alias cap are enforced" {
    var aliases = NickAlias.init(testing.allocator);
    defer aliases.deinit();

    try testing.expectError(error.InvalidName, aliases.add("alice", ""));

    var buf: [max_name_bytes]u8 = undefined;
    var idx: usize = 0;
    while (idx < max_aliases_per_account) : (idx += 1) {
        const alias = try std.fmt.bufPrint(&buf, "alias-{d}", .{idx});
        _ = try aliases.add("alice", alias);
    }
    try testing.expectError(error.TooManyAliases, aliases.add("alice", "overflow"));
}
