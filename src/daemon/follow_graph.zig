//! Bounded directed follow edges keyed by account name.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyAccount,
    AccountTooLong,
    TooManyAccounts,
    TooManyEdges,
    SelfFollow,
};

pub const Config = struct {
    max_accounts: usize = 65_536,
    max_edges_per_account: usize = 4096,
    max_account_len: usize = 128,
};

const EdgeList = struct {
    items: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *EdgeList, allocator: std.mem.Allocator) void {
        for (self.items.items) |name| allocator.free(name);
        self.items.deinit(allocator);
        self.* = undefined;
    }

    fn find(self: *const EdgeList, account: []const u8) ?usize {
        for (self.items.items, 0..) |name, i| {
            if (std.mem.eql(u8, name, account)) return i;
        }
        return null;
    }
};

pub const FollowGraph = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    edges: std.StringHashMap(EdgeList),

    pub fn init(allocator: std.mem.Allocator) FollowGraph {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) FollowGraph {
        std.debug.assert(cfg.max_accounts > 0);
        std.debug.assert(cfg.max_edges_per_account > 0);
        std.debug.assert(cfg.max_account_len > 0);
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .edges = std.StringHashMap(EdgeList).init(allocator),
        };
    }

    pub fn deinit(self: *FollowGraph) void {
        var it = self.edges.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.edges.deinit();
        self.* = undefined;
    }

    pub fn follow(self: *FollowGraph, a: []const u8, b: []const u8) Error!bool {
        try self.validateAccount(a);
        try self.validateAccount(b);
        if (std.mem.eql(u8, a, b)) return error.SelfFollow;

        const list = try self.ensureSource(a);
        if (list.find(b) != null) return false;
        if (list.items.items.len >= self.cfg.max_edges_per_account) return error.TooManyEdges;

        const owned_target = try self.allocator.dupe(u8, b);
        errdefer self.allocator.free(owned_target);
        try list.items.append(self.allocator, owned_target);
        return true;
    }

    pub fn unfollow(self: *FollowGraph, a: []const u8, b: []const u8) bool {
        const entry = self.edges.getEntry(a) orelse return false;
        const idx = entry.value_ptr.find(b) orelse return false;
        self.allocator.free(entry.value_ptr.items.items[idx]);
        _ = entry.value_ptr.items.orderedRemove(idx);
        if (entry.value_ptr.items.items.len == 0) self.dropSource(entry);
        return true;
    }

    pub fn following(self: *const FollowGraph, a: []const u8) []const []const u8 {
        const list = self.edges.getPtr(a) orelse return &.{};
        return list.items.items;
    }

    pub fn isFollowing(self: *const FollowGraph, a: []const u8, b: []const u8) bool {
        const list = self.edges.getPtr(a) orelse return false;
        return list.find(b) != null;
    }

    fn ensureSource(self: *FollowGraph, account: []const u8) Error!*EdgeList {
        if (self.edges.getPtr(account)) |list| return list;
        if (self.edges.count() >= self.cfg.max_accounts) return error.TooManyAccounts;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.edges.putNoClobber(owned, .{});
        return self.edges.getPtr(account).?;
    }

    fn dropSource(self: *FollowGraph, entry: std.StringHashMap(EdgeList).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.edges.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn validateAccount(self: *const FollowGraph, account: []const u8) Error!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > self.cfg.max_account_len) return error.AccountTooLong;
    }
};

const testing = std.testing;

test "follow adds directed edges and deduplicates" {
    var graph = FollowGraph.init(testing.allocator);
    defer graph.deinit();

    try testing.expect(try graph.follow("alice", "bob"));
    try testing.expect(!try graph.follow("alice", "bob"));
    try testing.expect(graph.isFollowing("alice", "bob"));
    try testing.expect(!graph.isFollowing("bob", "alice"));
    try testing.expectEqual(@as(usize, 1), graph.following("alice").len);
}

test "unfollow removes edges and prunes empty source" {
    var graph = FollowGraph.init(testing.allocator);
    defer graph.deinit();

    try testing.expect(try graph.follow("alice", "bob"));
    try testing.expect(graph.unfollow("alice", "bob"));
    try testing.expect(!graph.unfollow("alice", "bob"));
    try testing.expect(!graph.isFollowing("alice", "bob"));
    try testing.expectEqual(@as(usize, 0), graph.following("alice").len);
}

test "bounds and validation are enforced" {
    var graph = FollowGraph.initWithConfig(testing.allocator, .{
        .max_accounts = 1,
        .max_edges_per_account = 1,
        .max_account_len = 5,
    });
    defer graph.deinit();

    try testing.expectError(error.EmptyAccount, graph.follow("", "bob"));
    try testing.expectError(error.AccountTooLong, graph.follow("abcdef", "bob"));
    try testing.expectError(error.SelfFollow, graph.follow("alice", "alice"));
    try testing.expect(try graph.follow("alice", "bob"));
    try testing.expectError(error.TooManyEdges, graph.follow("alice", "carol"));
    try testing.expectError(error.TooManyAccounts, graph.follow("dave", "erin"));
}
