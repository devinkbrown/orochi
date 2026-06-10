//! Orochi account block lists.
//!
//! Stores owned account names and blocked-account names in bounded per-account
//! lists. Returned slices are borrowed and stay valid until the next mutation.
const std = @import("std");

pub const max_accounts: usize = 65536;
pub const max_blocks_per_account: usize = 1024;
pub const max_name_bytes: usize = 64;

pub const Error = std.mem.Allocator.Error || error{
    InvalidName,
    TooManyAccounts,
    TooManyBlocks,
};

const BlockSet = struct {
    items: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *BlockSet, allocator: std.mem.Allocator) void {
        for (self.items.items) |blocked| allocator.free(blocked);
        self.items.deinit(allocator);
    }

    fn indexOf(self: *const BlockSet, who: []const u8) ?usize {
        for (self.items.items, 0..) |item, idx| {
            if (std.mem.eql(u8, item, who)) return idx;
        }
        return null;
    }
};

pub const BlockList = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(BlockSet),

    pub fn init(allocator: std.mem.Allocator) BlockList {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(BlockSet).init(allocator),
        };
    }

    pub fn deinit(self: *BlockList) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn block(self: *BlockList, account: []const u8, who: []const u8) Error!bool {
        try validateName(account);
        try validateName(who);

        const set = try self.ensureAccount(account);
        if (set.indexOf(who) != null) return false;
        if (set.items.items.len >= max_blocks_per_account) return error.TooManyBlocks;

        const owned_who = try self.allocator.dupe(u8, who);
        errdefer self.allocator.free(owned_who);
        try set.items.append(self.allocator, owned_who);
        return true;
    }

    pub fn unblock(self: *BlockList, account: []const u8, who: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOf(who) orelse return false;
        const removed = entry.value_ptr.items.orderedRemove(idx);
        self.allocator.free(removed);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return true;
    }

    pub fn isBlocked(self: *const BlockList, account: []const u8, who: []const u8) bool {
        const set = self.accounts.getPtr(account) orelse return false;
        return set.indexOf(who) != null;
    }

    pub fn list(self: *const BlockList, account: []const u8) []const []const u8 {
        const set = self.accounts.getPtr(account) orelse return &.{};
        return set.items.items;
    }

    fn ensureAccount(self: *BlockList, account: []const u8) Error!*BlockSet {
        if (self.accounts.getPtr(account)) |set| return set;
        if (self.accounts.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }

    fn dropAccount(self: *BlockList, entry: std.StringHashMap(BlockSet).Entry) void {
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

test "block is idempotent and isBlocked reflects membership" {
    var blocks = BlockList.init(testing.allocator);
    defer blocks.deinit();

    try testing.expect(try blocks.block("alice", "mallory"));
    try testing.expect(!try blocks.block("alice", "mallory"));
    try testing.expect(try blocks.block("alice", "trent"));
    try testing.expect(blocks.isBlocked("alice", "mallory"));
    try testing.expect(!blocks.isBlocked("alice", "victor"));
    try testing.expectEqual(@as(usize, 2), blocks.list("alice").len);
}

test "unblock removes entries and prunes empty accounts" {
    var blocks = BlockList.init(testing.allocator);
    defer blocks.deinit();

    _ = try blocks.block("alice", "mallory");
    try testing.expect(blocks.unblock("alice", "mallory"));
    try testing.expect(!blocks.unblock("alice", "mallory"));
    try testing.expect(!blocks.isBlocked("alice", "mallory"));
    try testing.expectEqual(@as(usize, 0), blocks.list("alice").len);
}

test "accounts maintain independent block sets" {
    var blocks = BlockList.init(testing.allocator);
    defer blocks.deinit();

    _ = try blocks.block("alice", "mallory");
    _ = try blocks.block("zoe", "mallory");
    _ = try blocks.block("alice", "trent");
    try testing.expect(blocks.isBlocked("alice", "trent"));
    try testing.expect(!blocks.isBlocked("zoe", "trent"));
    try testing.expectEqualStrings("mallory", blocks.list("zoe")[0]);
}

test "invalid names and per-account cap are enforced" {
    var blocks = BlockList.init(testing.allocator);
    defer blocks.deinit();

    try testing.expectError(error.InvalidName, blocks.block("alice", ""));

    var buf: [max_name_bytes]u8 = undefined;
    var idx: usize = 0;
    while (idx < max_blocks_per_account) : (idx += 1) {
        const name = try std.fmt.bufPrint(&buf, "blocked-{d}", .{idx});
        _ = try blocks.block("alice", name);
    }
    try testing.expectError(error.TooManyBlocks, blocks.block("alice", "overflow"));
}
