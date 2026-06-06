//! Per-account mention counters with last-context memory.
const std = @import("std");

pub const max_accounts: usize = 8192;
pub const max_account_bytes: usize = 64;
pub const max_context_bytes: usize = 300;

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    InvalidContext,
    TooManyAccounts,
};

pub const Entry = struct {
    count: u32,
    last: []const u8,
};

const StoredEntry = struct {
    count: u32 = 0,
    last: []u8,

    fn deinit(self: *StoredEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.last);
    }
};

pub const MentionIndex = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(StoredEntry),

    pub fn init(allocator: std.mem.Allocator) MentionIndex {
        return .{ .allocator = allocator, .entries = std.StringHashMap(StoredEntry).init(allocator) };
    }

    pub fn deinit(self: *MentionIndex) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn bump(self: *MentionIndex, account: []const u8, context: []const u8) Error!void {
        try validateAccount(account);
        if (context.len == 0 or context.len > max_context_bytes) return error.InvalidContext;

        const replacement = try self.allocator.dupe(u8, context);
        errdefer self.allocator.free(replacement);

        if (self.entries.getPtr(account)) |entry| {
            self.allocator.free(entry.last);
            entry.last = replacement;
            if (entry.count < std.math.maxInt(u32)) entry.count += 1;
            return;
        }

        if (self.entries.count() >= max_accounts) return error.TooManyAccounts;
        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.entries.putNoClobber(owned_account, .{ .count = 1, .last = replacement });
    }

    /// Returns a borrowed entry. The `last` slice is invalidated by mutation.
    pub fn get(self: *const MentionIndex, account: []const u8) ?Entry {
        const entry = self.entries.getPtr(account) orelse return null;
        return .{ .count = entry.count, .last = entry.last };
    }

    pub fn clear(self: *MentionIndex, account: []const u8) bool {
        const entry = self.entries.getEntry(account) orelse return false;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.entries.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return true;
    }

    fn validateAccount(account: []const u8) Error!void {
        if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
    }
};

const testing = std.testing;

test "bump creates and updates an account entry" {
    var index = MentionIndex.init(testing.allocator);
    defer index.deinit();

    try index.bump("alice", "#chat hello");
    try index.bump("alice", "#ops ping");
    const entry = index.get("alice").?;
    try testing.expectEqual(@as(u32, 2), entry.count);
    try testing.expectEqualStrings("#ops ping", entry.last);
}

test "clear removes entries and reports presence" {
    var index = MentionIndex.init(testing.allocator);
    defer index.deinit();

    try index.bump("alice", "first");
    try testing.expect(index.clear("alice"));
    try testing.expect(!index.clear("alice"));
    try testing.expect(index.get("alice") == null);
}

test "accounts remain independent" {
    var index = MentionIndex.init(testing.allocator);
    defer index.deinit();

    try index.bump("alice", "a1");
    try index.bump("bob", "b1");
    try index.bump("alice", "a2");
    try testing.expectEqual(@as(u32, 2), index.get("alice").?.count);
    try testing.expectEqual(@as(u32, 1), index.get("bob").?.count);
    try testing.expectEqualStrings("b1", index.get("bob").?.last);
}

test "input caps reject invalid entries" {
    var index = MentionIndex.init(testing.allocator);
    defer index.deinit();

    try testing.expectError(error.InvalidAccount, index.bump("", "ctx"));
    try testing.expectError(error.InvalidContext, index.bump("alice", ""));
    try testing.expectError(error.InvalidContext, index.bump("alice", "x" ** (max_context_bytes + 1)));
}
