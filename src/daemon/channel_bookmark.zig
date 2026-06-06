//! Per-account channel bookmarks.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyAccount,
    AccountTooLong,
    EmptyChannel,
    ChannelTooLong,
    TooManyAccounts,
    TooManyBookmarks,
};

pub const Config = struct {
    max_accounts: usize = 16384,
    max_account_len: usize = 64,
    max_channel_len: usize = 128,
    max_bookmarks_per_account: usize = 512,
};

const ChannelSet = struct {
    channels: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *ChannelSet, allocator: std.mem.Allocator) void {
        for (self.channels.items) |channel| allocator.free(channel);
        self.channels.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const ChannelSet, channel: []const u8) ?usize {
        for (self.channels.items, 0..) |item, idx| {
            if (std.mem.eql(u8, item, channel)) return idx;
        }
        return null;
    }
};

pub const ChannelBookmark = struct {
    allocator: std.mem.Allocator,
    config: Config,
    accounts: std.StringHashMap(ChannelSet),

    pub fn init(allocator: std.mem.Allocator) ChannelBookmark {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) ChannelBookmark {
        return .{
            .allocator = allocator,
            .config = config,
            .accounts = std.StringHashMap(ChannelSet).init(allocator),
        };
    }

    pub fn deinit(self: *ChannelBookmark) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn add(self: *ChannelBookmark, account: []const u8, channel: []const u8) Error!bool {
        try self.validateAccount(account);
        try self.validateChannel(channel);

        const channel_set = try self.ensureAccount(account);
        if (channel_set.indexOf(channel) != null) return false;
        if (channel_set.channels.items.len >= self.config.max_bookmarks_per_account) return error.TooManyBookmarks;

        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try channel_set.channels.append(self.allocator, owned);
        return true;
    }

    pub fn remove(self: *ChannelBookmark, account: []const u8, channel: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOf(channel) orelse return false;
        self.allocator.free(entry.value_ptr.channels.items[idx]);
        _ = entry.value_ptr.channels.orderedRemove(idx);
        if (entry.value_ptr.channels.items.len == 0) self.dropAccount(entry);
        return true;
    }

    pub fn has(self: *const ChannelBookmark, account: []const u8, channel: []const u8) bool {
        const channel_set = self.accounts.getPtr(account) orelse return false;
        return channel_set.indexOf(channel) != null;
    }

    pub fn list(self: *const ChannelBookmark, account: []const u8) []const []const u8 {
        const channel_set = self.accounts.getPtr(account) orelse return &.{};
        return channel_set.channels.items;
    }

    fn ensureAccount(self: *ChannelBookmark, account: []const u8) Error!*ChannelSet {
        if (self.accounts.getPtr(account)) |channel_set| return channel_set;
        if (self.accounts.count() >= self.config.max_accounts) return error.TooManyAccounts;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.accounts.putNoClobber(owned, .{});
        return self.accounts.getPtr(account).?;
    }

    fn dropAccount(self: *ChannelBookmark, entry: std.StringHashMap(ChannelSet).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn validateAccount(self: *const ChannelBookmark, account: []const u8) Error!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > self.config.max_account_len) return error.AccountTooLong;
    }

    fn validateChannel(self: *const ChannelBookmark, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.config.max_channel_len) return error.ChannelTooLong;
    }
};

const testing = std.testing;

test "add stores account bookmarks and deduplicates" {
    var bookmarks = ChannelBookmark.init(testing.allocator);
    defer bookmarks.deinit();

    try testing.expect(try bookmarks.add("alice", "#main"));
    try testing.expect(!try bookmarks.add("alice", "#main"));
    try testing.expect(try bookmarks.add("alice", "#help"));
    try testing.expect(bookmarks.has("alice", "#main"));
    try testing.expectEqual(@as(usize, 2), bookmarks.list("alice").len);
}

test "accounts are independent" {
    var bookmarks = ChannelBookmark.init(testing.allocator);
    defer bookmarks.deinit();

    _ = try bookmarks.add("alice", "#main");
    _ = try bookmarks.add("bob", "#main");
    _ = try bookmarks.add("bob", "#ops");
    try testing.expect(bookmarks.has("alice", "#main"));
    try testing.expect(!bookmarks.has("alice", "#ops"));
    try testing.expectEqual(@as(usize, 2), bookmarks.list("bob").len);
}

test "remove drops a bookmark and prunes empty accounts" {
    var bookmarks = ChannelBookmark.init(testing.allocator);
    defer bookmarks.deinit();

    _ = try bookmarks.add("alice", "#main");
    try testing.expect(bookmarks.remove("alice", "#main"));
    try testing.expect(!bookmarks.remove("alice", "#main"));
    try testing.expect(!bookmarks.has("alice", "#main"));
    try testing.expectEqual(@as(usize, 0), bookmarks.list("alice").len);
}

test "bookmark caps are enforced" {
    var bookmarks = ChannelBookmark.initWithConfig(testing.allocator, .{ .max_bookmarks_per_account = 2 });
    defer bookmarks.deinit();

    _ = try bookmarks.add("alice", "#a");
    _ = try bookmarks.add("alice", "#b");
    try testing.expectError(error.TooManyBookmarks, bookmarks.add("alice", "#c"));
}

test "input caps reject invalid account and channel values" {
    var bookmarks = ChannelBookmark.initWithConfig(testing.allocator, .{ .max_account_len = 3, .max_channel_len = 4 });
    defer bookmarks.deinit();

    try testing.expectError(error.EmptyAccount, bookmarks.add("", "#ok"));
    try testing.expectError(error.AccountTooLong, bookmarks.add("toolong", "#ok"));
    try testing.expectError(error.EmptyChannel, bookmarks.add("bob", ""));
    try testing.expectError(error.ChannelTooLong, bookmarks.add("bob", "#wide"));
}
