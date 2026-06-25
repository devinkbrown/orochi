// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-account channel auto-join lists.
const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("autojoin requires a 64-bit target");
}

/// Numeric replies reserved for auto-join list command integration.
pub const AutoJoinNumeric = enum(u16) {
    /// One channel entry in an account auto-join list.
    RPL_AUTOJOINLIST = 795,
    /// End of an account auto-join list response.
    RPL_ENDOFAUTOJOINLIST = 796,
    /// The account or per-account channel bound was reached.
    ERR_AUTOJOINFULL = 797,
    /// The channel is already present in the account auto-join list.
    ERR_AUTOJOINEXISTS = 798,
    /// The channel is not present in the account auto-join list.
    ERR_AUTOJOINNOTSET = 799,

    /// Return the stable symbolic name for this numeric.
    pub fn tag(self: AutoJoinNumeric) []const u8 {
        return switch (self) {
            .RPL_AUTOJOINLIST => "RPL_AUTOJOINLIST",
            .RPL_ENDOFAUTOJOINLIST => "RPL_ENDOFAUTOJOINLIST",
            .ERR_AUTOJOINFULL => "ERR_AUTOJOINFULL",
            .ERR_AUTOJOINEXISTS => "ERR_AUTOJOINEXISTS",
            .ERR_AUTOJOINNOTSET => "ERR_AUTOJOINNOTSET",
        };
    }
};

/// Tunable bounds for an auto-join store.
pub const Params = struct {
    /// Maximum number of accounts with at least one stored channel.
    max_accounts: usize = 16384,
    /// Maximum byte length of an account identifier.
    max_account_bytes: usize = 64,
    /// Maximum byte length of a channel name.
    max_channel_bytes: usize = 128,
    /// Maximum number of auto-join channels per account.
    max_channels_per_account: usize = 64,
};

/// Errors returned by auto-join list operations.
pub const AutoJoinError = std.mem.Allocator.Error || error{
    EmptyAccount,
    AccountTooLong,
    EmptyChannel,
    ChannelTooLong,
    TooManyAccounts,
    TooManyChannels,
    AutoJoinExists,
    AutoJoinNotFound,
};

const ChannelList = struct {
    channels: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *ChannelList, allocator: std.mem.Allocator) void {
        for (self.channels.items) |channel| allocator.free(channel);
        self.channels.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const ChannelList, channel: []const u8) ?usize {
        for (self.channels.items, 0..) |item, idx| {
            if (std.ascii.eqlIgnoreCase(item, channel)) return idx;
        }
        return null;
    }
};

/// Owning, bounded account-to-channel auto-join store.
pub const AutoJoin = struct {
    allocator: std.mem.Allocator,
    params: Params,
    accounts: std.StringHashMap(ChannelList),

    /// Create an empty auto-join store with default bounds.
    pub fn init(allocator: std.mem.Allocator) AutoJoin {
        return initWithParams(allocator, .{});
    }

    /// Create an empty auto-join store with caller-supplied bounds.
    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) AutoJoin {
        return .{
            .allocator = allocator,
            .params = params,
            .accounts = std.StringHashMap(ChannelList).init(allocator),
        };
    }

    /// Free every owned account key, channel value, and map allocation.
    pub fn deinit(self: *AutoJoin) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    /// Add `channel` to `account`'s auto-join list.
    pub fn add(self: *AutoJoin, account: []const u8, channel: []const u8) AutoJoinError!void {
        try self.validateAccount(account);
        try self.validateChannel(channel);

        if (self.findAccount(account)) |entry| {
            if (entry.value_ptr.indexOf(channel) != null) return error.AutoJoinExists;
            if (entry.value_ptr.channels.items.len >= self.params.max_channels_per_account) {
                return error.TooManyChannels;
            }

            const owned_channel = try self.allocator.dupe(u8, channel);
            errdefer self.allocator.free(owned_channel);
            try entry.value_ptr.channels.append(self.allocator, owned_channel);
            return;
        }

        if (self.accounts.count() >= self.params.max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);

        const owned_channel = try self.allocator.dupe(u8, channel);
        var new_list: ChannelList = .{};
        new_list.channels.append(self.allocator, owned_channel) catch |err| {
            self.allocator.free(owned_channel);
            return err;
        };
        errdefer new_list.deinit(self.allocator);

        try self.accounts.putNoClobber(owned_account, new_list);
    }

    /// Remove `channel` from `account`'s auto-join list.
    pub fn remove(self: *AutoJoin, account: []const u8, channel: []const u8) AutoJoinError!void {
        try self.validateAccount(account);
        try self.validateChannel(channel);

        const entry = self.findAccount(account) orelse return error.AutoJoinNotFound;
        const idx = entry.value_ptr.indexOf(channel) orelse return error.AutoJoinNotFound;

        self.allocator.free(entry.value_ptr.channels.items[idx]);
        _ = entry.value_ptr.channels.orderedRemove(idx);

        if (entry.value_ptr.channels.items.len == 0) self.dropAccount(entry);
    }

    /// Return true when `channel` is in `account`'s auto-join list.
    pub fn contains(self: *const AutoJoin, account: []const u8, channel: []const u8) AutoJoinError!bool {
        try self.validateAccount(account);
        try self.validateChannel(channel);

        const entry = self.findAccount(account) orelse return false;
        return entry.value_ptr.indexOf(channel) != null;
    }

    /// Return the stored channel list for `account`.
    pub fn list(self: *const AutoJoin, account: []const u8) AutoJoinError![]const []const u8 {
        try self.validateAccount(account);

        const entry = self.findAccount(account) orelse return &.{};
        return entry.value_ptr.channels.items;
    }

    fn findAccount(self: *const AutoJoin, account: []const u8) ?std.StringHashMap(ChannelList).Entry {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }

    fn dropAccount(self: *AutoJoin, entry: std.StringHashMap(ChannelList).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn validateAccount(self: *const AutoJoin, account: []const u8) AutoJoinError!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > self.params.max_account_bytes) return error.AccountTooLong;
    }

    fn validateChannel(self: *const AutoJoin, channel: []const u8) AutoJoinError!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.params.max_channel_bytes) return error.ChannelTooLong;
    }
};

const testing = std.testing;

test "add stores channels for an account and list returns owned entries" {
    // Arrange.
    var autojoin = AutoJoin.init(testing.allocator);
    defer autojoin.deinit();

    // Act.
    try autojoin.add("alice", "#main");
    try autojoin.add("alice", "#ops");
    const channels = try autojoin.list("alice");

    // Assert.
    try testing.expectEqual(@as(usize, 2), channels.len);
    try testing.expectEqualStrings("#main", channels[0]);
    try testing.expectEqualStrings("#ops", channels[1]);
}

test "add rejects duplicate channels case-insensitively" {
    // Arrange.
    var autojoin = AutoJoin.init(testing.allocator);
    defer autojoin.deinit();

    // Act.
    try autojoin.add("alice", "#Main");

    // Assert.
    try testing.expectError(error.AutoJoinExists, autojoin.add("ALICE", "#main"));
    try testing.expectEqual(@as(usize, 1), (try autojoin.list("alice")).len);
}

test "contains matches account and channel case-insensitively" {
    // Arrange.
    var autojoin = AutoJoin.init(testing.allocator);
    defer autojoin.deinit();

    // Act.
    try autojoin.add("Alice", "#Lobby");

    // Assert.
    try testing.expect(try autojoin.contains("alice", "#lobby"));
    try testing.expect(try autojoin.contains("ALICE", "#LOBBY"));
    try testing.expect(!try autojoin.contains("alice", "#other"));
    try testing.expect(!try autojoin.contains("unknown", "#lobby"));
}

test "remove deletes a channel and prunes empty account state" {
    // Arrange.
    var autojoin = AutoJoin.init(testing.allocator);
    defer autojoin.deinit();

    try autojoin.add("alice", "#main");

    // Act.
    try autojoin.remove("ALICE", "#MAIN");

    // Assert.
    try testing.expect(!try autojoin.contains("alice", "#main"));
    try testing.expectEqual(@as(usize, 0), (try autojoin.list("alice")).len);
    try testing.expectEqual(@as(u32, 0), autojoin.accounts.count());
}

test "remove reports missing accounts and channels with typed errors" {
    // Arrange.
    var autojoin = AutoJoin.init(testing.allocator);
    defer autojoin.deinit();

    try autojoin.add("alice", "#main");

    // Act and assert.
    try testing.expectError(error.AutoJoinNotFound, autojoin.remove("alice", "#missing"));
    try testing.expectError(error.AutoJoinNotFound, autojoin.remove("bob", "#main"));
}

test "bounds reject too many accounts and too many channels" {
    // Arrange.
    var autojoin = AutoJoin.initWithParams(testing.allocator, .{
        .max_accounts = 1,
        .max_channels_per_account = 2,
    });
    defer autojoin.deinit();

    // Act.
    try autojoin.add("alice", "#a");
    try autojoin.add("alice", "#b");

    // Assert.
    try testing.expectError(error.TooManyChannels, autojoin.add("alice", "#c"));
    try testing.expectError(error.TooManyAccounts, autojoin.add("bob", "#a"));
}

test "input validation rejects empty and oversized account or channel values" {
    // Arrange.
    var autojoin = AutoJoin.initWithParams(testing.allocator, .{
        .max_account_bytes = 3,
        .max_channel_bytes = 4,
    });
    defer autojoin.deinit();

    // Act and assert.
    try testing.expectError(error.EmptyAccount, autojoin.add("", "#ok"));
    try testing.expectError(error.AccountTooLong, autojoin.add("alice", "#ok"));
    try testing.expectError(error.EmptyChannel, autojoin.add("bob", ""));
    try testing.expectError(error.ChannelTooLong, autojoin.add("bob", "#wide"));
}

test "numeric tags are exhaustively mapped" {
    // Arrange.
    const numeric = AutoJoinNumeric.ERR_AUTOJOINEXISTS;

    // Act.
    const tag = numeric.tag();

    // Assert.
    try testing.expectEqualStrings("ERR_AUTOJOINEXISTS", tag);
}
