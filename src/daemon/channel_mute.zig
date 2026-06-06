//! Per-account muted channel sets.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyAccount,
    AccountTooLong,
    EmptyChannel,
    ChannelTooLong,
    TooManyAccounts,
    TooManyMutes,
};

pub const Config = struct {
    max_accounts: usize = 16384,
    max_account_len: usize = 64,
    max_channel_len: usize = 128,
    max_mutes_per_account: usize = 512,
};

const MuteSet = struct {
    channels: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *MuteSet, allocator: std.mem.Allocator) void {
        for (self.channels.items) |channel| allocator.free(channel);
        self.channels.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const MuteSet, channel: []const u8) ?usize {
        for (self.channels.items, 0..) |item, idx| {
            if (std.mem.eql(u8, item, channel)) return idx;
        }
        return null;
    }
};

pub const ChannelMute = struct {
    allocator: std.mem.Allocator,
    config: Config,
    accounts: std.StringHashMap(MuteSet),

    pub fn init(allocator: std.mem.Allocator) ChannelMute {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) ChannelMute {
        return .{
            .allocator = allocator,
            .config = config,
            .accounts = std.StringHashMap(MuteSet).init(allocator),
        };
    }

    pub fn deinit(self: *ChannelMute) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn mute(self: *ChannelMute, account: []const u8, channel: []const u8) Error!bool {
        try self.validateAccount(account);
        try self.validateChannel(channel);

        const mute_set = try self.ensureAccount(account);
        if (mute_set.indexOf(channel) != null) return false;
        if (mute_set.channels.items.len >= self.config.max_mutes_per_account) return error.TooManyMutes;

        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try mute_set.channels.append(self.allocator, owned);
        return true;
    }

    pub fn unmute(self: *ChannelMute, account: []const u8, channel: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOf(channel) orelse return false;
        self.allocator.free(entry.value_ptr.channels.items[idx]);
        _ = entry.value_ptr.channels.orderedRemove(idx);
        if (entry.value_ptr.channels.items.len == 0) self.dropAccount(entry);
        return true;
    }

    pub fn isMuted(self: *const ChannelMute, account: []const u8, channel: []const u8) bool {
        const mute_set = self.accounts.getPtr(account) orelse return false;
        return mute_set.indexOf(channel) != null;
    }

    pub fn list(self: *const ChannelMute, account: []const u8) []const []const u8 {
        const mute_set = self.accounts.getPtr(account) orelse return &.{};
        return mute_set.channels.items;
    }

    fn ensureAccount(self: *ChannelMute, account: []const u8) Error!*MuteSet {
        if (self.accounts.getPtr(account)) |mute_set| return mute_set;
        if (self.accounts.count() >= self.config.max_accounts) return error.TooManyAccounts;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.accounts.putNoClobber(owned, .{});
        return self.accounts.getPtr(account).?;
    }

    fn dropAccount(self: *ChannelMute, entry: std.StringHashMap(MuteSet).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn validateAccount(self: *const ChannelMute, account: []const u8) Error!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > self.config.max_account_len) return error.AccountTooLong;
    }

    fn validateChannel(self: *const ChannelMute, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.config.max_channel_len) return error.ChannelTooLong;
    }
};

const testing = std.testing;

test "mute stores account channel entries and deduplicates" {
    var mutes = ChannelMute.init(testing.allocator);
    defer mutes.deinit();

    try testing.expect(try mutes.mute("alice", "#main"));
    try testing.expect(!try mutes.mute("alice", "#main"));
    try testing.expect(try mutes.mute("alice", "#noise"));
    try testing.expect(mutes.isMuted("alice", "#main"));
    try testing.expectEqual(@as(usize, 2), mutes.list("alice").len);
}

test "unmute removes entries and prunes empty account state" {
    var mutes = ChannelMute.init(testing.allocator);
    defer mutes.deinit();

    _ = try mutes.mute("alice", "#main");
    try testing.expect(mutes.unmute("alice", "#main"));
    try testing.expect(!mutes.unmute("alice", "#main"));
    try testing.expect(!mutes.isMuted("alice", "#main"));
    try testing.expectEqual(@as(usize, 0), mutes.list("alice").len);
}

test "muted channel sets are account-local" {
    var mutes = ChannelMute.init(testing.allocator);
    defer mutes.deinit();

    _ = try mutes.mute("alice", "#main");
    _ = try mutes.mute("bob", "#random");
    try testing.expect(mutes.isMuted("alice", "#main"));
    try testing.expect(!mutes.isMuted("alice", "#random"));
    try testing.expect(mutes.isMuted("bob", "#random"));
}

test "mute cap is enforced per account" {
    var mutes = ChannelMute.initWithConfig(testing.allocator, .{ .max_mutes_per_account = 2 });
    defer mutes.deinit();

    _ = try mutes.mute("alice", "#a");
    _ = try mutes.mute("alice", "#b");
    try testing.expectError(error.TooManyMutes, mutes.mute("alice", "#c"));
}

test "input caps reject invalid account and channel values" {
    var mutes = ChannelMute.initWithConfig(testing.allocator, .{ .max_account_len = 3, .max_channel_len = 4 });
    defer mutes.deinit();

    try testing.expectError(error.EmptyAccount, mutes.mute("", "#ok"));
    try testing.expectError(error.AccountTooLong, mutes.mute("toolong", "#ok"));
    try testing.expectError(error.EmptyChannel, mutes.mute("bob", ""));
    try testing.expectError(error.ChannelTooLong, mutes.mute("bob", "#wide"));
}
