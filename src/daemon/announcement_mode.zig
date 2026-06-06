//! Announcement-only channel posting gate.
//!
//! When enabled for a channel, only allowlisted accounts may post. Disabled
//! channels allow posting by default.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_channel_bytes: usize = 128;
pub const max_account_bytes: usize = 128;
pub const max_accounts_per_channel: usize = 1024;

pub const Error = std.mem.Allocator.Error || error{
    InvalidChannel,
    InvalidAccount,
    TooManyChannels,
    TooManyAccounts,
};

const ChannelState = struct {
    enabled: bool = false,
    accounts: std.StringHashMap(void),

    fn init(allocator: std.mem.Allocator, enabled: bool) ChannelState {
        return .{
            .enabled = enabled,
            .accounts = std.StringHashMap(void).init(allocator),
        };
    }

    fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.accounts.deinit();
        self.* = undefined;
    }
};

pub const AnnouncementMode = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(ChannelState),

    pub fn init(allocator: std.mem.Allocator) AnnouncementMode {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(ChannelState).init(allocator),
        };
    }

    pub fn deinit(self: *AnnouncementMode) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn enable(self: *AnnouncementMode, channel: []const u8) Error!void {
        try validateChannel(channel);
        const state = try self.ensureChannel(channel, true);
        state.enabled = true;
    }

    pub fn disable(self: *AnnouncementMode, channel: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const was_enabled = entry.value_ptr.enabled;
        entry.value_ptr.enabled = false;
        if (entry.value_ptr.accounts.count() == 0) self.removeEntry(entry);
        return was_enabled;
    }

    pub fn isOn(self: *const AnnouncementMode, channel: []const u8) bool {
        const state = self.channels.getPtr(channel) orelse return false;
        return state.enabled;
    }

    pub fn allow(self: *AnnouncementMode, channel: []const u8, account: []const u8) Error!void {
        try validateChannel(channel);
        try validateAccount(account);

        const state = try self.ensureChannel(channel, false);
        if (state.accounts.contains(account)) return;
        if (state.accounts.count() >= max_accounts_per_channel) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try state.accounts.putNoClobber(owned_account, {});
    }

    pub fn mayPost(self: *const AnnouncementMode, channel: []const u8, account: []const u8) bool {
        const state = self.channels.getPtr(channel) orelse return true;
        if (!state.enabled) return true;
        return state.accounts.contains(account);
    }

    pub fn allowedCount(self: *const AnnouncementMode, channel: []const u8) usize {
        const state = self.channels.getPtr(channel) orelse return 0;
        return state.accounts.count();
    }

    fn ensureChannel(self: *AnnouncementMode, channel: []const u8, enabled: bool) Error!*ChannelState {
        if (self.channels.getPtr(channel)) |state| return state;
        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        try self.channels.putNoClobber(owned_channel, ChannelState.init(self.allocator, enabled));
        return self.channels.getPtr(channel).?;
    }

    fn removeEntry(self: *AnnouncementMode, entry: std.StringHashMap(ChannelState).Entry) void {
        const key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
    }
};

fn validateChannel(channel: []const u8) Error!void {
    if (channel.len == 0 or channel.len > max_channel_bytes) return error.InvalidChannel;
}

fn validateAccount(account: []const u8) Error!void {
    if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
}

const testing = std.testing;

test "enable disable and isOn track channel state" {
    var mode = AnnouncementMode.init(testing.allocator);
    defer mode.deinit();

    try testing.expect(!mode.isOn("#main"));
    try mode.enable("#main");
    try testing.expect(mode.isOn("#main"));
    try testing.expect(mode.disable("#main"));
    try testing.expect(!mode.isOn("#main"));
    try testing.expect(!mode.disable("#main"));
}

test "enabled channels allow only listed accounts" {
    var mode = AnnouncementMode.init(testing.allocator);
    defer mode.deinit();

    try mode.enable("#main");
    try testing.expect(!mode.mayPost("#main", "alice"));
    try mode.allow("#main", "alice");
    try testing.expect(mode.mayPost("#main", "alice"));
    try testing.expect(!mode.mayPost("#main", "bob"));
}

test "allowlist survives disable and re-enable" {
    var mode = AnnouncementMode.init(testing.allocator);
    defer mode.deinit();

    try mode.allow("#main", "alice");
    try testing.expectEqual(@as(usize, 1), mode.allowedCount("#main"));
    try testing.expect(mode.mayPost("#main", "bob"));
    try testing.expect(!mode.disable("#main"));

    try mode.enable("#main");
    try testing.expect(mode.mayPost("#main", "alice"));
    try testing.expect(!mode.mayPost("#main", "bob"));
}

test "duplicate allow is idempotent" {
    var mode = AnnouncementMode.init(testing.allocator);
    defer mode.deinit();

    try mode.allow("#main", "alice");
    try mode.allow("#main", "alice");
    try testing.expectEqual(@as(usize, 1), mode.allowedCount("#main"));
}

test "validation rejects empty fields" {
    var mode = AnnouncementMode.init(testing.allocator);
    defer mode.deinit();

    try testing.expectError(error.InvalidChannel, mode.enable(""));
    try testing.expectError(error.InvalidChannel, mode.allow("", "alice"));
    try testing.expectError(error.InvalidAccount, mode.allow("#main", ""));
}
