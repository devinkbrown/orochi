//! Announcement-only channel posting gate.
//!
//! When enabled for a channel, only allowlisted accounts may post. Disabled
//! channels allow posting by default.
const std = @import("std");
const toml = @import("../proto/toml.zig");

pub const default_max_channels: usize = 4096;
pub const default_max_channel_bytes: usize = 128;
pub const default_max_account_bytes: usize = 128;
pub const default_max_accounts_per_channel: usize = 1024;

/// Runtime-tunable announcement-mode limits. Defaults preserve the historical
/// hardcoded behaviour; the orchestrator overlays the `[filter]` TOML section
/// via `Config.applyToml` before constructing an `AnnouncementMode`.
pub const Config = struct {
    /// Max channels with announcement-only mode state.
    max_channels: usize = default_max_channels,
    /// Max channel-name length for the announcement-mode gate (bytes).
    max_channel_bytes: usize = default_max_channel_bytes,
    /// Max account-name length on the announcement allowlist (bytes).
    max_account_bytes: usize = default_max_account_bytes,
    /// Max allowlisted posters per announcement-only channel.
    max_accounts_per_channel: usize = default_max_accounts_per_channel,

    /// Overlay `[filter]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("filter.announce_mode_max_channels")) |v| {
            if (v >= 1) cfg.max_channels = @intCast(v);
        }
        if (doc.getUint("filter.announce_mode_channel_max_len")) |v| {
            if (v >= 1) cfg.max_channel_bytes = @intCast(v);
        }
        if (doc.getUint("filter.announce_mode_account_max_len")) |v| {
            if (v >= 1) cfg.max_account_bytes = @intCast(v);
        }
        if (doc.getUint("filter.announce_mode_allowlist_max")) |v| {
            if (v >= 1) cfg.max_accounts_per_channel = @intCast(v);
        }
    }
};

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
    cfg: Config = .{},

    pub fn init(allocator: std.mem.Allocator) AnnouncementMode {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) AnnouncementMode {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(ChannelState).init(allocator),
            .cfg = cfg,
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
        try validateChannel(channel, self.cfg.max_channel_bytes);
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
        try validateChannel(channel, self.cfg.max_channel_bytes);
        try validateAccount(account, self.cfg.max_account_bytes);

        const state = try self.ensureChannel(channel, false);
        if (state.accounts.contains(account)) return;
        if (state.accounts.count() >= self.cfg.max_accounts_per_channel) return error.TooManyAccounts;

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
        if (self.channels.count() >= self.cfg.max_channels) return error.TooManyChannels;
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

fn validateChannel(channel: []const u8, max_channel_bytes: usize) Error!void {
    if (channel.len == 0 or channel.len > max_channel_bytes) return error.InvalidChannel;
}

fn validateAccount(account: []const u8, max_account_bytes: usize) Error!void {
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

test "Config defaults preserve historical limits" {
    const cfg = Config{};
    try testing.expectEqual(default_max_channels, cfg.max_channels);
    try testing.expectEqual(default_max_channel_bytes, cfg.max_channel_bytes);
    try testing.expectEqual(default_max_account_bytes, cfg.max_account_bytes);
    try testing.expectEqual(default_max_accounts_per_channel, cfg.max_accounts_per_channel);
}

test "Config.applyToml overlays [filter] announce_mode keys" {
    var doc = try toml.parse(
        testing.allocator,
        "[filter]\nannounce_mode_max_channels = 256\nannounce_mode_channel_max_len = 16\nannounce_mode_account_max_len = 16\nannounce_mode_allowlist_max = 32\n",
    );
    defer doc.deinit(testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try testing.expectEqual(@as(usize, 256), cfg.max_channels);
    try testing.expectEqual(@as(usize, 16), cfg.max_channel_bytes);
    try testing.expectEqual(@as(usize, 16), cfg.max_account_bytes);
    try testing.expectEqual(@as(usize, 32), cfg.max_accounts_per_channel);
}

test "initWithConfig enforces a smaller allowlist cap" {
    var mode = AnnouncementMode.initWithConfig(testing.allocator, .{ .max_accounts_per_channel = 1 });
    defer mode.deinit();

    try mode.allow("#main", "alice");
    try testing.expectError(error.TooManyAccounts, mode.allow("#main", "bob"));
}
