//! Per-channel display color overrides for members.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyName,
    NameTooLong,
    EmptyColor,
    ColorTooLong,
    InvalidColor,
    TooManyEntries,
};

pub const Config = struct {
    max_entries: usize = 262_144,
    max_channel_len: usize = 128,
    max_member_len: usize = 128,
};

const max_key_len: usize = 128 + 1 + 128;
const ColorEntry = struct {
    channel_len: usize,
    color: []u8,
};

pub const NicknameColor = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    colors: std.StringHashMap(ColorEntry),

    pub fn init(allocator: std.mem.Allocator) NicknameColor {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) NicknameColor {
        std.debug.assert(cfg.max_entries > 0);
        std.debug.assert(cfg.max_channel_len > 0 and cfg.max_channel_len <= 128);
        std.debug.assert(cfg.max_member_len > 0 and cfg.max_member_len <= 128);
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .colors = std.StringHashMap(ColorEntry).init(allocator),
        };
    }

    pub fn deinit(self: *NicknameColor) void {
        var it = self.colors.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.color);
        }
        self.colors.deinit();
        self.* = undefined;
    }

    pub fn set(self: *NicknameColor, channel: []const u8, member: []const u8, hex: []const u8) Error!void {
        try self.validateName(channel, self.cfg.max_channel_len);
        try self.validateName(member, self.cfg.max_member_len);
        try validateColor(hex);

        var scratch: [max_key_len]u8 = undefined;
        const lookup = buildKeyInto(&scratch, channel, member);
        if (self.colors.getPtr(lookup)) |entry| {
            const owned_color = try self.allocator.dupe(u8, hex);
            self.allocator.free(entry.color);
            entry.color = owned_color;
            return;
        }
        if (self.colors.count() >= self.cfg.max_entries) return error.TooManyEntries;

        const owned_key = try makeKey(self.allocator, channel, member);
        errdefer self.allocator.free(owned_key);
        const owned_color = try self.allocator.dupe(u8, hex);
        errdefer self.allocator.free(owned_color);
        try self.colors.putNoClobber(owned_key, .{ .channel_len = channel.len, .color = owned_color });
    }

    pub fn get(self: *const NicknameColor, channel: []const u8, member: []const u8) ?[]const u8 {
        if (!self.validName(channel, self.cfg.max_channel_len)) return null;
        if (!self.validName(member, self.cfg.max_member_len)) return null;

        var scratch: [max_key_len]u8 = undefined;
        const lookup = buildKeyInto(&scratch, channel, member);
        const entry = self.colors.get(lookup) orelse return null;
        return entry.color;
    }

    pub fn clearChannel(self: *NicknameColor, channel: []const u8) usize {
        if (!self.validName(channel, self.cfg.max_channel_len)) return 0;

        var removed: usize = 0;
        while (self.removeOneFromChannel(channel)) {
            removed += 1;
        }
        return removed;
    }

    fn removeOneFromChannel(self: *NicknameColor, channel: []const u8) bool {
        var it = self.colors.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (entry.value_ptr.channel_len != channel.len) continue;
            if (!std.mem.eql(u8, key[0..channel.len], channel)) continue;

            const removed = self.colors.fetchRemove(key).?;
            self.allocator.free(removed.key);
            self.allocator.free(removed.value.color);
            return true;
        }
        return false;
    }

    fn validateName(self: *const NicknameColor, name: []const u8, max_len: usize) Error!void {
        _ = self;
        if (name.len == 0) return error.EmptyName;
        if (name.len > max_len) return error.NameTooLong;
    }

    fn validName(self: *const NicknameColor, name: []const u8, max_len: usize) bool {
        _ = self;
        return name.len > 0 and name.len <= max_len;
    }
};

fn makeKey(allocator: std.mem.Allocator, channel: []const u8, member: []const u8) std.mem.Allocator.Error![]u8 {
    const key = try allocator.alloc(u8, channel.len + 1 + member.len);
    _ = buildKeyInto(key, channel, member);
    return key;
}

fn buildKeyInto(buf: []u8, channel: []const u8, member: []const u8) []const u8 {
    std.debug.assert(buf.len >= channel.len + 1 + member.len);
    @memcpy(buf[0..channel.len], channel);
    buf[channel.len] = 0;
    @memcpy(buf[channel.len + 1 .. channel.len + 1 + member.len], member);
    return buf[0 .. channel.len + 1 + member.len];
}

fn validateColor(hex: []const u8) Error!void {
    if (hex.len == 0) return error.EmptyColor;
    if (hex.len > 9) return error.ColorTooLong;

    const start: usize = if (hex[0] == '#') 1 else 0;
    if (start == hex.len) return error.InvalidColor;
    for (hex[start..]) |c| {
        if (!std.ascii.isHex(c)) return error.InvalidColor;
    }
}

const testing = std.testing;

test "set and get color by channel and member" {
    var colors = NicknameColor.init(testing.allocator);
    defer colors.deinit();

    try colors.set("#main", "alice", "#a1B2c3");
    try testing.expectEqualStrings("#a1B2c3", colors.get("#main", "alice").?);
    try testing.expectEqual(@as(?[]const u8, null), colors.get("#main", "bob"));
    try testing.expectEqual(@as(?[]const u8, null), colors.get("#other", "alice"));
}

test "set replaces an existing color" {
    var colors = NicknameColor.init(testing.allocator);
    defer colors.deinit();

    try colors.set("#main", "alice", "ffffff");
    try colors.set("#main", "alice", "#111111");
    try testing.expectEqualStrings("#111111", colors.get("#main", "alice").?);
}

test "clearChannel removes only that channel" {
    var colors = NicknameColor.init(testing.allocator);
    defer colors.deinit();

    try colors.set("#main", "alice", "#111111");
    try colors.set("#main", "bob", "#222222");
    try colors.set("#side", "alice", "#333333");
    try testing.expectEqual(@as(usize, 2), colors.clearChannel("#main"));
    try testing.expectEqual(@as(?[]const u8, null), colors.get("#main", "alice"));
    try testing.expectEqualStrings("#333333", colors.get("#side", "alice").?);
}

test "color and entry caps are enforced" {
    var colors = NicknameColor.initWithConfig(testing.allocator, .{
        .max_entries = 1,
        .max_channel_len = 5,
        .max_member_len = 5,
    });
    defer colors.deinit();

    try testing.expectError(error.EmptyName, colors.set("", "alice", "#111111"));
    try testing.expectError(error.NameTooLong, colors.set("#toolong", "alice", "#111111"));
    try testing.expectError(error.EmptyColor, colors.set("#main", "alice", ""));
    try testing.expectError(error.ColorTooLong, colors.set("#main", "alice", "#123456789"));
    try testing.expectError(error.InvalidColor, colors.set("#main", "alice", "#12xx56"));
    try colors.set("#main", "alice", "#111111");
    try testing.expectError(error.TooManyEntries, colors.set("#main", "bob", "#222222"));
}
