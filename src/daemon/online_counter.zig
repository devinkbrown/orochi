//! Current per-channel online member counts with set semantics.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyName,
    NameTooLong,
    TooManyChannels,
    TooManyMembers,
};

pub const Config = struct {
    max_channels: usize = 65_536,
    max_members_per_channel: usize = 65_536,
    max_channel_len: usize = 128,
    max_id_len: usize = 128,
};

const MemberSet = struct {
    members: std.StringHashMap(void),

    fn init(allocator: std.mem.Allocator) MemberSet {
        return .{ .members = std.StringHashMap(void).init(allocator) };
    }

    fn deinit(self: *MemberSet, allocator: std.mem.Allocator) void {
        var it = self.members.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.members.deinit();
        self.* = undefined;
    }

    fn add(self: *MemberSet, allocator: std.mem.Allocator, id: []const u8, max_members: usize) Error!void {
        if (self.members.contains(id)) return;
        if (self.members.count() >= max_members) return error.TooManyMembers;

        const owned = try allocator.dupe(u8, id);
        errdefer allocator.free(owned);
        try self.members.putNoClobber(owned, {});
    }

    fn remove(self: *MemberSet, allocator: std.mem.Allocator, id: []const u8) bool {
        const removed = self.members.fetchRemove(id) orelse return false;
        allocator.free(removed.key);
        return true;
    }

    fn count(self: *const MemberSet) usize {
        return self.members.count();
    }
};

pub const OnlineCounter = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    channels: std.StringHashMap(MemberSet),

    pub fn init(allocator: std.mem.Allocator) OnlineCounter {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) OnlineCounter {
        std.debug.assert(cfg.max_channels > 0);
        std.debug.assert(cfg.max_members_per_channel > 0);
        std.debug.assert(cfg.max_channel_len > 0);
        std.debug.assert(cfg.max_id_len > 0);
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .channels = std.StringHashMap(MemberSet).init(allocator),
        };
    }

    pub fn deinit(self: *OnlineCounter) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn join(self: *OnlineCounter, channel: []const u8, id: []const u8) Error!void {
        try self.validate(channel, self.cfg.max_channel_len);
        try self.validate(id, self.cfg.max_id_len);

        if (self.channels.getPtr(channel)) |members| {
            try members.add(self.allocator, id, self.cfg.max_members_per_channel);
            return;
        }
        if (self.channels.count() >= self.cfg.max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);

        var members = MemberSet.init(self.allocator);
        errdefer members.deinit(self.allocator);
        try members.add(self.allocator, id, self.cfg.max_members_per_channel);

        try self.channels.putNoClobber(owned_channel, members);
    }

    pub fn leave(self: *OnlineCounter, channel: []const u8, id: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        if (!entry.value_ptr.remove(self.allocator, id)) return false;
        if (entry.value_ptr.count() == 0) self.dropChannel(entry);
        return true;
    }

    pub fn count(self: *const OnlineCounter, channel: []const u8) usize {
        const members = self.channels.getPtr(channel) orelse return 0;
        return members.count();
    }

    fn dropChannel(self: *OnlineCounter, entry: std.StringHashMap(MemberSet).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn validate(self: *const OnlineCounter, name: []const u8, max_len: usize) Error!void {
        _ = self;
        if (name.len == 0) return error.EmptyName;
        if (name.len > max_len) return error.NameTooLong;
    }
};

const testing = std.testing;

test "join counts unique ids only" {
    var online = OnlineCounter.init(testing.allocator);
    defer online.deinit();

    try online.join("#main", "a");
    try online.join("#main", "a");
    try online.join("#main", "b");
    try testing.expectEqual(@as(usize, 2), online.count("#main"));
}

test "leave removes ids and prunes empty channels" {
    var online = OnlineCounter.init(testing.allocator);
    defer online.deinit();

    try online.join("#main", "a");
    try testing.expect(online.leave("#main", "a"));
    try testing.expect(!online.leave("#main", "a"));
    try testing.expectEqual(@as(usize, 0), online.count("#main"));
}

test "channels remain independent" {
    var online = OnlineCounter.init(testing.allocator);
    defer online.deinit();

    try online.join("#main", "a");
    try online.join("#side", "a");
    try online.join("#side", "b");
    try testing.expectEqual(@as(usize, 1), online.count("#main"));
    try testing.expectEqual(@as(usize, 2), online.count("#side"));
}

test "validation and bounds are enforced" {
    var online = OnlineCounter.initWithConfig(testing.allocator, .{
        .max_channels = 1,
        .max_members_per_channel = 1,
        .max_channel_len = 5,
        .max_id_len = 3,
    });
    defer online.deinit();

    try testing.expectError(error.EmptyName, online.join("", "a"));
    try testing.expectError(error.NameTooLong, online.join("#abcdef", "a"));
    try testing.expectError(error.NameTooLong, online.join("#main", "abcd"));
    try online.join("#main", "a");
    try testing.expectError(error.TooManyMembers, online.join("#main", "b"));
    try testing.expectError(error.TooManyChannels, online.join("#side", "a"));
}
