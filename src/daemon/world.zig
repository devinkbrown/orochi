//! Single-server chat world state.
//!
//! This module intentionally models only local daemon state: nick ownership,
//! channel membership, and channel topics. It has no S2S/CRDT responsibilities.
const std = @import("std");

/// Opaque client handle value used by the local server world.
pub const ClientId = packed struct {
    shard: u12,
    slot: u20,
    gen: u32,

    pub const invalid: ClientId = .{
        .shard = std.math.maxInt(u12),
        .slot = std.math.maxInt(u20),
        .gen = std.math.maxInt(u32),
    };

    pub fn eql(self: ClientId, other: ClientId) bool {
        return self.shard == other.shard and
            self.slot == other.slot and
            self.gen == other.gen;
    }
};

pub const WorldError = std.mem.Allocator.Error || error{
    NickInUse,
    NoSuchChannel,
    NotOnChannel,
    NoSuchNick,
};

pub const MessageTarget = union(enum) {
    channel: []const u8,
    nick: ClientId,
};

const MemberMap = std.AutoHashMap(ClientId, void);
pub const MemberIterator = MemberMap.KeyIterator;

const Channel = struct {
    allocator: std.mem.Allocator,
    members: MemberMap,
    topic: ?[]u8 = null,

    fn init(allocator: std.mem.Allocator) Channel {
        return .{
            .allocator = allocator,
            .members = MemberMap.init(allocator),
        };
    }

    fn deinit(self: *Channel) void {
        if (self.topic) |topic| self.allocator.free(topic);
        self.members.deinit();
        self.* = undefined;
    }

    fn setTopic(self: *Channel, topic: []const u8) std.mem.Allocator.Error!void {
        const owned = try self.allocator.dupe(u8, topic);
        if (self.topic) |old| self.allocator.free(old);
        self.topic = owned;
    }
};

/// Owned local nick/channel registry.
pub const World = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(Channel),
    nicks: std.StringHashMap(ClientId),
    client_nicks: std.AutoHashMap(ClientId, []u8),

    pub fn init(allocator: std.mem.Allocator) World {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(Channel).init(allocator),
            .nicks = std.StringHashMap(ClientId).init(allocator),
            .client_nicks = std.AutoHashMap(ClientId, []u8).init(allocator),
        };
    }

    pub fn deinit(self: *World) void {
        var channel_it = self.channels.iterator();
        while (channel_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.channels.deinit();

        self.nicks.deinit();

        var nick_it = self.client_nicks.iterator();
        while (nick_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.client_nicks.deinit();
        self.* = undefined;
    }

    /// Register `nick` for `client`, rejecting collisions.
    pub fn registerNick(self: *World, nick: []const u8, client: ClientId) WorldError!void {
        if (self.nicks.get(nick)) |existing| {
            if (existing.eql(client)) return;
            return error.NickInUse;
        }

        if (self.client_nicks.contains(client)) {
            self.unregisterNick(client);
        }

        const owned = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned);

        try self.nicks.put(owned, client);
        errdefer _ = self.nicks.remove(owned);

        try self.client_nicks.put(client, owned);
    }

    /// Remove any nick owned by `client`.
    pub fn unregisterNick(self: *World, client: ClientId) void {
        if (self.client_nicks.fetchRemove(client)) |removed| {
            _ = self.nicks.remove(removed.value);
            self.allocator.free(removed.value);
        }
    }

    pub fn nickOf(self: *const World, client: ClientId) ?[]const u8 {
        return self.client_nicks.get(client);
    }

    pub fn findNick(self: *const World, nick: []const u8) ?ClientId {
        return self.nicks.get(nick);
    }

    /// Join a channel. Returns true when membership was newly added.
    pub fn join(self: *World, name: []const u8, client: ClientId) WorldError!bool {
        const channel = try self.ensureChannel(name);
        const member = try channel.members.getOrPut(client);
        if (!member.found_existing) {
            member.value_ptr.* = {};
        }
        return !member.found_existing;
    }

    /// Part a channel, deleting it when the last member leaves.
    pub fn part(self: *World, name: []const u8, client: ClientId) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        if (!channel.members.remove(client)) return error.NotOnChannel;
        if (channel.members.count() == 0) {
            self.removeChannel(name);
        }
    }

    pub fn isMember(self: *World, name: []const u8, client: ClientId) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.members.contains(client);
    }

    pub fn channelExists(self: *const World, name: []const u8) bool {
        return self.channels.contains(name);
    }

    pub fn channelCount(self: *const World) usize {
        return self.channels.count();
    }

    pub fn memberIterator(self: *World, name: []const u8) ?MemberIterator {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.members.keyIterator();
    }

    pub fn setTopic(self: *World, name: []const u8, text: []const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        try channel.setTopic(text);
    }

    pub fn topic(self: *const World, name: []const u8) ?[]const u8 {
        const channel = self.channels.get(name) orelse return null;
        return channel.topic;
    }

    pub fn resolveMessageTarget(self: *World, target: []const u8) WorldError!MessageTarget {
        if (isChannelName(target)) {
            const entry = self.channels.getEntry(target) orelse return error.NoSuchChannel;
            return .{ .channel = entry.key_ptr.* };
        }

        if (self.findNick(target)) |client| {
            return .{ .nick = client };
        }
        return error.NoSuchNick;
    }

    /// Remove `client` from all registries and channels.
    pub fn removeClient(self: *World, client: ClientId) void {
        self.unregisterNick(client);

        while (true) {
            var empty_channel: ?[]const u8 = null;
            var it = self.channels.iterator();
            while (it.next()) |entry| {
                _ = entry.value_ptr.members.remove(client);
                if (entry.value_ptr.members.count() == 0) {
                    empty_channel = entry.key_ptr.*;
                    break;
                }
            }
            if (empty_channel) |name| {
                self.removeChannel(name);
            } else {
                break;
            }
        }
    }

    fn ensureChannel(self: *World, name: []const u8) std.mem.Allocator.Error!*Channel {
        const entry = try self.channels.getOrPut(name);
        if (entry.found_existing) return entry.value_ptr;

        const owned_name = try self.allocator.dupe(u8, name);
        entry.key_ptr.* = owned_name;
        entry.value_ptr.* = Channel.init(self.allocator);
        return entry.value_ptr;
    }

    fn removeChannel(self: *World, name: []const u8) void {
        if (self.channels.getEntry(name)) |entry| {
            const owned_name = entry.key_ptr.*;
            entry.value_ptr.deinit();
            self.channels.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_name);
        }
    }
};

pub fn isChannelName(name: []const u8) bool {
    return name.len != 0 and name[0] == '#';
}

fn testClient(slot: u20) ClientId {
    return .{ .shard = 0, .slot = slot, .gen = 1 };
}

test "nick registry rejects collisions and supports lookup" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);
    try world.registerNick("A", a);

    try std.testing.expectEqual(a, world.findNick("A").?);
    try std.testing.expectEqualStrings("A", world.nickOf(a).?);
    try std.testing.expectError(error.NickInUse, world.registerNick("A", b));

    world.unregisterNick(a);
    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("A"));
    try std.testing.expectEqual(@as(?[]const u8, null), world.nickOf(a));
}

test "join part and membership cleanup" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try std.testing.expect(try world.join("#x", a));
    try std.testing.expect(!try world.join("#x", a));
    try std.testing.expect(try world.join("#x", b));
    try std.testing.expect(world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));
    try std.testing.expectEqual(@as(usize, 1), world.channelCount());

    try world.part("#x", a);
    try std.testing.expect(!world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));

    try world.part("#x", b);
    try std.testing.expect(!world.channelExists("#x"));
    try std.testing.expectEqual(@as(usize, 0), world.channelCount());
}

test "removeClient drops all channel memberships and nick ownership" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try world.registerNick("A", a);
    try world.registerNick("B", b);
    _ = try world.join("#x", a);
    _ = try world.join("#x", b);
    _ = try world.join("#y", a);

    world.removeClient(a);

    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("A"));
    try std.testing.expect(!world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));
    try std.testing.expect(!world.channelExists("#y"));
}

test "message target resolution distinguishes channel and nick targets" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try world.registerNick("A", a);
    _ = try world.join("#x", a);

    const channel = try world.resolveMessageTarget("#x");
    try std.testing.expectEqualStrings("#x", channel.channel);

    const nick = try world.resolveMessageTarget("A");
    try std.testing.expectEqual(a, nick.nick);

    try std.testing.expectError(error.NoSuchChannel, world.resolveMessageTarget("#missing"));
    try std.testing.expectError(error.NoSuchNick, world.resolveMessageTarget("missing"));
}

test "topics are owned and released" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    _ = try world.join("#x", a);
    try world.setTopic("#x", "first topic");
    try std.testing.expectEqualStrings("first topic", world.topic("#x").?);
    try world.setTopic("#x", "second topic");
    try std.testing.expectEqualStrings("second topic", world.topic("#x").?);
}
