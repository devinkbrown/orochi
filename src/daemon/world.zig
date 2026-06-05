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
    UnsupportedMode,
};

pub const MessageTarget = union(enum) {
    channel: []const u8,
    nick: ClientId,
};

const chanmode = @import("chanmode.zig");
const chanmode_ext = @import("../proto/chanmode_ext.zig");
const listx = @import("../proto/listx.zig");

/// Per-member channel status modes (op @, voice + — no halfop) keyed by client.
const MemberMap = std.AutoHashMap(ClientId, chanmode.MemberModes);
pub const MemberIterator = MemberMap.KeyIterator;
pub const MemberMode = chanmode.MemberMode;
pub const MemberModes = chanmode.MemberModes;
pub const ChannelMode = chanmode.ChannelMode;

const Channel = struct {
    allocator: std.mem.Allocator,
    members: MemberMap,
    topic: ?[]u8 = null,
    /// Channel-level flag modes (i/m/n/t/s).
    modes: chanmode.ChannelModes = chanmode.ChannelModes.empty(),
    /// +k key — allocator-owned heap (safe across HashMap rehash; never a
    /// self-slice). Null = no key.
    key: ?[]u8 = null,
    /// +l member limit. Null = unlimited.
    limit: ?u32 = null,
    /// +b ban masks (nick!user@host globs), allocator-owned.
    bans: std.ArrayListUnmanaged([]u8) = .empty,
    /// +e ban-exception masks: a match here overrides a +b ban on JOIN.
    exempts: std.ArrayListUnmanaged([]u8) = .empty,
    /// +I invite-exception masks: a match here lets a user bypass +i on JOIN.
    invex: std.ArrayListUnmanaged([]u8) = .empty,
    /// Pending invitations (INVITE) that satisfy +i, by client id.
    invites: std.AutoHashMapUnmanaged(ClientId, void) = .empty,
    /// +p private (shown but flagged) and +h IRCX HIDDEN (omitted from LIST).
    private: bool = false,
    hidden: bool = false,
    /// IRCX extended channel flags (AUTHONLY/AUDITORIUM/NOWHISPER/etc.) that have
    /// no slot in the base ChannelModes letter set.
    ext_modes: chanmode_ext.ExtChannelFlags = chanmode_ext.ExtChannelFlags.empty(),
    /// IRCX object id, assigned once at creation (0 = unset). Surfaced as the
    /// channel OID built-in property.
    oid: u32 = 0,

    fn init(allocator: std.mem.Allocator) Channel {
        return .{
            .allocator = allocator,
            .members = MemberMap.init(allocator),
            .modes = chanmode.ChannelModes.empty(),
        };
    }

    fn deinit(self: *Channel) void {
        if (self.topic) |topic| self.allocator.free(topic);
        if (self.key) |k| self.allocator.free(k);
        for (self.bans.items) |b| self.allocator.free(b);
        self.bans.deinit(self.allocator);
        for (self.exempts.items) |e| self.allocator.free(e);
        self.exempts.deinit(self.allocator);
        for (self.invex.items) |i| self.allocator.free(i);
        self.invex.deinit(self.allocator);
        self.invites.deinit(self.allocator);
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
    /// Monotonic IRCX object-id source. Each newly-created channel gets the next
    /// value; starts at 1 so 0 means "unset" (never a real OID).
    next_oid: u32 = 1,

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
        // The first member to join a freshly-created channel is its FOUNDER
        // (Mizuchi founder tier +Q, prefix ~ — above ophion/IRCX owner); later
        // joiners start with no status modes.
        const founding = channel.members.count() == 0;
        const member = try channel.members.getOrPut(client);
        if (!member.found_existing) {
            member.value_ptr.* = if (founding)
                MemberModes.fromModes(&.{.founder})
            else
                MemberModes.empty();
        }
        return !member.found_existing;
    }

    /// Status modes for `client` in `name`, or null if not a member / no channel.
    pub fn memberModes(self: *World, name: []const u8, client: ClientId) ?MemberModes {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.members.get(client);
    }

    /// Set or clear one status mode for a member. Returns true if it changed.
    pub fn setMemberMode(
        self: *World,
        name: []const u8,
        client: ClientId,
        mode: MemberMode,
        on: bool,
    ) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const entry = channel.members.getEntry(client) orelse return error.NotOnChannel;
        const before = entry.value_ptr.contains(mode);
        if (on) entry.value_ptr.add(mode) else entry.value_ptr.remove(mode);
        return before != on;
    }

    /// Whether channel flag `mode` (i/m/n/t/s) is set. False if no such channel.
    pub fn channelHasFlag(self: *World, name: []const u8, mode: ChannelMode) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.modes.containsFlag(mode);
    }

    /// Whether an IRCX extended channel flag is set.
    pub fn channelHasExtFlag(self: *World, name: []const u8, flag: chanmode_ext.ExtChannelFlag) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.ext_modes.has(flag);
    }

    /// The channel's IRCX extended flag set (empty if no such channel).
    pub fn channelExtModes(self: *World, name: []const u8) chanmode_ext.ExtChannelFlags {
        const channel = self.channels.getPtr(name) orelse return chanmode_ext.ExtChannelFlags.empty();
        return channel.ext_modes;
    }

    /// Set or clear an IRCX extended channel flag. Returns true if it changed.
    pub fn setChannelExtFlag(self: *World, name: []const u8, flag: chanmode_ext.ExtChannelFlag, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.ext_modes.has(flag);
        if (on) channel.ext_modes.set(flag) else channel.ext_modes.clear(flag);
        return before != on;
    }

    /// Set or clear a channel flag mode (i/m/n/t/s). Returns true if it changed.
    pub fn setChannelFlag(self: *World, name: []const u8, mode: ChannelMode, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.modes.containsFlag(mode);
        switch (mode) {
            .invite_only => channel.modes.invite_only = on,
            .moderated => channel.modes.moderated = on,
            .no_external => channel.modes.no_external = on,
            .topic_ops => channel.modes.topic_ops = on,
            .secret => channel.modes.secret = on,
            else => return error.UnsupportedMode, // not a flag mode (b/e/I/k/l)
        }
        return before != on;
    }

    /// Set (`key != null`) or clear the +k channel key. New key is heap-owned;
    /// any prior key is freed.
    pub fn setChannelKey(self: *World, name: []const u8, key: ?[]const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        if (channel.key) |old| self.allocator.free(old);
        channel.key = if (key) |k| try self.allocator.dupe(u8, k) else null;
    }

    pub fn channelKey(self: *World, name: []const u8) ?[]const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.key;
    }

    /// Set (`limit != null`) or clear the +l member limit.
    pub fn setChannelLimit(self: *World, name: []const u8, limit: ?u32) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        channel.limit = limit;
    }

    pub fn channelLimit(self: *World, name: []const u8) ?u32 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.limit;
    }

    /// The IRCX object id assigned to `name` at creation (null if no such channel).
    pub fn channelOid(self: *World, name: []const u8) ?u32 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.oid;
    }

    /// +p private channel flag.
    pub fn setPrivate(self: *World, name: []const u8, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.private;
        channel.private = on;
        return before != on;
    }
    pub fn isPrivate(self: *World, name: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.private;
    }

    /// +h IRCX HIDDEN channel flag (omit from LIST).
    pub fn setHidden(self: *World, name: []const u8, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.hidden;
        channel.hidden = on;
        return before != on;
    }
    pub fn isHidden(self: *World, name: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.hidden;
    }

    pub fn memberCount(self: *World, name: []const u8) usize {
        const channel = self.channels.getPtr(name) orelse return 0;
        return channel.members.count();
    }

    /// Add a +b ban mask. Returns true if newly added (false if already present).
    pub fn addBan(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        for (channel.bans.items) |b| {
            if (std.mem.eql(u8, b, mask)) return false;
        }
        const owned = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(owned);
        try channel.bans.append(self.allocator, owned);
        return true;
    }

    /// Remove a +b ban mask. Returns true if it existed.
    pub fn removeBan(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        for (channel.bans.items, 0..) |b, idx| {
            if (std.mem.eql(u8, b, mask)) {
                self.allocator.free(b);
                _ = channel.bans.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    /// Ban masks for RPL_BANLIST, or null if no such channel.
    pub fn bansOf(self: *World, name: []const u8) ?[]const []const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.bans.items;
    }

    fn listAddMask(self: *World, list: *std.ArrayListUnmanaged([]u8), mask: []const u8) WorldError!bool {
        for (list.items) |m| {
            if (std.mem.eql(u8, m, mask)) return false;
        }
        const owned = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(owned);
        try list.append(self.allocator, owned);
        return true;
    }

    fn listRemoveMask(self: *World, list: *std.ArrayListUnmanaged([]u8), mask: []const u8) bool {
        for (list.items, 0..) |m, idx| {
            if (std.mem.eql(u8, m, mask)) {
                self.allocator.free(m);
                _ = list.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    fn listMatches(list: []const []const u8, hostmask: []const u8) bool {
        for (list) |m| {
            if (listx.globMatch(m, hostmask)) return true;
        }
        return false;
    }

    /// +e ban-exception list operations.
    pub fn addExempt(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.exempts, mask);
    }
    pub fn removeExempt(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.exempts, mask);
    }
    pub fn exemptsOf(self: *World, name: []const u8) ?[]const []const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.exempts.items;
    }
    pub fn isExempt(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatches(channel.exempts.items, hostmask);
    }

    /// +I invite-exception list operations.
    pub fn addInvex(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.invex, mask);
    }
    pub fn removeInvex(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.invex, mask);
    }
    pub fn invexOf(self: *World, name: []const u8) ?[]const []const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.invex.items;
    }
    pub fn isInvexed(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatches(channel.invex.items, hostmask);
    }

    /// Whether `hostmask` (nick!user@host) matches any +b entry (case-insensitive
    /// glob via listx.globMatch).
    pub fn isBanned(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        // A +e ban-exception match overrides any +b ban.
        if (listMatches(channel.exempts.items, hostmask)) return false;
        return listMatches(channel.bans.items, hostmask);
    }

    /// Record an INVITE so the target may bypass +i.
    pub fn addInvite(self: *World, name: []const u8, client: ClientId) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        try channel.invites.put(self.allocator, client, {});
    }

    /// Whether `client` holds a pending invite (does not consume it).
    pub fn hasInvite(self: *World, name: []const u8, client: ClientId) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.invites.contains(client);
    }

    /// Render the active channel flag modes as a "+imnt"-style string into `out`.
    pub fn channelModeString(self: *World, name: []const u8, out: []u8) []const u8 {
        const channel = self.channels.getPtr(name) orelse {
            if (out.len >= 1) {
                out[0] = '+';
                return out[0..1];
            }
            return out[0..0];
        };
        var n: usize = 0;
        if (n < out.len) {
            out[n] = '+';
            n += 1;
        }
        const flags = [_]struct { m: ChannelMode, c: u8 }{
            .{ .m = .invite_only, .c = 'i' },
            .{ .m = .moderated, .c = 'm' },
            .{ .m = .no_external, .c = 'n' },
            .{ .m = .topic_ops, .c = 't' },
            .{ .m = .secret, .c = 's' },
        };
        for (flags) |f| {
            if (channel.modes.containsFlag(f.m) and n < out.len) {
                out[n] = f.c;
                n += 1;
            }
        }
        if (channel.private and n < out.len) {
            out[n] = 'p';
            n += 1;
        }
        if (channel.hidden and n < out.len) {
            out[n] = 'h';
            n += 1;
        }
        return out[0..n];
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

    /// Read-only view of a channel for LIST.
    pub const ChannelView = struct {
        name: []const u8,
        members: usize,
        topic: []const u8,
        secret: bool,
        hidden: bool,
    };

    pub const ChannelViewIterator = struct {
        inner: std.StringHashMap(Channel).Iterator,

        pub fn next(self: *ChannelViewIterator) ?ChannelView {
            if (self.inner.next()) |entry| {
                return .{
                    .name = entry.key_ptr.*,
                    .members = entry.value_ptr.members.count(),
                    .topic = entry.value_ptr.topic orelse "",
                    .secret = entry.value_ptr.modes.secret,
                    .hidden = entry.value_ptr.hidden,
                };
            }
            return null;
        }
    };

    pub fn channelIterator(self: *World) ChannelViewIterator {
        return .{ .inner = self.channels.iterator() };
    }

    /// Fill `out` with the names of channels `client` is a member of (scan; no
    /// reverse index yet). Returns the count written, capped at `out.len`.
    /// Channel-name slices borrow from world storage and stay valid until the
    /// channel is removed.
    pub fn channelsOf(self: *World, client: ClientId, out: [][]const u8) usize {
        var n: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (n >= out.len) break;
            if (entry.value_ptr.members.contains(client)) {
                out[n] = entry.key_ptr.*;
                n += 1;
            }
        }
        return n;
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
        entry.value_ptr.oid = self.next_oid;
        self.next_oid +%= 1;
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

test "channels receive monotonic, stable, unique IRCX object ids" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try std.testing.expect(try world.join("#first", a));
    try std.testing.expect(try world.join("#second", a));

    const oid1 = world.channelOid("#first").?;
    const oid2 = world.channelOid("#second").?;
    try std.testing.expectEqual(@as(u32, 1), oid1); // counter starts at 1
    try std.testing.expectEqual(@as(u32, 2), oid2);
    try std.testing.expect(oid1 != oid2);

    // OID is stable across further membership churn on the same channel.
    const b = testClient(2);
    try std.testing.expect(try world.join("#first", b));
    try std.testing.expectEqual(oid1, world.channelOid("#first").?);

    // Unknown channel has no OID.
    try std.testing.expect(world.channelOid("#nope") == null);
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

test "first joiner founds the channel as operator; later joiners have no status" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const founder = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const second = ClientId{ .shard = 0, .slot = 2, .gen = 1 };

    _ = try world.join("#x", founder);
    _ = try world.join("#x", second);

    try std.testing.expect(world.memberModes("#x", founder).?.contains(.founder));
    try std.testing.expect(world.memberModes("#x", founder).?.isOperator());
    try std.testing.expect(!world.memberModes("#x", second).?.contains(.founder));
    try std.testing.expectEqual(@as(u8, '~'), world.memberModes("#x", founder).?.highestPrefix());
    try std.testing.expectEqual(@as(u8, 0), world.memberModes("#x", second).?.highestPrefix());
}

test "setMemberMode adds and removes status and reports change" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a); // a founds (op)
    _ = try world.join("#x", b);

    try std.testing.expect(try world.setMemberMode("#x", b, .voice, true));
    try std.testing.expect(world.memberModes("#x", b).?.contains(.voice));
    // Idempotent set reports no change.
    try std.testing.expect(!(try world.setMemberMode("#x", b, .voice, true)));
    try std.testing.expect(try world.setMemberMode("#x", b, .voice, false));
    try std.testing.expect(!world.memberModes("#x", b).?.contains(.voice));

    try std.testing.expectError(error.NotOnChannel, world.setMemberMode("#x", ClientId{ .shard = 0, .slot = 9, .gen = 1 }, .op, true));
    try std.testing.expect(world.memberModes("#nope", a) == null);
}

test "channel key, limit, bans, and invites with ownership" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a);

    // Key: set, replace (frees old), clear (frees).
    try world.setChannelKey("#x", "first");
    try std.testing.expectEqualStrings("first", world.channelKey("#x").?);
    try world.setChannelKey("#x", "second");
    try std.testing.expectEqualStrings("second", world.channelKey("#x").?);
    try world.setChannelKey("#x", null);
    try std.testing.expect(world.channelKey("#x") == null);

    // Limit.
    try std.testing.expect(world.channelLimit("#x") == null);
    try world.setChannelLimit("#x", 42);
    try std.testing.expectEqual(@as(?u32, 42), world.channelLimit("#x"));

    // Bans: add (dedup), match (glob, case-insensitive), remove.
    try std.testing.expect(try world.addBan("#x", "bad!*@*"));
    try std.testing.expect(!(try world.addBan("#x", "bad!*@*"))); // dup
    try std.testing.expect(world.isBanned("#x", "BAD!user@host"));
    try std.testing.expect(!world.isBanned("#x", "good!user@host"));
    try std.testing.expectEqual(@as(usize, 1), world.bansOf("#x").?.len);
    try std.testing.expect(try world.removeBan("#x", "bad!*@*"));
    try std.testing.expect(!world.isBanned("#x", "BAD!user@host"));

    // +e exemption overrides a +b ban; +I invite-exception list is independent.
    try std.testing.expect(try world.addBan("#x", "bad!*@*"));
    try std.testing.expect(world.isBanned("#x", "bad!u@h"));
    try std.testing.expect(try world.addExempt("#x", "bad!vip@*"));
    try std.testing.expect(!world.isBanned("#x", "bad!vip@h")); // exempt wins
    try std.testing.expect(world.isBanned("#x", "bad!other@h")); // still banned
    try std.testing.expectEqual(@as(usize, 1), world.exemptsOf("#x").?.len);
    try std.testing.expect(try world.removeExempt("#x", "bad!vip@*"));
    try std.testing.expect(world.isBanned("#x", "bad!vip@h")); // ban back in force
    try std.testing.expect(try world.addInvex("#x", "friend!*@*"));
    try std.testing.expect(world.isInvexed("#x", "FRIEND!u@h"));
    try std.testing.expectEqual(@as(usize, 1), world.invexOf("#x").?.len);

    // Invites.
    try std.testing.expect(!world.hasInvite("#x", b));
    try world.addInvite("#x", b);
    try std.testing.expect(world.hasInvite("#x", b));

    // memberCount tracks membership.
    try std.testing.expectEqual(@as(usize, 1), world.memberCount("#x"));
    try std.testing.expectError(error.NoSuchChannel, world.setChannelKey("#nope", "k"));
}

test "channel flag modes set, query, and render" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#x", a);

    try std.testing.expect(!world.channelHasFlag("#x", .moderated));
    try std.testing.expect(try world.setChannelFlag("#x", .moderated, true));
    try std.testing.expect(try world.setChannelFlag("#x", .topic_ops, true));
    try std.testing.expect(world.channelHasFlag("#x", .moderated));
    // Idempotent set reports no change.
    try std.testing.expect(!(try world.setChannelFlag("#x", .moderated, true)));

    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("+mt", world.channelModeString("#x", &buf));

    try std.testing.expect(try world.setChannelFlag("#x", .moderated, false));
    try std.testing.expectEqualStrings("+t", world.channelModeString("#x", &buf));
    try std.testing.expectError(error.NoSuchChannel, world.setChannelFlag("#nope", .secret, true));
}

test "channelsOf lists a client's channels" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a);
    _ = try world.join("#y", a);
    _ = try world.join("#x", b);

    var buf: [8][]const u8 = undefined;
    const n = world.channelsOf(a, &buf);
    try std.testing.expectEqual(@as(usize, 2), n);
    // both #x and #y present (order is map-dependent)
    var seen_x = false;
    var seen_y = false;
    for (buf[0..n]) |c| {
        if (std.mem.eql(u8, c, "#x")) seen_x = true;
        if (std.mem.eql(u8, c, "#y")) seen_y = true;
    }
    try std.testing.expect(seen_x and seen_y);
    try std.testing.expectEqual(@as(usize, 1), world.channelsOf(b, &buf));
}
