//! Tiered channel keys for graduated entry trust.
//!
//! A channel can advertise up to three independent shared secrets. Callers
//! decide how `.none` is interpreted: if no keys exist, `.none` means the
//! channel is open; otherwise it means the presented secret did not match.

const std = @import("std");

pub const Tier = enum(u2) {
    none = 0,
    member = 1,
    host = 2,
    owner = 3,
};

pub const KeyError = std.mem.Allocator.Error || error{
    CannotSetOpenTier,
};

pub const ChannelKeys = struct {
    member_key: ?[]u8 = null,
    host_key: ?[]u8 = null,
    owner_key: ?[]u8 = null,

    const Self = @This();

    pub fn setKey(
        self: *Self,
        allocator: std.mem.Allocator,
        tier: Tier,
        key: []const u8,
    ) KeyError!void {
        const owned = try allocator.dupe(u8, key);
        errdefer allocator.free(owned);

        const slot = switch (tier) {
            .none => return error.CannotSetOpenTier,
            .member => &self.member_key,
            .host => &self.host_key,
            .owner => &self.owner_key,
        };

        if (slot.*) |old| {
            allocator.free(old);
        }
        slot.* = owned;
    }

    pub fn clearKey(self: *Self, allocator: std.mem.Allocator, tier: Tier) void {
        const slot = switch (tier) {
            .none => return,
            .member => &self.member_key,
            .host => &self.host_key,
            .owner => &self.owner_key,
        };

        if (slot.*) |old| {
            allocator.free(old);
            slot.* = null;
        }
    }

    pub fn grantFor(self: *const Self, presented_key: []const u8) Tier {
        const owner_match = matchesKey(self.owner_key, presented_key);
        const host_match = matchesKey(self.host_key, presented_key);
        const member_match = matchesKey(self.member_key, presented_key);

        if (owner_match) return .owner;
        if (host_match) return .host;
        if (member_match) return .member;
        return .none;
    }

    pub fn hasAnyKey(self: *const Self) bool {
        return self.member_key != null or self.host_key != null or self.owner_key != null;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.clearKey(allocator, .member);
        self.clearKey(allocator, .host);
        self.clearKey(allocator, .owner);
    }
};

fn matchesKey(stored_key: ?[]const u8, presented_key: []const u8) bool {
    const stored = stored_key orelse return false;
    return timingSafeSliceEql(stored, presented_key);
}

fn timingSafeSliceEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    var offset: usize = 0;
    while (offset + 32 <= a.len) : (offset += 32) {
        const left: *const [32]u8 = a[offset..][0..32];
        const right: *const [32]u8 = b[offset..][0..32];
        diff |= @intFromBool(!std.crypto.timing_safe.eql([32]u8, left.*, right.*));
    }

    while (offset < a.len) : (offset += 1) {
        diff |= a[offset] ^ b[offset];
    }

    return diff == 0;
}

const testing = std.testing;

test "owner key grants owner" {
    const allocator = testing.allocator;
    var keys = ChannelKeys{};
    defer keys.deinit(allocator);

    try keys.setKey(allocator, .member, "member-pass");
    try keys.setKey(allocator, .host, "host-pass");
    try keys.setKey(allocator, .owner, "owner-pass");

    try testing.expectEqual(Tier.owner, keys.grantFor("owner-pass"));
}

test "a key matching member only grants member" {
    const allocator = testing.allocator;
    var keys = ChannelKeys{};
    defer keys.deinit(allocator);

    try keys.setKey(allocator, .member, "shared-member");
    try keys.setKey(allocator, .host, "shared-host");
    try keys.setKey(allocator, .owner, "shared-owner");

    try testing.expectEqual(Tier.member, keys.grantFor("shared-member"));
}

test "highest matching tier wins" {
    const allocator = testing.allocator;
    var keys = ChannelKeys{};
    defer keys.deinit(allocator);

    try keys.setKey(allocator, .member, "same");
    try keys.setKey(allocator, .host, "same");
    try keys.setKey(allocator, .owner, "same");

    try testing.expectEqual(Tier.owner, keys.grantFor("same"));
}

test "no keys grants none for caller-open channel" {
    var keys = ChannelKeys{};

    try testing.expect(!keys.hasAnyKey());
    try testing.expectEqual(Tier.none, keys.grantFor("anything"));
}

test "clearing a tier removes only that key" {
    const allocator = testing.allocator;
    var keys = ChannelKeys{};
    defer keys.deinit(allocator);

    try keys.setKey(allocator, .member, "member-pass");
    try keys.setKey(allocator, .host, "host-pass");

    keys.clearKey(allocator, .member);

    try testing.expectEqual(Tier.none, keys.grantFor("member-pass"));
    try testing.expectEqual(Tier.host, keys.grantFor("host-pass"));
    try testing.expect(keys.hasAnyKey());
}

test "replace frees old key and preserves new grant" {
    const allocator = testing.allocator;
    var keys = ChannelKeys{};
    defer keys.deinit(allocator);

    try keys.setKey(allocator, .host, "old-host-pass");
    try keys.setKey(allocator, .host, "new-host-pass");

    try testing.expectEqual(Tier.none, keys.grantFor("old-host-pass"));
    try testing.expectEqual(Tier.host, keys.grantFor("new-host-pass"));
}

test "open tier cannot be assigned" {
    const allocator = testing.allocator;
    var keys = ChannelKeys{};
    defer keys.deinit(allocator);

    try testing.expectError(error.CannotSetOpenTier, keys.setKey(allocator, .none, "unused"));
}
