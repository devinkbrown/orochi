//! Bounded invite token registry.
//!
//! Tokens and channels are owned by the registry. Successful redeem calls return
//! a borrowed channel slice that remains valid until the token is revoked,
//! replaced, expired by a later redeem, or the registry is deinitialized.
const std = @import("std");

pub const max_tokens: usize = 4096;
pub const max_token_bytes: usize = 128;
pub const max_channel_bytes: usize = 128;

pub const Error = std.mem.Allocator.Error || error{
    InvalidToken,
    InvalidChannel,
    InvalidUses,
    TooManyTokens,
};

pub const InviteRecord = struct {
    channel: []u8,
    uses_left: u32,
    expires_ms: i64,

    fn deinit(self: *InviteRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.channel);
        self.* = undefined;
    }

    fn expired(self: *const InviteRecord, now_ms: i64) bool {
        return now_ms >= self.expires_ms;
    }
};

pub const InviteToken = struct {
    allocator: std.mem.Allocator,
    tokens: std.StringHashMap(InviteRecord),

    pub fn init(allocator: std.mem.Allocator) InviteToken {
        return .{
            .allocator = allocator,
            .tokens = std.StringHashMap(InviteRecord).init(allocator),
        };
    }

    pub fn deinit(self: *InviteToken) void {
        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.tokens.deinit();
        self.* = undefined;
    }

    /// Create or replace a token.
    pub fn create(self: *InviteToken, token: []const u8, channel: []const u8, uses: u32, expires_ms: i64) Error!void {
        try validateToken(token);
        try validateChannel(channel);
        if (uses == 0) return error.InvalidUses;

        const channel_owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_owned);

        if (self.tokens.getPtr(token)) |record| {
            self.allocator.free(record.channel);
            record.* = .{ .channel = channel_owned, .uses_left = uses, .expires_ms = expires_ms };
            return;
        }

        if (self.tokens.count() >= max_tokens) return error.TooManyTokens;
        const token_owned = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(token_owned);
        try self.tokens.putNoClobber(token_owned, .{
            .channel = channel_owned,
            .uses_left = uses,
            .expires_ms = expires_ms,
        });
    }

    /// Redeem a token at `now_ms`. Returns the channel on success.
    pub fn redeem(self: *InviteToken, token: []const u8, now_ms: i64) ?[]const u8 {
        const entry = self.tokens.getEntry(token) orelse return null;
        if (entry.value_ptr.expired(now_ms) or entry.value_ptr.uses_left == 0) {
            self.removeEntry(entry);
            return null;
        }

        entry.value_ptr.uses_left -= 1;
        return entry.value_ptr.channel;
    }

    pub fn revoke(self: *InviteToken, token: []const u8) bool {
        const entry = self.tokens.getEntry(token) orelse return false;
        self.removeEntry(entry);
        return true;
    }

    pub fn usesLeft(self: *const InviteToken, token: []const u8) u32 {
        const record = self.tokens.getPtr(token) orelse return 0;
        return record.uses_left;
    }

    fn removeEntry(self: *InviteToken, entry: std.StringHashMap(InviteRecord).Entry) void {
        const key = entry.key_ptr.*;
        var record = entry.value_ptr.*;
        self.tokens.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        record.deinit(self.allocator);
    }
};

fn validateToken(token: []const u8) Error!void {
    if (token.len == 0 or token.len > max_token_bytes) return error.InvalidToken;
}

fn validateChannel(channel: []const u8) Error!void {
    if (channel.len == 0 or channel.len > max_channel_bytes) return error.InvalidChannel;
}

const testing = std.testing;

test "create and redeem decrements uses" {
    var invites = InviteToken.init(testing.allocator);
    defer invites.deinit();

    try invites.create("tok1", "#main", 2, 100);

    const first = invites.redeem("tok1", 10).?;
    try testing.expectEqualStrings("#main", first);
    try testing.expectEqual(@as(u32, 1), invites.usesLeft("tok1"));

    const second = invites.redeem("tok1", 20).?;
    try testing.expectEqualStrings("#main", second);
    try testing.expectEqual(@as(u32, 0), invites.usesLeft("tok1"));
    try testing.expect(invites.redeem("tok1", 30) == null);
}

test "expired tokens are removed on redeem" {
    var invites = InviteToken.init(testing.allocator);
    defer invites.deinit();

    try invites.create("tok1", "#main", 1, 50);
    try testing.expect(invites.redeem("tok1", 50) == null);
    try testing.expectEqual(@as(u32, 0), invites.usesLeft("tok1"));
}

test "revoke removes only existing token" {
    var invites = InviteToken.init(testing.allocator);
    defer invites.deinit();

    try invites.create("tok1", "#main", 1, 100);
    try testing.expect(invites.revoke("tok1"));
    try testing.expect(!invites.revoke("tok1"));
    try testing.expect(invites.redeem("tok1", 10) == null);
}

test "create replaces existing token record" {
    var invites = InviteToken.init(testing.allocator);
    defer invites.deinit();

    try invites.create("tok1", "#old", 1, 100);
    try invites.create("tok1", "#new", 3, 200);

    const channel = invites.redeem("tok1", 150).?;
    try testing.expectEqualStrings("#new", channel);
    try testing.expectEqual(@as(u32, 2), invites.usesLeft("tok1"));
}

test "validation rejects empty fields and zero uses" {
    var invites = InviteToken.init(testing.allocator);
    defer invites.deinit();

    try testing.expectError(error.InvalidToken, invites.create("", "#main", 1, 100));
    try testing.expectError(error.InvalidChannel, invites.create("tok1", "", 1, 100));
    try testing.expectError(error.InvalidUses, invites.create("tok1", "#main", 0, 100));
}
