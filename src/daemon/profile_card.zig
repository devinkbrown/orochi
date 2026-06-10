//! Orochi per-account profile cards.
//!
//! Field values are owned by this store. Returned cards contain borrowed slices
//! and remain valid until the next mutation for the same account.
const std = @import("std");

pub const max_accounts: usize = 65536;
pub const max_account_bytes: usize = 64;
pub const max_bio_bytes: usize = 300;
pub const max_url_bytes: usize = 200;
pub const max_pronouns_bytes: usize = 32;

pub const Field = enum {
    bio,
    url,
    pronouns,
};

pub const Card = struct {
    bio: []const u8 = &.{},
    url: []const u8 = &.{},
    pronouns: []const u8 = &.{},
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    ValueTooLong,
    TooManyAccounts,
};

const StoredCard = struct {
    bio: []const u8 = &.{},
    url: []const u8 = &.{},
    pronouns: []const u8 = &.{},

    fn deinit(self: *StoredCard, allocator: std.mem.Allocator) void {
        freeIfOwned(allocator, self.bio);
        freeIfOwned(allocator, self.url);
        freeIfOwned(allocator, self.pronouns);
        self.* = undefined;
    }

    fn view(self: *const StoredCard) Card {
        return .{
            .bio = self.bio,
            .url = self.url,
            .pronouns = self.pronouns,
        };
    }

    fn replace(self: *StoredCard, allocator: std.mem.Allocator, field: Field, value: []const u8) std.mem.Allocator.Error!void {
        const owned = if (value.len == 0) &.{} else try allocator.dupe(u8, value);
        errdefer freeIfOwned(allocator, owned);

        switch (field) {
            .bio => {
                freeIfOwned(allocator, self.bio);
                self.bio = owned;
            },
            .url => {
                freeIfOwned(allocator, self.url);
                self.url = owned;
            },
            .pronouns => {
                freeIfOwned(allocator, self.pronouns);
                self.pronouns = owned;
            },
        }
    }
};

pub const ProfileCard = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(StoredCard),

    pub fn init(allocator: std.mem.Allocator) ProfileCard {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(StoredCard).init(allocator),
        };
    }

    pub fn deinit(self: *ProfileCard) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn setField(self: *ProfileCard, account: []const u8, field: Field, value: []const u8) Error!void {
        try validateAccount(account);
        try validateValue(field, value);

        const card = try self.ensureAccount(account);
        try card.replace(self.allocator, field, value);
    }

    pub fn get(self: *const ProfileCard, account: []const u8) ?Card {
        const card = self.accounts.getPtr(account) orelse return null;
        return card.view();
    }

    fn ensureAccount(self: *ProfileCard, account: []const u8) Error!*StoredCard {
        if (self.accounts.getPtr(account)) |card| return card;
        if (self.accounts.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }
};

fn freeIfOwned(allocator: std.mem.Allocator, value: []const u8) void {
    if (value.len != 0) allocator.free(value);
}

fn validateAccount(account: []const u8) error{InvalidAccount}!void {
    if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
}

fn validateValue(field: Field, value: []const u8) error{ValueTooLong}!void {
    const cap = switch (field) {
        .bio => max_bio_bytes,
        .url => max_url_bytes,
        .pronouns => max_pronouns_bytes,
    };
    if (value.len > cap) return error.ValueTooLong;
}

const testing = std.testing;

test "setField creates a card and get returns all fields" {
    var cards = ProfileCard.init(testing.allocator);
    defer cards.deinit();

    try testing.expect(cards.get("alice") == null);
    try cards.setField("alice", .bio, "Orochi user");
    try cards.setField("alice", .url, "https://example.test/alice");
    try cards.setField("alice", .pronouns, "she/her");

    const card = cards.get("alice").?;
    try testing.expectEqualStrings("Orochi user", card.bio);
    try testing.expectEqualStrings("https://example.test/alice", card.url);
    try testing.expectEqualStrings("she/her", card.pronouns);
}

test "replacing and clearing fields frees old values" {
    var cards = ProfileCard.init(testing.allocator);
    defer cards.deinit();

    try cards.setField("alice", .bio, "first");
    try cards.setField("alice", .bio, "second");
    try testing.expectEqualStrings("second", cards.get("alice").?.bio);
    try cards.setField("alice", .bio, "");
    try testing.expectEqualStrings("", cards.get("alice").?.bio);
}

test "accounts are independent" {
    var cards = ProfileCard.init(testing.allocator);
    defer cards.deinit();

    try cards.setField("alice", .pronouns, "they/them");
    try cards.setField("bob", .pronouns, "he/him");
    try testing.expectEqualStrings("they/them", cards.get("alice").?.pronouns);
    try testing.expectEqualStrings("he/him", cards.get("bob").?.pronouns);
    try testing.expectEqualStrings("", cards.get("bob").?.bio);
}

test "field length caps and account validation are enforced" {
    var cards = ProfileCard.init(testing.allocator);
    defer cards.deinit();

    try testing.expectError(error.InvalidAccount, cards.setField("", .bio, "hello"));

    var long_bio: [max_bio_bytes + 1]u8 = undefined;
    @memset(&long_bio, 'x');
    try testing.expectError(error.ValueTooLong, cards.setField("alice", .bio, &long_bio));

    var exact_pronouns: [max_pronouns_bytes]u8 = undefined;
    @memset(&exact_pronouns, 'p');
    try cards.setField("alice", .pronouns, &exact_pronouns);
    try testing.expectEqual(@as(usize, max_pronouns_bytes), cards.get("alice").?.pronouns.len);
}
