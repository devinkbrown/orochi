//! Bounded per-account notification sound selections.
const std = @import("std");

pub const max_accounts: usize = 65536;
pub const max_account_len: usize = 128;
pub const max_sound_id_len: usize = 48;

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    InvalidSoundId,
    FieldTooLong,
    TooManyAccounts,
};

pub const SoundPack = struct {
    allocator: std.mem.Allocator,
    selections: std.StringHashMap([]u8),
    limit: usize,

    pub fn init(allocator: std.mem.Allocator) SoundPack {
        return initWithLimit(allocator, max_accounts);
    }

    pub fn initWithLimit(allocator: std.mem.Allocator, limit: usize) SoundPack {
        return .{
            .allocator = allocator,
            .selections = std.StringHashMap([]u8).init(allocator),
            .limit = limit,
        };
    }

    pub fn deinit(self: *SoundPack) void {
        var it = self.selections.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.selections.deinit();
        self.* = undefined;
    }

    pub fn set(self: *SoundPack, account: []const u8, id: []const u8) Error!void {
        try validate(account, id);

        if (self.selections.getEntry(account)) |entry| {
            const next_id = try self.allocator.dupe(u8, id);
            errdefer self.allocator.free(next_id);
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = next_id;
            return;
        }

        if (self.selections.count() >= self.limit) return error.TooManyAccounts;
        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        const owned_id = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(owned_id);
        try self.selections.putNoClobber(owned_account, owned_id);
    }

    pub fn get(self: *const SoundPack, account: []const u8) ?[]const u8 {
        const id = self.selections.get(account) orelse return null;
        return id;
    }

    pub fn clear(self: *SoundPack, account: []const u8) bool {
        const kv = self.selections.fetchRemove(account) orelse return false;
        self.allocator.free(kv.key);
        self.allocator.free(kv.value);
        return true;
    }

    pub fn count(self: *const SoundPack) usize {
        return self.selections.count();
    }

    fn validate(account: []const u8, id: []const u8) Error!void {
        if (account.len == 0) return error.InvalidAccount;
        if (id.len == 0) return error.InvalidSoundId;
        if (account.len > max_account_len or id.len > max_sound_id_len) return error.FieldTooLong;
    }
};

const testing = std.testing;

test "set and get stores an account sound id" {
    var pack = SoundPack.init(testing.allocator);
    defer pack.deinit();

    try pack.set("alice", "soft-ping");
    try testing.expectEqualStrings("soft-ping", pack.get("alice").?);
    try testing.expect(pack.get("bob") == null);
}

test "set replaces an existing account selection" {
    var pack = SoundPack.init(testing.allocator);
    defer pack.deinit();

    try pack.set("alice", "soft-ping");
    try pack.set("alice", "sharp-chime");
    try testing.expectEqualStrings("sharp-chime", pack.get("alice").?);
    try testing.expectEqual(@as(usize, 1), pack.count());
}

test "clear reports whether a selection existed" {
    var pack = SoundPack.init(testing.allocator);
    defer pack.deinit();

    try pack.set("alice", "soft-ping");
    try testing.expect(pack.clear("alice"));
    try testing.expect(!pack.clear("alice"));
    try testing.expect(pack.get("alice") == null);
}

test "sound id length cap is enforced" {
    var pack = SoundPack.init(testing.allocator);
    defer pack.deinit();

    const long = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW";
    try testing.expect(long.len > max_sound_id_len);
    try testing.expectError(error.FieldTooLong, pack.set("alice", long));
}
