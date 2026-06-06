const std = @import("std");

pub const max_messages: usize = 4096;
pub const max_msgid_len: usize = 128;
pub const max_account_len: usize = 128;
pub const max_flags_per_message: usize = 1024;

pub const Error = std.mem.Allocator.Error || error{
    MessageIdTooLong,
    AccountTooLong,
    EmptyAccount,
    TooManyMessages,
    TooManyFlags,
};

const FlagSet = struct {
    accounts: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *FlagSet, allocator: std.mem.Allocator) void {
        for (self.accounts.items) |account| allocator.free(account);
        self.accounts.deinit(allocator);
    }

    fn find(self: *const FlagSet, account: []const u8) ?usize {
        for (self.accounts.items, 0..) |known, i| {
            if (std.mem.eql(u8, known, account)) return i;
        }
        return null;
    }
};

pub const MessageFlag = struct {
    allocator: std.mem.Allocator,
    messages: std.StringHashMap(FlagSet),

    pub fn init(allocator: std.mem.Allocator) MessageFlag {
        return .{ .allocator = allocator, .messages = std.StringHashMap(FlagSet).init(allocator) };
    }

    pub fn deinit(self: *MessageFlag) void {
        var it = self.messages.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.messages.deinit();
        self.* = undefined;
    }

    pub fn flag(self: *MessageFlag, msgid: []const u8, by: []const u8) Error!u32 {
        if (msgid.len > max_msgid_len) return error.MessageIdTooLong;
        if (by.len == 0) return error.EmptyAccount;
        if (by.len > max_account_len) return error.AccountTooLong;

        const set = try self.ensureMessage(msgid);
        if (set.find(by) != null) return @intCast(set.accounts.items.len);
        if (set.accounts.items.len >= max_flags_per_message) return error.TooManyFlags;

        const owned = try self.allocator.dupe(u8, by);
        errdefer self.allocator.free(owned);
        try set.accounts.append(self.allocator, owned);
        return @intCast(set.accounts.items.len);
    }

    pub fn cleared(self: *MessageFlag, msgid: []const u8) bool {
        const entry = self.messages.getEntry(msgid) orelse return false;
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.messages.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
        return true;
    }

    pub fn count(self: *const MessageFlag, msgid: []const u8) u32 {
        const set = self.messages.getPtr(msgid) orelse return 0;
        return @intCast(set.accounts.items.len);
    }

    fn ensureMessage(self: *MessageFlag, msgid: []const u8) Error!*FlagSet {
        if (self.messages.getPtr(msgid)) |set| return set;
        if (self.messages.count() >= max_messages) return error.TooManyMessages;

        const owned_key = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_key);
        try self.messages.putNoClobber(owned_key, .{});
        return self.messages.getPtr(msgid).?;
    }
};

const testing = std.testing;

test "flag returns distinct account count" {
    var flags = MessageFlag.init(testing.allocator);
    defer flags.deinit();

    try testing.expectEqual(@as(u32, 1), try flags.flag("m1", "alice"));
    try testing.expectEqual(@as(u32, 2), try flags.flag("m1", "bob"));
    try testing.expectEqual(@as(u32, 2), try flags.flag("m1", "alice"));
    try testing.expectEqual(@as(u32, 2), flags.count("m1"));
}

test "cleared drops a message flag set" {
    var flags = MessageFlag.init(testing.allocator);
    defer flags.deinit();

    _ = try flags.flag("m2", "alice");
    _ = try flags.flag("m3", "carol");
    try testing.expect(flags.cleared("m2"));
    try testing.expect(!flags.cleared("m2"));
    try testing.expectEqual(@as(u32, 0), flags.count("m2"));
    try testing.expectEqual(@as(u32, 1), flags.count("m3"));
}

test "separate messages keep separate flag counts" {
    var flags = MessageFlag.init(testing.allocator);
    defer flags.deinit();

    _ = try flags.flag("a", "one");
    _ = try flags.flag("a", "two");
    _ = try flags.flag("b", "one");
    try testing.expectEqual(@as(u32, 2), flags.count("a"));
    try testing.expectEqual(@as(u32, 1), flags.count("b"));
}

test "input caps are enforced" {
    var flags = MessageFlag.init(testing.allocator);
    defer flags.deinit();

    try testing.expectError(error.EmptyAccount, flags.flag("m", ""));
    try testing.expectError(error.MessageIdTooLong, flags.flag("m" ** (max_msgid_len + 1), "a"));
    try testing.expectError(error.AccountTooLong, flags.flag("m", "a" ** (max_account_len + 1)));
}
