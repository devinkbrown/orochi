//! Bounded message delivery receipt tracker.
const std = @import("std");

pub const max_receipts: usize = 8192;
pub const max_acks_per_receipt: usize = 256;
pub const max_msgid_bytes: usize = 128;
pub const max_account_bytes: usize = 64;

pub const Error = std.mem.Allocator.Error || error{
    InvalidMsgid,
    InvalidAccount,
    TooManyReceipts,
    TooManyAcks,
};

const AckSet = struct {
    accounts: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *AckSet, allocator: std.mem.Allocator) void {
        for (self.accounts.items) |account| allocator.free(account);
        self.accounts.deinit(allocator);
    }

    fn contains(self: *const AckSet, account: []const u8) bool {
        for (self.accounts.items) |stored| {
            if (std.mem.eql(u8, stored, account)) return true;
        }
        return false;
    }
};

pub const DeliveryReceipt = struct {
    allocator: std.mem.Allocator,
    receipts: std.StringHashMap(AckSet),

    pub fn init(allocator: std.mem.Allocator) DeliveryReceipt {
        return .{ .allocator = allocator, .receipts = std.StringHashMap(AckSet).init(allocator) };
    }

    pub fn deinit(self: *DeliveryReceipt) void {
        var it = self.receipts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.receipts.deinit();
        self.* = undefined;
    }

    pub fn ack(self: *DeliveryReceipt, msgid: []const u8, account: []const u8) Error!void {
        try validateMsgid(msgid);
        try validateAccount(account);

        const set = try self.ensureReceipt(msgid);
        if (set.contains(account)) return;
        if (set.accounts.items.len >= max_acks_per_receipt) return error.TooManyAcks;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try set.accounts.append(self.allocator, owned_account);
    }

    /// Returns borrowed acking account names, valid until the next mutation.
    pub fn acks(self: *const DeliveryReceipt, msgid: []const u8) []const []const u8 {
        const set = self.receipts.getPtr(msgid) orelse return &.{};
        return set.accounts.items;
    }

    pub fn clear(self: *DeliveryReceipt, msgid: []const u8) bool {
        const entry = self.receipts.getEntry(msgid) orelse return false;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.receipts.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return true;
    }

    fn ensureReceipt(self: *DeliveryReceipt, msgid: []const u8) Error!*AckSet {
        if (self.receipts.getPtr(msgid)) |set| return set;
        if (self.receipts.count() >= max_receipts) return error.TooManyReceipts;
        const owned_msgid = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_msgid);
        try self.receipts.putNoClobber(owned_msgid, .{});
        return self.receipts.getPtr(msgid).?;
    }

    fn validateMsgid(msgid: []const u8) Error!void {
        if (msgid.len == 0 or msgid.len > max_msgid_bytes) return error.InvalidMsgid;
    }

    fn validateAccount(account: []const u8) Error!void {
        if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
    }
};

const testing = std.testing;

test "ack records accounts once per message" {
    var receipts = DeliveryReceipt.init(testing.allocator);
    defer receipts.deinit();

    try receipts.ack("m1", "alice");
    try receipts.ack("m1", "alice");
    try receipts.ack("m1", "bob");
    const got = receipts.acks("m1");
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("alice", got[0]);
    try testing.expectEqualStrings("bob", got[1]);
}

test "clear drops one message without touching another" {
    var receipts = DeliveryReceipt.init(testing.allocator);
    defer receipts.deinit();

    try receipts.ack("m1", "alice");
    try receipts.ack("m2", "bob");
    try testing.expect(receipts.clear("m1"));
    try testing.expect(!receipts.clear("m1"));
    try testing.expectEqual(@as(usize, 0), receipts.acks("m1").len);
    try testing.expectEqualStrings("bob", receipts.acks("m2")[0]);
}

test "input caps reject invalid receipt data" {
    var receipts = DeliveryReceipt.init(testing.allocator);
    defer receipts.deinit();

    try testing.expectError(error.InvalidMsgid, receipts.ack("", "alice"));
    try testing.expectError(error.InvalidAccount, receipts.ack("m1", ""));
    try testing.expectError(error.InvalidMsgid, receipts.ack("x" ** (max_msgid_bytes + 1), "alice"));
    try testing.expectError(error.InvalidAccount, receipts.ack("m1", "x" ** (max_account_bytes + 1)));
}

test "ack cap is enforced" {
    var receipts = DeliveryReceipt.init(testing.allocator);
    defer receipts.deinit();

    var i: usize = 0;
    while (i < max_acks_per_receipt) : (i += 1) {
        var buf: [32]u8 = undefined;
        const account = try std.fmt.bufPrint(&buf, "user-{d}", .{i});
        try receipts.ack("m1", account);
    }
    try testing.expectError(error.TooManyAcks, receipts.ack("m1", "overflow"));
}
