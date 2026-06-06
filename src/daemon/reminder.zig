//! Per-account reminder queues ordered by due time.
//!
//! `popDue` returns an owned slice of owned reminder records. The caller must
//! release that slice with `freeOwnedSlice`.
const std = @import("std");

pub const Reminder = struct {
    pub const max_accounts: usize = 2048;
    pub const max_per_account: usize = 512;
    pub const max_account_len: usize = 128;
    pub const max_text_len: usize = 300;

    pub const Error = std.mem.Allocator.Error || error{
        AccountTooLong,
        TextTooLong,
        TooManyAccounts,
        TooManyReminders,
    };

    pub const Owned = struct {
        due_ms: i64,
        text: []u8,
    };

    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(AccountQueue),

    pub fn init(allocator: std.mem.Allocator) Reminder {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(AccountQueue).init(allocator),
        };
    }

    pub fn deinit(self: *Reminder) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn add(self: *Reminder, account: []const u8, due_ms: i64, text: []const u8) Error!void {
        if (account.len > max_account_len) return error.AccountTooLong;
        if (text.len > max_text_len) return error.TextTooLong;

        const queue = try self.ensureAccount(account);
        if (queue.items.items.len >= max_per_account) return error.TooManyReminders;

        const owned_text = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned_text);

        const index = queue.insertIndex(due_ms);
        try queue.items.insert(self.allocator, index, .{ .due_ms = due_ms, .text = owned_text });
    }

    /// Return all due reminders for `account` at or before `now_ms`.
    /// The returned slice and each `text` field are caller-owned.
    pub fn popDue(self: *Reminder, account: []const u8, now_ms: i64) Error![]Owned {
        const entry = self.accounts.getEntry(account) orelse return self.allocator.alloc(Owned, 0);
        const due_count = entry.value_ptr.dueCount(now_ms);
        if (due_count == 0) return self.allocator.alloc(Owned, 0);

        const out = try self.allocator.alloc(Owned, due_count);
        for (entry.value_ptr.items.items[0..due_count], 0..) |item, i| {
            out[i] = .{ .due_ms = item.due_ms, .text = item.text };
        }

        const remaining = entry.value_ptr.items.items[due_count..];
        std.mem.copyForwards(Entry, entry.value_ptr.items.items[0..remaining.len], remaining);
        entry.value_ptr.items.shrinkRetainingCapacity(remaining.len);

        if (entry.value_ptr.items.items.len == 0) {
            const owned_key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
        }

        return out;
    }

    pub fn freeOwnedSlice(self: *Reminder, reminders: []Owned) void {
        for (reminders) |item| self.allocator.free(item.text);
        self.allocator.free(reminders);
    }

    pub fn count(self: *const Reminder, account: []const u8) usize {
        const queue = self.accounts.getPtr(account) orelse return 0;
        return queue.items.items.len;
    }

    fn ensureAccount(self: *Reminder, account: []const u8) Error!*AccountQueue {
        if (self.accounts.getPtr(account)) |queue| return queue;
        if (self.accounts.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);

        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }
};

const Entry = struct {
    due_ms: i64,
    text: []u8,
};

const AccountQueue = struct {
    items: std.ArrayListUnmanaged(Entry) = .empty,

    fn deinit(self: *AccountQueue, allocator: std.mem.Allocator) void {
        for (self.items.items) |entry| allocator.free(entry.text);
        self.items.deinit(allocator);
        self.* = undefined;
    }

    fn insertIndex(self: *const AccountQueue, due_ms: i64) usize {
        for (self.items.items, 0..) |entry, i| {
            if (due_ms < entry.due_ms) return i;
        }
        return self.items.items.len;
    }

    fn dueCount(self: *const AccountQueue, now_ms: i64) usize {
        var total: usize = 0;
        while (total < self.items.items.len and self.items.items[total].due_ms <= now_ms) {
            total += 1;
        }
        return total;
    }
};

const testing = std.testing;

test "add and popDue return reminders in due-time order" {
    var reminders = Reminder.init(testing.allocator);
    defer reminders.deinit();

    try reminders.add("alice", 30, "third");
    try reminders.add("alice", 10, "first");
    try reminders.add("alice", 20, "second");

    const due = try reminders.popDue("alice", 25);
    defer reminders.freeOwnedSlice(due);

    try testing.expectEqual(@as(usize, 2), due.len);
    try testing.expectEqual(@as(i64, 10), due[0].due_ms);
    try testing.expectEqualStrings("first", due[0].text);
    try testing.expectEqual(@as(i64, 20), due[1].due_ms);
    try testing.expectEqualStrings("second", due[1].text);
    try testing.expectEqual(@as(usize, 1), reminders.count("alice"));
}

test "accounts are isolated and empty accounts are pruned" {
    var reminders = Reminder.init(testing.allocator);
    defer reminders.deinit();

    try reminders.add("alice", 10, "one");
    try reminders.add("bob", 10, "two");

    const alice = try reminders.popDue("alice", 10);
    defer reminders.freeOwnedSlice(alice);

    try testing.expectEqual(@as(usize, 1), alice.len);
    try testing.expectEqual(@as(usize, 0), reminders.count("alice"));
    try testing.expectEqual(@as(usize, 1), reminders.count("bob"));

    const missing = try reminders.popDue("carol", 10);
    defer reminders.freeOwnedSlice(missing);
    try testing.expectEqual(@as(usize, 0), missing.len);
}

test "text length cap is enforced" {
    var reminders = Reminder.init(testing.allocator);
    defer reminders.deinit();

    const text = "r" ** (Reminder.max_text_len + 1);
    try testing.expectError(error.TextTooLong, reminders.add("alice", 1, text));
    try testing.expectEqual(@as(usize, 0), reminders.count("alice"));
}
