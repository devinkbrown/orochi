//! Per-account priority inbox with owned message text.
const std = @import("std");

pub const Owned = struct {
    priority: u8,
    text: []u8,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
        self.* = undefined;
    }
};

pub const PriorityInbox = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(ItemList),
    next_sequence: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) PriorityInbox {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(ItemList).init(allocator),
        };
    }

    pub fn deinit(self: *PriorityInbox) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn push(self: *PriorityInbox, account: []const u8, priority: u8, text: []const u8) !usize {
        var list = try self.ensureAccount(account);
        const owned_text = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned_text);

        const sequence = self.next_sequence;
        self.next_sequence +%= 1;
        try list.items.append(self.allocator, .{
            .priority = priority,
            .text = owned_text,
            .sequence = sequence,
        });
        return list.items.items.len;
    }

    pub fn popTop(self: *PriorityInbox, account: []const u8) ?Owned {
        const entry = self.accounts.getEntry(account) orelse return null;
        const index = entry.value_ptr.topIndex() orelse return null;
        const item = entry.value_ptr.items.orderedRemove(index);

        if (entry.value_ptr.items.items.len == 0) {
            const owned_account = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_account);
        }

        return .{ .priority = item.priority, .text = item.text };
    }

    pub fn count(self: *const PriorityInbox, account: []const u8) usize {
        const list = self.accounts.getPtr(account) orelse return 0;
        return list.items.items.len;
    }

    fn ensureAccount(self: *PriorityInbox, account: []const u8) !*ItemList {
        if (self.accounts.getPtr(account)) |list| return list;
        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }
};

const Item = struct {
    priority: u8,
    text: []u8,
    sequence: u64,
};

const ItemList = struct {
    items: std.ArrayListUnmanaged(Item) = .empty,

    fn deinit(self: *ItemList, allocator: std.mem.Allocator) void {
        for (self.items.items) |item| allocator.free(item.text);
        self.items.deinit(allocator);
        self.* = undefined;
    }

    fn topIndex(self: *const ItemList) ?usize {
        if (self.items.items.len == 0) return null;
        var best_index: usize = 0;
        var best = self.items.items[0];

        for (self.items.items[1..], 1..) |item, index| {
            if (item.priority > best.priority or
                (item.priority == best.priority and item.sequence < best.sequence))
            {
                best_index = index;
                best = item;
            }
        }

        return best_index;
    }
};

const testing = std.testing;

test "push returns account count and count reads it back" {
    var inbox = PriorityInbox.init(testing.allocator);
    defer inbox.deinit();

    try testing.expectEqual(@as(usize, 1), try inbox.push("acct", 10, "first"));
    try testing.expectEqual(@as(usize, 2), try inbox.push("acct", 1, "second"));
    try testing.expectEqual(@as(usize, 2), inbox.count("acct"));
    try testing.expectEqual(@as(usize, 0), inbox.count("missing"));
}

test "popTop returns highest priority before lower priority" {
    var inbox = PriorityInbox.init(testing.allocator);
    defer inbox.deinit();

    _ = try inbox.push("acct", 1, "low");
    _ = try inbox.push("acct", 9, "high");

    var top = inbox.popTop("acct").?;
    defer top.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 9), top.priority);
    try testing.expectEqualStrings("high", top.text);
    try testing.expectEqual(@as(usize, 1), inbox.count("acct"));
}

test "equal priority items preserve insertion order" {
    var inbox = PriorityInbox.init(testing.allocator);
    defer inbox.deinit();

    _ = try inbox.push("acct", 5, "one");
    _ = try inbox.push("acct", 5, "two");

    var first = inbox.popTop("acct").?;
    defer first.deinit(testing.allocator);
    var second = inbox.popTop("acct").?;
    defer second.deinit(testing.allocator);

    try testing.expectEqualStrings("one", first.text);
    try testing.expectEqualStrings("two", second.text);
    try testing.expectEqual(@as(usize, 0), inbox.count("acct"));
}

test "accounts are isolated and empty pops return null" {
    var inbox = PriorityInbox.init(testing.allocator);
    defer inbox.deinit();

    _ = try inbox.push("a", 7, "alpha");
    _ = try inbox.push("b", 8, "beta");

    var a_item = inbox.popTop("a").?;
    defer a_item.deinit(testing.allocator);
    try testing.expectEqualStrings("alpha", a_item.text);
    try testing.expectEqual(@as(?Owned, null), inbox.popTop("a"));
    try testing.expectEqual(@as(usize, 1), inbox.count("b"));

    var b_item = inbox.popTop("b").?;
    defer b_item.deinit(testing.allocator);
    try testing.expectEqualStrings("beta", b_item.text);
}
