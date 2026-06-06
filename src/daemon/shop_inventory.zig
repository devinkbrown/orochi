//! Per-account item quantity inventory.
const std = @import("std");

const ItemMap = std.StringHashMap(u32);

const Bag = struct {
    items: ItemMap,

    fn init(allocator: std.mem.Allocator) Bag {
        return .{ .items = ItemMap.init(allocator) };
    }

    fn deinit(self: *Bag, allocator: std.mem.Allocator) void {
        var it = self.items.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        self.items.deinit();
        self.* = undefined;
    }
};

pub const ShopInventory = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(Bag),

    pub const Error = std.mem.Allocator.Error || error{ Insufficient, Overflow };

    pub fn init(allocator: std.mem.Allocator) ShopInventory {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(Bag).init(allocator),
        };
    }

    pub fn deinit(self: *ShopInventory) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn add(self: *ShopInventory, account: []const u8, item: []const u8, qty_to_add: u32) Error!u32 {
        const account_entry = try self.ensureAccount(account);
        if (account_entry.value_ptr.items.getEntry(item)) |item_entry| {
            const next = std.math.add(u32, item_entry.value_ptr.*, qty_to_add) catch return error.Overflow;
            item_entry.value_ptr.* = next;
            return next;
        }

        const owned_item = try self.allocator.dupe(u8, item);
        errdefer self.allocator.free(owned_item);
        try account_entry.value_ptr.items.putNoClobber(owned_item, qty_to_add);
        return qty_to_add;
    }

    pub fn remove(self: *ShopInventory, account: []const u8, item: []const u8, qty_to_remove: u32) Error!u32 {
        const bag = self.accounts.getPtr(account) orelse return error.Insufficient;
        const entry = bag.items.getEntry(item) orelse return error.Insufficient;
        if (entry.value_ptr.* < qty_to_remove) return error.Insufficient;

        const next = entry.value_ptr.* - qty_to_remove;
        if (next == 0) {
            const owned_key = entry.key_ptr.*;
            bag.items.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
        } else {
            entry.value_ptr.* = next;
        }
        return next;
    }

    pub fn qty(self: *const ShopInventory, account: []const u8, item: []const u8) u32 {
        const bag = self.accounts.getPtr(account) orelse return 0;
        return bag.items.get(item) orelse 0;
    }

    fn ensureAccount(self: *ShopInventory, account: []const u8) std.mem.Allocator.Error!std.StringHashMap(Bag).Entry {
        if (self.accounts.getEntry(account)) |entry| return entry;

        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);

        var bag = Bag.init(self.allocator);
        errdefer bag.deinit(self.allocator);
        try self.accounts.putNoClobber(owned, bag);
        return self.accounts.getEntry(account).?;
    }
};

const testing = std.testing;

test "add accumulates item quantities" {
    var inventory = ShopInventory.init(testing.allocator);
    defer inventory.deinit();

    try testing.expectEqual(@as(u32, 2), try inventory.add("alice", "badge", 2));
    try testing.expectEqual(@as(u32, 5), try inventory.add("alice", "badge", 3));
    try testing.expectEqual(@as(u32, 5), inventory.qty("alice", "badge"));
}

test "remove returns remaining quantity and clears empty items" {
    var inventory = ShopInventory.init(testing.allocator);
    defer inventory.deinit();

    _ = try inventory.add("alice", "badge", 5);
    try testing.expectEqual(@as(u32, 2), try inventory.remove("alice", "badge", 3));
    try testing.expectEqual(@as(u32, 0), try inventory.remove("alice", "badge", 2));
    try testing.expectEqual(@as(u32, 0), inventory.qty("alice", "badge"));
}

test "remove rejects missing or excessive quantity" {
    var inventory = ShopInventory.init(testing.allocator);
    defer inventory.deinit();

    try testing.expectError(error.Insufficient, inventory.remove("alice", "badge", 1));
    _ = try inventory.add("alice", "badge", 1);
    try testing.expectError(error.Insufficient, inventory.remove("alice", "badge", 2));
    try testing.expectEqual(@as(u32, 1), inventory.qty("alice", "badge"));
}
