const std = @import("std");

pub const StickerSet = struct {
    const Self = @This();
    const RefList = std.ArrayList([]const u8);

    const max_accounts = 16384;
    const max_refs_per_account = 256;
    const max_key_bytes = 128;

    allocator: std.mem.Allocator,
    by_account: std.StringHashMap(RefList),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .by_account = std.StringHashMap(RefList).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.by_account.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeRefs(self.allocator, entry.value_ptr);
        }
        self.by_account.deinit();
        self.* = undefined;
    }

    pub fn add(self: *Self, account: []const u8, ref_id: []const u8) !void {
        try checkKey(account);
        try checkKey(ref_id);

        if (self.by_account.getPtr(account)) |refs| {
            if (contains(refs.items, ref_id)) return;
            if (refs.items.len >= max_refs_per_account) return error.TooManyRefs;

            const owned_ref = try self.allocator.dupe(u8, ref_id);
            errdefer self.allocator.free(owned_ref);
            try refs.append(self.allocator, owned_ref);
            return;
        }

        if (self.by_account.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        const owned_ref = try self.allocator.dupe(u8, ref_id);
        errdefer self.allocator.free(owned_ref);

        var refs: RefList = .empty;
        var refs_owned = false;
        errdefer if (!refs_owned) refs.deinit(self.allocator);

        try refs.append(self.allocator, owned_ref);
        try self.by_account.put(owned_account, refs);
        refs_owned = true;
    }

    pub fn remove(self: *Self, account: []const u8, ref_id: []const u8) bool {
        const refs = self.by_account.getPtr(account) orelse return false;

        for (refs.items, 0..) |stored, i| {
            if (std.mem.eql(u8, stored, ref_id)) {
                const removed_ref = refs.orderedRemove(i);
                self.allocator.free(removed_ref);

                if (refs.items.len == 0) {
                    var removed_account = self.by_account.fetchRemove(account).?;
                    self.allocator.free(removed_account.key);
                    removed_account.value.deinit(self.allocator);
                }
                return true;
            }
        }

        return false;
    }

    pub fn has(self: *const Self, account: []const u8, ref_id: []const u8) bool {
        const refs = self.by_account.get(account) orelse return false;
        return contains(refs.items, ref_id);
    }

    pub fn list(self: *const Self, account: []const u8) []const []const u8 {
        if (self.by_account.get(account)) |refs| return refs.items;
        return &.{};
    }

    fn contains(refs: []const []const u8, ref_id: []const u8) bool {
        for (refs) |stored| {
            if (std.mem.eql(u8, stored, ref_id)) return true;
        }
        return false;
    }

    fn freeRefs(allocator: std.mem.Allocator, refs: *RefList) void {
        for (refs.items) |ref_id| allocator.free(ref_id);
        refs.deinit(allocator);
    }

    fn checkKey(value: []const u8) !void {
        if (value.len == 0) return error.EmptyKey;
        if (value.len > max_key_bytes) return error.KeyTooLong;
    }
};

test "add stores unique refs per account" {
    var set = StickerSet.init(std.testing.allocator);
    defer set.deinit();

    try set.add("alice", "wave");
    try set.add("alice", "wave");
    try set.add("alice", "spark");
    try set.add("bob", "leaf");

    try std.testing.expect(set.has("alice", "wave"));
    try std.testing.expect(set.has("alice", "spark"));
    try std.testing.expect(!set.has("alice", "leaf"));
    try std.testing.expectEqual(@as(usize, 2), set.list("alice").len);
}

test "remove deletes refs and empty account buckets" {
    var set = StickerSet.init(std.testing.allocator);
    defer set.deinit();

    try set.add("alice", "wave");

    try std.testing.expect(set.remove("alice", "wave"));
    try std.testing.expect(!set.has("alice", "wave"));
    try std.testing.expectEqual(@as(usize, 0), set.list("alice").len);
    try std.testing.expect(!set.remove("alice", "wave"));
}

test "list preserves insertion order" {
    var set = StickerSet.init(std.testing.allocator);
    defer set.deinit();

    try set.add("alice", "one");
    try set.add("alice", "two");
    try set.add("alice", "three");

    const refs = set.list("alice");
    try std.testing.expectEqualStrings("one", refs[0]);
    try std.testing.expectEqualStrings("two", refs[1]);
    try std.testing.expectEqualStrings("three", refs[2]);
}

test "empty and oversized values are rejected" {
    var set = StickerSet.init(std.testing.allocator);
    defer set.deinit();

    try std.testing.expectError(error.EmptyKey, set.add("", "wave"));

    var long: [129]u8 = undefined;
    @memset(&long, 'x');
    try std.testing.expectError(error.KeyTooLong, set.add("alice", &long));
}
