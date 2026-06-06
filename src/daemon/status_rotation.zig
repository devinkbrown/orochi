const std = @import("std");

pub const StatusRotation = struct {
    const Self = @This();
    const StatusList = std.ArrayList([]const u8);

    const max_accounts = 16384;
    const max_statuses_per_account = 64;
    const max_account_bytes = 128;
    const max_status_bytes = 200;

    const Bucket = struct {
        values: StatusList = .empty,
        cursor: usize = 0,
    };

    allocator: std.mem.Allocator,
    by_account: std.StringHashMap(Bucket),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .by_account = std.StringHashMap(Bucket).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.by_account.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeBucket(self.allocator, entry.value_ptr);
        }
        self.by_account.deinit();
        self.* = undefined;
    }

    pub fn add(self: *Self, account: []const u8, s: []const u8) !void {
        try checkAccount(account);
        try checkStatus(s);

        if (self.by_account.getPtr(account)) |bucket| {
            if (bucket.values.items.len >= max_statuses_per_account) return error.TooManyStatuses;

            const owned_status = try self.allocator.dupe(u8, s);
            errdefer self.allocator.free(owned_status);
            try bucket.values.append(self.allocator, owned_status);
            return;
        }

        if (self.by_account.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        const owned_status = try self.allocator.dupe(u8, s);
        errdefer self.allocator.free(owned_status);

        var bucket: Bucket = .{};
        var bucket_owned = false;
        errdefer if (!bucket_owned) bucket.values.deinit(self.allocator);

        try bucket.values.append(self.allocator, owned_status);
        try self.by_account.put(owned_account, bucket);
        bucket_owned = true;
    }

    pub fn next(self: *Self, account: []const u8) ?[]const u8 {
        const bucket = self.by_account.getPtr(account) orelse return null;
        if (bucket.values.items.len == 0) return null;

        if (bucket.cursor >= bucket.values.items.len) bucket.cursor = 0;
        const value = bucket.values.items[bucket.cursor];
        bucket.cursor = (bucket.cursor + 1) % bucket.values.items.len;
        return value;
    }

    pub fn clear(self: *Self, account: []const u8) bool {
        const removed = self.by_account.fetchRemove(account) orelse return false;
        self.allocator.free(removed.key);
        var bucket = removed.value;
        freeBucket(self.allocator, &bucket);
        return true;
    }

    fn freeBucket(allocator: std.mem.Allocator, bucket: *Bucket) void {
        for (bucket.values.items) |status| allocator.free(status);
        bucket.values.deinit(allocator);
    }

    fn checkAccount(account: []const u8) !void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > max_account_bytes) return error.AccountTooLong;
    }

    fn checkStatus(status: []const u8) !void {
        if (status.len == 0) return error.EmptyStatus;
        if (status.len > max_status_bytes) return error.StatusTooLong;
    }
};

test "next cycles statuses in insertion order" {
    var rotation = StatusRotation.init(std.testing.allocator);
    defer rotation.deinit();

    try rotation.add("alice", "coding");
    try rotation.add("alice", "testing");
    try rotation.add("alice", "shipping");

    try std.testing.expectEqualStrings("coding", rotation.next("alice").?);
    try std.testing.expectEqualStrings("testing", rotation.next("alice").?);
    try std.testing.expectEqualStrings("shipping", rotation.next("alice").?);
    try std.testing.expectEqualStrings("coding", rotation.next("alice").?);
}

test "missing and cleared accounts return null" {
    var rotation = StatusRotation.init(std.testing.allocator);
    defer rotation.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), rotation.next("alice"));
    try rotation.add("alice", "ready");
    try std.testing.expect(rotation.clear("alice"));
    try std.testing.expect(!rotation.clear("alice"));
    try std.testing.expectEqual(@as(?[]const u8, null), rotation.next("alice"));
}

test "accounts rotate independently" {
    var rotation = StatusRotation.init(std.testing.allocator);
    defer rotation.deinit();

    try rotation.add("alice", "one");
    try rotation.add("alice", "two");
    try rotation.add("bob", "solo");

    try std.testing.expectEqualStrings("one", rotation.next("alice").?);
    try std.testing.expectEqualStrings("solo", rotation.next("bob").?);
    try std.testing.expectEqualStrings("two", rotation.next("alice").?);
    try std.testing.expectEqualStrings("solo", rotation.next("bob").?);
}

test "invalid account and status values are rejected" {
    var rotation = StatusRotation.init(std.testing.allocator);
    defer rotation.deinit();

    try std.testing.expectError(error.EmptyAccount, rotation.add("", "ready"));
    try std.testing.expectError(error.EmptyStatus, rotation.add("alice", ""));

    var long_status: [201]u8 = undefined;
    @memset(&long_status, 'x');
    try std.testing.expectError(error.StatusTooLong, rotation.add("alice", &long_status));
}
