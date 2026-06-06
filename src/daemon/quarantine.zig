const std = @import("std");

pub const Quarantine = struct {
    pub const max_entries: usize = 1024;
    pub const max_account_len: usize = 128;
    pub const max_reason_len: usize = 200;

    pub const Error = std.mem.Allocator.Error || error{
        EmptyAccount,
        EmptyReason,
        AccountTooLong,
        ReasonTooLong,
        TooManyEntries,
    };

    pub const Entry = struct {
        account: []u8,
        reason: []u8,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(allocator: std.mem.Allocator) Quarantine {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Quarantine) void {
        for (self.entries.items) |*entry| {
            freeEntry(self.allocator, entry);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *Quarantine, account: []const u8, reason: []const u8) Error!void {
        try validateField(account, max_account_len, error.EmptyAccount, error.AccountTooLong);
        try validateField(reason, max_reason_len, error.EmptyReason, error.ReasonTooLong);

        if (self.indexOf(account)) |idx| {
            const new_reason = try self.allocator.dupe(u8, reason);
            self.allocator.free(self.entries.items[idx].reason);
            self.entries.items[idx].reason = new_reason;
            return;
        }

        if (self.entries.items.len >= max_entries) return error.TooManyEntries;

        var owned = Entry{
            .account = try self.allocator.dupe(u8, account),
            .reason = undefined,
        };
        errdefer self.allocator.free(owned.account);

        owned.reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned.reason);

        try self.entries.append(self.allocator, owned);
    }

    pub fn remove(self: *Quarantine, account: []const u8) bool {
        const idx = self.indexOf(account) orelse return false;
        var removed = self.entries.orderedRemove(idx);
        freeEntry(self.allocator, &removed);
        return true;
    }

    pub fn isQuarantined(self: *const Quarantine, account: []const u8) bool {
        return self.indexOf(account) != null;
    }

    pub fn reasonOf(self: *const Quarantine, account: []const u8) ?[]const u8 {
        const idx = self.indexOf(account) orelse return null;
        return self.entries.items[idx].reason;
    }

    fn indexOf(self: *const Quarantine, account: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.account, account)) return idx;
        }
        return null;
    }

    fn validateField(value: []const u8, max_len: usize, empty_error: Error, long_error: Error) Error!void {
        if (value.len == 0) return empty_error;
        if (value.len > max_len) return long_error;
    }

    fn freeEntry(allocator: std.mem.Allocator, entry: *Entry) void {
        allocator.free(entry.account);
        allocator.free(entry.reason);
        entry.* = undefined;
    }
};

const testing = std.testing;

test "add stores account reason and lookup state" {
    var q = Quarantine.init(testing.allocator);
    defer q.deinit();

    try q.add("alice", "manual review");

    try testing.expect(q.isQuarantined("alice"));
    try testing.expect(!q.isQuarantined("bob"));
    try testing.expectEqualStrings("manual review", q.reasonOf("alice").?);
    try testing.expect(q.reasonOf("bob") == null);
}

test "add updates an existing account reason" {
    var q = Quarantine.init(testing.allocator);
    defer q.deinit();

    try q.add("alice", "first reason");
    try q.add("alice", "second reason");

    try testing.expectEqual(@as(usize, 1), q.entries.items.len);
    try testing.expectEqualStrings("second reason", q.reasonOf("alice").?);
}

test "remove frees entry and reports whether it existed" {
    var q = Quarantine.init(testing.allocator);
    defer q.deinit();

    try q.add("alice", "review");

    try testing.expect(q.remove("alice"));
    try testing.expect(!q.remove("alice"));
    try testing.expect(!q.isQuarantined("alice"));
}

test "reason and table sizes are bounded" {
    var q = Quarantine.init(testing.allocator);
    defer q.deinit();

    const long_reason = "x" ** (Quarantine.max_reason_len + 1);
    try testing.expectError(error.ReasonTooLong, q.add("alice", long_reason));

    var i: usize = 0;
    while (i < Quarantine.max_entries) : (i += 1) {
        var buf: [32]u8 = undefined;
        const account = try std.fmt.bufPrint(&buf, "acct-{d}", .{i});
        try q.add(account, "r");
    }
    try testing.expectError(error.TooManyEntries, q.add("overflow", "r"));
}
