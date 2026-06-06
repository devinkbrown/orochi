const std = @import("std");

pub const AwaySchedule = struct {
    const Self = @This();
    const WindowList = std.ArrayList(Window);

    const max_accounts = 16384;
    const max_windows_per_account = 128;
    const max_account_bytes = 128;
    const max_msg_bytes = 200;

    pub const Window = struct {
        start_ms: i64,
        end_ms: i64,
        msg: []const u8,
    };

    allocator: std.mem.Allocator,
    by_account: std.StringHashMap(WindowList),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .by_account = std.StringHashMap(WindowList).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.by_account.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeWindows(self.allocator, entry.value_ptr);
        }
        self.by_account.deinit();
        self.* = undefined;
    }

    pub fn add(self: *Self, account: []const u8, start_ms: i64, end_ms: i64, msg: []const u8) !void {
        try checkAccount(account);
        if (end_ms <= start_ms) return error.InvalidWindow;
        if (msg.len > max_msg_bytes) return error.MessageTooLong;

        const owned_msg = try self.allocator.dupe(u8, msg);
        errdefer self.allocator.free(owned_msg);
        var msg_owned = false;
        errdefer if (!msg_owned) self.allocator.free(owned_msg);

        const window: Window = .{
            .start_ms = start_ms,
            .end_ms = end_ms,
            .msg = owned_msg,
        };

        if (self.by_account.getPtr(account)) |windows| {
            if (windows.items.len >= max_windows_per_account) return error.TooManyWindows;
            try windows.append(self.allocator, window);
            msg_owned = true;
            return;
        }

        if (self.by_account.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        var windows: WindowList = .empty;
        var list_owned = false;
        errdefer if (!list_owned) windows.deinit(self.allocator);

        try windows.append(self.allocator, window);
        try self.by_account.put(owned_account, windows);
        list_owned = true;
        msg_owned = true;
    }

    pub fn activeMsg(self: *const Self, account: []const u8, now: i64) ?[]const u8 {
        const windows = self.by_account.get(account) orelse return null;
        for (windows.items) |window| {
            if (now >= window.start_ms and now < window.end_ms) return window.msg;
        }
        return null;
    }

    pub fn clear(self: *Self, account: []const u8) bool {
        const removed = self.by_account.fetchRemove(account) orelse return false;
        self.allocator.free(removed.key);
        var windows = removed.value;
        freeWindows(self.allocator, &windows);
        return true;
    }

    fn freeWindows(allocator: std.mem.Allocator, windows: *WindowList) void {
        for (windows.items) |window| allocator.free(window.msg);
        windows.deinit(allocator);
    }

    fn checkAccount(account: []const u8) !void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > max_account_bytes) return error.AccountTooLong;
    }
};

test "active message is returned inside a window" {
    var schedule = AwaySchedule.init(std.testing.allocator);
    defer schedule.deinit();

    try schedule.add("alice", 100, 200, "lunch");

    try std.testing.expectEqual(@as(?[]const u8, null), schedule.activeMsg("alice", 99));
    try std.testing.expectEqualStrings("lunch", schedule.activeMsg("alice", 100).?);
    try std.testing.expectEqualStrings("lunch", schedule.activeMsg("alice", 199).?);
    try std.testing.expectEqual(@as(?[]const u8, null), schedule.activeMsg("alice", 200));
}

test "first active window wins when windows overlap" {
    var schedule = AwaySchedule.init(std.testing.allocator);
    defer schedule.deinit();

    try schedule.add("alice", 100, 300, "focus");
    try schedule.add("alice", 150, 250, "meeting");

    try std.testing.expectEqualStrings("focus", schedule.activeMsg("alice", 175).?);
}

test "clear removes all account windows" {
    var schedule = AwaySchedule.init(std.testing.allocator);
    defer schedule.deinit();

    try schedule.add("alice", 100, 200, "lunch");
    try schedule.add("alice", 300, 400, "errand");

    try std.testing.expect(schedule.clear("alice"));
    try std.testing.expect(!schedule.clear("alice"));
    try std.testing.expectEqual(@as(?[]const u8, null), schedule.activeMsg("alice", 150));
}

test "invalid windows and oversized messages are rejected" {
    var schedule = AwaySchedule.init(std.testing.allocator);
    defer schedule.deinit();

    try std.testing.expectError(error.InvalidWindow, schedule.add("alice", 200, 200, "bad"));
    try std.testing.expectError(error.EmptyAccount, schedule.add("", 100, 200, "bad"));

    var long_msg: [201]u8 = undefined;
    @memset(&long_msg, 'x');
    try std.testing.expectError(error.MessageTooLong, schedule.add("alice", 100, 200, &long_msg));
}
