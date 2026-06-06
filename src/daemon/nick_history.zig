//! Per-account nickname change history.
//!
//! This module keeps rename audit entries separate from disconnect history.
//! Account keys and nickname values are heap-owned, bounded by compile-time
//! limits, and released on eviction, clear, and deinit.
const std = @import("std");

/// Compile-time limits for nickname history storage.
pub const Params = struct {
    max_accounts: usize = 1024,
    max_entries_per_account: usize = 32,
    max_account_bytes: usize = 64,
    max_nick_bytes: usize = 64,
};

/// Validation and storage errors for nickname history.
pub const NickHistoryError = std.mem.Allocator.Error || error{
    EmptyAccount,
    AccountTooLong,
    InvalidAccount,
    EmptyNick,
    NickTooLong,
    InvalidNick,
    NegativeTimestamp,
    AccountFull,
};

/// Public view of one nickname change.
///
/// Values returned from `list` borrow from the history store and remain valid
/// until the corresponding account ring slot is evicted, cleared, or destroyed.
pub const Entry = struct {
    old: []const u8,
    new: []const u8,
    ts: i64,
};

/// Bounded per-account nickname history.
pub fn NickHistory(comptime params: Params) type {
    comptime validateParams(params);

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        accounts: std.StringHashMap(AccountRing),
        account_count: usize = 0,

        /// Initialize an empty history store.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .accounts = std.StringHashMap(AccountRing).init(allocator),
                .account_count = 0,
            };
        }

        /// Free every owned account key, ring slot, and map allocation.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.accounts.deinit();
            self.* = undefined;
        }

        /// Remove every account and recorded nickname change.
        pub fn clear(self: *Self) void {
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.accounts.clearRetainingCapacity();
            self.account_count = 0;
        }

        /// Record a nickname change for `account`, evicting that account's oldest entry at capacity.
        pub fn record(self: *Self, account: []const u8, old: []const u8, new: []const u8, ts: i64) NickHistoryError!void {
            try validateNick(params, old);
            try validateNick(params, new);
            if (ts < 0) return error.NegativeTimestamp;

            var ring = try self.getOrCreateAccount(account);
            try ring.append(self.allocator, old, new, ts);
        }

        /// List one account's nickname changes newest-first into `out`.
        pub fn list(self: *const Self, account: []const u8, out: []Entry) NickHistoryError![]Entry {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(params, account, &account_buf);
            const ring = self.accounts.get(account_key) orelse return out[0..0];
            return ring.list(out);
        }

        /// Return the number of account rings currently allocated.
        pub fn accountCount(self: *const Self) usize {
            return self.account_count;
        }

        /// Return the number of entries stored for `account`.
        pub fn entryCount(self: *const Self, account: []const u8) NickHistoryError!usize {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(params, account, &account_buf);
            const ring = self.accounts.get(account_key) orelse return 0;
            return ring.count;
        }

        fn getOrCreateAccount(self: *Self, account: []const u8) NickHistoryError!*AccountRing {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(params, account, &account_buf);
            if (self.accounts.getPtr(account_key)) |ring| return ring;
            if (self.account_count >= params.max_accounts) return error.AccountFull;

            const owned_key = try self.allocator.dupe(u8, account_key);
            errdefer self.allocator.free(owned_key);

            var ring = try AccountRing.init(self.allocator);
            errdefer ring.deinit(self.allocator);

            try self.accounts.putNoClobber(owned_key, ring);
            self.account_count += 1;
            return self.accounts.getPtr(owned_key).?;
        }

        const AccountRing = struct {
            slots: []Slot,
            next: usize = 0,
            count: usize = 0,

            fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!AccountRing {
                const slots = try allocator.alloc(Slot, params.max_entries_per_account);
                @memset(slots, Slot.empty);
                return .{ .slots = slots, .next = 0, .count = 0 };
            }

            fn deinit(self: *AccountRing, allocator: std.mem.Allocator) void {
                for (self.slots) |*slot| {
                    slot.deinit(allocator);
                }
                allocator.free(self.slots);
                self.* = undefined;
            }

            fn append(self: *AccountRing, allocator: std.mem.Allocator, old: []const u8, new: []const u8, ts: i64) NickHistoryError!void {
                var slot = &self.slots[self.next];
                try slot.replace(allocator, old, new, ts);

                self.next += 1;
                if (self.next == self.slots.len) self.next = 0;
                if (self.count < self.slots.len) self.count += 1;
            }

            fn list(self: AccountRing, out: []Entry) []Entry {
                const limit = @min(out.len, self.count);
                if (limit == 0) return out[0..0];

                var written: usize = 0;
                var scanned: usize = 0;
                var index = if (self.next == 0) self.slots.len - 1 else self.next - 1;

                while (scanned < self.count and written < limit) : (scanned += 1) {
                    out[written] = self.slots[index].entry();
                    written += 1;
                    index = if (index == 0) self.slots.len - 1 else index - 1;
                }

                return out[0..written];
            }
        };

        const Slot = struct {
            const empty: Slot = .{ .old_nick = null, .new_nick = null, .ts = 0 };

            old_nick: ?[]u8 = null,
            new_nick: ?[]u8 = null,
            ts: i64 = 0,

            fn replace(self: *Slot, allocator: std.mem.Allocator, old: []const u8, new: []const u8, ts: i64) std.mem.Allocator.Error!void {
                const owned_old = try allocator.dupe(u8, old);
                errdefer allocator.free(owned_old);

                const owned_new = try allocator.dupe(u8, new);
                errdefer allocator.free(owned_new);

                self.deinit(allocator);
                self.old_nick = owned_old;
                self.new_nick = owned_new;
                self.ts = ts;
            }

            fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
                if (self.old_nick) |old| allocator.free(old);
                if (self.new_nick) |new| allocator.free(new);
                self.* = Slot.empty;
            }

            fn entry(self: Slot) Entry {
                return .{
                    .old = self.old_nick.?,
                    .new = self.new_nick.?,
                    .ts = self.ts,
                };
            }
        };
    };
}

/// Default nickname history store.
pub const DefaultHistory = NickHistory(.{});

fn validateParams(comptime params: Params) void {
    if (params.max_accounts == 0) @compileError("nickname history account limit must be non-zero");
    if (params.max_entries_per_account == 0) @compileError("nickname history entry limit must be non-zero");
    if (params.max_account_bytes == 0) @compileError("nickname history account length must be non-zero");
    if (params.max_nick_bytes == 0) @compileError("nickname history nick length must be non-zero");
}

fn normalizeAccount(comptime params: Params, account: []const u8, out: []u8) NickHistoryError![]const u8 {
    try validateAccount(params, account);
    for (account, 0..) |ch, index| {
        out[index] = std.ascii.toLower(ch);
    }
    return out[0..account.len];
}

fn validateAccount(comptime params: Params, account: []const u8) NickHistoryError!void {
    if (account.len == 0) return error.EmptyAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |ch| {
        if (!validAccountByte(ch)) return error.InvalidAccount;
    }
}

fn validateNick(comptime params: Params, nick: []const u8) NickHistoryError!void {
    if (nick.len == 0) return error.EmptyNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

fn validAccountByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':' => true,
        else => false,
    };
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

const TestHistory = NickHistory(.{
    .max_accounts = 2,
    .max_entries_per_account = 3,
    .max_account_bytes = 16,
    .max_nick_bytes = 16,
});

test "record then list returns nickname changes newest first" {
    // Arrange.
    var history = TestHistory.init(std.testing.allocator);
    defer history.deinit();

    // Act.
    try history.record("alice", "Alice", "Alicia", 10);
    try history.record("alice", "Alicia", "Ally", 20);
    try history.record("alice", "Ally", "Alice2", 30);

    var out: [4]Entry = undefined;
    const entries = try history.list("alice", &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("Ally", entries[0].old);
    try std.testing.expectEqualStrings("Alice2", entries[0].new);
    try std.testing.expectEqual(@as(i64, 30), entries[0].ts);
    try std.testing.expectEqualStrings("Alicia", entries[1].old);
    try std.testing.expectEqualStrings("Ally", entries[1].new);
    try std.testing.expectEqual(@as(i64, 20), entries[1].ts);
    try std.testing.expectEqualStrings("Alice", entries[2].old);
    try std.testing.expectEqualStrings("Alicia", entries[2].new);
    try std.testing.expectEqual(@as(i64, 10), entries[2].ts);
}

test "list is scoped per account and normalizes account case" {
    // Arrange.
    var history = TestHistory.init(std.testing.allocator);
    defer history.deinit();

    // Act.
    try history.record("Alice", "Alice", "Alicia", 10);
    try history.record("bob", "Bob", "Bobby", 11);

    var alice_out: [2]Entry = undefined;
    var bob_out: [2]Entry = undefined;
    const alice_entries = try history.list("alice", &alice_out);
    const bob_entries = try history.list("BOB", &bob_out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), history.accountCount());
    try std.testing.expectEqual(@as(usize, 1), alice_entries.len);
    try std.testing.expectEqualStrings("Alicia", alice_entries[0].new);
    try std.testing.expectEqual(@as(usize, 1), bob_entries.len);
    try std.testing.expectEqualStrings("Bobby", bob_entries[0].new);
}

test "bounded account ring evicts oldest nickname change" {
    // Arrange.
    var history = TestHistory.init(std.testing.allocator);
    defer history.deinit();

    // Act.
    try history.record("alice", "n1", "n2", 1);
    try history.record("alice", "n2", "n3", 2);
    try history.record("alice", "n3", "n4", 3);
    try history.record("alice", "n4", "n5", 4);

    var out: [4]Entry = undefined;
    const entries = try history.list("alice", &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 3), try history.entryCount("alice"));
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("n4", entries[0].old);
    try std.testing.expectEqualStrings("n3", entries[1].old);
    try std.testing.expectEqualStrings("n2", entries[2].old);
}

test "list writes at most caller buffer length" {
    // Arrange.
    var history = TestHistory.init(std.testing.allocator);
    defer history.deinit();

    // Act.
    try history.record("alice", "a", "b", 1);
    try history.record("alice", "b", "c", 2);
    try history.record("alice", "c", "d", 3);

    var out: [2]Entry = undefined;
    const entries = try history.list("alice", &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("c", entries[0].old);
    try std.testing.expectEqualStrings("b", entries[1].old);
}

test "clear frees entries and permits reuse" {
    // Arrange.
    var history = TestHistory.init(std.testing.allocator);
    defer history.deinit();

    try history.record("alice", "Alice", "Alicia", 10);
    try history.record("bob", "Bob", "Bobby", 11);

    // Act.
    history.clear();
    try history.record("carol", "Carol", "Caz", 12);

    var old_out: [1]Entry = undefined;
    var new_out: [1]Entry = undefined;
    const old_entries = try history.list("alice", &old_out);
    const new_entries = try history.list("carol", &new_out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), history.accountCount());
    try std.testing.expectEqual(@as(usize, 0), old_entries.len);
    try std.testing.expectEqual(@as(usize, 1), new_entries.len);
    try std.testing.expectEqualStrings("Caz", new_entries[0].new);
}

test "validation rejects malformed account nick and timestamp input" {
    // Arrange.
    var history = TestHistory.init(std.testing.allocator);
    defer history.deinit();

    // Act and assert.
    try std.testing.expectError(error.EmptyAccount, history.record("", "old", "new", 1));
    try std.testing.expectError(error.InvalidAccount, history.record("bad account", "old", "new", 1));
    try std.testing.expectError(error.AccountTooLong, history.record("account-name-too-long", "old", "new", 1));
    try std.testing.expectError(error.EmptyNick, history.record("acct", "", "new", 1));
    try std.testing.expectError(error.InvalidNick, history.record("acct", "bad nick", "new", 1));
    try std.testing.expectError(error.NickTooLong, history.record("acct", "nick-name-too-long", "new", 1));
    try std.testing.expectError(error.NegativeTimestamp, history.record("acct", "old", "new", -1));
}

test "new account creation observes configured account limit" {
    // Arrange.
    var history = TestHistory.init(std.testing.allocator);
    defer history.deinit();

    // Act.
    try history.record("alice", "Alice", "Alicia", 1);
    try history.record("bob", "Bob", "Bobby", 2);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), history.accountCount());
    try std.testing.expectError(error.AccountFull, history.record("carol", "Carol", "Caz", 3));
}
