// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory grouped-nick and offline memo storage.
//!
//! This module owns every account key, nick, sender, and memo body it stores.
//! Account keys are normalized to lowercase for all insertions and lookups.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("memo_group requires a 64-bit target");
}

/// Storage limits for grouped nick and memo state.
pub const Params = struct {
    /// Maximum number of account buckets in each store.
    max_accounts: usize = 65536,
    /// Maximum grouped nicks retained for one account.
    max_nicks_per_group: usize = 16,
    /// Maximum memos retained for one account.
    max_memos_per_account: usize = 100,
    /// Maximum account name length in bytes.
    max_account_bytes: usize = 64,
    /// Maximum grouped nick length in bytes.
    max_nick_bytes: usize = 64,
    /// Maximum sender name length in bytes.
    max_sender_bytes: usize = 64,
    /// Maximum memo body length in bytes.
    max_body_bytes: usize = 512,
};

/// Stable policy codes for the grouped-nick and memo stores.
pub const PolicyCode = enum(u8) {
    /// Grouped-nick policy.
    group = 1,
    /// Offline memo policy.
    memo = 2,

    /// Return the stable numeric value for this policy code.
    pub fn numeric(self: PolicyCode) u8 {
        return switch (self) {
            .group => 1,
            .memo => 2,
        };
    }
};

/// Errors returned by grouped-nick and memo operations.
pub const Error = std.mem.Allocator.Error || error{
    /// The supplied account name was empty.
    InvalidAccount,
    /// The supplied account name exceeded `Params.max_account_bytes`.
    AccountTooLong,
    /// The supplied nick was empty.
    InvalidNick,
    /// The supplied nick exceeded `Params.max_nick_bytes`.
    NickTooLong,
    /// The supplied memo sender was empty.
    InvalidSender,
    /// The supplied memo sender exceeded `Params.max_sender_bytes`.
    SenderTooLong,
    /// The supplied memo body was empty.
    EmptyBody,
    /// The supplied memo body exceeded `Params.max_body_bytes`.
    BodyTooLong,
    /// The store has reached `Params.max_accounts`.
    TooManyAccounts,
    /// The nick group has reached `Params.max_nicks_per_group`.
    TooManyNicks,
    /// The requested nick is not grouped with that account.
    NickNotGrouped,
    /// The caller-provided output buffer is too small.
    OutputTooSmall,
    /// The memo box has reached `Params.max_memos_per_account`.
    MemoBoxFull,
    /// Memo id allocation would overflow.
    IdOverflow,
};

/// A borrowed view of one offline memo.
pub const Memo = struct {
    /// Monotonic memo id assigned by the memo box.
    id: u64,
    /// Sender name borrowed from the memo box.
    from: []const u8,
    /// Memo body borrowed from the memo box.
    body: []const u8,
    /// Caller-provided timestamp.
    ts: i64,
    /// Whether the memo has been marked read.
    read: bool,
};

/// Build a grouped-nick store type with custom limits.
pub fn NickGroupWith(comptime params: Params) type {
    comptime {
        if (params.max_accounts == 0) @compileError("NickGroup needs account storage");
        if (params.max_nicks_per_group == 0) @compileError("NickGroup needs nick storage");
        if (params.max_account_bytes == 0) @compileError("NickGroup needs account key storage");
        if (params.max_nick_bytes == 0) @compileError("NickGroup needs nick storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        accounts: std.StringHashMap(GroupState),

        const GroupState = struct {
            nicks: std.ArrayListUnmanaged([]u8) = .empty,
            primary_index: usize = 0,

            fn deinit(self: *GroupState, allocator: std.mem.Allocator) void {
                for (self.nicks.items) |nick| allocator.free(nick);
                self.nicks.deinit(allocator);
            }

            fn indexOf(self: *const GroupState, nick: []const u8) ?usize {
                for (self.nicks.items, 0..) |item, idx| {
                    if (std.mem.eql(u8, item, nick)) return idx;
                }
                return null;
            }
        };

        /// Create an empty grouped-nick store backed by `allocator`.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .accounts = std.StringHashMap(GroupState).init(allocator),
            };
        }

        /// Release all account keys and grouped nick strings.
        pub fn deinit(self: *Self) void {
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.accounts.deinit();
            self.* = undefined;
        }

        /// Add `nick` to `account`'s group.
        ///
        /// The first nick added to an account becomes primary. Adding an
        /// existing nick is idempotent and returns `false`.
        pub fn add(self: *Self, account: []const u8, nick: []const u8) Error!bool {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            try validateNickWith(params, nick);

            const state = try self.ensureAccount(account_key);
            if (state.indexOf(nick) != null) return false;
            if (state.nicks.items.len >= params.max_nicks_per_group) return error.TooManyNicks;

            const owned_nick = try self.allocator.dupe(u8, nick);
            errdefer self.allocator.free(owned_nick);
            try state.nicks.append(self.allocator, owned_nick);
            return true;
        }

        /// Remove `nick` from `account`'s group.
        ///
        /// If the primary nick is removed and other nicks remain, the earliest
        /// remaining nick becomes primary. Empty groups are pruned.
        pub fn remove(self: *Self, account: []const u8, nick: []const u8) Error!bool {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            try validateNickWith(params, nick);

            const entry = self.accounts.getEntry(account_key) orelse return false;
            const idx = entry.value_ptr.indexOf(nick) orelse return false;
            const removed = entry.value_ptr.nicks.orderedRemove(idx);
            self.allocator.free(removed);

            if (entry.value_ptr.nicks.items.len == 0) {
                self.dropAccount(entry);
                return true;
            }
            if (entry.value_ptr.primary_index == idx) {
                entry.value_ptr.primary_index = 0;
            } else if (entry.value_ptr.primary_index > idx) {
                entry.value_ptr.primary_index -= 1;
            }
            return true;
        }

        /// Copy `account`'s grouped nick list into `out`.
        ///
        /// Returned nick slices are borrowed from the store and remain valid
        /// until that account is mutated or the store is deinitialized.
        pub fn list(self: *const Self, account: []const u8, out: [][]const u8) Error![]const []const u8 {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            const state = self.accounts.getPtr(account_key) orelse return out[0..0];
            if (out.len < state.nicks.items.len) return error.OutputTooSmall;

            for (state.nicks.items, 0..) |nick, idx| out[idx] = nick;
            return out[0..state.nicks.items.len];
        }

        /// Return whether `nick` belongs to `account`'s group.
        pub fn contains(self: *const Self, account: []const u8, nick: []const u8) Error!bool {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            try validateNickWith(params, nick);

            const state = self.accounts.getPtr(account_key) orelse return false;
            return state.indexOf(nick) != null;
        }

        /// Mark `nick` as `account`'s primary grouped nick.
        pub fn setPrimary(self: *Self, account: []const u8, nick: []const u8) Error!void {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            try validateNickWith(params, nick);

            const state = self.accounts.getPtr(account_key) orelse return error.NickNotGrouped;
            state.primary_index = state.indexOf(nick) orelse return error.NickNotGrouped;
        }

        /// Return `account`'s primary grouped nick, if the account has a group.
        pub fn primary(self: *const Self, account: []const u8) Error!?[]const u8 {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            const state = self.accounts.getPtr(account_key) orelse return null;
            return state.nicks.items[state.primary_index];
        }

        fn ensureAccount(self: *Self, account_key: []const u8) Error!*GroupState {
            if (self.accounts.getPtr(account_key)) |state| return state;
            if (self.accounts.count() >= params.max_accounts) return error.TooManyAccounts;

            const owned_account = try self.allocator.dupe(u8, account_key);
            errdefer self.allocator.free(owned_account);
            try self.accounts.putNoClobber(owned_account, .{});
            return self.accounts.getPtr(owned_account).?;
        }

        fn dropAccount(self: *Self, entry: std.StringHashMap(GroupState).Entry) void {
            const owned_account = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_account);
        }
    };
}

/// Default grouped-nick store.
pub const NickGroup = NickGroupWith(.{});

/// Build a memo-box store type with custom limits.
pub fn MemoBoxWith(comptime params: Params) type {
    comptime {
        if (params.max_accounts == 0) @compileError("MemoBox needs account storage");
        if (params.max_memos_per_account == 0) @compileError("MemoBox needs memo storage");
        if (params.max_account_bytes == 0) @compileError("MemoBox needs account key storage");
        if (params.max_sender_bytes == 0) @compileError("MemoBox needs sender storage");
        if (params.max_body_bytes == 0) @compileError("MemoBox needs body storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        accounts: std.StringHashMap(MemoList),
        next_id: u64 = 1,

        const MemoList = std.ArrayListUnmanaged(StoredMemo);

        const StoredMemo = struct {
            id: u64,
            from: []u8,
            body: []u8,
            ts: i64,
            read: bool = false,

            fn view(self: *const StoredMemo) Memo {
                return .{
                    .id = self.id,
                    .from = self.from,
                    .body = self.body,
                    .ts = self.ts,
                    .read = self.read,
                };
            }

            fn deinit(self: *StoredMemo, allocator: std.mem.Allocator) void {
                allocator.free(self.from);
                allocator.free(self.body);
            }
        };

        /// Create an empty memo box backed by `allocator`.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .accounts = std.StringHashMap(MemoList).init(allocator),
            };
        }

        /// Release all account keys, sender strings, and memo bodies.
        pub fn deinit(self: *Self) void {
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                freeMemoList(self.allocator, entry.value_ptr);
            }
            self.accounts.deinit();
            self.* = undefined;
        }

        /// Store one unread memo for `to` and return its id.
        ///
        /// This store uses reject-when-full policy: once an account reaches
        /// `Params.max_memos_per_account`, new sends fail with `MemoBoxFull`.
        pub fn send(self: *Self, to: []const u8, from: []const u8, body: []const u8, ts: i64) Error!u64 {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, to, &account_buf);
            try validateSenderWith(params, from);
            try validateBodyWith(params, body);

            const list_ptr = try self.ensureAccount(account_key);
            if (list_ptr.items.len >= params.max_memos_per_account) return error.MemoBoxFull;
            if (self.next_id == std.math.maxInt(u64)) return error.IdOverflow;

            const owned_from = try self.allocator.dupe(u8, from);
            errdefer self.allocator.free(owned_from);
            const owned_body = try self.allocator.dupe(u8, body);
            errdefer self.allocator.free(owned_body);

            const id = self.next_id;
            try list_ptr.append(self.allocator, .{
                .id = id,
                .from = owned_from,
                .body = owned_body,
                .ts = ts,
            });
            self.next_id += 1;
            return id;
        }

        /// Copy `account`'s memos into `out`.
        ///
        /// Returned sender and body slices are borrowed from the memo box and
        /// remain valid until that memo is deleted or the store is deinitialized.
        pub fn list(self: *const Self, account: []const u8, out: []Memo) Error![]const Memo {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            const memos = self.accounts.getPtr(account_key) orelse return out[0..0];
            if (out.len < memos.items.len) return error.OutputTooSmall;

            for (memos.items, 0..) |*memo, idx| out[idx] = memo.view();
            return out[0..memos.items.len];
        }

        /// Mark memo `id` in `account`'s box as read.
        ///
        /// Returns `true` when a matching memo exists.
        pub fn read(self: *Self, account: []const u8, id: u64) Error!bool {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            const memos = self.accounts.getPtr(account_key) orelse return false;

            for (memos.items) |*memo| {
                if (memo.id == id) {
                    memo.read = true;
                    return true;
                }
            }
            return false;
        }

        /// Delete memo `id` from `account`'s box.
        ///
        /// Returns `true` when a matching memo was deleted.
        pub fn del(self: *Self, account: []const u8, id: u64) Error!bool {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            const entry = self.accounts.getEntry(account_key) orelse return false;

            for (entry.value_ptr.items, 0..) |*memo, idx| {
                if (memo.id == id) {
                    memo.deinit(self.allocator);
                    _ = entry.value_ptr.orderedRemove(idx);
                    if (entry.value_ptr.items.len == 0) self.dropAccount(entry);
                    return true;
                }
            }
            return false;
        }

        /// Return the number of memos held for `account`.
        pub fn count(self: *const Self, account: []const u8) Error!usize {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            const memos = self.accounts.getPtr(account_key) orelse return 0;
            return memos.items.len;
        }

        /// Return the number of unread memos held for `account`.
        pub fn unreadCount(self: *const Self, account: []const u8) Error!usize {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try lowerAccountWith(params, account, &account_buf);
            const memos = self.accounts.getPtr(account_key) orelse return 0;

            var unread: usize = 0;
            for (memos.items) |memo| {
                if (!memo.read) unread += 1;
            }
            return unread;
        }

        fn ensureAccount(self: *Self, account_key: []const u8) Error!*MemoList {
            if (self.accounts.getPtr(account_key)) |memos| return memos;
            if (self.accounts.count() >= params.max_accounts) return error.TooManyAccounts;

            const owned_account = try self.allocator.dupe(u8, account_key);
            errdefer self.allocator.free(owned_account);
            try self.accounts.putNoClobber(owned_account, .empty);
            return self.accounts.getPtr(owned_account).?;
        }

        fn dropAccount(self: *Self, entry: std.StringHashMap(MemoList).Entry) void {
            const owned_account = entry.key_ptr.*;
            freeMemoList(self.allocator, entry.value_ptr);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_account);
        }

        fn freeMemoList(allocator: std.mem.Allocator, memos: *MemoList) void {
            for (memos.items) |*memo| memo.deinit(allocator);
            memos.deinit(allocator);
        }
    };
}

/// Default per-account memo box.
pub const MemoBox = MemoBoxWith(.{});

/// Build an aggregate grouped-nick and memo store type with custom limits.
pub fn StoreWith(comptime params: Params) type {
    return struct {
        const Self = @This();
        const GroupStore = NickGroupWith(params);
        const MemoStore = MemoBoxWith(params);

        /// Grouped-nick state.
        groups: GroupStore,
        /// Offline memo state.
        memos: MemoStore,

        /// Create an aggregate store using one allocator for both sub-stores.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .groups = GroupStore.init(allocator),
                .memos = MemoStore.init(allocator),
            };
        }

        /// Release grouped-nick and memo state.
        pub fn deinit(self: *Self) void {
            self.groups.deinit();
            self.memos.deinit();
            self.* = undefined;
        }
    };
}

/// Default aggregate grouped-nick and memo store.
pub const Store = StoreWith(.{});

fn lowerAccountWith(comptime params: Params, account: []const u8, out: *[params.max_account_bytes]u8) Error![]const u8 {
    try validateAccountWith(params, account);
    for (account, 0..) |byte, idx| out[idx] = std.ascii.toLower(byte);
    return out[0..account.len];
}

fn validateAccountWith(comptime params: Params, account: []const u8) Error!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
}

fn validateNickWith(comptime params: Params, nick: []const u8) Error!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
}

fn validateSenderWith(comptime params: Params, sender: []const u8) Error!void {
    if (sender.len == 0) return error.InvalidSender;
    if (sender.len > params.max_sender_bytes) return error.SenderTooLong;
}

fn validateBodyWith(comptime params: Params, body: []const u8) Error!void {
    if (body.len == 0) return error.EmptyBody;
    if (body.len > params.max_body_bytes) return error.BodyTooLong;
}

const testing = std.testing;

test "nick group add sets primary and list preserves insertion order" {
    // Arrange.
    var groups = NickGroup.init(testing.allocator);
    defer groups.deinit();

    // Act.
    try testing.expect(try groups.add("alice", "Alice"));
    try testing.expect(try groups.add("alice", "Alicia"));
    try testing.expect(!try groups.add("alice", "Alice"));

    // Assert.
    var out: [2][]const u8 = undefined;
    const listed = try groups.list("alice", &out);
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("Alice", listed[0]);
    try testing.expectEqualStrings("Alicia", listed[1]);
    try testing.expectEqualStrings("Alice", (try groups.primary("alice")).?);
}

test "nick group set primary and remove reassigns primary" {
    // Arrange.
    var groups = NickGroup.init(testing.allocator);
    defer groups.deinit();
    _ = try groups.add("alice", "one");
    _ = try groups.add("alice", "two");
    _ = try groups.add("alice", "three");

    // Act.
    try groups.setPrimary("alice", "two");
    const removed = try groups.remove("alice", "two");

    // Assert.
    try testing.expect(removed);
    try testing.expectEqualStrings("one", (try groups.primary("alice")).?);
    try testing.expect(!try groups.contains("alice", "two"));
}

test "nick group enforces per-account limit" {
    // Arrange.
    const TinyGroup = NickGroupWith(.{ .max_nicks_per_group = 2 });
    var groups = TinyGroup.init(testing.allocator);
    defer groups.deinit();

    // Act.
    _ = try groups.add("alice", "one");
    _ = try groups.add("alice", "two");

    // Assert.
    try testing.expectError(error.TooManyNicks, groups.add("alice", "three"));
}

test "nick group normalizes account keys case-insensitively" {
    // Arrange.
    var groups = NickGroup.init(testing.allocator);
    defer groups.deinit();

    // Act.
    _ = try groups.add("Alice", "one");
    try groups.setPrimary("ALICE", "one");

    // Assert.
    try testing.expect(try groups.contains("alice", "one"));
    try testing.expectEqualStrings("one", (try groups.primary("aLiCe")).?);
}

test "memo box send list read unread count and delete" {
    // Arrange.
    var memos = MemoBox.init(testing.allocator);
    defer memos.deinit();

    // Act.
    const first_id = try memos.send("alice", "bob", "hello", 10);
    const second_id = try memos.send("alice", "cara", "ping", 20);
    try testing.expect(try memos.read("alice", first_id));

    // Assert.
    try testing.expectEqual(@as(usize, 2), try memos.count("alice"));
    try testing.expectEqual(@as(usize, 1), try memos.unreadCount("alice"));
    var out: [2]Memo = undefined;
    const listed = try memos.list("alice", &out);
    try testing.expectEqual(first_id, listed[0].id);
    try testing.expectEqualStrings("bob", listed[0].from);
    try testing.expectEqualStrings("hello", listed[0].body);
    try testing.expect(listed[0].read);
    try testing.expectEqual(second_id, listed[1].id);
    try testing.expect(!listed[1].read);

    try testing.expect(try memos.del("alice", first_id));
    try testing.expect(!try memos.del("alice", first_id));
    try testing.expectEqual(@as(usize, 1), try memos.count("alice"));
    try testing.expectEqual(@as(usize, 1), try memos.unreadCount("alice"));
}

test "memo box rejects full accounts instead of dropping oldest memo" {
    // Arrange.
    const TinyMemoBox = MemoBoxWith(.{ .max_memos_per_account = 2 });
    var memos = TinyMemoBox.init(testing.allocator);
    defer memos.deinit();

    // Act.
    _ = try memos.send("alice", "bob", "one", 1);
    _ = try memos.send("alice", "bob", "two", 2);

    // Assert.
    try testing.expectError(error.MemoBoxFull, memos.send("alice", "bob", "three", 3));
    try testing.expectEqual(@as(usize, 2), try memos.count("alice"));
}

test "memo box normalizes account keys case-insensitively" {
    // Arrange.
    var memos = MemoBox.init(testing.allocator);
    defer memos.deinit();

    // Act.
    const id = try memos.send("Alice", "bob", "hello", 1);
    try testing.expect(try memos.read("ALICE", id));

    // Assert.
    var out: [1]Memo = undefined;
    const listed = try memos.list("aLiCe", &out);
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expect(listed[0].read);
    try testing.expectEqual(@as(usize, 0), try memos.unreadCount("alice"));
}

test "memo box enforces output and validation limits" {
    // Arrange.
    const SmallMemoBox = MemoBoxWith(.{ .max_body_bytes = 4, .max_sender_bytes = 3 });
    var memos = SmallMemoBox.init(testing.allocator);
    defer memos.deinit();

    // Act.
    _ = try memos.send("alice", "bob", "body", 1);

    // Assert.
    var too_small: [0]Memo = undefined;
    try testing.expectError(error.OutputTooSmall, memos.list("alice", &too_small));
    try testing.expectError(error.SenderTooLong, memos.send("alice", "cara", "ok", 2));
    try testing.expectError(error.BodyTooLong, memos.send("alice", "bob", "large", 2));
    try testing.expectError(error.EmptyBody, memos.send("alice", "bob", "", 2));
}

test "store deinit releases grouped nicks and memos together" {
    // Arrange.
    var store = Store.init(testing.allocator);
    defer store.deinit();

    // Act.
    _ = try store.groups.add("alice", "one");
    _ = try store.memos.send("alice", "bob", "hello", 1);

    // Assert.
    try testing.expect(try store.groups.contains("ALICE", "one"));
    try testing.expectEqual(@as(usize, 1), try store.memos.count("ALICE"));
}
