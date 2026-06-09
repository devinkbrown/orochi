//! Pure services memo metadata index.
//!
//! This module intentionally imports only `std`. It is a bounded, in-memory
//! index over memo metadata and parser state for real server-side services
//! commands. It does not model services as pseudo-clients.

const std = @import("std");

pub const default_max_accounts: usize = 65_536;
pub const default_max_memos_per_account: usize = 100;
pub const default_max_account_bytes: usize = 64;
pub const default_max_sender_bytes: usize = 64;

pub const Params = struct {
    max_accounts: usize = default_max_accounts,
    max_memos_per_account: usize = default_max_memos_per_account,
    max_account_bytes: usize = default_max_account_bytes,
    max_sender_bytes: usize = default_max_sender_bytes,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidSender,
    SenderTooLong,
    InvalidId,
    DuplicateId,
    TooManyAccounts,
    MemoIndexFull,
    OutputTooSmall,
    MissingParameter,
    TooManyParameters,
    UnknownCommand,
    InvalidParameter,
};

pub const MemoMeta = struct {
    id: u64,
    from: []const u8,
    sent_at: i64,
    read: bool,
};

pub const Request = union(enum) {
    list,
    mark_read: u64,
    del: u64,
    unread_count,
};

pub fn MemoIndexWith(comptime params: Params) type {
    comptime {
        if (params.max_accounts == 0) @compileError("MemoIndex needs account storage");
        if (params.max_memos_per_account == 0) @compileError("MemoIndex needs memo storage");
        if (params.max_account_bytes == 0) @compileError("MemoIndex needs account key storage");
        if (params.max_sender_bytes == 0) @compileError("MemoIndex needs sender storage");
    }

    return struct {
        const Self = @This();
        const AccountList = std.ArrayListUnmanaged(StoredMeta);

        allocator: std.mem.Allocator,
        accounts: std.StringHashMap(AccountList),

        const StoredMeta = struct {
            id: u64,
            from: []u8,
            sent_at: i64,
            read: bool,

            fn view(self: *const StoredMeta) MemoMeta {
                return .{
                    .id = self.id,
                    .from = self.from,
                    .sent_at = self.sent_at,
                    .read = self.read,
                };
            }

            fn deinit(self: *StoredMeta, allocator: std.mem.Allocator) void {
                allocator.free(self.from);
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .accounts = std.StringHashMap(AccountList).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            self.accounts.deinit();
            self.* = undefined;
        }

        pub fn clear(self: *Self) void {
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                freeList(self.allocator, entry.value_ptr);
            }
            self.accounts.clearRetainingCapacity();
        }

        /// Add memo metadata for `account`.
        ///
        /// The memo id is expected to come from the backing memo box. New
        /// entries are inserted in ascending `(sent_at, id)` order so LIST is
        /// deterministic even when restored from durable state out of order.
        pub fn add(
            self: *Self,
            account: []const u8,
            id: u64,
            from: []const u8,
            sent_at: i64,
        ) Error!void {
            if (id == 0) return error.InvalidId;

            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(account, &account_buf);
            try validateSender(from);

            const entries = try self.ensureAccount(account_key);
            if (entries.items.len >= params.max_memos_per_account) return error.MemoIndexFull;
            if (indexOf(entries, id) != null) return error.DuplicateId;

            const owned_from = try self.allocator.dupe(u8, from);
            errdefer self.allocator.free(owned_from);

            const insert_at = orderedInsertIndex(entries, id, sent_at);
            try entries.insert(self.allocator, insert_at, .{
                .id = id,
                .from = owned_from,
                .sent_at = sent_at,
                .read = false,
            });
        }

        /// Copy `account`'s ordered metadata into `out`.
        ///
        /// Returned sender slices are borrowed from the index and remain valid
        /// until that account is mutated, deleted, cleared, or deinitialized.
        pub fn list(self: *const Self, account: []const u8, out: []MemoMeta) Error![]const MemoMeta {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(account, &account_buf);
            const entries = self.accounts.getPtr(account_key) orelse return out[0..0];
            if (out.len < entries.items.len) return error.OutputTooSmall;

            for (entries.items, 0..) |*entry, idx| out[idx] = entry.view();
            return out[0..entries.items.len];
        }

        pub fn markRead(self: *Self, account: []const u8, id: u64) Error!bool {
            if (id == 0) return error.InvalidId;

            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(account, &account_buf);
            const entries = self.accounts.getPtr(account_key) orelse return false;
            const idx = indexOf(entries, id) orelse return false;
            entries.items[idx].read = true;
            return true;
        }

        pub fn del(self: *Self, account: []const u8, id: u64) Error!bool {
            if (id == 0) return error.InvalidId;

            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(account, &account_buf);
            const entry = self.accounts.getEntry(account_key) orelse return false;
            const idx = indexOf(entry.value_ptr, id) orelse return false;

            var removed = entry.value_ptr.orderedRemove(idx);
            removed.deinit(self.allocator);
            if (entry.value_ptr.items.len == 0) self.dropAccount(entry);
            return true;
        }

        pub fn count(self: *const Self, account: []const u8) Error!usize {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(account, &account_buf);
            const entries = self.accounts.getPtr(account_key) orelse return 0;
            return entries.items.len;
        }

        pub fn unreadCount(self: *const Self, account: []const u8) Error!usize {
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = try normalizeAccount(account, &account_buf);
            const entries = self.accounts.getPtr(account_key) orelse return 0;

            var unread: usize = 0;
            for (entries.items) |entry| {
                if (!entry.read) unread += 1;
            }
            return unread;
        }

        fn ensureAccount(self: *Self, account_key: []const u8) Error!*AccountList {
            if (self.accounts.getPtr(account_key)) |entries| return entries;
            if (self.accounts.count() >= params.max_accounts) return error.TooManyAccounts;

            const owned_account = try self.allocator.dupe(u8, account_key);
            errdefer self.allocator.free(owned_account);
            try self.accounts.putNoClobber(owned_account, .empty);
            return self.accounts.getPtr(owned_account).?;
        }

        fn dropAccount(self: *Self, entry: std.StringHashMap(AccountList).Entry) void {
            const owned_account = entry.key_ptr.*;
            freeList(self.allocator, entry.value_ptr);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_account);
        }

        fn freeList(allocator: std.mem.Allocator, entries: *AccountList) void {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        fn indexOf(entries: *const AccountList, id: u64) ?usize {
            for (entries.items, 0..) |entry, idx| {
                if (entry.id == id) return idx;
            }
            return null;
        }

        fn orderedInsertIndex(entries: *const AccountList, id: u64, sent_at: i64) usize {
            for (entries.items, 0..) |entry, idx| {
                if (sent_at < entry.sent_at) return idx;
                if (sent_at == entry.sent_at and id < entry.id) return idx;
            }
            return entries.items.len;
        }

        fn normalizeAccount(account: []const u8, out: *[params.max_account_bytes]u8) Error![]const u8 {
            if (account.len == 0) return error.InvalidAccount;
            if (account.len > params.max_account_bytes) return error.AccountTooLong;

            for (account, 0..) |byte, idx| {
                if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidAccount;
                out[idx] = std.ascii.toLower(byte);
            }
            return out[0..account.len];
        }

        fn validateSender(sender: []const u8) Error!void {
            if (sender.len == 0) return error.InvalidSender;
            if (sender.len > params.max_sender_bytes) return error.SenderTooLong;
            for (sender) |byte| {
                if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidSender;
            }
        }
    };
}

pub const MemoIndex = MemoIndexWith(.{});

pub fn parse(line: []const u8) Error!Request {
    var it = std.mem.tokenizeAny(u8, line, " \t\r\n");
    const command = it.next() orelse return error.MissingParameter;

    if (asciiEqlIgnoreCase(command, "LIST")) {
        if (it.next() != null) return error.TooManyParameters;
        return .list;
    }
    if (asciiEqlIgnoreCase(command, "READ") or asciiEqlIgnoreCase(command, "MARKREAD")) {
        const id_token = it.next() orelse return error.MissingParameter;
        if (it.next() != null) return error.TooManyParameters;
        return .{ .mark_read = try parseId(id_token) };
    }
    if (asciiEqlIgnoreCase(command, "DEL") or asciiEqlIgnoreCase(command, "DELETE")) {
        const id_token = it.next() orelse return error.MissingParameter;
        if (it.next() != null) return error.TooManyParameters;
        return .{ .del = try parseId(id_token) };
    }
    if (asciiEqlIgnoreCase(command, "UNREAD") or asciiEqlIgnoreCase(command, "UNREADCOUNT")) {
        if (it.next() != null) return error.TooManyParameters;
        return .unread_count;
    }

    return error.UnknownCommand;
}

pub fn parseParams(params: []const []const u8) Error!Request {
    if (params.len == 0) return error.MissingParameter;
    if (asciiEqlIgnoreCase(params[0], "LIST")) {
        if (params.len != 1) return error.TooManyParameters;
        return .list;
    }
    if (asciiEqlIgnoreCase(params[0], "READ") or asciiEqlIgnoreCase(params[0], "MARKREAD")) {
        if (params.len < 2) return error.MissingParameter;
        if (params.len > 2) return error.TooManyParameters;
        return .{ .mark_read = try parseId(params[1]) };
    }
    if (asciiEqlIgnoreCase(params[0], "DEL") or asciiEqlIgnoreCase(params[0], "DELETE")) {
        if (params.len < 2) return error.MissingParameter;
        if (params.len > 2) return error.TooManyParameters;
        return .{ .del = try parseId(params[1]) };
    }
    if (asciiEqlIgnoreCase(params[0], "UNREAD") or asciiEqlIgnoreCase(params[0], "UNREADCOUNT")) {
        if (params.len != 1) return error.TooManyParameters;
        return .unread_count;
    }
    return error.UnknownCommand;
}

fn parseId(token: []const u8) Error!u64 {
    if (token.len == 0 or token[0] == '+') return error.InvalidId;
    const id = std.fmt.parseUnsigned(u64, token, 10) catch return error.InvalidId;
    if (id == 0) return error.InvalidId;
    return id;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

const testing = std.testing;

test "add list orders by sent_at then id without owning bodies" {
    var idx = MemoIndex.init(testing.allocator);
    defer idx.deinit();

    try idx.add("Alice", 30, "carol", 300);
    try idx.add("alice", 10, "bob", 100);
    try idx.add("ALICE", 20, "dave", 300);

    var out: [3]MemoMeta = undefined;
    const listed = try idx.list("aLiCe", &out);
    try testing.expectEqual(@as(usize, 3), listed.len);
    try testing.expectEqual(@as(u64, 10), listed[0].id);
    try testing.expectEqual(@as(i64, 100), listed[0].sent_at);
    try testing.expectEqualStrings("bob", listed[0].from);
    try testing.expect(!listed[0].read);
    try testing.expectEqual(@as(u64, 20), listed[1].id);
    try testing.expectEqual(@as(u64, 30), listed[2].id);
}

test "mark read is idempotent and unread count tracks state" {
    var idx = MemoIndex.init(testing.allocator);
    defer idx.deinit();

    try idx.add("alice", 1, "bob", 10);
    try idx.add("alice", 2, "carol", 20);
    try testing.expectEqual(@as(usize, 2), try idx.unreadCount("alice"));

    try testing.expect(try idx.markRead("ALICE", 1));
    try testing.expect(try idx.markRead("alice", 1));
    try testing.expectEqual(@as(usize, 1), try idx.unreadCount("alice"));

    try testing.expect(!try idx.markRead("alice", 99));
    try testing.expectEqual(@as(usize, 1), try idx.unreadCount("alice"));
}

test "delete removes one id and prunes empty account buckets" {
    var idx = MemoIndex.init(testing.allocator);
    defer idx.deinit();

    try idx.add("alice", 1, "bob", 10);
    try idx.add("alice", 2, "carol", 20);
    try testing.expectEqual(@as(usize, 2), try idx.count("alice"));

    try testing.expect(try idx.del("alice", 1));
    try testing.expect(!try idx.del("alice", 1));
    try testing.expectEqual(@as(usize, 1), try idx.count("alice"));

    try testing.expect(try idx.del("ALICE", 2));
    try testing.expectEqual(@as(usize, 0), try idx.count("alice"));
    try testing.expectEqual(@as(usize, 0), try idx.unreadCount("alice"));
}

test "bounded accounts and per-account memo capacity are enforced" {
    const Tiny = MemoIndexWith(.{
        .max_accounts = 1,
        .max_memos_per_account = 2,
        .max_account_bytes = 8,
        .max_sender_bytes = 8,
    });
    var idx = Tiny.init(testing.allocator);
    defer idx.deinit();

    try idx.add("alice", 1, "bob", 10);
    try idx.add("alice", 2, "carol", 20);
    try testing.expectError(error.MemoIndexFull, idx.add("alice", 3, "dave", 30));
    try testing.expectError(error.TooManyAccounts, idx.add("eve", 4, "mallory", 40));
}

test "validation rejects bad account sender id duplicates and short output" {
    const Small = MemoIndexWith(.{
        .max_accounts = 4,
        .max_memos_per_account = 4,
        .max_account_bytes = 4,
        .max_sender_bytes = 3,
    });
    var idx = Small.init(testing.allocator);
    defer idx.deinit();

    try testing.expectError(error.InvalidAccount, idx.add("", 1, "bob", 1));
    try testing.expectError(error.InvalidAccount, idx.add("a b", 1, "bob", 1));
    try testing.expectError(error.AccountTooLong, idx.add("alice", 1, "bob", 1));
    try testing.expectError(error.InvalidId, idx.add("al", 0, "bob", 1));
    try testing.expectError(error.InvalidSender, idx.add("al", 1, "", 1));
    try testing.expectError(error.InvalidSender, idx.add("al", 1, "b b", 1));
    try testing.expectError(error.SenderTooLong, idx.add("al", 1, "cara", 1));

    try idx.add("al", 1, "bob", 1);
    try testing.expectError(error.DuplicateId, idx.add("AL", 1, "ann", 2));

    var out: [0]MemoMeta = undefined;
    try testing.expectError(error.OutputTooSmall, idx.list("al", &out));
}

test "clear releases retained entries and permits reuse" {
    var idx = MemoIndex.init(testing.allocator);
    defer idx.deinit();

    try idx.add("alice", 1, "bob", 10);
    try idx.add("bob", 2, "alice", 20);
    idx.clear();

    try testing.expectEqual(@as(usize, 0), try idx.count("alice"));
    try idx.add("alice", 3, "carol", 30);
    try testing.expectEqual(@as(usize, 1), try idx.unreadCount("alice"));
}

test "parse service memo index command lines" {
    try testing.expectEqual(Request.list, try parse(" LIST "));
    try testing.expectEqual(Request{ .mark_read = 42 }, try parse("read 42"));
    try testing.expectEqual(Request{ .mark_read = 42 }, try parse("MARKREAD\t42"));
    try testing.expectEqual(Request{ .del = 7 }, try parse("delete 7"));
    try testing.expectEqual(Request.unread_count, try parse("unread"));
    try testing.expectEqual(Request.unread_count, try parse("UNREADCOUNT"));
}

test "parse params from an already tokenized server command" {
    const list_params = [_][]const u8{"LIST"};
    const read_params = [_][]const u8{ "READ", "99" };
    const del_params = [_][]const u8{ "DEL", "100" };
    try testing.expectEqual(Request.list, try parseParams(&list_params));
    try testing.expectEqual(Request{ .mark_read = 99 }, try parseParams(&read_params));
    try testing.expectEqual(Request{ .del = 100 }, try parseParams(&del_params));
}

test "parser rejects malformed commands and ids" {
    try testing.expectError(error.MissingParameter, parse(""));
    try testing.expectError(error.UnknownCommand, parse("SEND bob hi"));
    try testing.expectError(error.MissingParameter, parse("READ"));
    try testing.expectError(error.TooManyParameters, parse("LIST now"));
    try testing.expectError(error.TooManyParameters, parse("DEL 1 extra"));
    try testing.expectError(error.InvalidId, parse("READ 0"));
    try testing.expectError(error.InvalidId, parse("READ +1"));
    try testing.expectError(error.InvalidId, parse("READ nope"));

    const empty_params = [_][]const u8{};
    const too_many = [_][]const u8{ "READ", "1", "2" };
    try testing.expectError(error.MissingParameter, parseParams(&empty_params));
    try testing.expectError(error.TooManyParameters, parseParams(&too_many));
}
