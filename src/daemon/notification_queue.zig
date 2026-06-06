//! Bounded per-account notification inboxes.
const std = @import("std");

pub const max_accounts: usize = 8192;
pub const max_notes_per_account: usize = 100;
pub const max_account_bytes: usize = 64;
pub const max_kind_bytes: usize = 40;
pub const max_body_bytes: usize = 300;

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    InvalidKind,
    InvalidBody,
    TooManyAccounts,
};

pub const Note = struct {
    kind: []u8,
    body: []u8,
    at_ms: i64,

    pub fn deinit(self: *Note, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        allocator.free(self.body);
        self.* = undefined;
    }
};

const Inbox = struct {
    notes: std.ArrayListUnmanaged(Note) = .empty,

    fn deinit(self: *Inbox, allocator: std.mem.Allocator) void {
        for (self.notes.items) |*note| note.deinit(allocator);
        self.notes.deinit(allocator);
    }
};

pub const NotificationQueue = struct {
    allocator: std.mem.Allocator,
    inboxes: std.StringHashMap(Inbox),

    pub fn init(allocator: std.mem.Allocator) NotificationQueue {
        return .{ .allocator = allocator, .inboxes = std.StringHashMap(Inbox).init(allocator) };
    }

    pub fn deinit(self: *NotificationQueue) void {
        var it = self.inboxes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.inboxes.deinit();
        self.* = undefined;
    }

    /// Pushes one note and returns the resulting account inbox depth. The inbox
    /// keeps the newest `max_notes_per_account` entries, evicting oldest first.
    pub fn push(self: *NotificationQueue, account: []const u8, kind: []const u8, body: []const u8, now_ms: i64) Error!usize {
        try validateAccount(account);
        if (kind.len == 0 or kind.len > max_kind_bytes) return error.InvalidKind;
        if (body.len > max_body_bytes) return error.InvalidBody;

        const inbox = try self.ensureInbox(account);
        const owned_kind = try self.allocator.dupe(u8, kind);
        errdefer self.allocator.free(owned_kind);
        const owned_body = try self.allocator.dupe(u8, body);
        errdefer self.allocator.free(owned_body);

        try inbox.notes.append(self.allocator, .{ .kind = owned_kind, .body = owned_body, .at_ms = now_ms });
        if (inbox.notes.items.len > max_notes_per_account) {
            var evicted = inbox.notes.orderedRemove(0);
            evicted.deinit(self.allocator);
        }
        return inbox.notes.items.len;
    }

    /// Drains `account` into newly owned notes allocated with `allocator`.
    /// Caller owns the returned slice and each note's fields; free every note
    /// with `Note.deinit(allocator)`, then free the slice with `allocator`.
    pub fn drainOwned(self: *NotificationQueue, account: []const u8, allocator: std.mem.Allocator) Error![]Note {
        const entry = self.inboxes.getEntry(account) orelse return &.{};
        const source = entry.value_ptr.notes.items;
        var out = try allocator.alloc(Note, source.len);
        errdefer allocator.free(out);

        var copied: usize = 0;
        errdefer {
            for (out[0..copied]) |*note| note.deinit(allocator);
        }

        for (source, 0..) |note, i| {
            const kind = try allocator.dupe(u8, note.kind);
            errdefer allocator.free(kind);
            const body = try allocator.dupe(u8, note.body);
            out[i] = .{ .kind = kind, .body = body, .at_ms = note.at_ms };
            copied += 1;
        }

        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.inboxes.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return out;
    }

    pub fn count(self: *const NotificationQueue, account: []const u8) usize {
        const inbox = self.inboxes.getPtr(account) orelse return 0;
        return inbox.notes.items.len;
    }

    fn ensureInbox(self: *NotificationQueue, account: []const u8) Error!*Inbox {
        if (self.inboxes.getPtr(account)) |inbox| return inbox;
        if (self.inboxes.count() >= max_accounts) return error.TooManyAccounts;
        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.inboxes.putNoClobber(owned, .{});
        return self.inboxes.getPtr(account).?;
    }

    fn validateAccount(account: []const u8) Error!void {
        if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
    }
};

const testing = std.testing;

test "push stores notes per account and count is isolated" {
    var queue = NotificationQueue.init(testing.allocator);
    defer queue.deinit();

    try testing.expectEqual(@as(usize, 1), try queue.push("alice", "mention", "hello", 10));
    try testing.expectEqual(@as(usize, 2), try queue.push("alice", "invite", "join", 11));
    try testing.expectEqual(@as(usize, 1), try queue.push("bob", "alert", "ping", 12));
    try testing.expectEqual(@as(usize, 2), queue.count("alice"));
    try testing.expectEqual(@as(usize, 1), queue.count("bob"));
}

test "drainOwned returns FIFO notes and clears account" {
    var queue = NotificationQueue.init(testing.allocator);
    defer queue.deinit();

    _ = try queue.push("alice", "one", "first", 1);
    _ = try queue.push("alice", "two", "second", 2);
    const drained = try queue.drainOwned("alice", testing.allocator);
    defer testing.allocator.free(drained);
    defer for (drained) |*note| note.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), drained.len);
    try testing.expectEqualStrings("one", drained[0].kind);
    try testing.expectEqualStrings("second", drained[1].body);
    try testing.expectEqual(@as(i64, 2), drained[1].at_ms);
    try testing.expectEqual(@as(usize, 0), queue.count("alice"));
}

test "per-account cap evicts oldest note" {
    var queue = NotificationQueue.init(testing.allocator);
    defer queue.deinit();

    var i: usize = 0;
    while (i < max_notes_per_account + 3) : (i += 1) {
        _ = try queue.push("alice", "k", "b", @intCast(i));
    }
    try testing.expectEqual(max_notes_per_account, queue.count("alice"));

    const drained = try queue.drainOwned("alice", testing.allocator);
    defer testing.allocator.free(drained);
    defer for (drained) |*note| note.deinit(testing.allocator);
    try testing.expectEqual(@as(i64, 3), drained[0].at_ms);
}

test "input caps reject invalid notes" {
    var queue = NotificationQueue.init(testing.allocator);
    defer queue.deinit();

    try testing.expectError(error.InvalidAccount, queue.push("", "kind", "body", 0));
    try testing.expectError(error.InvalidKind, queue.push("alice", "", "body", 0));
    try testing.expectError(error.InvalidBody, queue.push("alice", "kind", "x" ** (max_body_bytes + 1), 0));
}
