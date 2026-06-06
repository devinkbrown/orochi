//! Tegami (手紙) — Mizuchi-native offline messaging keyed by account.
//!
//! The bouncer rewind replays *channel* history a session missed; Tegami covers
//! the other gap: a direct message left for an account that has no attached
//! session. Messages are stored per recipient account and delivered when that
//! account next logs in (REGISTER / IDENTIFY / SASL). In-memory + bounded; a
//! WAL/snapshot backing can be layered later (mirroring the account store).
const std = @import("std");

pub const max_text_bytes: usize = 400;
pub const max_from_bytes: usize = 64;
pub const max_per_account: usize = 64;
pub const max_accounts: usize = 65536;

pub const Error = std.mem.Allocator.Error || error{ TooManyAccounts, MailboxFull, MessageInvalid };

pub const Message = struct {
    from: []u8,
    text: []u8,
    sent_ms: i64,

    fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.from);
        allocator.free(self.text);
    }
};

const Mailbox = struct {
    items: std.ArrayListUnmanaged(Message) = .empty,

    fn deinit(self: *Mailbox, allocator: std.mem.Allocator) void {
        for (self.items.items) |*m| m.deinit(allocator);
        self.items.deinit(allocator);
    }
};

pub const TegamiBox = struct {
    allocator: std.mem.Allocator,
    boxes: std.StringHashMap(Mailbox),

    pub fn init(allocator: std.mem.Allocator) TegamiBox {
        return .{ .allocator = allocator, .boxes = std.StringHashMap(Mailbox).init(allocator) };
    }

    pub fn deinit(self: *TegamiBox) void {
        var it = self.boxes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.boxes.deinit();
        self.* = undefined;
    }

    /// Store a message for `to_account` from `from`. Returns the new mailbox
    /// depth. Errors on empty/oversize fields, a full mailbox, or too many
    /// accounts. `from`/`text` are copied.
    pub fn send(self: *TegamiBox, to_account: []const u8, from: []const u8, text: []const u8, now_ms: i64) Error!usize {
        if (to_account.len == 0 or from.len == 0 or from.len > max_from_bytes) return error.MessageInvalid;
        if (text.len == 0 or text.len > max_text_bytes) return error.MessageInvalid;
        const box = try self.ensure(to_account);
        if (box.items.items.len >= max_per_account) return error.MailboxFull;

        const from_owned = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(from_owned);
        const text_owned = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_owned);
        try box.items.append(self.allocator, .{ .from = from_owned, .text = text_owned, .sent_ms = now_ms });
        return box.items.items.len;
    }

    /// Borrowed pending messages for `account` (empty if none). Valid until the
    /// next mutation of this account's mailbox.
    pub fn pending(self: *const TegamiBox, account: []const u8) []const Message {
        const box = self.boxes.getPtr(account) orelse return &.{};
        return box.items.items;
    }

    pub fn count(self: *const TegamiBox, account: []const u8) usize {
        return self.pending(account).len;
    }

    /// Drop all of `account`'s messages (e.g. after delivery). Returns how many
    /// were removed and prunes the (now-empty) mailbox.
    pub fn clear(self: *TegamiBox, account: []const u8) usize {
        const entry = self.boxes.getEntry(account) orelse return 0;
        const n = entry.value_ptr.items.items.len;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.boxes.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return n;
    }

    fn ensure(self: *TegamiBox, account: []const u8) Error!*Mailbox {
        if (self.boxes.getPtr(account)) |box| return box;
        if (self.boxes.count() >= max_accounts) return error.TooManyAccounts;
        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.boxes.putNoClobber(owned, .{});
        return self.boxes.getPtr(account).?;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "send then pending then clear" {
    var t = TegamiBox.init(testing.allocator);
    defer t.deinit();
    try testing.expectEqual(@as(usize, 0), t.count("alice"));
    try testing.expectEqual(@as(usize, 1), try t.send("alice", "bob", "hi alice", 100));
    try testing.expectEqual(@as(usize, 2), try t.send("alice", "carol", "ping", 200));
    const msgs = t.pending("alice");
    try testing.expectEqual(@as(usize, 2), msgs.len);
    try testing.expectEqualStrings("bob", msgs[0].from);
    try testing.expectEqualStrings("ping", msgs[1].text);
    try testing.expectEqual(@as(usize, 2), t.clear("alice"));
    try testing.expectEqual(@as(usize, 0), t.count("alice")); // pruned
}

test "rejects invalid fields and enforces mailbox cap" {
    var t = TegamiBox.init(testing.allocator);
    defer t.deinit();
    try testing.expectError(error.MessageInvalid, t.send("alice", "bob", "", 0));
    try testing.expectError(error.MessageInvalid, t.send("alice", "", "hi", 0));
    var i: usize = 0;
    while (i < max_per_account) : (i += 1) _ = try t.send("bob", "x", "m", 0);
    try testing.expectError(error.MailboxFull, t.send("bob", "x", "m", 0));
}

test "mailboxes are independent per account" {
    var t = TegamiBox.init(testing.allocator);
    defer t.deinit();
    _ = try t.send("alice", "bob", "for alice", 0);
    _ = try t.send("carol", "bob", "for carol", 0);
    try testing.expectEqual(@as(usize, 1), t.count("alice"));
    try testing.expectEqual(@as(usize, 1), t.count("carol"));
    _ = t.clear("alice");
    try testing.expectEqual(@as(usize, 0), t.count("alice"));
    try testing.expectEqual(@as(usize, 1), t.count("carol"));
}
