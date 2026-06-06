//! Per-account personal bookmark list of message ids with a short note.
//!
//! Each account owns a list of bookmark entries. An entry pairs a message id
//! with a brief human-authored note. Lists are capped to keep memory bounded
//! and notes are length-limited so a single bookmark cannot grow unbounded.
//!
//! This module owns all of its memory: keys, message ids, and notes are
//! duplicated on insertion and freed on removal or in `deinit`.

const std = @import("std");

/// Maximum number of bookmark entries retained per account.
pub const max_entries_per_account: usize = 200;

/// Maximum length, in bytes, of a bookmark note.
pub const max_note_len: usize = 120;

/// Errors that bookmark operations may surface to callers.
pub const SaveError = error{
    /// The supplied message id was empty.
    EmptyMessageId,
    /// The account has reached `max_entries_per_account`.
    ListFull,
    /// Memory allocation failed while storing the entry.
    OutOfMemory,
};

/// A single bookmark: a message id paired with a short note.
///
/// Both fields are owned by the `SavedMessages` instance that produced them
/// and remain valid until the entry is removed or the store is deinitialized.
pub const Entry = struct {
    msgid: []u8,
    note: []u8,
};

const EntryList = std.ArrayListUnmanaged(Entry);

/// A collection of per-account bookmark lists.
pub const SavedMessages = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMapUnmanaged(EntryList),

    /// Create an empty store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) SavedMessages {
        return .{
            .allocator = allocator,
            .accounts = .empty,
        };
    }

    /// Release every account list, entry, and account key.
    pub fn deinit(self: *SavedMessages) void {
        var it = self.accounts.iterator();
        while (it.next()) |kv| {
            freeList(self.allocator, kv.value_ptr);
            self.allocator.free(kv.key_ptr.*);
        }
        self.accounts.deinit(self.allocator);
        self.* = undefined;
    }

    /// Save (or update) a bookmark for `account`.
    ///
    /// If the message id is already bookmarked, its note is replaced in place.
    /// The note is truncated to `max_note_len` bytes. Returns the resulting
    /// number of bookmarks held by the account.
    ///
    /// Rejects an empty `msgid`. Rejects new entries once the account list is
    /// full, though updating an existing entry is always permitted.
    pub fn save(
        self: *SavedMessages,
        account: []const u8,
        msgid: []const u8,
        note: []const u8,
    ) SaveError!usize {
        if (msgid.len == 0) return SaveError.EmptyMessageId;

        const clamped_note = note[0..@min(note.len, max_note_len)];

        const gop = try self.accounts.getOrPut(self.allocator, account);
        if (!gop.found_existing) {
            // Duplicate the key so the store does not alias the caller's slice.
            const key_copy = self.allocator.dupe(u8, account) catch |err| {
                self.accounts.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .empty;
        }

        const entries = gop.value_ptr;

        // Update path: replace the note on an existing message id.
        for (entries.items) |*entry| {
            if (std.mem.eql(u8, entry.msgid, msgid)) {
                const new_note = try self.allocator.dupe(u8, clamped_note);
                self.allocator.free(entry.note);
                entry.note = new_note;
                return entries.items.len;
            }
        }

        if (entries.items.len >= max_entries_per_account) return SaveError.ListFull;

        const msgid_copy = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(msgid_copy);
        const note_copy = try self.allocator.dupe(u8, clamped_note);
        errdefer self.allocator.free(note_copy);

        try entries.append(self.allocator, .{ .msgid = msgid_copy, .note = note_copy });
        return entries.items.len;
    }

    /// Remove the bookmark for `msgid` from `account`.
    ///
    /// Returns `true` if an entry was removed, `false` if no matching entry
    /// (or account) existed.
    pub fn remove(self: *SavedMessages, account: []const u8, msgid: []const u8) bool {
        const entries = self.accounts.getPtr(account) orelse return false;
        for (entries.items, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.msgid, msgid)) {
                self.allocator.free(entry.msgid);
                self.allocator.free(entry.note);
                _ = entries.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    /// Return the bookmarks held by `account`.
    ///
    /// The slice is valid until the next mutating call for that account or
    /// until `deinit`. Unknown accounts yield an empty slice.
    pub fn list(self: *SavedMessages, account: []const u8) []const Entry {
        const entries = self.accounts.getPtr(account) orelse return &.{};
        return entries.items;
    }

    fn freeList(allocator: std.mem.Allocator, entries: *EntryList) void {
        for (entries.items) |entry| {
            allocator.free(entry.msgid);
            allocator.free(entry.note);
        }
        entries.deinit(allocator);
    }
};

test "save stores entries and returns running count" {
    const allocator = std.testing.allocator;
    var store = SavedMessages.init(allocator);
    defer store.deinit();

    try std.testing.expectEqual(@as(usize, 1), try store.save("nyx", "msg-1", "first"));
    try std.testing.expectEqual(@as(usize, 2), try store.save("nyx", "msg-2", "second"));

    const items = store.list("nyx");
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("msg-1", items[0].msgid);
    try std.testing.expectEqualStrings("second", items[1].note);
}

test "save rejects empty message id and isolates accounts" {
    const allocator = std.testing.allocator;
    var store = SavedMessages.init(allocator);
    defer store.deinit();

    try std.testing.expectError(SaveError.EmptyMessageId, store.save("nyx", "", "note"));
    try std.testing.expectEqual(@as(usize, 0), store.list("nyx").len);

    _ = try store.save("nyx", "a", "x");
    _ = try store.save("kraken", "b", "y");
    try std.testing.expectEqual(@as(usize, 1), store.list("nyx").len);
    try std.testing.expectEqual(@as(usize, 1), store.list("kraken").len);
    try std.testing.expectEqual(@as(usize, 0), store.list("unknown").len);
}

test "save updates note in place without growing the list" {
    const allocator = std.testing.allocator;
    var store = SavedMessages.init(allocator);
    defer store.deinit();

    _ = try store.save("nyx", "dup", "before");
    const count = try store.save("nyx", "dup", "after");
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings("after", store.list("nyx")[0].note);
}

test "remove deletes matching entry and reports outcome" {
    const allocator = std.testing.allocator;
    var store = SavedMessages.init(allocator);
    defer store.deinit();

    _ = try store.save("nyx", "keep", "k");
    _ = try store.save("nyx", "drop", "d");

    try std.testing.expect(store.remove("nyx", "drop"));
    try std.testing.expect(!store.remove("nyx", "drop"));
    try std.testing.expect(!store.remove("ghost", "drop"));

    const items = store.list("nyx");
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expectEqualStrings("keep", items[0].msgid);
}

test "notes are truncated to the maximum length" {
    const allocator = std.testing.allocator;
    var store = SavedMessages.init(allocator);
    defer store.deinit();

    const long_note = "z" ** (max_note_len + 50);
    _ = try store.save("nyx", "long", long_note);
    try std.testing.expectEqual(max_note_len, store.list("nyx")[0].note.len);
}

test "list cap is enforced for new entries" {
    const allocator = std.testing.allocator;
    var store = SavedMessages.init(allocator);
    defer store.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < max_entries_per_account) : (i += 1) {
        const id = try std.fmt.bufPrint(&buf, "m{d}", .{i});
        _ = try store.save("nyx", id, "n");
    }
    try std.testing.expectEqual(max_entries_per_account, store.list("nyx").len);
    try std.testing.expectError(SaveError.ListFull, store.save("nyx", "overflow", "n"));

    // Updating an existing entry must still succeed even when full.
    try std.testing.expectEqual(
        max_entries_per_account,
        try store.save("nyx", "m0", "updated"),
    );
}
