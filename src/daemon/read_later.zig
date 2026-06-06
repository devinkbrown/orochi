//! ReadLater: per-account queue of message ids a user wants to revisit.
//!
//! Each account owns an ordered, capacity-bounded list of message-id strings
//! ("kept" messages). Strings are duplicated on insertion and freed on removal
//! or teardown, so the caller retains ownership of nothing it passes in.
//!
//! This is a clean-room implementation: it depends solely on the Zig standard
//! library and targets 64-bit hosts.

const std = @import("std");

/// Maximum number of pending message ids retained per account.
pub const max_per_account: usize = 200;

/// A per-account queue of message ids to revisit later.
pub const ReadLater = struct {
    allocator: std.mem.Allocator,
    /// Maps an owned account-name string to an owned queue of owned msgid strings.
    queues: std.StringHashMapUnmanaged(Queue) = .{},

    const Queue = std.ArrayListUnmanaged([]const u8);

    /// Initialize an empty store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ReadLater {
        return .{ .allocator = allocator };
    }

    /// Release every owned account key, every queued msgid, and the maps.
    pub fn deinit(self: *ReadLater) void {
        var it = self.queues.iterator();
        while (it.next()) |entry| {
            self.freeQueue(entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.queues.deinit(self.allocator);
        self.* = undefined;
    }

    fn freeQueue(self: *ReadLater, queue: *Queue) void {
        for (queue.items) |msgid| self.allocator.free(msgid);
        queue.deinit(self.allocator);
    }

    /// Queue `msgid` for `account`.
    ///
    /// Returns true when the id was newly added. Returns false (without
    /// mutating anything) when the id is already queued for the account or
    /// when the account is already at `max_per_account`. Errors only on
    /// allocation failure, in which case no partial state is retained.
    pub fn add(self: *ReadLater, account: []const u8, msgid: []const u8) !bool {
        const gop = try self.queues.getOrPut(self.allocator, account);
        if (!gop.found_existing) {
            // We just inserted a borrowed key; replace it with an owned copy.
            const owned_key = self.allocator.dupe(u8, account) catch |err| {
                _ = self.queues.remove(account);
                return err;
            };
            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = Queue.empty;
        }

        const queue = gop.value_ptr;

        for (queue.items) |existing| {
            if (std.mem.eql(u8, existing, msgid)) return false;
        }
        if (queue.items.len >= max_per_account) return false;

        const owned_msgid = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_msgid);
        try queue.append(self.allocator, owned_msgid);
        return true;
    }

    /// Remove `msgid` from `account`'s queue.
    ///
    /// Returns true if an entry was removed, false if the account or id was
    /// not present. Preserves the relative order of the remaining entries.
    pub fn done(self: *ReadLater, account: []const u8, msgid: []const u8) bool {
        const queue = self.queues.getPtr(account) orelse return false;
        for (queue.items, 0..) |existing, idx| {
            if (std.mem.eql(u8, existing, msgid)) {
                const removed = queue.orderedRemove(idx);
                self.allocator.free(removed);
                return true;
            }
        }
        return false;
    }

    /// Return the queued msgids for `account` in insertion order.
    ///
    /// The returned slice and its strings are owned by the store and remain
    /// valid only until the next mutation of this account's queue.
    pub fn list(self: *const ReadLater, account: []const u8) []const []const u8 {
        const queue = self.queues.getPtr(account) orelse return &.{};
        return queue.items;
    }

    /// Return the number of queued msgids for `account`.
    pub fn count(self: *const ReadLater, account: []const u8) usize {
        const queue = self.queues.getPtr(account) orelse return 0;
        return queue.items.len;
    }
};

test "add queues ids, rejects duplicates, and tracks count" {
    var store = ReadLater.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(try store.add("kappa", "msg-1"));
    try std.testing.expect(try store.add("kappa", "msg-2"));
    // Duplicate within the same account is rejected.
    try std.testing.expect(!(try store.add("kappa", "msg-1")));
    try std.testing.expectEqual(@as(usize, 2), store.count("kappa"));

    // Distinct accounts keep independent queues.
    try std.testing.expect(try store.add("nure", "msg-1"));
    try std.testing.expectEqual(@as(usize, 1), store.count("nure"));
    try std.testing.expectEqual(@as(usize, 0), store.count("absent"));
}

test "list preserves insertion order and done removes entries" {
    var store = ReadLater.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(try store.add("kappa", "a"));
    try std.testing.expect(try store.add("kappa", "b"));
    try std.testing.expect(try store.add("kappa", "c"));

    {
        const items = store.list("kappa");
        try std.testing.expectEqual(@as(usize, 3), items.len);
        try std.testing.expectEqualStrings("a", items[0]);
        try std.testing.expectEqualStrings("b", items[1]);
        try std.testing.expectEqualStrings("c", items[2]);
    }

    // Removing a middle entry preserves order of the rest.
    try std.testing.expect(store.done("kappa", "b"));
    try std.testing.expect(!store.done("kappa", "b")); // already gone
    try std.testing.expect(!store.done("missing", "a")); // unknown account

    {
        const items = store.list("kappa");
        try std.testing.expectEqual(@as(usize, 2), items.len);
        try std.testing.expectEqualStrings("a", items[0]);
        try std.testing.expectEqualStrings("c", items[1]);
    }

    // Empty / unknown account yields an empty slice, never null.
    try std.testing.expectEqual(@as(usize, 0), store.list("nobody").len);
}

test "add enforces the per-account capacity cap" {
    var store = ReadLater.init(std.testing.allocator);
    defer store.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < max_per_account) : (i += 1) {
        const id = try std.fmt.bufPrint(&buf, "m{d}", .{i});
        try std.testing.expect(try store.add("whale", id));
    }
    try std.testing.expectEqual(max_per_account, store.count("whale"));

    // One past the cap is refused without error.
    try std.testing.expect(!(try store.add("whale", "overflow")));
    try std.testing.expectEqual(max_per_account, store.count("whale"));

    // Freeing a slot allows a fresh insert again.
    try std.testing.expect(store.done("whale", "m0"));
    try std.testing.expect(try store.add("whale", "overflow"));
    try std.testing.expectEqual(max_per_account, store.count("whale"));
}

test "ids are owned: source buffers can be mutated after add" {
    var store = ReadLater.init(std.testing.allocator);
    defer store.deinit();

    var account_buf = [_]u8{ 'a', 'c', 'c' };
    var msg_buf = [_]u8{ 'i', 'd', '1' };
    try std.testing.expect(try store.add(&account_buf, &msg_buf));

    // Scribble over the caller's buffers; the store must hold its own copies.
    @memset(&account_buf, 'X');
    @memset(&msg_buf, 'Y');

    try std.testing.expectEqual(@as(usize, 1), store.count("acc"));
    const items = store.list("acc");
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expectEqualStrings("id1", items[0]);
}
