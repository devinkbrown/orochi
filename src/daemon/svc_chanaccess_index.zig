//! Reverse channel-access index for the Mizuchi IRC daemon.
//!
//! The primary channel-access tables in Mizuchi are keyed by channel: each
//! registered channel owns a list of (account, level) grants. That layout
//! answers "who has access to this channel" cheaply but makes the inverse
//! question — "which channels does this account hold access in" — an O(all
//! channels) scan. A LISTCHANS-style query (an account asking the server to
//! enumerate every channel it can administer) needs the inverse direction.
//!
//! This module maintains that reverse index as a pure data structure: a map
//! from account name to the set of channels where the account holds an access
//! grant, each paired with the highest level recorded for that pair. It owns
//! every string it stores (account names and channel names are duplicated on
//! insert and freed on removal or teardown) and never references daemon state,
//! so it depends on `std` alone and is fully unit-testable in isolation.
//!
//! Operations:
//!   * `add(account, channel, level)`     — record/overwrite a grant.
//!   * `remove(account, channel)`         — drop a single grant.
//!   * `removeChannel(channel)`           — drop every grant on a channel
//!                                          (used when a channel is dropped).
//!   * `listFor(account)`                 — owned, sorted snapshot of grants.
//!   * `countFor(account)`                — number of grants for an account.

const std = @import("std");

/// Maximum permitted account-name length, in bytes.
pub const MAX_ACCOUNT_LEN: usize = 64;

/// Maximum permitted channel-name length, in bytes.
pub const MAX_CHANNEL_LEN: usize = 128;

/// Maximum number of distinct channels a single account may hold access in.
/// Bounds memory per account and matches the daemon's per-account grant cap.
pub const MAX_CHANNELS_PER_ACCOUNT: usize = 512;

/// Errors surfaced by index mutations.
pub const IndexError = error{
    /// The account name was empty or exceeded `MAX_ACCOUNT_LEN`.
    InvalidAccount,
    /// The channel name was empty or exceeded `MAX_CHANNEL_LEN`.
    InvalidChannel,
    /// The account already holds the maximum number of channel grants and the
    /// requested grant is for a new channel.
    TooManyChannels,
} || std.mem.Allocator.Error;

/// Access tiers, ranked low-to-high. Declaration order is the rank order, so
/// `@intFromEnum` doubles as the precedence value used to break list ties and
/// to decide which level wins when a pair is recorded more than once.
pub const Level = enum(u8) {
    voice = 0,
    op = 1,
    owner = 2,
    founder = 3,

    /// Numeric precedence; higher wins. Equivalent to `@intFromEnum`.
    pub fn rank(self: Level) u8 {
        return @intFromEnum(self);
    }
};

/// One entry in a `listFor` snapshot: a channel the account can access and the
/// highest level it holds there. The `channel` slice is owned by the snapshot
/// (see `Listing`), not by the index.
pub const Grant = struct {
    channel: []const u8,
    level: Level,

    /// Total order for sorting: channel name ascending (byte order), then, for
    /// the degenerate case of equal names, higher level first.
    fn lessThan(_: void, a: Grant, b: Grant) bool {
        const order = std.mem.order(u8, a.channel, b.channel);
        if (order != .eq) return order == .lt;
        return a.level.rank() > b.level.rank();
    }
};

/// An owned, sorted snapshot of an account's grants. Callers must call
/// `deinit` to release the duplicated channel strings and the backing array.
pub const Listing = struct {
    allocator: std.mem.Allocator,
    items: []Grant,

    /// Free every duplicated channel string and the backing slice.
    pub fn deinit(self: *Listing) void {
        for (self.items) |grant| self.allocator.free(grant.channel);
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

/// Internal record: an owned channel string plus the level held there.
const Record = struct {
    channel: []const u8,
    level: Level,
};

/// A per-account list of owned channel records.
const ChannelList = std.ArrayListUnmanaged(Record);

/// Reverse index mapping account name -> channels where it holds access.
pub const ChanAccessIndex = struct {
    allocator: std.mem.Allocator,
    /// Maps an owned account name to its owned list of channel records.
    by_account: std.StringHashMapUnmanaged(ChannelList),

    /// Create an empty index backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ChanAccessIndex {
        return .{
            .allocator = allocator,
            .by_account = .empty,
        };
    }

    /// Free every owned account name, every owned channel string, and the
    /// backing tables. The index must not be used after this call.
    pub fn deinit(self: *ChanAccessIndex) void {
        var it = self.by_account.iterator();
        while (it.next()) |entry| {
            self.freeList(entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.by_account.deinit(self.allocator);
        self.* = undefined;
    }

    /// Free every owned channel string in a list, then the list storage.
    fn freeList(self: *ChanAccessIndex, list: *ChannelList) void {
        for (list.items) |rec| self.allocator.free(rec.channel);
        list.deinit(self.allocator);
    }

    /// Record that `account` holds `level` access in `channel`.
    ///
    /// If a record for the same (account, channel) pair already exists, its
    /// level is raised to `level` whenever `level` outranks the stored value
    /// and left unchanged otherwise — the index always reflects the highest
    /// level seen for a pair. Adding a grant for a new channel is rejected with
    /// `error.TooManyChannels` once the account is at `MAX_CHANNELS_PER_ACCOUNT`.
    /// On any error the index is left exactly as it was.
    pub fn add(
        self: *ChanAccessIndex,
        account: []const u8,
        channel: []const u8,
        level: Level,
    ) IndexError!void {
        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;
        if (channel.len == 0 or channel.len > MAX_CHANNEL_LEN) return error.InvalidChannel;

        const gop = try self.by_account.getOrPut(self.allocator, account);
        if (!gop.found_existing) {
            // New account: own the key and start an empty list. Roll back the
            // map slot if duplicating the key fails so no dangling entry leaks.
            const key_copy = self.allocator.dupe(u8, account) catch |err| {
                std.debug.assert(self.by_account.remove(account));
                return err;
            };
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .empty;
        }
        const list = gop.value_ptr;

        // Existing pair: keep the strongest level, allocate nothing.
        for (list.items) |*rec| {
            if (std.mem.eql(u8, rec.channel, channel)) {
                if (level.rank() > rec.level.rank()) rec.level = level;
                return;
            }
        }

        // New channel for this account: enforce the per-account bound before
        // allocating. An account that has just been created with an empty list
        // is preserved on rejection; it carries no records and is harmless.
        if (list.items.len >= MAX_CHANNELS_PER_ACCOUNT) return error.TooManyChannels;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        try list.append(self.allocator, .{ .channel = channel_copy, .level = level });
    }

    /// Remove the grant for (`account`, `channel`). Returns true if a record
    /// was removed. When the account's last grant is removed, its now-empty
    /// list and owned key are dropped from the map so the account leaves no
    /// residue. Order of remaining records is not specified (`listFor` sorts).
    pub fn remove(self: *ChanAccessIndex, account: []const u8, channel: []const u8) bool {
        const entry = self.by_account.getEntry(account) orelse return false;
        const list = entry.value_ptr;

        const idx = self.indexOf(list, channel) orelse return false;
        self.allocator.free(list.items[idx].channel);
        _ = list.swapRemove(idx);

        if (list.items.len == 0) {
            const owned_key = entry.key_ptr.*;
            list.deinit(self.allocator);
            std.debug.assert(self.by_account.remove(account));
            self.allocator.free(owned_key);
        }
        return true;
    }

    /// Remove every grant on `channel` across all accounts (used when the
    /// channel is dropped). Returns the number of records removed. Accounts
    /// left with no remaining grants are pruned from the map.
    pub fn removeChannel(self: *ChanAccessIndex, channel: []const u8) usize {
        var removed: usize = 0;

        // Gather accounts that end up empty; mutating the map while iterating
        // it is unsafe, so prune in a second pass.
        var emptied: std.ArrayListUnmanaged([]const u8) = .empty;
        defer emptied.deinit(self.allocator);

        var it = self.by_account.iterator();
        while (it.next()) |entry| {
            const list = entry.value_ptr;
            if (self.indexOf(list, channel)) |idx| {
                self.allocator.free(list.items[idx].channel);
                _ = list.swapRemove(idx);
                removed += 1;
                if (list.items.len == 0) {
                    // Best-effort: if recording the empty account fails we leave
                    // it in place (harmless empty list), never leaking.
                    emptied.append(self.allocator, entry.key_ptr.*) catch {};
                }
            }
        }

        for (emptied.items) |account| {
            if (self.by_account.fetchRemove(account)) |kv| {
                var list = kv.value;
                list.deinit(self.allocator);
                self.allocator.free(kv.key);
            }
        }
        return removed;
    }

    /// Number of channels `account` holds access in. Zero for unknown accounts.
    pub fn countFor(self: *const ChanAccessIndex, account: []const u8) usize {
        const list = self.by_account.getPtr(account) orelse return 0;
        return list.items.len;
    }

    /// Produce an owned, sorted snapshot of every grant held by `account`.
    /// Channel names are duplicated into the snapshot, which the caller frees
    /// via `Listing.deinit`; the returned data is independent of subsequent
    /// index mutations. An unknown account yields an empty (but valid) listing.
    pub fn listFor(self: *const ChanAccessIndex, account: []const u8) IndexError!Listing {
        const list = self.by_account.getPtr(account);
        const count: usize = if (list) |l| l.items.len else 0;

        const out = try self.allocator.alloc(Grant, count);
        // Free already-duplicated channels if a later dupe fails mid-loop.
        var filled: usize = 0;
        errdefer {
            for (out[0..filled]) |g| self.allocator.free(g.channel);
            self.allocator.free(out);
        }

        if (list) |l| {
            for (l.items) |rec| {
                const channel_copy = try self.allocator.dupe(u8, rec.channel);
                out[filled] = .{ .channel = channel_copy, .level = rec.level };
                filled += 1;
            }
        }

        std.mem.sort(Grant, out, {}, Grant.lessThan);
        return .{ .allocator = self.allocator, .items = out };
    }

    /// Find a channel record within a list by exact name. Linear scan; the
    /// per-account list is bounded by `MAX_CHANNELS_PER_ACCOUNT`.
    fn indexOf(self: *const ChanAccessIndex, list: *const ChannelList, channel: []const u8) ?usize {
        _ = self;
        for (list.items, 0..) |rec, i| {
            if (std.mem.eql(u8, rec.channel, channel)) return i;
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "add then listFor returns the single grant" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    try idx.add("alice", "#dev", .founder);

    var listing = try idx.listFor("alice");
    defer listing.deinit();

    try std.testing.expectEqual(@as(usize, 1), listing.items.len);
    try std.testing.expectEqualStrings("#dev", listing.items[0].channel);
    try std.testing.expectEqual(Level.founder, listing.items[0].level);
}

test "multi-channel aggregation for one account, sorted by channel name" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    // Insert out of order to prove listFor sorts.
    try idx.add("bob", "#zeta", .voice);
    try idx.add("bob", "#alpha", .owner);
    try idx.add("bob", "#mid", .op);

    try std.testing.expectEqual(@as(usize, 3), idx.countFor("bob"));

    var listing = try idx.listFor("bob");
    defer listing.deinit();

    try std.testing.expectEqual(@as(usize, 3), listing.items.len);
    try std.testing.expectEqualStrings("#alpha", listing.items[0].channel);
    try std.testing.expectEqualStrings("#mid", listing.items[1].channel);
    try std.testing.expectEqualStrings("#zeta", listing.items[2].channel);
    try std.testing.expectEqual(Level.owner, listing.items[0].level);
    try std.testing.expectEqual(Level.op, listing.items[1].level);
    try std.testing.expectEqual(Level.voice, listing.items[2].level);
}

test "accounts are isolated from one another" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    try idx.add("alice", "#a1", .op);
    try idx.add("alice", "#a2", .voice);
    try idx.add("bob", "#b1", .founder);

    try std.testing.expectEqual(@as(usize, 2), idx.countFor("alice"));
    try std.testing.expectEqual(@as(usize, 1), idx.countFor("bob"));
    try std.testing.expectEqual(@as(usize, 0), idx.countFor("carol"));
}

test "re-adding the same pair keeps the highest level (raise then ignore lower)" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    try idx.add("alice", "#dev", .voice);
    try idx.add("alice", "#dev", .founder); // raise
    try idx.add("alice", "#dev", .op); // lower: ignored

    // No duplicate channel created.
    try std.testing.expectEqual(@as(usize, 1), idx.countFor("alice"));

    var listing = try idx.listFor("alice");
    defer listing.deinit();
    try std.testing.expectEqual(@as(usize, 1), listing.items.len);
    try std.testing.expectEqual(Level.founder, listing.items[0].level);
}

test "remove drops a single grant and reports outcome" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    try idx.add("alice", "#one", .op);
    try idx.add("alice", "#two", .voice);

    try std.testing.expect(idx.remove("alice", "#one"));
    try std.testing.expectEqual(@as(usize, 1), idx.countFor("alice"));

    // Removing a non-existent channel returns false and changes nothing.
    try std.testing.expect(!idx.remove("alice", "#nope"));
    try std.testing.expect(!idx.remove("ghost", "#two"));
    try std.testing.expectEqual(@as(usize, 1), idx.countFor("alice"));

    var listing = try idx.listFor("alice");
    defer listing.deinit();
    try std.testing.expectEqual(@as(usize, 1), listing.items.len);
    try std.testing.expectEqualStrings("#two", listing.items[0].channel);
}

test "removing the last grant prunes the account entirely" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    try idx.add("solo", "#only", .founder);
    try std.testing.expect(idx.remove("solo", "#only"));

    try std.testing.expectEqual(@as(usize, 0), idx.countFor("solo"));

    // Re-adding after a full prune works and starts fresh.
    try idx.add("solo", "#again", .op);
    try std.testing.expectEqual(@as(usize, 1), idx.countFor("solo"));
}

test "removeChannel drops the channel across every account and prunes emptied accounts" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    try idx.add("alice", "#shared", .owner);
    try idx.add("alice", "#keep", .voice);
    try idx.add("bob", "#shared", .op);
    try idx.add("carol", "#shared", .founder); // carol only has #shared

    const removed = idx.removeChannel("#shared");
    try std.testing.expectEqual(@as(usize, 3), removed);

    // Alice keeps her other channel.
    try std.testing.expectEqual(@as(usize, 1), idx.countFor("alice"));
    var alice = try idx.listFor("alice");
    defer alice.deinit();
    try std.testing.expectEqualStrings("#keep", alice.items[0].channel);

    // Bob and carol had only #shared -> pruned.
    try std.testing.expectEqual(@as(usize, 0), idx.countFor("bob"));
    try std.testing.expectEqual(@as(usize, 0), idx.countFor("carol"));

    // Removing a channel nobody has is a no-op.
    try std.testing.expectEqual(@as(usize, 0), idx.removeChannel("#missing"));
}

test "listFor on unknown account yields an empty valid listing" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    var listing = try idx.listFor("nobody");
    defer listing.deinit();
    try std.testing.expectEqual(@as(usize, 0), listing.items.len);
}

test "input validation rejects empty and oversize names without mutating" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    const long_account = "a" ** (MAX_ACCOUNT_LEN + 1);
    const long_channel = "#" ++ ("c" ** MAX_CHANNEL_LEN); // length MAX+1

    try std.testing.expectError(error.InvalidAccount, idx.add("", "#x", .op));
    try std.testing.expectError(error.InvalidAccount, idx.add(long_account, "#x", .op));
    try std.testing.expectError(error.InvalidChannel, idx.add("alice", "", .op));
    try std.testing.expectError(error.InvalidChannel, idx.add("alice", long_channel, .op));

    // Boundary lengths are accepted.
    const max_account = "a" ** MAX_ACCOUNT_LEN;
    const max_channel = "#" ++ ("c" ** (MAX_CHANNEL_LEN - 1)); // length == MAX
    try idx.add(max_account, max_channel, .voice);
    try std.testing.expectEqual(@as(usize, 1), idx.countFor(max_account));

    // No phantom account was created by the rejected inserts.
    try std.testing.expectEqual(@as(usize, 0), idx.countFor("alice"));
}

test "per-account channel bound is enforced and leaves state intact" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < MAX_CHANNELS_PER_ACCOUNT) : (i += 1) {
        const name = try std.fmt.bufPrint(&buf, "#c{d}", .{i});
        try idx.add("packrat", name, .voice);
    }
    try std.testing.expectEqual(MAX_CHANNELS_PER_ACCOUNT, idx.countFor("packrat"));

    // One more distinct channel is rejected.
    try std.testing.expectError(error.TooManyChannels, idx.add("packrat", "#overflow", .op));
    try std.testing.expectEqual(MAX_CHANNELS_PER_ACCOUNT, idx.countFor("packrat"));

    // Re-adding an existing channel at the cap still succeeds (no growth).
    try idx.add("packrat", "#c0", .founder);
    try std.testing.expectEqual(MAX_CHANNELS_PER_ACCOUNT, idx.countFor("packrat"));
}

test "listFor snapshot is independent of later mutations" {
    const a = std.testing.allocator;
    var idx = ChanAccessIndex.init(a);
    defer idx.deinit();

    try idx.add("alice", "#x", .op);

    var listing = try idx.listFor("alice");
    defer listing.deinit();

    // Mutating the index after snapshotting must not affect the snapshot.
    try std.testing.expect(idx.remove("alice", "#x"));
    try idx.add("alice", "#y", .founder);

    try std.testing.expectEqual(@as(usize, 1), listing.items.len);
    try std.testing.expectEqualStrings("#x", listing.items[0].channel);
    try std.testing.expectEqual(Level.op, listing.items[0].level);
}

test "ties on equal channel names order by higher level first" {
    // Exercises the secondary sort key directly via the comparator.
    const high: Grant = .{ .channel = "#same", .level = .founder };
    const low: Grant = .{ .channel = "#same", .level = .voice };
    try std.testing.expect(Grant.lessThan({}, high, low));
    try std.testing.expect(!Grant.lessThan({}, low, high));
}
