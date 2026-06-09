//! Registered-channel record store.
//!
//! Backs the REGISTER / DROP channel commands: it maps an owning account to a
//! channel via a `ChannelRecord` keyed by case-insensitive channel name. This
//! is pure record-keeping — services in Mizuchi are real server commands and
//! numerics, never pseudo-clients, so this module owns no transport, no live
//! world state, and no protocol formatting. It just stores the registration
//! facts and owns every string it returns.
//!
//! Case-insensitivity follows ASCII case folding for the lookup key; the
//! original founder-supplied channel name is preserved verbatim for display.
const std = @import("std");

/// Runtime limits for `ChanRegStore`. All bounds are enforced eagerly so a
/// hostile or buggy caller cannot exhaust memory or smuggle oversized strings.
pub const Params = struct {
    /// Maximum number of registered channels held at once.
    max_channels: usize = 65536,
    /// Maximum channel name length in bytes (includes the `#`/`&` prefix).
    max_name_bytes: usize = 64,
    /// Maximum account name length in bytes (founder and successor alike).
    max_account_bytes: usize = 64,
    /// Maximum channel description length in bytes.
    max_desc_bytes: usize = 512,
};

/// Errors returned by `ChanRegStore` operations.
pub const Error = std.mem.Allocator.Error || error{
    /// Channel name is empty, too long, or missing a valid channel prefix.
    InvalidName,
    /// Founder/successor account name is empty or too long.
    InvalidAccount,
    /// Description exceeds `Params.max_desc_bytes`.
    InvalidDescription,
    /// A registration already exists for this (case-folded) channel name.
    AlreadyRegistered,
    /// No registration exists for the requested channel name.
    NotRegistered,
    /// The store is already holding `Params.max_channels` channels.
    TooManyChannels,
};

/// A single registered-channel record. All slices are owned by the store and
/// remain valid until the record is dropped or the store is deinitialized.
/// Callers must treat the slices as borrowed (read-only) views.
pub const ChannelRecord = struct {
    /// Original founder-supplied channel name (display form, owned).
    name: []const u8,
    /// Owning account at registration time (owned, verbatim).
    founder_account: []const u8,
    /// Monotonic-ish registration timestamp supplied by the caller.
    registered_at: i64,
    /// Last time the channel was used, updated via `touch`.
    last_used_at: i64,
    /// Free-form description (owned, possibly empty).
    description: []const u8,
    /// Optional successor account that inherits the channel if the founder
    /// is gone (owned when present).
    successor_account: ?[]const u8,
};

/// Owns registered-channel records keyed by case-folded channel name.
pub const ChanRegStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    /// Key: case-folded channel name (owned). Value: owned record.
    records: std.StringHashMapUnmanaged(ChannelRecord),

    /// Initialize an empty store. Does not allocate until first `register`.
    pub fn init(allocator: std.mem.Allocator, params: Params) ChanRegStore {
        return .{
            .allocator = allocator,
            .params = params,
            .records = .empty,
        };
    }

    /// Free every record and the map itself.
    pub fn deinit(self: *ChanRegStore) void {
        var it = self.records.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.freeRecord(entry.value_ptr);
        }
        self.records.deinit(self.allocator);
        self.* = undefined;
    }

    /// Register `channel` to `founder`. Rejects a duplicate (case-insensitive).
    /// On any error the store is left exactly as it was. Returns a borrowed
    /// view of the freshly stored record.
    pub fn register(
        self: *ChanRegStore,
        channel: []const u8,
        founder: []const u8,
        description: []const u8,
        now: i64,
    ) Error!ChannelRecord {
        try self.validateName(channel);
        try self.validateAccount(founder);
        if (description.len > self.params.max_desc_bytes) return error.InvalidDescription;

        const key = try self.foldKey(channel);
        errdefer self.allocator.free(key);

        if (self.records.contains(key)) return error.AlreadyRegistered;
        if (self.records.count() >= self.params.max_channels) return error.TooManyChannels;

        // Duplicate every owned slice up front so a mid-way failure frees
        // cleanly and never leaves a half-built record in the map.
        const owned_name = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_name);
        const owned_founder = try self.allocator.dupe(u8, founder);
        errdefer self.allocator.free(owned_founder);
        const owned_desc = try self.allocator.dupe(u8, description);
        errdefer self.allocator.free(owned_desc);

        const record = ChannelRecord{
            .name = owned_name,
            .founder_account = owned_founder,
            .registered_at = now,
            .last_used_at = now,
            .description = owned_desc,
            .successor_account = null,
        };

        try self.records.putNoClobber(self.allocator, key, record);
        return record;
    }

    /// Remove the registration for `channel`. Returns `error.NotRegistered`
    /// when no matching record exists. All owned storage is freed.
    pub fn drop(self: *ChanRegStore, channel: []const u8) Error!void {
        const key = try self.foldKey(channel);
        defer self.allocator.free(key);

        const removed = self.records.fetchRemove(key) orelse return error.NotRegistered;
        self.allocator.free(removed.key);
        var rec = removed.value;
        self.freeRecord(&rec);
    }

    /// Look up the record for `channel`. Returns a borrowed view or null.
    /// The returned slices are valid until the record is dropped/mutated.
    pub fn get(self: *const ChanRegStore, channel: []const u8) Error!?ChannelRecord {
        const key = try self.foldKeyConst(channel);
        defer self.allocator.free(key);
        return self.records.get(key);
    }

    /// Set or clear the successor account for `channel`. Passing null clears
    /// any existing successor. The previous successor storage is freed.
    pub fn setSuccessor(
        self: *ChanRegStore,
        channel: []const u8,
        successor: ?[]const u8,
    ) Error!void {
        if (successor) |s| try self.validateAccount(s);

        const key = try self.foldKey(channel);
        defer self.allocator.free(key);

        const entry = self.records.getPtr(key) orelse return error.NotRegistered;

        const owned: ?[]const u8 = if (successor) |s|
            try self.allocator.dupe(u8, s)
        else
            null;
        // Only after the (possible) allocation succeeds do we mutate, so a
        // failure leaves the existing successor untouched.
        if (entry.successor_account) |old| self.allocator.free(old);
        entry.successor_account = owned;
    }

    /// Update `last_used_at` for `channel` to `now`.
    pub fn touch(self: *ChanRegStore, channel: []const u8, now: i64) Error!void {
        const key = try self.foldKey(channel);
        defer self.allocator.free(key);
        const entry = self.records.getPtr(key) orelse return error.NotRegistered;
        entry.last_used_at = now;
    }

    /// Number of registered channels.
    pub fn count(self: *const ChanRegStore) usize {
        return self.records.count();
    }

    // --- internal helpers -------------------------------------------------

    fn freeRecord(self: *ChanRegStore, rec: *ChannelRecord) void {
        self.allocator.free(rec.name);
        self.allocator.free(rec.founder_account);
        self.allocator.free(rec.description);
        if (rec.successor_account) |s| self.allocator.free(s);
        rec.* = undefined;
    }

    fn validateName(self: *const ChanRegStore, channel: []const u8) Error!void {
        if (channel.len == 0 or channel.len > self.params.max_name_bytes)
            return error.InvalidName;
        if (!isChannelPrefix(channel[0])) return error.InvalidName;
        // Reject embedded spaces and commas: both are protocol separators and
        // would make a stored channel name unaddressable.
        for (channel) |ch| {
            if (ch == ' ' or ch == ',' or ch == 0 or ch == '\r' or ch == '\n')
                return error.InvalidName;
        }
    }

    fn validateAccount(self: *const ChanRegStore, account: []const u8) Error!void {
        if (account.len == 0 or account.len > self.params.max_account_bytes)
            return error.InvalidAccount;
    }

    /// Allocate a case-folded copy of `channel` for use as a map key.
    fn foldKey(self: *ChanRegStore, channel: []const u8) Error![]u8 {
        try self.validateName(channel);
        return self.dupeFold(channel);
    }

    /// `foldKey` for const contexts (e.g. `get`); validation still applies.
    fn foldKeyConst(self: *const ChanRegStore, channel: []const u8) Error![]u8 {
        try self.validateName(channel);
        return self.dupeFold(channel);
    }

    fn dupeFold(self: *const ChanRegStore, input: []const u8) Error![]u8 {
        const out = try self.allocator.dupe(u8, input);
        for (out) |*ch| ch.* = std.ascii.toLower(ch.*);
        return out;
    }
};

/// Valid IRC channel-name prefixes accepted by this store.
fn isChannelPrefix(c: u8) bool {
    return c == '#' or c == '&' or c == '+' or c == '!';
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn testStore() ChanRegStore {
    return ChanRegStore.init(testing.allocator, .{});
}

test "register stores a record and returns a borrowed view" {
    var store = testStore();
    defer store.deinit();

    const rec = try store.register("#mizuchi", "kain", "the lair", 100);
    try testing.expectEqualStrings("#mizuchi", rec.name);
    try testing.expectEqualStrings("kain", rec.founder_account);
    try testing.expectEqualStrings("the lair", rec.description);
    try testing.expectEqual(@as(i64, 100), rec.registered_at);
    try testing.expectEqual(@as(i64, 100), rec.last_used_at);
    try testing.expectEqual(@as(?[]const u8, null), rec.successor_account);
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "register rejects a duplicate channel (case-insensitive)" {
    var store = testStore();
    defer store.deinit();

    _ = try store.register("#Chan", "alice", "", 1);
    try testing.expectError(error.AlreadyRegistered, store.register("#chan", "bob", "", 2));
    try testing.expectError(error.AlreadyRegistered, store.register("#CHAN", "bob", "", 3));
    // The original registration must survive a rejected duplicate.
    try testing.expectEqual(@as(usize, 1), store.count());
    const got = (try store.get("#chan")).?;
    try testing.expectEqualStrings("alice", got.founder_account);
}

test "get is case-insensitive and preserves display name" {
    var store = testStore();
    defer store.deinit();

    _ = try store.register("#HeLLo", "founder1", "desc", 5);
    const got = (try store.get("#hello")).?;
    try testing.expectEqualStrings("#HeLLo", got.name); // display form preserved
    const got2 = (try store.get("#HELLO")).?;
    try testing.expectEqualStrings("founder1", got2.founder_account);
    try testing.expectEqual(@as(?ChannelRecord, null), try store.get("#nope"));
}

test "drop removes the registration" {
    var store = testStore();
    defer store.deinit();

    _ = try store.register("#dropme", "owner", "", 10);
    try testing.expectEqual(@as(usize, 1), store.count());

    try store.drop("#DropMe"); // case-insensitive
    try testing.expectEqual(@as(usize, 0), store.count());
    try testing.expectEqual(@as(?ChannelRecord, null), try store.get("#dropme"));
    try testing.expectError(error.NotRegistered, store.drop("#dropme"));
}

test "setSuccessor sets, replaces, and clears" {
    var store = testStore();
    defer store.deinit();

    _ = try store.register("#succ", "founder", "", 0);
    try testing.expectEqual(@as(?[]const u8, null), (try store.get("#succ")).?.successor_account);

    try store.setSuccessor("#succ", "heir1");
    try testing.expectEqualStrings("heir1", (try store.get("#SUCC")).?.successor_account.?);

    // Replacing frees the previous successor; no leak (allocator checks).
    try store.setSuccessor("#succ", "heir2");
    try testing.expectEqualStrings("heir2", (try store.get("#succ")).?.successor_account.?);

    try store.setSuccessor("#succ", null);
    try testing.expectEqual(@as(?[]const u8, null), (try store.get("#succ")).?.successor_account);

    try testing.expectError(error.NotRegistered, store.setSuccessor("#ghost", "x"));
}

test "touch updates last_used_at without changing registered_at" {
    var store = testStore();
    defer store.deinit();

    _ = try store.register("#used", "owner", "", 1000);
    try store.touch("#USED", 2000);

    const got = (try store.get("#used")).?;
    try testing.expectEqual(@as(i64, 1000), got.registered_at);
    try testing.expectEqual(@as(i64, 2000), got.last_used_at);
    try testing.expectError(error.NotRegistered, store.touch("#missing", 1));
}

test "register validates channel name, account, and description bounds" {
    var store = testStore();
    defer store.deinit();

    // Bad channel names.
    try testing.expectError(error.InvalidName, store.register("", "a", "", 0));
    try testing.expectError(error.InvalidName, store.register("nohash", "a", "", 0));
    try testing.expectError(error.InvalidName, store.register("#bad name", "a", "", 0));
    try testing.expectError(error.InvalidName, store.register("#bad,name", "a", "", 0));

    const long_name = "#" ++ ("x" ** 64); // 65 bytes > max 64
    try testing.expectError(error.InvalidName, store.register(long_name, "a", "", 0));

    // Bad accounts.
    try testing.expectError(error.InvalidAccount, store.register("#ok", "", "", 0));
    const long_acct = "a" ** 65;
    try testing.expectError(error.InvalidAccount, store.register("#ok", long_acct, "", 0));

    // Bad description.
    const long_desc = "d" ** 513;
    try testing.expectError(error.InvalidDescription, store.register("#ok", "a", long_desc, 0));

    // None of the rejected attempts left anything behind.
    try testing.expectEqual(@as(usize, 0), store.count());

    // Valid alternate prefixes are accepted.
    _ = try store.register("&local", "a", "", 0);
    _ = try store.register("!12345", "a", "", 0);
    try testing.expectEqual(@as(usize, 2), store.count());
}

test "max_channels bound is enforced" {
    var store = ChanRegStore.init(testing.allocator, .{ .max_channels = 2 });
    defer store.deinit();

    _ = try store.register("#one", "a", "", 0);
    _ = try store.register("#two", "a", "", 0);
    try testing.expectError(error.TooManyChannels, store.register("#three", "a", "", 0));
    try testing.expectEqual(@as(usize, 2), store.count());

    // Dropping frees a slot for a new registration.
    try store.drop("#one");
    _ = try store.register("#three", "a", "", 0);
    try testing.expectEqual(@as(usize, 2), store.count());
}

test "setSuccessor validates the successor account name" {
    var store = testStore();
    defer store.deinit();

    _ = try store.register("#v", "owner", "", 0);
    try testing.expectError(error.InvalidAccount, store.setSuccessor("#v", ""));
    const long_acct = "a" ** 65;
    try testing.expectError(error.InvalidAccount, store.setSuccessor("#v", long_acct));
    // Successor unchanged after a rejected set.
    try testing.expectEqual(@as(?[]const u8, null), (try store.get("#v")).?.successor_account);
}
