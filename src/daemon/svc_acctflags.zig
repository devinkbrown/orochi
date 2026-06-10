//! Administrative account-state flags.
//!
//! Operators attach per-account state flags that gate or protect a registered
//! account. Each flag records the setter, the time it was applied, and a free
//! text reason. This module stores flag state only; command dispatch, numeric
//! replies, and clock reads stay with the caller.
//!
//! Flags:
//!   - frozen:    login is refused while set (account is administratively locked)
//!   - held:      nick/account is reserved and cannot be dropped or expired
//!   - marked:    an oper note is attached for review; purely informational
//!   - noexpire:  account is exempt from inactivity expiry
//!
//! Orochi services are real server commands and numerics, never pseudo-clients,
//! so this store is consumed directly by an oper command handler.

const std = @import("std");

/// The administrative flags that may be applied to an account.
pub const Flag = enum {
    frozen,
    held,
    marked,
    noexpire,

    /// Stable lowercase name used in numerics and audit output.
    pub fn name(self: Flag) []const u8 {
        return switch (self) {
            .frozen => "frozen",
            .held => "held",
            .marked => "marked",
            .noexpire => "noexpire",
        };
    }
};

/// A single applied flag with its provenance, owned by `AccountFlags`.
pub const FlagRecord = struct {
    /// Which flag this record describes.
    flag: Flag,
    /// Oper (or service identity) that applied the flag, as supplied.
    setter: []const u8,
    /// Free-text reason recorded with the flag.
    reason: []const u8,
    /// Millisecond timestamp when the flag was applied.
    set_ms: u64,

    fn deinit(self: *FlagRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.setter);
        allocator.free(self.reason);
        self.* = undefined;
    }
};

/// Runtime bounds and policy for flag storage.
pub const Params = struct {
    /// Maximum number of distinct accounts that may carry any flag.
    max_accounts: usize = 65536,
    /// Maximum account name length accepted.
    max_account_bytes: usize = 128,
    /// Maximum setter identity length accepted.
    max_setter_bytes: usize = 128,
    /// Maximum reason length accepted.
    max_reason_bytes: usize = 320,
};

/// Errors returned while setting account flags.
pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidSetter,
    SetterTooLong,
    InvalidReason,
    ReasonTooLong,
    TooManyAccounts,
};

const flag_count = @typeInfo(Flag).@"enum".fields.len;

/// Per-account flag set: a fixed array of optional records keyed by `Flag`.
const AccountEntry = struct {
    records: [flag_count]?FlagRecord = [_]?FlagRecord{null} ** flag_count,

    fn slot(self: *AccountEntry, flag: Flag) *?FlagRecord {
        return &self.records[@intFromEnum(flag)];
    }

    fn slotConst(self: *const AccountEntry, flag: Flag) *const ?FlagRecord {
        return &self.records[@intFromEnum(flag)];
    }

    fn isEmpty(self: *const AccountEntry) bool {
        for (self.records) |record| {
            if (record != null) return false;
        }
        return true;
    }

    fn deinit(self: *AccountEntry, allocator: std.mem.Allocator) void {
        for (&self.records) |*record| {
            if (record.*) |*present| present.deinit(allocator);
            record.* = null;
        }
    }
};

/// Owned account-flag records keyed by normalized account name.
pub const AccountFlags = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.StringHashMap(AccountEntry),

    /// Creates an empty flag store using caller-provided bounds.
    pub fn init(allocator: std.mem.Allocator, params: Params) AccountFlags {
        return .{
            .allocator = allocator,
            .params = params,
            .entries = std.StringHashMap(AccountEntry).init(allocator),
        };
    }

    /// Frees all flag records and invalidates the store.
    pub fn deinit(self: *AccountFlags) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Sets (or replaces) a flag on an account, recording setter, reason, and
    /// timestamp. Replacing an existing flag overwrites its provenance.
    pub fn set(
        self: *AccountFlags,
        account: []const u8,
        flag: Flag,
        setter: []const u8,
        reason: []const u8,
        now: u64,
    ) Error!void {
        try self.validateAccount(account);
        try self.validateSetter(setter);
        try self.validateReason(reason);

        var record = try self.makeRecord(flag, setter, reason, now);
        errdefer record.deinit(self.allocator);

        if (self.findEntry(account)) |entry| {
            const dest = entry.value_ptr.slot(flag);
            if (dest.*) |*existing| existing.deinit(self.allocator);
            dest.* = record;
            return;
        }

        if (self.entries.count() >= self.params.max_accounts) return error.TooManyAccounts;

        const owned_key = try self.normalizedAccount(account);
        errdefer self.allocator.free(owned_key);

        var fresh = AccountEntry{};
        fresh.slot(flag).* = record;
        try self.entries.putNoClobber(owned_key, fresh);
    }

    /// Clears a flag from an account. Returns true when a flag was removed.
    /// Removes the account entry entirely once its last flag is cleared.
    pub fn clear(self: *AccountFlags, account: []const u8, flag: Flag) bool {
        const entry = self.findEntry(account) orelse return false;
        const dest = entry.value_ptr.slot(flag);
        if (dest.* == null) return false;
        dest.*.?.deinit(self.allocator);
        dest.* = null;
        if (entry.value_ptr.isEmpty()) self.dropEntry(entry);
        return true;
    }

    /// Returns a borrowed snapshot of the record for a flag, if set.
    pub fn get(self: *const AccountFlags, account: []const u8, flag: Flag) ?FlagRecord {
        const entry = self.findEntry(account) orelse return null;
        return entry.value_ptr.slotConst(flag).*;
    }

    /// Returns true when the flag is currently set on the account.
    pub fn has(self: *const AccountFlags, account: []const u8, flag: Flag) bool {
        return self.get(account, flag) != null;
    }

    /// Login policy helper: an account may log in unless it is frozen.
    pub fn loginAllowed(self: *const AccountFlags, account: []const u8) bool {
        return !self.has(account, .frozen);
    }

    /// Expiry policy helper: an account is protected from inactivity expiry
    /// while it is held or marked noexpire.
    pub fn expiryAllowed(self: *const AccountFlags, account: []const u8) bool {
        return !self.has(account, .held) and !self.has(account, .noexpire);
    }

    /// Number of accounts currently carrying at least one flag.
    pub fn count(self: *const AccountFlags) usize {
        return self.entries.count();
    }

    fn makeRecord(
        self: *AccountFlags,
        flag: Flag,
        setter: []const u8,
        reason: []const u8,
        now: u64,
    ) Error!FlagRecord {
        const owned_setter = try self.allocator.dupe(u8, setter);
        errdefer self.allocator.free(owned_setter);
        const owned_reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned_reason);
        return .{
            .flag = flag,
            .setter = owned_setter,
            .reason = owned_reason,
            .set_ms = now,
        };
    }

    fn normalizedAccount(self: *AccountFlags, account: []const u8) Error![]u8 {
        const owned_key = try self.allocator.alloc(u8, account.len);
        for (account, 0..) |byte, index| {
            owned_key[index] = std.ascii.toLower(byte);
        }
        return owned_key;
    }

    fn validateAccount(self: *const AccountFlags, account: []const u8) Error!void {
        if (account.len == 0) return error.InvalidAccount;
        if (account.len > self.params.max_account_bytes) return error.AccountTooLong;
        for (account) |byte| {
            if (!validAccountByte(byte)) return error.InvalidAccount;
        }
    }

    fn validateSetter(self: *const AccountFlags, setter: []const u8) Error!void {
        if (setter.len == 0) return error.InvalidSetter;
        if (setter.len > self.params.max_setter_bytes) return error.SetterTooLong;
        for (setter) |byte| {
            if (!validAccountByte(byte)) return error.InvalidSetter;
        }
    }

    fn validateReason(self: *const AccountFlags, reason: []const u8) Error!void {
        if (reason.len == 0) return error.InvalidReason;
        if (reason.len > self.params.max_reason_bytes) return error.ReasonTooLong;
        for (reason) |byte| {
            if (!validReasonByte(byte)) return error.InvalidReason;
        }
    }

    fn findEntry(self: *const AccountFlags, account: []const u8) ?std.StringHashMap(AccountEntry).Entry {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }

    fn dropEntry(self: *AccountFlags, entry: std.StringHashMap(AccountEntry).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.entries.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }
};

fn validAccountByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '@', '[', ']', '{', '}', '\\', '|', '^', '`' => true,
        else => false,
    };
}

fn validReasonByte(byte: u8) bool {
    return switch (byte) {
        // Printable ASCII including spaces; reject control bytes.
        0x20...0x7e => true,
        else => false,
    };
}

const testing = std.testing;

test "flag names are stable" {
    try testing.expectEqualStrings("frozen", Flag.frozen.name());
    try testing.expectEqualStrings("held", Flag.held.name());
    try testing.expectEqualStrings("marked", Flag.marked.name());
    try testing.expectEqualStrings("noexpire", Flag.noexpire.name());
}

test "set then get retains setter, reason, and timestamp" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{});
    defer store.deinit();

    // Act.
    try store.set("Alice", .marked, "oper.bob", "spam from this account", 1000);
    const record = store.get("alice", .marked).?;

    // Assert.
    try testing.expectEqual(Flag.marked, record.flag);
    try testing.expectEqualStrings("oper.bob", record.setter);
    try testing.expectEqualStrings("spam from this account", record.reason);
    try testing.expectEqual(@as(u64, 1000), record.set_ms);
    try testing.expect(store.has("ALICE", .marked));
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "login refused while frozen and allowed otherwise" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{});
    defer store.deinit();

    // Act and assert: unknown account may log in.
    try testing.expect(store.loginAllowed("carol"));

    try store.set("carol", .frozen, "oper.dave", "abuse investigation", 2000);
    try testing.expect(!store.loginAllowed("CAROL"));

    // A non-frozen flag does not block login.
    try store.set("erin", .marked, "oper.dave", "watch", 2100);
    try testing.expect(store.loginAllowed("erin"));
}

test "clear removes flag and frees the entry when last flag goes" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{});
    defer store.deinit();
    try store.set("dave", .frozen, "oper.x", "locked", 3000);

    // Act.
    const removed = store.clear("DAVE", .frozen);
    const missing = store.clear("dave", .frozen);

    // Assert.
    try testing.expect(removed);
    try testing.expect(!missing);
    try testing.expect(store.loginAllowed("dave"));
    try testing.expect(!store.has("dave", .frozen));
    try testing.expectEqual(@as(usize, 0), store.count());
    try testing.expectEqual(@as(?FlagRecord, null), store.get("dave", .frozen));
}

test "clearing one flag preserves the others on the same account" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{});
    defer store.deinit();
    try store.set("frank", .frozen, "oper.a", "locked", 4000);
    try store.set("frank", .marked, "oper.b", "noted", 4001);

    // Act.
    try testing.expect(store.clear("frank", .frozen));

    // Assert: account entry survives because marked remains.
    try testing.expect(store.loginAllowed("frank"));
    try testing.expect(store.has("frank", .marked));
    try testing.expectEqual(@as(usize, 1), store.count());
    const note = store.get("frank", .marked).?;
    try testing.expectEqualStrings("oper.b", note.setter);
}

test "setting an existing flag replaces its provenance without leaking" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{});
    defer store.deinit();

    // Act.
    try store.set("grace", .frozen, "oper.first", "first reason", 5000);
    try store.set("GRACE", .frozen, "oper.second", "second reason", 6000);
    const record = store.get("grace", .frozen).?;

    // Assert.
    try testing.expectEqualStrings("oper.second", record.setter);
    try testing.expectEqualStrings("second reason", record.reason);
    try testing.expectEqual(@as(u64, 6000), record.set_ms);
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "held or noexpire protects an account from expiry" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{});
    defer store.deinit();

    // Act and assert.
    try testing.expect(store.expiryAllowed("heidi"));

    try store.set("heidi", .held, "oper.q", "reserved nick", 7000);
    try testing.expect(!store.expiryAllowed("heidi"));
    try testing.expect(store.clear("heidi", .held));
    try testing.expect(store.expiryAllowed("heidi"));

    try store.set("heidi", .noexpire, "oper.q", "permanent", 7100);
    try testing.expect(!store.expiryAllowed("HEIDI"));
}

test "bounds reject invalid inputs without leaks" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{
        .max_accounts = 1,
        .max_account_bytes = 4,
        .max_setter_bytes = 6,
        .max_reason_bytes = 8,
    });
    defer store.deinit();

    // Act and assert.
    try testing.expectError(error.InvalidAccount, store.set("", .frozen, "oper", "why", 1));
    try testing.expectError(error.AccountTooLong, store.set("abcde", .frozen, "oper", "why", 1));
    try testing.expectError(error.InvalidAccount, store.set("a b", .frozen, "oper", "why", 1));
    try testing.expectError(error.InvalidSetter, store.set("abc", .frozen, "", "why", 1));
    try testing.expectError(error.SetterTooLong, store.set("abc", .frozen, "operator", "why", 1));
    try testing.expectError(error.InvalidReason, store.set("abc", .frozen, "oper", "", 1));
    try testing.expectError(error.ReasonTooLong, store.set("abc", .frozen, "oper", "way too long", 1));
    try testing.expectError(error.InvalidReason, store.set("abc", .frozen, "oper", "bad\nrsn", 1));

    // First account fits; a second distinct account exceeds the bound.
    try store.set("abc", .frozen, "oper", "ok", 1);
    try testing.expectError(error.TooManyAccounts, store.set("def", .frozen, "oper", "ok", 1));

    // Replacing a flag on the existing account does not hit the account bound.
    try store.set("abc", .marked, "oper", "ok", 2);
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "get and has report unset flags as absent" {
    // Arrange.
    var store = AccountFlags.init(testing.allocator, .{});
    defer store.deinit();
    try store.set("ivan", .frozen, "oper", "locked", 1);

    // Assert.
    try testing.expectEqual(@as(?FlagRecord, null), store.get("ivan", .marked));
    try testing.expect(!store.has("ivan", .marked));
    try testing.expect(store.has("ivan", .frozen));
    try testing.expect(!store.has("unknown", .frozen));
}
