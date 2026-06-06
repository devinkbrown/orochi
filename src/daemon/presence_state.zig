//! Mizuchi account presence state.
//!
//! Tracks explicit per-account presence plus optional custom text. Missing
//! accounts read as online with no custom text.
const std = @import("std");

pub const max_accounts: usize = 65536;
pub const max_account_bytes: usize = 64;
pub const max_text_bytes: usize = 64;

pub const State = enum {
    online,
    idle,
    dnd,
    offline,
};

pub const Entry = struct {
    state: State = .online,
    text: ?[]const u8 = null,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    TextTooLong,
    TooManyAccounts,
};

const StoredEntry = struct {
    state: State = .online,
    text: ?[]const u8 = null,

    fn deinit(self: *StoredEntry, allocator: std.mem.Allocator) void {
        if (self.text) |value| freeIfOwned(allocator, value);
        self.* = undefined;
    }

    fn view(self: *const StoredEntry) Entry {
        return .{
            .state = self.state,
            .text = self.text,
        };
    }

    fn replace(self: *StoredEntry, allocator: std.mem.Allocator, state: State, text: ?[]const u8) std.mem.Allocator.Error!void {
        const owned_text: ?[]const u8 = if (text) |value|
            if (value.len == 0) &.{} else try allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_text) |value| freeIfOwned(allocator, value);

        if (self.text) |old| freeIfOwned(allocator, old);
        self.state = state;
        self.text = owned_text;
    }
};

pub const PresenceState = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(StoredEntry),

    pub fn init(allocator: std.mem.Allocator) PresenceState {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(StoredEntry).init(allocator),
        };
    }

    pub fn deinit(self: *PresenceState) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn set(self: *PresenceState, account: []const u8, state: State, text: ?[]const u8) Error!void {
        try validateAccount(account);
        if (text) |value| {
            if (value.len > max_text_bytes) return error.TextTooLong;
        }

        const entry = try self.ensureAccount(account);
        try entry.replace(self.allocator, state, text);
    }

    pub fn get(self: *const PresenceState, account: []const u8) Entry {
        const entry = self.accounts.getPtr(account) orelse return .{};
        return entry.view();
    }

    pub fn clear(self: *PresenceState, account: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const owned_account = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_account);
        return true;
    }

    fn ensureAccount(self: *PresenceState, account: []const u8) Error!*StoredEntry {
        if (self.accounts.getPtr(account)) |entry| return entry;
        if (self.accounts.count() >= max_accounts) return error.TooManyAccounts;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }
};

fn freeIfOwned(allocator: std.mem.Allocator, value: []const u8) void {
    if (value.len != 0) allocator.free(value);
}

fn validateAccount(account: []const u8) error{InvalidAccount}!void {
    if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
}

const testing = std.testing;

test "missing accounts default to online without text" {
    var states = PresenceState.init(testing.allocator);
    defer states.deinit();

    const entry = states.get("alice");
    try testing.expectEqual(State.online, entry.state);
    try testing.expect(entry.text == null);
    try testing.expect(!states.clear("alice"));
}

test "set stores state and optional custom text" {
    var states = PresenceState.init(testing.allocator);
    defer states.deinit();

    try states.set("alice", .idle, "back soon");
    const entry = states.get("alice");
    try testing.expectEqual(State.idle, entry.state);
    try testing.expectEqualStrings("back soon", entry.text.?);

    try states.set("alice", .dnd, null);
    const updated = states.get("alice");
    try testing.expectEqual(State.dnd, updated.state);
    try testing.expect(updated.text == null);
}

test "clear removes explicit state and restores default reads" {
    var states = PresenceState.init(testing.allocator);
    defer states.deinit();

    try states.set("alice", .offline, "done");
    try testing.expect(states.clear("alice"));
    try testing.expect(!states.clear("alice"));
    const entry = states.get("alice");
    try testing.expectEqual(State.online, entry.state);
    try testing.expect(entry.text == null);
}

test "empty text is distinct from no text" {
    var states = PresenceState.init(testing.allocator);
    defer states.deinit();

    try states.set("alice", .online, "");
    const entry = states.get("alice");
    try testing.expect(entry.text != null);
    try testing.expectEqualStrings("", entry.text.?);
}

test "account and text caps are enforced" {
    var states = PresenceState.init(testing.allocator);
    defer states.deinit();

    try testing.expectError(error.InvalidAccount, states.set("", .online, null));

    var long_text: [max_text_bytes + 1]u8 = undefined;
    @memset(&long_text, 'x');
    try testing.expectError(error.TextTooLong, states.set("alice", .online, &long_text));
}
