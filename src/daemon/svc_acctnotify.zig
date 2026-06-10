//! Account-keyed WATCH notification state for Orochi.
//!
//! This module is deliberately pure: it owns only data structures, parses the
//! real IRC `WATCH` command shape, and reports real WATCH numerics for callers
//! to translate into server replies. It never models services as fake users.
const std = @import("std");

pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_WATCHERS: usize = 65_536;
pub const DEFAULT_MAX_WATCHES_PER_ACCOUNT: usize = 1_024;

const target_prefix_bytes: usize = 2;
const max_target_key_bytes: usize = target_prefix_bytes + @max(DEFAULT_MAX_ACCOUNT_BYTES, DEFAULT_MAX_NICK_BYTES);

pub const Error = std.mem.Allocator.Error || error{
    InvalidCommand,
    MissingParameter,
    TooManyOperations,
    InvalidAccount,
    AccountTooLong,
    InvalidNick,
    NickTooLong,
    InvalidTarget,
    TooManyWatchers,
    TooManyWatches,
    TooManyNotifications,
};

pub const Config = struct {
    max_watchers: usize = DEFAULT_MAX_WATCHERS,
    max_watches_per_account: usize = DEFAULT_MAX_WATCHES_PER_ACCOUNT,
};

/// Real WATCH numerics used by IRC daemons that implement WATCH.
pub const WatchNumeric = enum(u16) {
    RPL_LOGON = 600,
    RPL_LOGOFF = 601,
    RPL_WATCHOFF = 602,
    RPL_WATCHSTAT = 603,
    RPL_NOWON = 604,
    RPL_NOWOFF = 605,
    RPL_WATCHLIST = 606,
    RPL_ENDOFWATCHLIST = 607,
    ERR_TOOMANYWATCH = 512,

    pub fn code(self: WatchNumeric) u16 {
        return @intFromEnum(self);
    }
};

pub const TargetKind = enum {
    nick,
    account,
};

/// Borrowed target supplied by the caller or parser.
pub const Target = struct {
    kind: TargetKind,
    name: []const u8,
};

/// Borrowed target view returned from `WatchStore.list`.
pub const WatchedTarget = struct {
    kind: TargetKind,
    name: []const u8,
};

pub const Presence = enum {
    online,
    offline,

    pub fn transitionNumeric(self: Presence) WatchNumeric {
        return switch (self) {
            .online => .RPL_LOGON,
            .offline => .RPL_LOGOFF,
        };
    }

    pub fn addReplyNumeric(self: Presence) WatchNumeric {
        return switch (self) {
            .online => .RPL_NOWON,
            .offline => .RPL_NOWOFF,
        };
    }
};

pub const WatchOp = union(enum) {
    add: Target,
    remove: Target,
    list,
    clear,
    status,
};

pub const Notification = struct {
    watcher_account: []const u8,
    target: WatchedTarget,
    presence: Presence,
    numeric: WatchNumeric,
};

pub const NotificationSink = struct {
    notifications: []Notification,
    count: usize = 0,

    pub fn append(
        self: *NotificationSink,
        watcher_account: []const u8,
        target: WatchedTarget,
        presence: Presence,
    ) Error!void {
        if (self.count >= self.notifications.len) return error.TooManyNotifications;
        self.notifications[self.count] = .{
            .watcher_account = watcher_account,
            .target = target,
            .presence = presence,
            .numeric = presence.transitionNumeric(),
        };
        self.count += 1;
    }

    pub fn slice(self: *const NotificationSink) []const Notification {
        return self.notifications[0..self.count];
    }

    pub fn reset(self: *NotificationSink) void {
        self.count = 0;
    }
};

const WatchSet = struct {
    items: std.ArrayListUnmanaged(WatchedTarget) = .empty,

    fn deinit(self: *WatchSet, allocator: std.mem.Allocator) void {
        for (self.items.items) |item| allocator.free(item.name);
        self.items.deinit(allocator);
    }

    fn indexOfTarget(self: *const WatchSet, kind: TargetKind, normalized_name: []const u8) ?usize {
        for (self.items.items, 0..) |item, index| {
            if (item.kind == kind and std.mem.eql(u8, item.name, normalized_name)) return index;
        }
        return null;
    }
};

const WatcherList = struct {
    accounts: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *WatcherList, allocator: std.mem.Allocator) void {
        for (self.accounts.items) |account| allocator.free(account);
        self.accounts.deinit(allocator);
    }

    fn indexOf(self: *const WatcherList, account: []const u8) ?usize {
        for (self.accounts.items, 0..) |item, index| {
            if (std.mem.eql(u8, item, account)) return index;
        }
        return null;
    }
};

pub const WatchStore = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    watchers: std.StringHashMap(WatchSet),
    reverse: std.StringHashMap(WatcherList),

    pub fn init(allocator: std.mem.Allocator) WatchStore {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) WatchStore {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .watchers = std.StringHashMap(WatchSet).init(allocator),
            .reverse = std.StringHashMap(WatcherList).init(allocator),
        };
    }

    pub fn deinit(self: *WatchStore) void {
        var watcher_it = self.watchers.iterator();
        while (watcher_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.watchers.deinit();

        var reverse_it = self.reverse.iterator();
        while (reverse_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.reverse.deinit();
        self.* = undefined;
    }

    /// Add a target to a watcher account. Returns false when the watch already exists.
    pub fn add(self: *WatchStore, watcher_account: []const u8, target: Target) Error!bool {
        var watcher_buf: [DEFAULT_MAX_ACCOUNT_BYTES]u8 = undefined;
        const watcher_key = try normalizedAccountInto(&watcher_buf, watcher_account);

        var target_buf: [max_target_key_bytes]u8 = undefined;
        const target_key = try normalizedTargetInto(&target_buf, target);
        const target_kind = target.kind;

        const set = try self.ensureWatcher(watcher_key);
        const target_name = target_key[target_prefix_bytes..];
        if (set.indexOfTarget(target_kind, target_name) != null) return false;
        if (set.items.items.len >= self.cfg.max_watches_per_account) return error.TooManyWatches;

        const reverse_list = try self.ensureReverseTarget(target_key);
        const owned_target_name = try self.allocator.dupe(u8, target_name);
        errdefer self.allocator.free(owned_target_name);

        const owned_watcher_key = try self.allocator.dupe(u8, watcher_key);
        var reverse_appended = false;
        errdefer if (!reverse_appended) self.allocator.free(owned_watcher_key);

        try reverse_list.accounts.append(self.allocator, owned_watcher_key);
        reverse_appended = true;
        errdefer if (reverse_appended) self.removeWatcherFromReverse(target_key, watcher_key);

        try set.items.append(self.allocator, .{ .kind = target_kind, .name = owned_target_name });
        return true;
    }

    /// Remove a target from a watcher account. Returns false when absent.
    pub fn remove(self: *WatchStore, watcher_account: []const u8, target: Target) Error!bool {
        var watcher_buf: [DEFAULT_MAX_ACCOUNT_BYTES]u8 = undefined;
        const watcher_key = try normalizedAccountInto(&watcher_buf, watcher_account);

        var target_buf: [max_target_key_bytes]u8 = undefined;
        const target_key = try normalizedTargetInto(&target_buf, target);

        const entry = self.watchers.getEntry(watcher_key) orelse return false;
        const index = entry.value_ptr.indexOfTarget(target.kind, target_key[target_prefix_bytes..]) orelse return false;
        const removed = entry.value_ptr.items.orderedRemove(index);
        self.removeWatcherFromReverse(target_key, watcher_key);
        self.allocator.free(removed.name);

        if (entry.value_ptr.items.items.len == 0) self.dropWatcher(entry);
        return true;
    }

    /// Remove every target for a watcher account. Returns the removed count.
    pub fn clear(self: *WatchStore, watcher_account: []const u8) Error!usize {
        var watcher_buf: [DEFAULT_MAX_ACCOUNT_BYTES]u8 = undefined;
        const watcher_key = try normalizedAccountInto(&watcher_buf, watcher_account);
        const entry = self.watchers.getEntry(watcher_key) orelse return 0;
        return self.clearWatcherEntry(entry);
    }

    /// Borrowed watch list for an account, valid until the next mutation.
    pub fn list(self: *const WatchStore, watcher_account: []const u8) Error![]const WatchedTarget {
        var watcher_buf: [DEFAULT_MAX_ACCOUNT_BYTES]u8 = undefined;
        const watcher_key = try normalizedAccountInto(&watcher_buf, watcher_account);
        const set = self.watchers.getPtr(watcher_key) orelse return &.{};
        return set.items.items;
    }

    /// Borrowed watcher-account list for a target, valid until the next mutation.
    pub fn watchersOf(self: *const WatchStore, target: Target) Error![]const []const u8 {
        var target_buf: [max_target_key_bytes]u8 = undefined;
        const target_key = try normalizedTargetInto(&target_buf, target);
        const list_ptr = self.reverse.getPtr(target_key) orelse return &.{};
        return list_ptr.accounts.items;
    }

    pub fn isWatching(self: *const WatchStore, watcher_account: []const u8, target: Target) Error!bool {
        var watcher_buf: [DEFAULT_MAX_ACCOUNT_BYTES]u8 = undefined;
        const watcher_key = try normalizedAccountInto(&watcher_buf, watcher_account);

        var target_buf: [max_target_key_bytes]u8 = undefined;
        const target_key = try normalizedTargetInto(&target_buf, target);

        const set = self.watchers.getPtr(watcher_key) orelse return false;
        return set.indexOfTarget(target.kind, target_key[target_prefix_bytes..]) != null;
    }

    /// Select watcher accounts that must receive LOGON/LOGOFF for a target transition.
    pub fn selectNotifications(
        self: *const WatchStore,
        target: Target,
        presence: Presence,
        sink: *NotificationSink,
    ) Error!void {
        var target_buf: [max_target_key_bytes]u8 = undefined;
        const target_key = try normalizedTargetInto(&target_buf, target);
        const entry = self.reverse.getEntry(target_key) orelse return;
        const stored_target = WatchedTarget{ .kind = target.kind, .name = entry.key_ptr.*[target_prefix_bytes..] };
        for (entry.value_ptr.accounts.items) |watcher_account| {
            try sink.append(watcher_account, stored_target, presence);
        }
    }

    pub fn watcherCount(self: *const WatchStore) usize {
        return self.watchers.count();
    }

    pub fn reverseTargetCount(self: *const WatchStore) usize {
        return self.reverse.count();
    }

    fn ensureWatcher(self: *WatchStore, watcher_key: []const u8) Error!*WatchSet {
        if (self.watchers.getPtr(watcher_key)) |set| return set;
        if (self.watchers.count() >= self.cfg.max_watchers) return error.TooManyWatchers;

        const owned = try self.allocator.dupe(u8, watcher_key);
        errdefer self.allocator.free(owned);
        try self.watchers.putNoClobber(owned, .{});
        return self.watchers.getPtr(watcher_key).?;
    }

    fn ensureReverseTarget(self: *WatchStore, target_key: []const u8) Error!*WatcherList {
        if (self.reverse.getPtr(target_key)) |list_ptr| return list_ptr;

        const owned = try self.allocator.dupe(u8, target_key);
        errdefer self.allocator.free(owned);
        try self.reverse.putNoClobber(owned, .{});
        return self.reverse.getPtr(target_key).?;
    }

    fn removeWatcherFromReverse(self: *WatchStore, target_key: []const u8, watcher_key: []const u8) void {
        const entry = self.reverse.getEntry(target_key) orelse return;
        if (entry.value_ptr.indexOf(watcher_key)) |index| {
            const removed = entry.value_ptr.accounts.orderedRemove(index);
            self.allocator.free(removed);
        }
        if (entry.value_ptr.accounts.items.len == 0) self.dropReverseTarget(entry);
    }

    fn clearWatcherEntry(self: *WatchStore, entry: std.StringHashMap(WatchSet).Entry) usize {
        const removed_count = entry.value_ptr.items.items.len;
        const watcher_key = entry.key_ptr.*;
        for (entry.value_ptr.items.items) |item| {
            var target_buf: [max_target_key_bytes]u8 = undefined;
            const target_key = normalizedTargetInto(&target_buf, .{ .kind = item.kind, .name = item.name }) catch unreachable;
            self.removeWatcherFromReverse(target_key, watcher_key);
            self.allocator.free(item.name);
        }
        entry.value_ptr.items.deinit(self.allocator);
        self.watchers.removeByPtr(entry.key_ptr);
        self.allocator.free(watcher_key);
        return removed_count;
    }

    fn dropWatcher(self: *WatchStore, entry: std.StringHashMap(WatchSet).Entry) void {
        const watcher_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.watchers.removeByPtr(entry.key_ptr);
        self.allocator.free(watcher_key);
    }

    fn dropReverseTarget(self: *WatchStore, entry: std.StringHashMap(WatcherList).Entry) void {
        const target_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.reverse.removeByPtr(entry.key_ptr);
        self.allocator.free(target_key);
    }
};

/// Parse `WATCH` command parameters into caller-owned operation storage.
///
/// Supported tokens are the real WATCH controls `L`, `S`, `C`, plus add/remove
/// targets (`+nick`, `-nick`). Account targets use explicit server-side target
/// syntax: `+account:name`, `-account:name`, `+acct:name`, or `+nick:name`.
pub fn parseWatchParams(params: []const []const u8, out: []WatchOp) Error![]const WatchOp {
    if (params.len == 0) return error.MissingParameter;
    if (params.len > out.len) return error.TooManyOperations;

    var count: usize = 0;
    for (params) |param| {
        out[count] = try parseWatchToken(param);
        count += 1;
    }
    return out[0..count];
}

/// Parse one raw IRC command line beginning with `WATCH`.
pub fn parseWatchLine(line: []const u8, out: []WatchOp) Error![]const WatchOp {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    var it = std.mem.tokenizeAny(u8, trimmed, " \t");
    const command = it.next() orelse return error.InvalidCommand;
    if (!std.ascii.eqlIgnoreCase(command, "WATCH")) return error.InvalidCommand;

    var count: usize = 0;
    while (it.next()) |token| {
        if (count >= out.len) return error.TooManyOperations;
        out[count] = try parseWatchToken(token);
        count += 1;
    }
    if (count == 0) return error.MissingParameter;
    return out[0..count];
}

pub fn parseWatchToken(token: []const u8) Error!WatchOp {
    if (token.len == 0) return error.MissingParameter;
    if (token.len == 1) {
        return switch (std.ascii.toUpper(token[0])) {
            'L' => .list,
            'C' => .clear,
            'S' => .status,
            else => error.InvalidTarget,
        };
    }

    return switch (token[0]) {
        '+' => .{ .add = try parseTargetSpec(token[1..]) },
        '-' => .{ .remove = try parseTargetSpec(token[1..]) },
        else => error.InvalidTarget,
    };
}

pub fn validateWatcherAccount(account: []const u8) Error!void {
    try validateAccount(account);
}

pub fn validateTarget(target: Target) Error!void {
    switch (target.kind) {
        .nick => try validateNick(target.name),
        .account => try validateAccount(target.name),
    }
}

pub fn parseTargetSpec(spec: []const u8) Error!Target {
    if (startsWithIgnoreCase(spec, "account:")) {
        const name = spec["account:".len..];
        try validateAccount(name);
        return .{ .kind = .account, .name = name };
    }
    if (startsWithIgnoreCase(spec, "acct:")) {
        const name = spec["acct:".len..];
        try validateAccount(name);
        return .{ .kind = .account, .name = name };
    }
    if (startsWithIgnoreCase(spec, "nick:")) {
        const name = spec["nick:".len..];
        try validateNick(name);
        return .{ .kind = .nick, .name = name };
    }
    try validateNick(spec);
    return .{ .kind = .nick, .name = spec };
}

fn validateAccount(account: []const u8) Error!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > DEFAULT_MAX_ACCOUNT_BYTES) return error.AccountTooLong;
    for (account) |byte| {
        if (!validAccountByte(byte)) return error.InvalidAccount;
    }
}

fn validateNick(nick: []const u8) Error!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > DEFAULT_MAX_NICK_BYTES) return error.NickTooLong;
    if (!validNickFirstByte(nick[0])) return error.InvalidNick;
    for (nick[1..]) |byte| {
        if (!validNickByte(byte)) return error.InvalidNick;
    }
}

fn normalizedAccountInto(out: *[DEFAULT_MAX_ACCOUNT_BYTES]u8, account: []const u8) Error![]const u8 {
    try validateAccount(account);
    for (account, 0..) |byte, index| out[index] = std.ascii.toLower(byte);
    return out[0..account.len];
}

fn normalizedTargetInto(out: *[max_target_key_bytes]u8, target: Target) Error![]const u8 {
    try validateTarget(target);
    out[0] = switch (target.kind) {
        .nick => 'n',
        .account => 'a',
    };
    out[1] = ':';
    for (target.name, 0..) |byte, index| out[target_prefix_bytes + index] = std.ascii.toLower(byte);
    return out[0 .. target_prefix_bytes + target.name.len];
}

fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..needle.len], needle);
}

fn validAccountByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_' => true,
        else => false,
    };
}

fn validNickFirstByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '[', ']', '\\', '`', '_', '^', '{', '|', '}' => true,
        else => false,
    };
}

fn validNickByte(byte: u8) bool {
    return validNickFirstByte(byte) or switch (byte) {
        '0'...'9', '-' => true,
        else => false,
    };
}

const testing = std.testing;

fn expectTarget(target: Target, kind: TargetKind, name: []const u8) !void {
    try testing.expectEqual(kind, target.kind);
    try testing.expectEqualStrings(name, target.name);
}

fn expectWatched(target: WatchedTarget, kind: TargetKind, name: []const u8) !void {
    try testing.expectEqual(kind, target.kind);
    try testing.expectEqualStrings(name, target.name);
}

test "WATCH numeric values are the real daemon numerics" {
    try testing.expectEqual(@as(u16, 600), WatchNumeric.RPL_LOGON.code());
    try testing.expectEqual(@as(u16, 601), WatchNumeric.RPL_LOGOFF.code());
    try testing.expectEqual(@as(u16, 602), WatchNumeric.RPL_WATCHOFF.code());
    try testing.expectEqual(@as(u16, 603), WatchNumeric.RPL_WATCHSTAT.code());
    try testing.expectEqual(@as(u16, 604), WatchNumeric.RPL_NOWON.code());
    try testing.expectEqual(@as(u16, 605), WatchNumeric.RPL_NOWOFF.code());
    try testing.expectEqual(@as(u16, 606), WatchNumeric.RPL_WATCHLIST.code());
    try testing.expectEqual(@as(u16, 607), WatchNumeric.RPL_ENDOFWATCHLIST.code());
    try testing.expectEqual(@as(u16, 512), WatchNumeric.ERR_TOOMANYWATCH.code());
}

test "parser handles real WATCH controls and nick targets" {
    var ops: [5]WatchOp = undefined;
    const parsed = try parseWatchLine("WATCH +Alice -nick:Bob L S C\r\n", &ops);

    try testing.expectEqual(@as(usize, 5), parsed.len);
    try expectTarget(parsed[0].add, .nick, "Alice");
    try expectTarget(parsed[1].remove, .nick, "Bob");
    try testing.expect(parsed[2] == .list);
    try testing.expect(parsed[3] == .status);
    try testing.expect(parsed[4] == .clear);
}

test "parser handles explicit account targets without service pseudo-clients" {
    var ops: [3]WatchOp = undefined;
    const params = [_][]const u8{ "+account:Alice_Account", "-acct:bob.account", "+nick:Carol" };
    const parsed = try parseWatchParams(&params, &ops);

    try expectTarget(parsed[0].add, .account, "Alice_Account");
    try expectTarget(parsed[1].remove, .account, "bob.account");
    try expectTarget(parsed[2].add, .nick, "Carol");
}

test "parser rejects bad command, missing params, and invalid targets" {
    var ops: [1]WatchOp = undefined;

    try testing.expectError(error.InvalidCommand, parseWatchLine("PRIVMSG +alice", &ops));
    try testing.expectError(error.MissingParameter, parseWatchLine("WATCH", &ops));
    try testing.expectError(error.InvalidNick, parseWatchLine("WATCH +1bad", &ops));
    try testing.expectError(error.InvalidAccount, parseWatchLine("WATCH +account:bad/account", &ops));
    try testing.expectError(error.TooManyOperations, parseWatchLine("WATCH +alice -bob", &ops));
}

test "add is idempotent and list is account keyed case-insensitively" {
    var store = WatchStore.init(testing.allocator);
    defer store.deinit();

    try testing.expect(try store.add("Alice", .{ .kind = .nick, .name = "Suzuki" }));
    try testing.expect(!try store.add("alice", .{ .kind = .nick, .name = "suzuki" }));
    try testing.expect(try store.add("ALICE", .{ .kind = .account, .name = "Bob_Account" }));

    const list = try store.list("alice");
    try testing.expectEqual(@as(usize, 2), list.len);
    try expectWatched(list[0], .nick, "suzuki");
    try expectWatched(list[1], .account, "bob_account");
    try testing.expect(try store.isWatching("ALIce", .{ .kind = .nick, .name = "SUZUKI" }));
}

test "reverse index selects only watchers of changed target" {
    var store = WatchStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("alice", .{ .kind = .nick, .name = "target" });
    _ = try store.add("bob", .{ .kind = .nick, .name = "Target" });
    _ = try store.add("carol", .{ .kind = .account, .name = "target" });
    _ = try store.add("dave", .{ .kind = .nick, .name = "other" });

    var out: [4]Notification = undefined;
    var sink = NotificationSink{ .notifications = &out };
    try store.selectNotifications(.{ .kind = .nick, .name = "TARGET" }, .online, &sink);

    const got = sink.slice();
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("alice", got[0].watcher_account);
    try testing.expectEqualStrings("bob", got[1].watcher_account);
    try testing.expectEqual(.online, got[0].presence);
    try testing.expectEqual(WatchNumeric.RPL_LOGON, got[0].numeric);
    try expectWatched(got[0].target, .nick, "target");
}

test "account target notifications are distinct from nick target notifications" {
    var store = WatchStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("alice", .{ .kind = .account, .name = "Shared" });
    _ = try store.add("bob", .{ .kind = .nick, .name = "Shared" });

    var out: [2]Notification = undefined;
    var sink = NotificationSink{ .notifications = &out };
    try store.selectNotifications(.{ .kind = .account, .name = "shared" }, .offline, &sink);

    const got = sink.slice();
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("alice", got[0].watcher_account);
    try testing.expectEqual(WatchNumeric.RPL_LOGOFF, got[0].numeric);
    try expectWatched(got[0].target, .account, "shared");
}

test "remove updates both forward and reverse indexes" {
    var store = WatchStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("alice", .{ .kind = .nick, .name = "target" });
    _ = try store.add("bob", .{ .kind = .nick, .name = "target" });
    try testing.expect(try store.remove("alice", .{ .kind = .nick, .name = "TARGET" }));
    try testing.expect(!try store.remove("alice", .{ .kind = .nick, .name = "target" }));

    const watchers = try store.watchersOf(.{ .kind = .nick, .name = "target" });
    try testing.expectEqual(@as(usize, 1), watchers.len);
    try testing.expectEqualStrings("bob", watchers[0]);
    try testing.expectEqual(@as(usize, 1), store.watcherCount());
    try testing.expectEqual(@as(usize, 1), store.reverseTargetCount());
}

test "clear removes all watches and prunes reverse targets" {
    var store = WatchStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("alice", .{ .kind = .nick, .name = "one" });
    _ = try store.add("alice", .{ .kind = .account, .name = "two" });
    _ = try store.add("bob", .{ .kind = .nick, .name = "one" });

    try testing.expectEqual(@as(usize, 2), try store.clear("ALICE"));
    try testing.expectEqual(@as(usize, 0), (try store.list("alice")).len);

    const one_watchers = try store.watchersOf(.{ .kind = .nick, .name = "one" });
    try testing.expectEqual(@as(usize, 1), one_watchers.len);
    try testing.expectEqualStrings("bob", one_watchers[0]);
    try testing.expectEqual(@as(usize, 0), (try store.watchersOf(.{ .kind = .account, .name = "two" })).len);
}

test "limits map to real too-many-watch condition" {
    var store = WatchStore.initWithConfig(testing.allocator, .{ .max_watchers = 1, .max_watches_per_account = 2 });
    defer store.deinit();

    _ = try store.add("alice", .{ .kind = .nick, .name = "one" });
    _ = try store.add("alice", .{ .kind = .nick, .name = "two" });
    try testing.expectError(error.TooManyWatches, store.add("alice", .{ .kind = .nick, .name = "three" }));
    try testing.expectEqual(WatchNumeric.ERR_TOOMANYWATCH, WatchNumeric.ERR_TOOMANYWATCH);
    try testing.expectError(error.TooManyWatchers, store.add("bob", .{ .kind = .nick, .name = "one" }));
}

test "notification sink reports capacity instead of allocating" {
    var store = WatchStore.init(testing.allocator);
    defer store.deinit();

    _ = try store.add("alice", .{ .kind = .nick, .name = "target" });
    _ = try store.add("bob", .{ .kind = .nick, .name = "target" });

    var out: [1]Notification = undefined;
    var sink = NotificationSink{ .notifications = &out };
    try testing.expectError(
        error.TooManyNotifications,
        store.selectNotifications(.{ .kind = .nick, .name = "target" }, .online, &sink),
    );
}

test "presence helper maps online and offline replies" {
    try testing.expectEqual(WatchNumeric.RPL_LOGON, Presence.online.transitionNumeric());
    try testing.expectEqual(WatchNumeric.RPL_LOGOFF, Presence.offline.transitionNumeric());
    try testing.expectEqual(WatchNumeric.RPL_NOWON, Presence.online.addReplyNumeric());
    try testing.expectEqual(WatchNumeric.RPL_NOWOFF, Presence.offline.addReplyNumeric());
}
