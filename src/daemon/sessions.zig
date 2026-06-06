//! Multi-session registry: account -> set of live client sessions (Phase 3).
//!
//! Mizuchi treats an *account* as the durable identity and each connection as a
//! *session* of that account. This store tracks, per account, the live sessions
//! (client id + a reclaim token + signon time) so the daemon can list a user's
//! devices (`SESSION`), reclaim a dropped session by token, and route per-account
//! fan-out (bouncer). Pure and self-contained: the caller keys sessions by the
//! flat `u64` client id (the same packed id used by MONITOR / activity subs) and
//! supplies the reclaim token (generated from the daemon CSPRNG). A flat per-
//! account list keeps ownership trivial (one owned account-name key per account).
const std = @import("std");

pub const ClientId = u64;
pub const Token = [16]u8;

pub const Error = std.mem.Allocator.Error || error{ TooManyAccounts, TooManySessions };

pub const Config = struct {
    max_accounts: usize = 65536,
    max_sessions_per_account: usize = 64,
};

pub const Session = struct {
    client: ClientId,
    token: Token,
    signon_ms: i64,
    /// True while the underlying connection is attached; false when the client
    /// dropped but the session is retained for reclaim/bouncer buffering.
    attached: bool = true,
};

const SessionList = struct {
    items: std.ArrayListUnmanaged(Session) = .empty,

    fn deinit(self: *SessionList, allocator: std.mem.Allocator) void {
        self.items.deinit(allocator);
    }

    fn indexOfClient(self: *const SessionList, client: ClientId) ?usize {
        for (self.items.items, 0..) |s, i| {
            if (s.client == client) return i;
        }
        return null;
    }
};

pub const SessionStore = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    accounts: std.StringHashMap(SessionList),

    pub fn init(allocator: std.mem.Allocator) SessionStore {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) SessionStore {
        return .{ .allocator = allocator, .cfg = cfg, .accounts = std.StringHashMap(SessionList).init(allocator) };
    }

    pub fn deinit(self: *SessionStore) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    /// Register a live session for `account`. Idempotent on `client` (re-attach
    /// refreshes its token/signon and marks it attached). Returns the session.
    pub fn attach(self: *SessionStore, account: []const u8, client: ClientId, token: Token, signon_ms: i64) Error!Session {
        const list = try self.ensureAccount(account);
        if (list.indexOfClient(client)) |idx| {
            list.items.items[idx] = .{ .client = client, .token = token, .signon_ms = signon_ms, .attached = true };
            return list.items.items[idx];
        }
        if (list.items.items.len >= self.cfg.max_sessions_per_account) {
            // At cap: evict the oldest *detached* ghost to make room for the live
            // session. Never evict an attached session (that would drop a peer).
            if (oldestDetached(list)) |evict| {
                _ = list.items.swapRemove(evict);
            } else return error.TooManySessions;
        }
        const session = Session{ .client = client, .token = token, .signon_ms = signon_ms, .attached = true };
        try list.items.append(self.allocator, session);
        return session;
    }

    /// Index of the oldest (lowest signon) detached session in `list`, or null.
    fn oldestDetached(list: *const SessionList) ?usize {
        var best: ?usize = null;
        for (list.items.items, 0..) |s, i| {
            if (s.attached) continue;
            if (best) |b| {
                if (s.signon_ms < list.items.items[b].signon_ms) best = i;
            } else best = i;
        }
        return best;
    }

    /// Mark a session detached (connection dropped) but retain it for reclaim/
    /// bouncer. Returns true if it was present. The session is NOT removed.
    pub fn markDetached(self: *SessionStore, account: []const u8, client: ClientId) bool {
        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        list.items.items[idx].attached = false;
        return true;
    }

    /// Fully remove a session (e.g. explicit logout / reclaim consumed). Prunes
    /// the account when its last session goes. Returns true if removed.
    pub fn remove(self: *SessionStore, account: []const u8, client: ClientId) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOfClient(client) orelse return false;
        _ = entry.value_ptr.items.swapRemove(idx);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return true;
    }

    /// Drop a client from whatever account holds it (disconnect path, when the
    /// caller may not know the account). Returns the account name match count (0/1).
    pub fn removeClient(self: *SessionStore, client: ClientId) usize {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.indexOfClient(client)) |idx| {
                _ = entry.value_ptr.items.swapRemove(idx);
                if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
                return 1;
            }
        }
        return 0;
    }

    /// Borrowed session list for `account` (empty if none). Valid until the next
    /// mutation touching this account.
    pub fn sessions(self: *const SessionStore, account: []const u8) []const Session {
        const list = self.accounts.getPtr(account) orelse return &.{};
        return list.items.items;
    }

    pub const Match = struct { account: []const u8, client: ClientId };

    /// Find the session bearing `token` (for reclaim). The returned `account`
    /// borrows the store's key storage.
    pub fn findByToken(self: *const SessionStore, token: Token) ?Match {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |s| {
                if (std.mem.eql(u8, &s.token, &token)) return .{ .account = entry.key_ptr.*, .client = s.client };
            }
        }
        return null;
    }

    /// Look up a session by token *within* `account` (reclaim is scoped to the
    /// caller's own account — a token never reaches across accounts). Returns the
    /// matched client id, or null if no session in `account` bears the token.
    pub fn findTokenInAccount(self: *const SessionStore, account: []const u8, token: Token) ?ClientId {
        const list = self.accounts.getPtr(account) orelse return null;
        for (list.items.items) |s| {
            if (std.mem.eql(u8, &s.token, &token)) return s.client;
        }
        return null;
    }

    fn ensureAccount(self: *SessionStore, account: []const u8) Error!*SessionList {
        if (self.accounts.getPtr(account)) |list| return list;
        if (self.accounts.count() >= self.cfg.max_accounts) return error.TooManyAccounts;
        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.accounts.putNoClobber(owned, .{});
        return self.accounts.getPtr(account).?;
    }

    fn dropAccount(self: *SessionStore, entry: std.StringHashMap(SessionList).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn tok(b: u8) Token {
    return [_]u8{b} ** 16;
}

test "attach lists a multi-device account; idempotent re-attach" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 100);
    _ = try s.attach("alice", 2, tok(2), 200);
    try testing.expectEqual(@as(usize, 2), s.sessions("alice").len);
    // Re-attaching the same client refreshes, not duplicates.
    _ = try s.attach("alice", 1, tok(9), 300);
    try testing.expectEqual(@as(usize, 2), s.sessions("alice").len);
}

test "markDetached retains the session; remove prunes; empty account drops" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("bob", 7, tok(7), 1);
    try testing.expect(s.markDetached("bob", 7));
    try testing.expectEqual(@as(usize, 1), s.sessions("bob").len); // retained
    try testing.expect(!s.sessions("bob")[0].attached);
    try testing.expect(s.remove("bob", 7));
    try testing.expectEqual(@as(usize, 0), s.sessions("bob").len); // account pruned
}

test "findByToken locates a session for reclaim" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(0xAB), 1);
    _ = try s.attach("carol", 2, tok(0xCD), 1);
    const m = s.findByToken(tok(0xCD)).?;
    try testing.expectEqualStrings("carol", m.account);
    try testing.expectEqual(@as(ClientId, 2), m.client);
    try testing.expect(s.findByToken(tok(0xEE)) == null);
}

test "removeClient drops a client without knowing its account" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 1);
    _ = try s.attach("alice", 2, tok(2), 1);
    try testing.expectEqual(@as(usize, 1), s.removeClient(1));
    try testing.expectEqual(@as(usize, 1), s.sessions("alice").len);
    try testing.expectEqual(@as(usize, 0), s.removeClient(999)); // unknown
}

test "per-account session cap is enforced for attached sessions" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 1);
    _ = try s.attach("alice", 2, tok(2), 1);
    try testing.expectError(error.TooManySessions, s.attach("alice", 3, tok(3), 1));
}

test "at cap, attach evicts the oldest detached ghost instead of failing" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 10); // older
    _ = try s.attach("alice", 2, tok(2), 20);
    try testing.expect(s.markDetached("alice", 1)); // client 1 is the ghost
    // New live session evicts the detached ghost (client 1), not client 2.
    _ = try s.attach("alice", 3, tok(3), 30);
    try testing.expectEqual(@as(usize, 2), s.sessions("alice").len);
    try testing.expect(s.findTokenInAccount("alice", tok(1)) == null); // evicted
    try testing.expectEqual(@as(ClientId, 2), s.findTokenInAccount("alice", tok(2)).?);
    try testing.expectEqual(@as(ClientId, 3), s.findTokenInAccount("alice", tok(3)).?);
}

test "findTokenInAccount is scoped to the account" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(0xAB), 1);
    _ = try s.attach("bob", 2, tok(0xCD), 1);
    try testing.expectEqual(@as(ClientId, 1), s.findTokenInAccount("alice", tok(0xAB)).?);
    // bob's token must not resolve under alice.
    try testing.expect(s.findTokenInAccount("alice", tok(0xCD)) == null);
}
