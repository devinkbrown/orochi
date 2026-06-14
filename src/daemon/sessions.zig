//! Multi-session registry: account -> set of live client sessions (Phase 3).
//!
//! Orochi treats an *account* as the durable identity and each connection as a
//! *session* of that account. This store tracks, per account, the live sessions
//! (client id + a reclaim token + signon time) so the daemon can list a user's
//! devices (`SESSION`), reclaim a dropped session by token, and route per-account
//! fan-out (bouncer). Pure and self-contained: the caller keys sessions by the
//! flat `u64` client id (the same packed id used by MONITOR / activity subs) and
//! supplies the reclaim token (generated from the daemon CSPRNG). A flat per-
//! account list keeps ownership trivial (one owned account-name key per account).
const std = @import("std");
const rwlock = @import("../substrate/rwlock.zig");

pub const ClientId = u64;
pub const Token = [16]u8;
pub const snapshot_capacity: usize = 64;

pub const Error = std.mem.Allocator.Error || error{ TooManyAccounts, TooManySessions };

pub const Config = struct {
    max_accounts: usize = 65536,
    max_sessions_per_account: usize = snapshot_capacity,
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
    lock: rwlock.RwLock = .{},

    pub fn init(allocator: std.mem.Allocator) SessionStore {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) SessionStore {
        return .{ .allocator = allocator, .cfg = cfg, .accounts = std.StringHashMap(SessionList).init(allocator) };
    }

    pub fn deinit(self: *SessionStore) void {
        {
            self.lock.lockExclusive();
            defer self.lock.unlockExclusive();

            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.accounts.deinit();
        }
        self.* = undefined;
    }

    /// Register a live session for `account`. Idempotent on `client` (re-attach
    /// refreshes its token/signon and marks it attached). Returns the session.
    pub fn attach(self: *SessionStore, account: []const u8, client: ClientId, token: Token, signon_ms: i64) Error!Session {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

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
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        list.items.items[idx].attached = false;
        return true;
    }

    /// Fully remove a session (e.g. explicit logout / reclaim consumed). Prunes
    /// the account when its last session goes. Returns true if removed.
    pub fn remove(self: *SessionStore, account: []const u8, client: ClientId) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOfClient(client) orelse return false;
        _ = entry.value_ptr.items.swapRemove(idx);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return true;
    }

    /// Drop a client from whatever account holds it (disconnect path, when the
    /// caller may not know the account). Returns the account name match count (0/1).
    pub fn removeClient(self: *SessionStore, client: ClientId) usize {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

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

    /// Copy a snapshot of the session list for `account` into caller-owned
    /// storage (empty if none). The returned slice borrows `out`, not the store.
    pub fn sessionsInto(self: *const SessionStore, account: []const u8, out: []Session) []const Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return out[0..0];
        const n = @min(list.items.items.len, out.len);
        @memcpy(out[0..n], list.items.items[0..n]);
        return out[0..n];
    }

    pub const Match = struct { account: []const u8, client: ClientId };

    /// Find the session bearing `token` (for reclaim). The returned `account`
    /// borrows `account_out`, not the store.
    pub fn findByTokenInto(self: *const SessionStore, token: Token, account_out: []u8) ?Match {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |s| {
                if (std.crypto.timing_safe.eql(Token, s.token, token)) {
                    if (entry.key_ptr.*.len > account_out.len) return null;
                    @memcpy(account_out[0..entry.key_ptr.*.len], entry.key_ptr.*);
                    return .{ .account = account_out[0..entry.key_ptr.*.len], .client = s.client };
                }
            }
        }
        return null;
    }

    /// Look up a session by token *within* `account` (reclaim is scoped to the
    /// caller's own account — a token never reaches across accounts). Returns the
    /// matched client id, or null if no session in `account` bears the token.
    pub fn findTokenInAccount(self: *const SessionStore, account: []const u8, token: Token) ?ClientId {
        return if (self.findTokenSessionInAccount(account, token)) |s| s.client else null;
    }

    /// Look up a session by token *within* `account`, returning a copied snapshot
    /// so callers can distinguish attached live sessions from detached ghosts.
    pub fn findTokenSessionInAccount(self: *const SessionStore, account: []const u8, token: Token) ?Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        for (list.items.items) |s| {
            if (std.crypto.timing_safe.eql(Token, s.token, token)) return s;
        }
        return null;
    }

    /// Reclaim lookup that intentionally ignores still-attached sessions. A live
    /// sibling token must not be consumable by another connection of the account.
    pub fn findDetachedTokenInAccount(self: *const SessionStore, account: []const u8, token: Token) ?ClientId {
        const s = self.findTokenSessionInAccount(account, token) orelse return null;
        return if (s.attached) null else s.client;
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
    var out: [64]Session = undefined;
    _ = try s.attach("alice", 1, tok(1), 100);
    _ = try s.attach("alice", 2, tok(2), 200);
    try testing.expectEqual(@as(usize, 2), s.sessionsInto("alice", &out).len);
    // Re-attaching the same client refreshes, not duplicates.
    _ = try s.attach("alice", 1, tok(9), 300);
    try testing.expectEqual(@as(usize, 2), s.sessionsInto("alice", &out).len);
}

test "markDetached retains the session; remove prunes; empty account drops" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var out: [64]Session = undefined;
    _ = try s.attach("bob", 7, tok(7), 1);
    try testing.expect(s.markDetached("bob", 7));
    const retained = s.sessionsInto("bob", &out);
    try testing.expectEqual(@as(usize, 1), retained.len); // retained
    try testing.expect(!retained[0].attached);
    try testing.expect(s.remove("bob", 7));
    try testing.expectEqual(@as(usize, 0), s.sessionsInto("bob", &out).len); // account pruned
}

test "findByTokenInto locates a session for reclaim" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var account_buf: [64]u8 = undefined;
    _ = try s.attach("alice", 1, tok(0xAB), 1);
    _ = try s.attach("carol", 2, tok(0xCD), 1);
    const m = s.findByTokenInto(tok(0xCD), &account_buf).?;
    try testing.expectEqualStrings("carol", m.account);
    try testing.expectEqual(@as(ClientId, 2), m.client);
    try testing.expect(s.findByTokenInto(tok(0xEE), &account_buf) == null);
}

test "removeClient drops a client without knowing its account" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var out: [64]Session = undefined;
    _ = try s.attach("alice", 1, tok(1), 1);
    _ = try s.attach("alice", 2, tok(2), 1);
    try testing.expectEqual(@as(usize, 1), s.removeClient(1));
    try testing.expectEqual(@as(usize, 1), s.sessionsInto("alice", &out).len);
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
    var out: [2]Session = undefined;
    _ = try s.attach("alice", 1, tok(1), 10); // older
    _ = try s.attach("alice", 2, tok(2), 20);
    try testing.expect(s.markDetached("alice", 1)); // client 1 is the ghost
    // New live session evicts the detached ghost (client 1), not client 2.
    _ = try s.attach("alice", 3, tok(3), 30);
    try testing.expectEqual(@as(usize, 2), s.sessionsInto("alice", &out).len);
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

test "findDetachedTokenInAccount rejects attached sibling tokens" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0xAB), 1);
    _ = try s.attach("alice", 2, tok(0xCD), 2);
    try testing.expect(s.findDetachedTokenInAccount("alice", tok(0xCD)) == null);

    try testing.expect(s.markDetached("alice", 2));
    try testing.expectEqual(@as(ClientId, 2), s.findDetachedTokenInAccount("alice", tok(0xCD)).?);
    const snap = s.findTokenSessionInAccount("alice", tok(0xCD)).?;
    try testing.expect(!snap.attached);
}

test "sessionsInto and findByTokenInto do not retain snapshots" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 1);

    var out: [64]Session = undefined;
    var account_buf: [64]u8 = undefined;
    for (0..10_000) |_| {
        const list = s.sessionsInto("alice", &out);
        try testing.expectEqual(@as(usize, 1), list.len);
        try testing.expectEqual(@as(ClientId, 1), list[0].client);
        const found = s.findByTokenInto(tok(1), &account_buf).?;
        try testing.expectEqualStrings("alice", found.account);
        try testing.expectEqual(@as(ClientId, 1), found.client);
    }
}

const SessionMtCtx = struct {
    store: *SessionStore,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    fn account(out: *[16]u8, writer_id: usize) []const u8 {
        return std.fmt.bufPrint(out, "acct{d}", .{writer_id}) catch unreachable;
    }

    fn tempAccount(out: *[24]u8, writer_id: usize, i: usize) []const u8 {
        return std.fmt.bufPrint(out, "tmp{d}_{d}", .{ writer_id, i }) catch unreachable;
    }

    fn client(writer_id: usize, i: usize) ClientId {
        return @intCast(1000 + writer_id * 100 + i);
    }

    fn tempClient(writer_id: usize, i: usize) ClientId {
        return @intCast(10000 + writer_id * 100 + i);
    }

    fn writer(ctx: *SessionMtCtx) void {
        var acct_buf: [16]u8 = undefined;
        var tmp_buf: [24]u8 = undefined;
        const acct = account(&acct_buf, ctx.writer_id);
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const cid = client(ctx.writer_id, i);
            _ = ctx.store.attach(acct, cid, tok(@intCast(i + 2)), @intCast(i)) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if ((i & 1) == 0) {
                if (!ctx.store.markDetached(acct, cid)) {
                    _ = ctx.failures.fetchAdd(1, .monotonic);
                    return;
                }
                _ = ctx.store.attach(acct, cid, tok(@intCast(i + 3)), @intCast(i + 1000)) catch {
                    _ = ctx.failures.fetchAdd(1, .monotonic);
                    return;
                };
            }

            const tmp = tempAccount(&tmp_buf, ctx.writer_id, i);
            const tmp_cid = tempClient(ctx.writer_id, i);
            _ = ctx.store.attach(tmp, tmp_cid, tok(@intCast(i + 4)), @intCast(i)) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            const removed = if ((i & 1) == 0)
                ctx.store.remove(tmp, tmp_cid)
            else
                ctx.store.removeClient(tmp_cid) == 1;
            if (!removed) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
        }
    }

    fn reader(ctx: *SessionMtCtx) void {
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            var out: [64]Session = undefined;
            var account_buf: [64]u8 = undefined;
            const seed_sessions = ctx.store.sessionsInto("seed", &out);
            if (seed_sessions.len != 1 or seed_sessions[0].client != 1) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            const found = ctx.store.findByTokenInto(tok(1), &account_buf) orelse {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (!std.mem.eql(u8, found.account, "seed") or found.client != 1) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            if (ctx.store.findTokenInAccount("seed", tok(1)) != 1) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
        }
    }
};

test "SessionStore concurrent writers and readers preserve sessions" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("seed", 1, tok(1), 1);

    const writers = 4;
    const readers = 4;
    const iters = 64;
    var failures = std.atomic.Value(u32).init(0);
    var ctxs: [writers]SessionMtCtx = undefined;
    for (0..writers) |i| {
        ctxs[i] = .{ .store = &s, .writer_id = i, .iters = iters, .failures = &failures };
    }

    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, SessionMtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, SessionMtCtx.reader, .{&ctxs[i % writers]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    var seed_out: [64]Session = undefined;
    try testing.expectEqual(@as(usize, 1), s.sessionsInto("seed", &seed_out).len);
    var acct_buf: [16]u8 = undefined;
    for (0..writers) |w| {
        const acct = SessionMtCtx.account(&acct_buf, w);
        var out: [64]Session = undefined;
        const list = s.sessionsInto(acct, &out);
        try testing.expectEqual(@as(usize, iters), list.len);
        for (list) |session| try testing.expect(session.attached);
    }
}
