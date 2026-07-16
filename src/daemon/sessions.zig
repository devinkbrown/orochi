// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Multi-session registry: account -> set of live client sessions (Phase 3).
//!
//! Orochi treats an *account* as the durable identity, a reclaim token as one
//! logical resumable session, and each connection as an attachment to that
//! session. Multiple attached rows may therefore deliberately carry the SAME
//! token: presenting a valid token joins the logical session; it does not steal
//! it from another live client. This store tracks, per account, the attachments
//! (client id + logical-session token + signon time) so the daemon can list a
//! user's devices, resume a dropped attachment, and route per-session fan-out.
//! Pure and self-contained: the caller keys attachments by the
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
    /// Optional server-owned encoded restore snapshot for detached sessions.
    snapshot: ?[]u8 = null,
    /// True after a portable (mesh-sealed) resume credential has been revealed
    /// for this exact session. Only opted-in sessions need their detached state
    /// replicated to mesh peers.
    portable_resume: bool = false,
};

pub const ResumeHandle = struct {
    token: Token,
    portable: bool,
};

pub const AttachOutcome = struct {
    session: Session,
    /// Authority silently displaced to make room for the new live attachment.
    /// The daemon uses this to publish a mesh REVOKE if this was the last local
    /// row for an opted-in portable token.
    evicted: ?ResumeHandle = null,
};

pub const DetachedSnapshot = struct {
    client: ClientId,
    signon_ms: i64,
    snapshot: []u8,
};

pub const PortableDetachedSnapshot = struct {
    account: []u8,
    token: Token,
    snapshot: []u8,

    pub fn deinit(self: *PortableDetachedSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.snapshot);
        self.* = undefined;
    }
};

const SessionList = struct {
    items: std.ArrayListUnmanaged(Session) = .empty,

    fn deinit(self: *SessionList, allocator: std.mem.Allocator) void {
        for (self.items.items) |*session| freeSnapshot(allocator, session);
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
        return (try self.attachReportingEviction(account, client, token, signon_ms)).session;
    }

    /// `attach`, plus the portable authority of an oldest detached row evicted
    /// at the per-account cap. Keeping the legacy `attach` wrapper makes pure
    /// callers simple while letting the live daemon close the mesh lifecycle.
    pub fn attachReportingEviction(self: *SessionStore, account: []const u8, client: ClientId, token: Token, signon_ms: i64) Error!AttachOutcome {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = try self.ensureAccount(account);
        if (list.indexOfClient(client)) |idx| {
            const displaced = list.items.items[idx];
            freeSnapshot(self.allocator, &list.items.items[idx]);
            list.items.items[idx] = .{ .client = client, .token = token, .signon_ms = signon_ms, .attached = true };
            return .{
                .session = list.items.items[idx],
                .evicted = .{ .token = displaced.token, .portable = displaced.portable_resume },
            };
        }
        var evicted: ?ResumeHandle = null;
        if (list.items.items.len >= self.cfg.max_sessions_per_account) {
            // At cap: evict the oldest *detached* ghost to make room for the live
            // session. Never evict an attached session (that would drop a peer).
            if (oldestDetached(list)) |evict| {
                const displaced = list.items.items[evict];
                evicted = .{ .token = displaced.token, .portable = displaced.portable_resume };
                freeSnapshot(self.allocator, &list.items.items[evict]);
                _ = list.items.swapRemove(evict);
            } else return error.TooManySessions;
        }
        const session = Session{ .client = client, .token = token, .signon_ms = signon_ms, .attached = true };
        try list.items.append(self.allocator, session);
        return .{ .session = session, .evicted = evicted };
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
        return self.markDetachedWithSnapshot(account, client, null);
    }

    /// Mark a session detached and persist an optional encoded restore snapshot.
    /// The snapshot is copied into the store and freed when the session is
    /// reattached, removed, evicted, or the account is dropped.
    pub fn markDetachedWithSnapshot(self: *SessionStore, account: []const u8, client: ClientId, snapshot: ?[]const u8) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        const session = &list.items.items[idx];
        const copied = if (snapshot) |bytes|
            if (bytes.len != 0) self.allocator.dupe(u8, bytes) catch null else null
        else
            null;
        freeSnapshot(self.allocator, session);
        session.snapshot = copied;
        session.attached = false;
        return true;
    }

    /// Mark that this session's portable resume credential was successfully
    /// emitted to its owner. Idempotent; never creates a session implicitly.
    pub fn markPortableResumeIssued(self: *SessionStore, account: []const u8, client: ClientId) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        list.items.items[idx].portable_resume = true;
        return true;
    }

    /// Restore the carried portable-resume bit during a Helix adoption. This is
    /// deliberately separate from `attach`: a normal re-attach rotates the local
    /// token and resets portability, while an in-place upgrade preserves both.
    pub fn restorePortableResumeIssued(self: *SessionStore, account: []const u8, client: ClientId, issued: bool) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        list.items.items[idx].portable_resume = issued;
        return true;
    }

    /// Return the stable local token and portability state for one tracked
    /// connection. Used by detach to decide whether a peer snapshot is owed.
    pub fn resumeHandleForClient(self: *const SessionStore, account: []const u8, client: ClientId) ?ResumeHandle {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        const idx = list.indexOfClient(client) orelse return null;
        const session = list.items.items[idx];
        return .{ .token = session.token, .portable = session.portable_resume };
    }

    /// Join `client` to the logical session identified by `token`. The client
    /// must already be tracked under `account`; this only rebinds its generated
    /// first-login token to the presented stable session credential. Other live
    /// attachments keep the same token and remain connected. Portable issuance
    /// is group-wide: a newly joined attachment inherits it from any sibling so
    /// its later detach is replicated too.
    pub fn joinTokenGroup(self: *SessionStore, account: []const u8, client: ClientId, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        var portable = list.items.items[idx].portable_resume;
        var found = false;
        for (list.items.items) |session| {
            if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
            found = true;
            portable = portable or session.portable_resume;
        }
        if (!found) return false;
        list.items.items[idx].token = token;
        list.items.items[idx].portable_resume = portable;
        return true;
    }

    /// Bind a tracked client to a token whose authority was established outside
    /// the local store (for example by a verified mesh credential + signed
    /// migration replica). Unlike `joinTokenGroup`, this does not require a
    /// pre-existing local attachment bearing the token.
    pub fn adoptTokenGroup(self: *SessionStore, account: []const u8, client: ClientId, token: Token, portable: bool) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        list.items.items[idx].token = token;
        list.items.items[idx].portable_resume = portable;
        return true;
    }

    /// Whether this exact attached client already belongs to `token`'s logical
    /// session. Kept separate from token lookup because duplicate tokens across
    /// live attachments are intentional.
    pub fn clientHasToken(self: *const SessionStore, account: []const u8, client: ClientId, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        return std.crypto.timing_safe.eql(Token, list.items.items[idx].token, token);
    }

    /// Exact client membership probe that does not truncate at the public list
    /// snapshot size. Session tracking uses this so high configured caps cannot
    /// accidentally mint a second token for an already-tracked client.
    pub fn containsClient(self: *const SessionStore, account: []const u8, client: ClientId) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return false;
        return list.indexOfClient(client) != null;
    }

    /// Fully remove a session (e.g. explicit logout / reclaim consumed). Prunes
    /// the account when its last session goes. Returns true if removed.
    pub fn remove(self: *SessionStore, account: []const u8, client: ClientId) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOfClient(client) orelse return false;
        freeSnapshot(self.allocator, &entry.value_ptr.items.items[idx]);
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
                freeSnapshot(self.allocator, &entry.value_ptr.items.items[idx]);
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
        for (out[0..n]) |*session| session.snapshot = null;
        return out[0..n];
    }

    /// Allocate an exact, complete snapshot for callers whose correctness cannot
    /// depend on a fixed stack buffer. Snapshot payload pointers are deliberately
    /// stripped; use the dedicated detached-snapshot APIs for owned payload data.
    pub fn copySessionsAlloc(self: *const SessionStore, allocator: std.mem.Allocator, account: []const u8) std.mem.Allocator.Error![]Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return try allocator.alloc(Session, 0);
        const out = try allocator.alloc(Session, list.items.items.len);
        @memcpy(out, list.items.items);
        for (out) |*session| session.snapshot = null;
        return out;
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
            if (std.crypto.timing_safe.eql(Token, s.token, token)) {
                var copied = s;
                copied.snapshot = null;
                return copied;
            }
        }
        return null;
    }

    /// Find a LIVE attachment to `token`, excluding the caller. A stable session
    /// credential is reusable, so this is the source from which a second client
    /// clones current state and joins the same live token group.
    pub fn findAttachedTokenSessionInAccount(
        self: *const SessionStore,
        account: []const u8,
        token: Token,
        exclude_client: ClientId,
    ) ?Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        for (list.items.items) |s| {
            if (s.client == exclude_client or !s.attached) continue;
            if (!std.crypto.timing_safe.eql(Token, s.token, token)) continue;
            var copied = s;
            copied.snapshot = null;
            return copied;
        }
        return null;
    }

    /// Find the newest detached attachment to `token`. Attached rows bearing the
    /// same group token are skipped instead of hiding a valid detached snapshot.
    pub fn findDetachedTokenSessionInAccount(self: *const SessionStore, account: []const u8, token: Token) ?Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        var best: ?Session = null;
        for (list.items.items) |s| {
            if (s.attached or !std.crypto.timing_safe.eql(Token, s.token, token)) continue;
            if (best == null or s.signon_ms >= best.?.signon_ms) {
                best = s;
                best.?.snapshot = null;
            }
        }
        return best;
    }

    /// Detached lookup within a reusable logical-session token group. Attached
    /// siblings bearing the same token do not mask the detached row.
    pub fn findDetachedTokenInAccount(self: *const SessionStore, account: []const u8, token: Token) ?ClientId {
        const s = self.findDetachedTokenSessionInAccount(account, token) orelse return null;
        return s.client;
    }

    /// Copy the encoded restore snapshot for a detached token in `account`.
    /// Returns null when the token is unknown, still attached, or has no snapshot.
    pub fn copyDetachedSnapshotInAccount(
        self: *const SessionStore,
        allocator: std.mem.Allocator,
        account: []const u8,
        token: Token,
    ) std.mem.Allocator.Error!?[]u8 {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        var matched: ?*const Session = null;
        for (list.items.items) |*s| {
            if (!std.crypto.timing_safe.eql(Token, s.token, token)) continue;
            if (s.attached or s.snapshot == null) continue;
            if (matched == null or s.signon_ms >= matched.?.signon_ms) matched = s;
        }
        const bytes = (matched orelse return null).snapshot.?;
        return try allocator.dupe(u8, bytes);
    }

    /// Copy the newest detached restore snapshot for `account`, excluding the
    /// caller's current live client id. Used by login-time auto-restore so a
    /// reconnecting web client does not autojoin channels under a generated nick
    /// while waiting for an explicit SESSION RESUME round trip.
    pub fn copyNewestDetachedSnapshotInAccount(
        self: *const SessionStore,
        allocator: std.mem.Allocator,
        account: []const u8,
        exclude_client: ClientId,
    ) std.mem.Allocator.Error!?DetachedSnapshot {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        var matched_client: ClientId = 0;
        var matched_signon: i64 = std.math.minInt(i64);
        var matched_snapshot: ?[]u8 = null;
        for (list.items.items) |s| {
            if (s.client == exclude_client or s.attached) continue;
            const bytes = s.snapshot orelse continue;
            if (matched_snapshot == null or s.signon_ms >= matched_signon) {
                matched_client = s.client;
                matched_signon = s.signon_ms;
                matched_snapshot = bytes;
            }
        }
        const bytes = matched_snapshot orelse return null;
        return .{
            .client = matched_client,
            .signon_ms = matched_signon,
            .snapshot = try allocator.dupe(u8, bytes),
        };
    }

    /// Deep-copy every detached snapshot whose portable credential was issued.
    /// Used when a secured peer (re)establishes after missing the detach-time
    /// broadcast. The returned records and outer slice are caller-owned.
    pub fn copyPortableDetachedSnapshots(self: *const SessionStore, allocator: std.mem.Allocator) std.mem.Allocator.Error![]PortableDetachedSnapshot {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        var count: usize = 0;
        var count_it = self.accounts.iterator();
        while (count_it.next()) |entry| {
            for (entry.value_ptr.items.items) |session| {
                if (!session.attached and session.portable_resume and session.snapshot != null) count += 1;
            }
        }

        const out = try allocator.alloc(PortableDetachedSnapshot, count);
        errdefer allocator.free(out);
        var n: usize = 0;
        errdefer for (out[0..n]) |*record| record.deinit(allocator);
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |session| {
                if (session.attached or !session.portable_resume) continue;
                const snapshot = session.snapshot orelse continue;
                const account = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(account);
                const copied = try allocator.dupe(u8, snapshot);
                out[n] = .{ .account = account, .token = session.token, .snapshot = copied };
                n += 1;
            }
        }
        return out;
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

fn freeSnapshot(allocator: std.mem.Allocator, session: *Session) void {
    if (session.snapshot) |bytes| allocator.free(bytes);
    session.snapshot = null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn tok(b: u8) Token {
    return @as([16]u8, @splat(b));
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

test "detached session snapshots are copied and released across lifecycle paths" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "nick=alice;channels=#root,#ops"));

    const copied = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(1))).?;
    defer testing.allocator.free(copied);
    try testing.expectEqualStrings("nick=alice;channels=#root,#ops", copied);

    _ = try s.attach("alice", 2, tok(2), 20); // evicts detached client 1 and its snapshot
    try testing.expect((try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(1))) == null);
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "second"));
    _ = try s.attach("alice", 2, tok(3), 30); // reattach same client frees old snapshot
    try testing.expect((try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(3))) == null);
}

test "portable resume issuance is explicit and resets on a normal re-attach" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expectEqual(false, s.resumeHandleForClient("alice", 1).?.portable);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expectEqual(true, s.resumeHandleForClient("alice", 1).?.portable);

    // A normal same-client attach rotates the token and requires the client to
    // request a fresh portable credential.
    _ = try s.attach("alice", 1, tok(2), 20);
    const refreshed = s.resumeHandleForClient("alice", 1).?;
    try testing.expectEqualSlices(u8, &tok(2), &refreshed.token);
    try testing.expectEqual(false, refreshed.portable);

    // Helix adoption is the exceptional path: it restores the carried bit.
    try testing.expect(s.restorePortableResumeIssued("alice", 1, true));
    try testing.expectEqual(true, s.resumeHandleForClient("alice", 1).?.portable);
}

test "attach reports portable authority displaced by same-client replacement" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    const outcome = try s.attachReportingEviction("alice", 1, tok(2), 20);
    const evicted = outcome.evicted orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &tok(1), &evicted.token);
    try testing.expect(evicted.portable);
    try testing.expectEqualSlices(u8, &tok(2), &outcome.session.token);
}

test "attach reports portable detached authority evicted at account cap" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetached("alice", 1));
    const outcome = try s.attachReportingEviction("alice", 2, tok(2), 20);
    const evicted = outcome.evicted orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &tok(1), &evicted.token);
    try testing.expect(evicted.portable);
    try testing.expectEqualSlices(u8, &tok(2), &outcome.session.token);
}

test "portable detached anti-entropy copies only opted-in snapshots" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 1);
    _ = try s.attach("alice", 2, tok(2), 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "portable"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "local-only"));

    const copies = try s.copyPortableDetachedSnapshots(testing.allocator);
    defer {
        for (copies) |*copy| copy.deinit(testing.allocator);
        testing.allocator.free(copies);
    }
    try testing.expectEqual(@as(usize, 1), copies.len);
    try testing.expectEqualStrings("alice", copies[0].account);
    try testing.expectEqualStrings("portable", copies[0].snapshot);
    try testing.expectEqualSlices(u8, &tok(1), &copies[0].token);
}

test "copyNewestDetachedSnapshotInAccount ignores current client and returns newest ghost" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    _ = try s.attach("alice", 2, tok(2), 30);
    _ = try s.attach("alice", 3, tok(3), 20);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "old"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "new"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 3, "current"));

    const copied = (try s.copyNewestDetachedSnapshotInAccount(testing.allocator, "alice", 3)).?;
    defer testing.allocator.free(copied.snapshot);
    try testing.expectEqual(@as(ClientId, 2), copied.client);
    try testing.expectEqual(@as(i64, 30), copied.signon_ms);
    try testing.expectEqualStrings("new", copied.snapshot);

    _ = try s.attach("alice", 4, tok(4), 40);
    const copied_again = (try s.copyNewestDetachedSnapshotInAccount(testing.allocator, "alice", 4)).?;
    defer testing.allocator.free(copied_again.snapshot);
    try testing.expectEqual(@as(ClientId, 2), copied_again.client);
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

test "detached token lookup ignores attached members of the same token group" {
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

test "multiple live clients join one reusable token group" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0xAA), 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    _ = try s.attach("alice", 2, tok(0xBB), 20);
    try testing.expect(s.joinTokenGroup("alice", 2, tok(0xAA)));

    try testing.expect(s.clientHasToken("alice", 1, tok(0xAA)));
    try testing.expect(s.clientHasToken("alice", 2, tok(0xAA)));
    try testing.expectEqual(true, s.resumeHandleForClient("alice", 2).?.portable);
    try testing.expectEqual(@as(ClientId, 1), s.findAttachedTokenSessionInAccount("alice", tok(0xAA), 2).?.client);

    // A detached member remains discoverable even while another attachment to
    // the same logical session is live.
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "shared-state"));
    try testing.expectEqual(@as(ClientId, 1), s.findDetachedTokenInAccount("alice", tok(0xAA)).?);
    const copied = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(0xAA))).?;
    defer testing.allocator.free(copied);
    try testing.expectEqualStrings("shared-state", copied);
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

test "allocated session snapshot is complete above the legacy stack capacity" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = snapshot_capacity + 8 });
    defer s.deinit();
    for (0..snapshot_capacity + 8) |i| {
        var token: Token = @splat(0);
        std.mem.writeInt(u64, token[0..8], i, .little);
        _ = try s.attach("wide", @intCast(i + 1), token, @intCast(i));
    }

    const all = try s.copySessionsAlloc(testing.allocator, "wide");
    defer testing.allocator.free(all);
    try testing.expectEqual(snapshot_capacity + 8, all.len);
    try testing.expect(s.containsClient("wide", snapshot_capacity + 8));
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
