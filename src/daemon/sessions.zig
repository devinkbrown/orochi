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
    /// A local state mutation for this reusable token has not yet been accepted
    /// by the signed replica store. Dirty is a token-group property: whenever
    /// one row is dirty, every local row bearing the exact token is dirty.
    replica_dirty: bool = false,
    /// A signed replica was accepted but has not yet been projected into every
    /// local attachment's live state. This receive-side retry lane is separate
    /// from `replica_dirty` so projection never mints or republishes a replica.
    replica_projection_dirty: bool = false,
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

/// Authority used to bind one already-tracked attachment to a reusable token.
/// `join_existing` requires that the exact account already contains a row with
/// the target token. `adopt_verified` is reserved for callers that established
/// the token outside this store (for example, a verified mesh credential); its
/// payload is the portable-resume state to install on the claimant row.
pub const TokenBindKind = union(enum) {
    join_existing,
    adopt_verified: bool,
};

/// A token bind prepared while holding the store's exclusive lock. Preparation
/// captures every value needed by the commit, so `commit` performs no allocation
/// and cannot expose a half-applied token-group merge. The lock remains held after
/// commit so a caller can finish its World/connection commit before calling
/// `finish`; an uncommitted plan must use `abort`.
///
/// This type is logically non-copyable and single-use: keep one mutable instance
/// and call lifecycle methods through its pointer. Install `defer plan.deinit()`
/// immediately after preparation; it aborts an uncommitted plan and asserts if a
/// committed plan escaped without the required explicit `finish`.
pub const PreparedTokenBind = struct {
    const State = enum { prepared, committed, aborted, finished };

    store: *SessionStore,
    list: *SessionList,
    index: usize,
    client: ClientId,
    expected_token: Token,
    expected_portable: bool,
    expected_dirty: bool,
    expected_projection_dirty: bool,
    target_token: Token,
    kind: TokenBindKind,
    target_portable: bool,
    target_dirty: bool,
    target_projection_dirty: bool,
    result_portable: bool,
    state: State = .prepared,

    /// Commit the prepared bind without allocating or releasing the exclusive
    /// lock. Defensive revalidation rejects a stale/corrupted ticket without
    /// applying the target token. Ordinary store users cannot make it stale
    /// because the ticket owns the exclusive lock, but keeping this check at the
    /// commit boundary prevents a future refactor from weakening that guarantee.
    pub fn commit(self: *PreparedTokenBind) bool {
        if (self.state != .prepared) return false;

        if (self.index >= self.list.items.items.len) return false;
        const claimant = &self.list.items.items[self.index];
        if (claimant.client != self.client or
            !std.crypto.timing_safe.eql(Token, claimant.token, self.expected_token) or
            claimant.portable_resume != self.expected_portable or
            claimant.replica_dirty != self.expected_dirty or
            claimant.replica_projection_dirty != self.expected_projection_dirty)
        {
            return false;
        }

        var current_target_portable = false;
        var target_in_account = false;
        for (self.list.items.items) |session| {
            if (!std.crypto.timing_safe.eql(Token, session.token, self.target_token)) continue;
            target_in_account = true;
            current_target_portable = current_target_portable or session.portable_resume;
        }
        if (self.kind == .join_existing and
            (!target_in_account or current_target_portable != self.target_portable))
        {
            return false;
        }
        const current_target = self.store.tokenGroupStateLocked(self.target_token);
        if (current_target.dirty != self.target_dirty or
            current_target.projection_dirty != self.target_projection_dirty)
        {
            return false;
        }

        claimant.token = self.target_token;
        claimant.portable_resume = self.result_portable;
        self.store.setTokenGroupDirtyLocked(
            self.target_token,
            self.expected_dirty or self.target_dirty,
        );
        self.store.setTokenGroupProjectionDirtyLocked(
            self.target_token,
            self.expected_projection_dirty or self.target_projection_dirty,
        );
        self.state = .committed;
        return true;
    }

    /// Release the exclusive lock after the caller has completed every other
    /// no-fail authority mutation. Calling this before commit is a lifecycle bug.
    pub fn finish(self: *PreparedTokenBind) void {
        if (self.state == .finished) return;
        std.debug.assert(self.state == .committed);
        if (self.state != .committed) return;
        self.state = .finished;
        self.store.lock.unlockExclusive();
    }

    /// Discard an uncommitted plan and release the exclusive lock. Calling this
    /// after commit is a lifecycle bug; committed plans require `finish`.
    pub fn abort(self: *PreparedTokenBind) void {
        if (self.state == .aborted or self.state == .finished) return;
        std.debug.assert(self.state == .prepared);
        if (self.state != .prepared) return;
        self.state = .aborted;
        self.store.lock.unlockExclusive();
    }

    /// Lifecycle guard for deferred cleanup. An uncommitted plan is safely
    /// aborted. A committed-but-unfinished plan is unlocked to avoid poisoning
    /// the store, then asserted so tests/debug builds catch the missing finish.
    pub fn deinit(self: *PreparedTokenBind) void {
        switch (self.state) {
            .prepared => self.abort(),
            .committed => {
                self.state = .finished;
                self.store.lock.unlockExclusive();
                std.debug.assert(false);
            },
            .aborted, .finished => {},
        }
    }
};

pub const SessionStore = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    accounts: std.StringHashMap(SessionList),
    lock: rwlock.RwLock = .{},
    /// Number of rows carrying `replica_dirty`, maintained under `lock`. This is
    /// deliberately a row count (not a token count), so every mutation remains
    /// O(1) once the affected row is known and collection can skip an empty
    /// store without allocating an auxiliary token set.
    dirty_replica_rows: usize = 0,
    /// Last token returned by the bounded dirty scan. Advancing from this
    /// caller-owned-value cursor prevents one permanently failing first token
    /// from starving later groups without retaining pointers into the hash map.
    dirty_scan_cursor: ?Token = null,
    /// Projection retry bookkeeping mirrors the publish lane but advances
    /// independently; a blocked local projection cannot perturb publish order.
    dirty_projection_rows: usize = 0,
    projection_scan_cursor: ?Token = null,

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
            const inherited = self.tokenGroupStateLocked(token);
            self.removeDirtyRowLocked(&list.items.items[idx]);
            freeSnapshot(self.allocator, &list.items.items[idx]);
            list.items.items[idx] = .{
                .client = client,
                .token = token,
                .signon_ms = signon_ms,
                .attached = true,
                .replica_dirty = inherited.dirty,
                .replica_projection_dirty = inherited.projection_dirty,
            };
            if (inherited.dirty) self.dirty_replica_rows += 1;
            if (inherited.projection_dirty) self.dirty_projection_rows += 1;
            self.setTokenGroupDirtyLocked(token, inherited.dirty);
            self.setTokenGroupProjectionDirtyLocked(token, inherited.projection_dirty);
            return .{
                .session = list.items.items[idx],
                .evicted = .{ .token = displaced.token, .portable = displaced.portable_resume },
            };
        }
        // Capture destination retry state before capacity eviction: if the new
        // attachment replaces the only detached row of this same exact token,
        // its pending publish/projection work must move with the logical group.
        const inherited = self.tokenGroupStateLocked(token);
        var evicted: ?ResumeHandle = null;
        if (list.items.items.len >= self.cfg.max_sessions_per_account) {
            // At cap: evict the oldest *detached* ghost to make room for the live
            // session. Never evict an attached session (that would drop a peer).
            if (oldestDetached(list)) |evict| {
                const displaced = list.items.items[evict];
                evicted = .{ .token = displaced.token, .portable = displaced.portable_resume };
                self.removeDirtyRowLocked(&list.items.items[evict]);
                freeSnapshot(self.allocator, &list.items.items[evict]);
                _ = list.items.swapRemove(evict);
            } else return error.TooManySessions;
        }
        const session = Session{
            .client = client,
            .token = token,
            .signon_ms = signon_ms,
            .attached = true,
            .replica_dirty = inherited.dirty,
            .replica_projection_dirty = inherited.projection_dirty,
        };
        try list.items.append(self.allocator, session);
        if (inherited.dirty) self.dirty_replica_rows += 1;
        if (inherited.projection_dirty) self.dirty_projection_rows += 1;
        self.setTokenGroupDirtyLocked(token, inherited.dirty);
        self.setTokenGroupProjectionDirtyLocked(token, inherited.projection_dirty);
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
    /// bouncer. A previously-owned snapshot is deliberately preserved: callers
    /// use this no-allocation fallback when encoding a fresher disconnect image
    /// fails, and erasing the last retry source would strand a dirty portable
    /// token after ConnState is freed. Returns true if the row was present.
    pub fn markDetached(self: *SessionStore, account: []const u8, client: ClientId) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        list.items.items[idx].attached = false;
        return true;
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
            if (bytes.len != 0) self.allocator.dupe(u8, bytes) catch {
                // Transport loss still detaches the row, but snapshot replacement
                // is transactional: retain the previous retry source and every
                // token-group flag when allocation pressure prevents the update.
                // Returning false lets interested callers surface the degraded
                // capture while legacy disconnect callers remain fail-safe.
                session.attached = false;
                return false;
            } else null
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
        var prepared = self.prepareTokenBind(account, client, token, .join_existing) orelse return false;
        defer prepared.deinit();
        if (!prepared.commit()) {
            prepared.abort();
            return false;
        }
        prepared.finish();
        return true;
    }

    /// Bind a tracked client to a token whose authority was established outside
    /// the local store (for example by a verified mesh credential + signed
    /// migration replica). Unlike `joinTokenGroup`, this does not require a
    /// pre-existing local attachment bearing the token.
    pub fn adoptTokenGroup(self: *SessionStore, account: []const u8, client: ClientId, token: Token, portable: bool) bool {
        var prepared = self.prepareTokenBind(account, client, token, .{ .adopt_verified = portable }) orelse return false;
        defer prepared.deinit();
        if (!prepared.commit()) {
            prepared.abort();
            return false;
        }
        prepared.finish();
        return true;
    }

    /// Prepare an exact account/client/token bind and retain the exclusive lock
    /// through its later commit/abort boundary. This is deliberately allocation-
    /// free: a daemon restore transaction may stage every fallible World change
    /// first, prepare this ticket last, then commit all authority with no error
    /// path remaining.
    pub fn prepareTokenBind(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        kind: TokenBindKind,
    ) ?PreparedTokenBind {
        self.lock.lockExclusive();
        var keep_locked = false;
        defer if (!keep_locked) self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return null;
        const index = list.indexOfClient(client) orelse return null;
        const claimant = list.items.items[index];

        var target_portable = false;
        var target_in_account = false;
        for (list.items.items) |session| {
            if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
            target_in_account = true;
            target_portable = target_portable or session.portable_resume;
        }
        if (kind == .join_existing and !target_in_account) return null;

        const target = self.tokenGroupStateLocked(token);
        const result_portable = switch (kind) {
            .join_existing => claimant.portable_resume or target_portable,
            .adopt_verified => |portable| portable,
        };
        keep_locked = true;
        return .{
            .store = self,
            .list = list,
            .index = index,
            .client = client,
            .expected_token = claimant.token,
            .expected_portable = claimant.portable_resume,
            .expected_dirty = claimant.replica_dirty,
            .expected_projection_dirty = claimant.replica_projection_dirty,
            .target_token = token,
            .kind = kind,
            .target_portable = target_portable,
            .target_dirty = target.dirty,
            .target_projection_dirty = target.projection_dirty,
            .result_portable = result_portable,
        };
    }

    /// Mark an opted-in logical session dirty before publishing its next signed
    /// replica. The operation is all-or-nothing: a token with no portable local
    /// row is rejected and no row is modified. Once eligible, every exact-token
    /// row is marked so a mutation from any sibling survives that sibling's
    /// removal or migration.
    pub fn markTokenReplicaDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found or !state.portable) return false;
        self.setTokenGroupDirtyLocked(token, true);
        return true;
    }

    /// Clear an exact token group only after the caller's signed replica was
    /// synchronously accepted. Returns false only when no local row bears the
    /// token; clearing an already-clean group is idempotent.
    pub fn clearTokenReplicaDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return false;
        self.setTokenGroupDirtyLocked(token, false);
        return true;
    }

    /// Whether an exact token group still has an unpublished local mutation.
    /// Deferred mesh sidecars consult this after checking their bound token so
    /// an older same-origin Store row can never masquerade as acceptance of the
    /// current restored snapshot.
    pub fn tokenReplicaDirty(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.tokenGroupStateLocked(token).dirty;
    }

    pub fn tokenReplicaProjectionDirty(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.tokenGroupStateLocked(token).projection_dirty;
    }

    /// Copy at most `out.len` unique dirty portable tokens into caller storage.
    /// `replica_dirty` can only be minted after group portability was verified,
    /// so it remains the durable eligibility proof if the issuing sibling is
    /// removed before retry. No allocation occurs and the returned slice borrows
    /// `out`; a dirty token remains visible until explicitly cleared.
    pub fn dirtyPortableTokensInto(self: *SessionStore, out: []Token) []const Token {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        return self.dirtyTokensIntoLocked(out, .publish);
    }

    /// Mark receive-side projection pending after a signed replica was accepted.
    /// Store acceptance is the authority, so unlike publish dirtiness this does
    /// not require a locally issued portable credential.
    pub fn markTokenReplicaProjectionDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return false;
        self.setTokenGroupProjectionDirtyLocked(token, true);
        return true;
    }

    /// Clear receive-side projection retry only after every applicable local
    /// attachment accepted the snapshot. Idempotent for an existing group.
    pub fn clearTokenReplicaProjectionDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return false;
        self.setTokenGroupProjectionDirtyLocked(token, false);
        return true;
    }

    /// Fair, bounded, allocation-free projection retry collection. This cursor
    /// is independent from `dirtyPortableTokensInto`.
    pub fn dirtyProjectionTokensInto(self: *SessionStore, out: []Token) []const Token {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        return self.dirtyTokensIntoLocked(out, .projection);
    }

    const DirtyKind = enum { publish, projection };

    fn dirtyTokensIntoLocked(self: *SessionStore, out: []Token, kind: DirtyKind) []const Token {
        const dirty_rows = switch (kind) {
            .publish => self.dirty_replica_rows,
            .projection => self.dirty_projection_rows,
        };
        if (dirty_rows == 0 or out.len == 0) return out[0..0];

        const cursor_ptr = switch (kind) {
            .publish => &self.dirty_scan_cursor,
            .projection => &self.projection_scan_cursor,
        };
        var n: usize = 0;
        const original_cursor = cursor_ptr.*;
        var wrapped = original_cursor == null;
        var lower_bound = original_cursor;
        while (n < out.len) {
            var candidate: ?Token = null;
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                for (entry.value_ptr.items.items) |session| {
                    if (!sessionDirty(session, kind)) continue;
                    if (tokenInSlice(out[0..n], session.token)) continue;

                    if (lower_bound) |lower| {
                        if (std.mem.order(u8, &session.token, &lower) != .gt) continue;
                    }
                    if (wrapped) {
                        if (original_cursor) |upper| {
                            if (std.mem.order(u8, &session.token, &upper) == .gt) continue;
                        }
                    }
                    if (candidate == null or std.mem.order(u8, &session.token, &candidate.?) == .lt) {
                        candidate = session.token;
                    }
                }
            }

            if (candidate) |token| {
                out[n] = token;
                n += 1;
                lower_bound = token;
                continue;
            }
            if (wrapped) break;
            // Complete the circular scan at the smallest token. The ordering is
            // by token value, not hash-map position, so this remains fair even
            // when the previous cursor token was removed between calls.
            wrapped = true;
            lower_bound = null;
        }

        if (n != 0) cursor_ptr.* = out[n - 1];
        return out[0..n];
    }

    fn sessionDirty(session: Session, kind: DirtyKind) bool {
        return switch (kind) {
            .publish => session.replica_dirty,
            .projection => session.replica_projection_dirty,
        };
    }

    fn tokenInSlice(tokens: []const Token, needle: Token) bool {
        for (tokens) |token| {
            if (std.crypto.timing_safe.eql(Token, token, needle)) return true;
        }
        return false;
    }

    /// Exact count of dirty rows. Exposed for scheduling/diagnostics; callers
    /// needing unique tokens must use `dirtyPortableTokensInto`.
    pub fn dirtyReplicaRowCount(self: *const SessionStore) usize {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.dirty_replica_rows;
    }

    pub fn dirtyReplicaProjectionRowCount(self: *const SessionStore) usize {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.dirty_projection_rows;
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
        self.removeDirtyRowLocked(&entry.value_ptr.items.items[idx]);
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
                self.removeDirtyRowLocked(&entry.value_ptr.items.items[idx]);
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

    const TokenGroupState = struct {
        found: bool = false,
        portable: bool = false,
        dirty: bool = false,
        projection_dirty: bool = false,
    };

    /// Caller holds `lock` exclusively or shared for the duration of the scan.
    fn tokenGroupStateLocked(self: *const SessionStore, token: Token) TokenGroupState {
        var state: TokenGroupState = .{};
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                state.found = true;
                state.portable = state.portable or session.portable_resume;
                state.dirty = state.dirty or session.replica_dirty;
                state.projection_dirty = state.projection_dirty or session.replica_projection_dirty;
            }
        }
        return state;
    }

    /// Apply token-group dirty state and keep `dirty_replica_rows` exact. Caller
    /// holds `lock` exclusively. Portability remains a per-row issuance fact;
    /// token-group eligibility is computed by OR in `tokenGroupStateLocked`.
    fn setTokenGroupDirtyLocked(self: *SessionStore, token: Token, dirty: bool) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |*session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                self.setReplicaDirtyLocked(session, dirty);
            }
        }
    }

    fn setTokenGroupProjectionDirtyLocked(self: *SessionStore, token: Token, dirty: bool) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |*session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                self.setReplicaProjectionDirtyLocked(session, dirty);
            }
        }
    }

    fn setReplicaDirtyLocked(self: *SessionStore, session: *Session, dirty: bool) void {
        if (session.replica_dirty == dirty) return;
        session.replica_dirty = dirty;
        if (dirty) {
            self.dirty_replica_rows += 1;
        } else {
            std.debug.assert(self.dirty_replica_rows != 0);
            self.dirty_replica_rows -= 1;
        }
    }

    fn removeDirtyRowLocked(self: *SessionStore, session: *const Session) void {
        if (session.replica_dirty) {
            std.debug.assert(self.dirty_replica_rows != 0);
            self.dirty_replica_rows -= 1;
        }
        if (session.replica_projection_dirty) {
            std.debug.assert(self.dirty_projection_rows != 0);
            self.dirty_projection_rows -= 1;
        }
    }

    fn setReplicaProjectionDirtyLocked(self: *SessionStore, session: *Session, dirty: bool) void {
        if (session.replica_projection_dirty == dirty) return;
        session.replica_projection_dirty = dirty;
        if (dirty) {
            self.dirty_projection_rows += 1;
        } else {
            std.debug.assert(self.dirty_projection_rows != 0);
            self.dirty_projection_rows -= 1;
        }
    }

    fn dropAccount(self: *SessionStore, entry: std.StringHashMap(SessionList).Entry) void {
        const owned_key = entry.key_ptr.*;
        for (entry.value_ptr.items.items) |session| self.removeDirtyRowLocked(&session);
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

test "allocation-free detach preserves the last owned portable snapshot" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const token = tok(0x6d);
    _ = try s.attach("alice", 1, token, 10);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "last-publishable-state"));

    // Models encodeMigrationSnapshot failing during the later close path.
    try testing.expect(s.markDetached("alice", 1));
    const copied = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", token)).?;
    defer testing.allocator.free(copied);
    try testing.expectEqualStrings("last-publishable-state", copied);
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

test "prepared token join aborts cleanly then commits without allocation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const target = tok(0xA1);
    const generated = tok(0xB2);
    _ = try s.attach("alice", 1, target, 10);
    _ = try s.attach("alice", 2, generated, 20);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(target));
    try testing.expect(s.markTokenReplicaProjectionDirty(target));

    // Abort is a true no-op and releases the lock for ordinary store calls.
    var abandoned = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer abandoned.deinit();
    try testing.expect(!s.lock.tryLockExclusive());
    abandoned.abort();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(!s.clientHasToken("alice", 2, target));

    // Fail the allocator's very next request. Neither preparation nor commit may
    // touch it, so the exact group transition still completes in one step.
    failing.fail_index = failing.alloc_index;
    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expect(prepared.commit());
    try testing.expect(!failing.has_induced_failure);
    // Commit publishes the row change but deliberately retains the lock until
    // the enclosing World/Conn transaction calls finish.
    try testing.expect(!s.lock.tryLockExclusive());
    try testing.expect(std.crypto.timing_safe.eql(Token, prepared.list.items.items[prepared.index].token, target));
    prepared.finish();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();

    try testing.expect(s.clientHasToken("alice", 1, target));
    try testing.expect(s.clientHasToken("alice", 2, target));
    const joined = s.findTokenSessionInAccount("alice", target) orelse
        return error.TestUnexpectedResult;
    try testing.expect(joined.portable_resume);
    try testing.expect(s.tokenReplicaDirty(target));
    try testing.expect(s.tokenReplicaProjectionDirty(target));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
}

test "prepared verified adopt is exact-account and preserves retry state" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const generated = tok(0x11);
    const verified = tok(0x99);
    _ = try s.attach("alice", 1, generated, 10);
    _ = try s.attach("bob", 2, verified, 20);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(generated));
    try testing.expect(s.markTokenReplicaProjectionDirty(generated));

    // A row in another account never authorizes join_existing.
    try testing.expect(s.prepareTokenBind("alice", 1, verified, .join_existing) == null);
    try testing.expect(s.clientHasToken("alice", 1, generated));

    // Verified mesh authority may adopt a rowless token. Its explicit portable
    // bit replaces the claimant's old issuance bit, while pending retry work is
    // carried across to the new exact group.
    var prepared = s.prepareTokenBind("alice", 1, verified, .{ .adopt_verified = false }) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expect(prepared.commit());
    try testing.expect(!s.lock.tryLockExclusive());
    prepared.finish();
    const adopted = s.resumeHandleForClient("alice", 1) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &verified, &adopted.token);
    try testing.expect(!adopted.portable);
    try testing.expect(s.tokenReplicaDirty(verified));
    try testing.expect(s.tokenReplicaProjectionDirty(verified));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
}

test "prepared token bind rejects invalid and stale preconditions without mutation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const target = tok(0x44);
    const generated = tok(0x55);
    _ = try s.attach("alice", 1, target, 10);
    _ = try s.attach("alice", 2, generated, 20);

    try testing.expect(s.prepareTokenBind("missing", 2, target, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("alice", 99, target, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("alice", 2, tok(0xEE), .join_existing) == null);
    try testing.expect(s.clientHasToken("alice", 2, generated));

    var stale = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer stale.deinit();
    // Model a stale/corrupted ticket at the commit boundary. Revalidation must
    // reject it and leave every live row untouched until explicit abort.
    stale.expected_token = tok(0xFE);
    try testing.expect(!stale.commit());
    // Rejection keeps the plan prepared and the lock held until explicit abort.
    try testing.expect(!s.lock.tryLockExclusive());
    stale.abort();
    try testing.expect(!stale.commit());
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 1, target));
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(!s.clientHasToken("alice", 2, target));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());
}

test "prepared token bind remains no-allocation after exhaustive setup failures" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();

            const target = tok(0x71);
            _ = try s.attach("sweep", 1, target, 1);
            _ = try s.attach("sweep", 2, tok(0x72), 2);
            try testing.expect(s.markPortableResumeIssued("sweep", 1));

            var prepared = s.prepareTokenBind("sweep", 2, target, .join_existing) orelse
                return error.TestUnexpectedResult;
            defer prepared.deinit();
            try testing.expect(prepared.commit());
            try testing.expect(!s.lock.tryLockExclusive());
            prepared.finish();
            try testing.expect(s.clientHasToken("sweep", 1, target));
            try testing.expect(s.clientHasToken("sweep", 2, target));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "detached snapshot replacement OOM preserves prior retry state" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const token = tok(0xAD);
    _ = try s.attach("alice", 1, token, 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(token));
    try testing.expect(s.markTokenReplicaProjectionDirty(token));
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "last-good-snapshot"));

    // Fail exactly the replacement copy. The row must still be detached and
    // publishable from its previous owned snapshot; OOM must not erase either
    // token-group durability bit or the portable credential.
    failing.fail_index = failing.alloc_index;
    try testing.expect(!s.markDetachedWithSnapshot("alice", 1, "newer-snapshot"));
    try testing.expect(failing.has_induced_failure);

    const row = s.findTokenSessionInAccount("alice", token) orelse
        return error.TestUnexpectedResult;
    try testing.expect(!row.attached);
    try testing.expect(row.portable_resume);
    try testing.expect(row.replica_dirty);
    try testing.expect(row.replica_projection_dirty);
    try testing.expect(s.tokenReplicaDirty(token));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());

    const retained = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", token)) orelse
        return error.TestUnexpectedResult;
    defer testing.allocator.free(retained);
    try testing.expectEqualStrings("last-good-snapshot", retained);
}

test "portable and dirty state are exact token group properties" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0xA1), 1);
    _ = try s.attach("alice", 2, tok(0xA1), 2);
    _ = try s.attach("bob", 3, tok(0xB2), 3);
    _ = try s.attach("carol", 4, tok(0xC3), 4);

    // Issuance remains an exact-row fact; token-group eligibility is its OR.
    try testing.expect(s.markPortableResumeIssued("alice", 2));
    try testing.expect(s.markPortableResumeIssued("bob", 3));
    var alice_rows: [4]Session = undefined;
    for (s.sessionsInto("alice", &alice_rows)) |session| {
        try testing.expectEqual(session.client == 2, session.portable_resume);
    }

    // A non-portable token is rejected without leaving a partial dirty mark.
    try testing.expect(!s.markTokenReplicaDirty(tok(0xC3)));
    try testing.expect(!s.tokenReplicaDirty(tok(0xC3)));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    // A mutation from either sibling marks every row in that group.
    try testing.expect(s.markTokenReplicaDirty(tok(0xA1)));
    try testing.expect(s.markTokenReplicaDirty(tok(0xB2)));
    try testing.expect(s.tokenReplicaDirty(tok(0xA1)));
    try testing.expect(s.tokenReplicaDirty(tok(0xB2)));
    try testing.expectEqual(@as(usize, 3), s.dirtyReplicaRowCount());
    for (s.sessionsInto("alice", &alice_rows)) |session| {
        try testing.expect(session.replica_dirty);
    }

    // Dirty is the durable eligibility proof after marking: removing the only
    // row that received the credential must not strand the surviving sibling's
    // pending group publication.
    try testing.expect(s.remove("alice", 2));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    const surviving = s.sessionsInto("alice", &alice_rows);
    try testing.expectEqual(@as(usize, 1), surviving.len);
    try testing.expect(!surviving[0].portable_resume);
    try testing.expect(surviving[0].replica_dirty);

    // Collection is caller-bounded, allocation-free, and unique even though
    // token A's credential-issuing row has already disappeared.
    var one: [1]Token = undefined;
    try testing.expectEqual(@as(usize, 1), s.dirtyPortableTokensInto(&one).len);
    var all: [4]Token = undefined;
    const dirty = s.dirtyPortableTokensInto(&all);
    try testing.expectEqual(@as(usize, 2), dirty.len);
    var saw_a = false;
    var saw_b = false;
    for (dirty) |token| {
        saw_a = saw_a or std.mem.eql(u8, &token, &tok(0xA1));
        saw_b = saw_b or std.mem.eql(u8, &token, &tok(0xB2));
    }
    try testing.expect(saw_a and saw_b);

    // Acceptance clears only its exact group; failed/unaccepted work remains.
    try testing.expect(s.clearTokenReplicaDirty(tok(0xA1)));
    try testing.expect(!s.tokenReplicaDirty(tok(0xA1)));
    try testing.expect(s.tokenReplicaDirty(tok(0xB2)));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    const retained = s.dirtyPortableTokensInto(&all);
    try testing.expectEqual(@as(usize, 1), retained.len);
    try testing.expectEqualSlices(u8, &tok(0xB2), &retained[0]);
    try testing.expect(s.clearTokenReplicaDirty(tok(0xA1))); // idempotent
    try testing.expect(!s.clearTokenReplicaDirty(tok(0xEE)));
}

test "join and adopt OR dirty portable state across token groups" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x11), 1);
    _ = try s.attach("alice", 2, tok(0x22), 2);
    _ = try s.attach("alice", 3, tok(0x33), 3);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(tok(0x11)));

    // Moving the dirty source into an existing clean group dirties every
    // destination sibling without losing its pending retry. Per-row portable
    // issuance stays exact.
    try testing.expect(s.joinTokenGroup("alice", 1, tok(0x22)));
    var rows: [8]Session = undefined;
    const joined = s.sessionsInto("alice", &rows);
    for (joined) |session| {
        if (!std.mem.eql(u8, &session.token, &tok(0x22))) continue;
        try testing.expectEqual(session.client == 1, session.portable_resume);
        try testing.expect(session.replica_dirty);
    }
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());

    // A clean adopted attachment inherits the destination group's OR state.
    try testing.expect(s.adoptTokenGroup("alice", 3, tok(0x22), false));
    try testing.expectEqual(@as(usize, 3), s.dirtyReplicaRowCount());
    for (s.sessionsInto("alice", &rows)) |session| {
        try testing.expectEqualSlices(u8, &tok(0x22), &session.token);
        try testing.expectEqual(session.client == 1, session.portable_resume);
        try testing.expect(session.replica_dirty);
    }
}

test "bounded dirty collection rotates past an uncleared failing token" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    for (0..9) |i| {
        var account_buf: [16]u8 = undefined;
        const account = try std.fmt.bufPrint(&account_buf, "rotate-{d}", .{i});
        const token = tok(@intCast(0x60 + i));
        _ = try s.attach(account, @intCast(i + 1), token, @intCast(i));
        try testing.expect(s.markPortableResumeIssued(account, @intCast(i + 1)));
        try testing.expect(s.markTokenReplicaDirty(token));
    }

    var first_buf: [4]Token = undefined;
    const first = s.dirtyPortableTokensInto(&first_buf);
    try testing.expectEqual(@as(usize, 4), first.len);

    // Nothing is cleared: model all four publications failing. The next batch
    // still advances to four other unique groups instead of returning the same
    // stable hash-map prefix forever.
    var second_buf: [4]Token = undefined;
    const second = s.dirtyPortableTokensInto(&second_buf);
    try testing.expectEqual(@as(usize, 4), second.len);
    for (second) |token| try testing.expect(!SessionStore.tokenInSlice(first, token));

    // Remove the cursor token itself. Ordering by the retained token value (not
    // a hash-map position) still advances to 0x68 before wrapping to 0x60.
    try testing.expect(s.remove("rotate-7", 8));
    var third_buf: [4]Token = undefined;
    const third = s.dirtyPortableTokensInto(&third_buf);
    try testing.expectEqual(@as(usize, 4), third.len);
    try testing.expectEqualSlices(u8, &tok(0x68), &third[0]);
    try testing.expectEqualSlices(u8, &tok(0x60), &third[1]);
    try testing.expectEqualSlices(u8, &tok(0x61), &third[2]);
    try testing.expectEqualSlices(u8, &tok(0x62), &third[3]);
    try testing.expectEqual(@as(usize, 8), s.dirtyReplicaRowCount());
}

test "projection retry is group-wide durable and independent from publish retry" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x71), 1);
    _ = try s.attach("alice", 2, tok(0x71), 2);

    // Signed Store acceptance, not local token issuance, authorizes projection.
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(0x71)));
    try testing.expect(!s.markTokenReplicaProjectionDirty(tok(0x72)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    var rows: [4]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |session| {
        try testing.expect(session.replica_projection_dirty);
        try testing.expect(!session.replica_dirty);
    }
    var projection_buf: [2]Token = undefined;
    const projection = s.dirtyProjectionTokensInto(&projection_buf);
    try testing.expectEqual(@as(usize, 1), projection.len);
    try testing.expectEqualSlices(u8, &tok(0x71), &projection[0]);

    // Removing one sibling and attaching another to its exact token preserves
    // the pending projection and the exact row count.
    try testing.expect(s.remove("alice", 1));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    _ = try s.attach("alice", 3, tok(0x73), 3);
    try testing.expect(s.adoptTokenGroup("alice", 3, tok(0x71), false));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());

    // Publish dirtiness can coexist, and clearing projection cannot clear it.
    try testing.expect(s.markPortableResumeIssued("alice", 2));
    try testing.expect(s.markTokenReplicaDirty(tok(0x71)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expect(s.clearTokenReplicaProjectionDirty(tok(0x71)));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expect(!s.clearTokenReplicaProjectionDirty(tok(0xEE)));
}

test "bounded projection collection rotates independently without allocation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    for (0..9) |i| {
        var account_buf: [20]u8 = undefined;
        const account = try std.fmt.bufPrint(&account_buf, "projection-{d}", .{i});
        const token = tok(@intCast(0x80 + i));
        _ = try s.attach(account, @intCast(i + 1), token, @intCast(i));
        try testing.expect(s.markTokenReplicaProjectionDirty(token));
    }

    var first_buf: [4]Token = undefined;
    const first = s.dirtyProjectionTokensInto(&first_buf);
    try testing.expectEqual(@as(usize, 4), first.len);
    var second_buf: [4]Token = undefined;
    const second = s.dirtyProjectionTokensInto(&second_buf);
    try testing.expectEqual(@as(usize, 4), second.len);
    for (second) |token| try testing.expect(!SessionStore.tokenInSlice(first, token));

    // Advancing projection did not move or populate the independent publish
    // cursor/lane.
    var publish_buf: [4]Token = undefined;
    try testing.expectEqual(@as(usize, 0), s.dirtyPortableTokensInto(&publish_buf).len);
    try testing.expectEqual(@as(usize, 9), s.dirtyReplicaProjectionRowCount());
}

test "projection dirty count tracks replacement eviction and drop paths" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x91), 1);
    _ = try s.attach("alice", 2, tok(0x91), 2);
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(0x91)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());

    // A new token resets the replaced row while the surviving old-token group
    // remains pending.
    _ = try s.attach("alice", 1, tok(0x92), 3);
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    // Replacing it back into the dirty token inherits the destination OR state.
    _ = try s.attach("alice", 1, tok(0x91), 4);
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());

    try testing.expect(s.markDetached("alice", 1));
    _ = try s.attach("alice", 3, tok(0x93), 5); // evicts dirty detached row 1
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 1), s.removeClient(2));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());

    _ = try s.attach("drop", 9, tok(0x99), 9);
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(0x99)));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    try testing.expect(s.remove("drop", 9)); // prunes the now-empty account
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());
}

test "dirty row count survives removal replacement and detached eviction" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x41), 1);
    _ = try s.attach("alice", 2, tok(0x41), 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(tok(0x41)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());

    try testing.expect(s.remove("alice", 1));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.removeClient(2));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    _ = try s.attach("evict", 10, tok(0x51), 10);
    try testing.expect(s.markPortableResumeIssued("evict", 10));
    try testing.expect(s.markTokenReplicaDirty(tok(0x51)));
    try testing.expect(s.markDetached("evict", 10));
    _ = try s.attach("evict", 11, tok(0x52), 20);
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    _ = try s.attach("evict", 12, tok(0x53), 30); // evicts dirty client 10
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    try testing.expect(s.markPortableResumeIssued("evict", 11));
    try testing.expect(s.markTokenReplicaDirty(tok(0x52)));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    _ = try s.attach("evict", 11, tok(0x54), 40); // same-client replacement
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());
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
