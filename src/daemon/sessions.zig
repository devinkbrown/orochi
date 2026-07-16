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

/// The all-zero value records a locally tracked session when no CSPRNG was
/// available. It is deliberately not a reclaim credential and therefore must
/// never acquire global token-group or cross-account capability semantics.
fn tokenIsSentinel(token: Token) bool {
    return std.mem.allEqual(u8, &token, 0);
}

pub const snapshot_capacity: usize = 64;
/// The configuration parser caps CHANNELLEN at 200 bytes. Keeping each complete
/// name inline makes replacement/read/clear allocation-free once a row journal
/// exists; first-arm allocation is staged before any generation or row changes.
pub const local_channel_name_capacity: usize = 200;
/// Capacity is the number of concurrently unresolved channel mutations, not a
/// joined-channel limit. The command boundary must arm before mutating World;
/// a ninth distinct pending channel therefore fails closed and can be retried
/// after the projector clears a slot. Re-arming a pending case-insensitive
/// channel replaces it even while all eight slots are occupied.
pub const local_channel_projection_capacity: usize = 8;

pub const Error = std.mem.Allocator.Error || error{
    TooManyAccounts,
    TooManySessions,
    TokenAccountMismatch,
};

pub const Config = struct {
    max_accounts: usize = 65536,
    max_sessions_per_account: usize = snapshot_capacity,
};

/// One durable desired channel image within an exact reusable-token group.
///
/// Every local row bearing the token carries the same bounded set. That
/// deliberate duplication lets any sibling detach or disappear without taking
/// the retry source with it. A newer same-channel arm receives a generation, so
/// an older in-flight retry cannot clear the replacement.
pub const LocalChannelProjection = struct {
    generation: u64 = 0,
    channel_len: u8 = 0,
    channel_bytes: [local_channel_name_capacity]u8 = @splat(0),
    present: bool = false,
    member_mode_bits: u8 = 0,

    pub fn channel(self: *const LocalChannelProjection) []const u8 {
        return self.channel_bytes[0..self.channel_len];
    }
};

/// Canonically sorted, fixed-capacity pending work for one exact token group.
/// Rows acquire an owned copy lazily on the first pending mutation. Arm stages
/// every missing allocation before publishing any pointer, generation, or count;
/// read/retry/CAS-clear remain allocation-free.
const LocalChannelProjectionSet = struct {
    revision: u64 = 0,
    len: u8 = 0,
    items: [local_channel_projection_capacity]LocalChannelProjection = @splat(.{}),

    fn slice(self: *const LocalChannelProjectionSet) []const LocalChannelProjection {
        return self.items[0..self.len];
    }

    fn isEmpty(self: *const LocalChannelProjectionSet) bool {
        return self.len == 0;
    }
};

pub const LocalChannelProjectionWork = struct {
    token: Token,
    projection: LocalChannelProjection,
};

/// One accepted arm plus the exact same-channel intent it replaced. Producers
/// that can still reject before their first live mutation use this to restore
/// older accepted work instead of accidentally erasing it.
pub const LocalChannelProjectionArm = struct {
    intent: LocalChannelProjection,
    previous: ?LocalChannelProjection,
};

pub const LocalProjectionArmError = std.mem.Allocator.Error || error{
    InvalidChannel,
    NoSuchToken,
    TooManyPendingChannels,
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
    /// Lazily allocated retry journal. Each row owns a complete copy so sibling
    /// removal cannot erase pending work; null means no channel is pending.
    local_channel_projections: ?*LocalChannelProjectionSet = null,
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
        for (self.items.items) |*session| freeSessionOwned(allocator, session);
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

/// Pointer-free account-row image captured by `PreparedTokenBind` while its
/// retained exclusive lock freezes every ASCII-fold-equivalent account key.
/// Restore planners may safely inspect this slice without borrowing Session or
/// snapshot storage that another attachment could replace or free.
pub const TokenBindRowSnapshot = struct {
    client: ClientId,
    token: Token,
    attached: bool,
    portable_resume: bool,
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
    /// Store-owned account key for the claimant. The exclusive lock keeps this
    /// slice alive through commit/abort, so defensive commit revalidation can
    /// enforce the same folded-account token boundary as preparation.
    account: []const u8,
    list: *SessionList,
    index: usize,
    client: ClientId,
    expected_token: Token,
    expected_portable: bool,
    expected_dirty: bool,
    expected_projection_dirty: bool,
    expected_local_projection_revision: u64,
    target_token: Token,
    kind: TokenBindKind,
    target_portable: bool,
    target_dirty: bool,
    target_projection_dirty: bool,
    target_local_projection_revision: u64,
    merged_local_projections: LocalChannelProjectionSet,
    /// Complete, deterministically ordered folded-account view captured under
    /// the retained exclusive lock. Freed immediately before that lock is
    /// released on every lifecycle exit.
    locked_account_rows: []TokenBindRowSnapshot,
    /// Missing per-row journals allocated during preparation. They remain
    /// detached from store state until commit and are destroyed on abort.
    staged_local_projection_sets: ?[]*LocalChannelProjectionSet = null,
    result_portable: bool,
    state: State = .prepared,

    /// Return the complete folded-account row image frozen by this ticket. The
    /// slice remains valid through commit and until finish/abort releases the
    /// retained SessionStore lock.
    pub fn accountRows(self: *const PreparedTokenBind) []const TokenBindRowSnapshot {
        std.debug.assert(self.state == .prepared or self.state == .committed);
        if (self.state != .prepared and self.state != .committed) return &.{};
        return self.locked_account_rows;
    }

    /// Portable authority that commit will install on the claimant's target
    /// group, derived under the same retained lock as `accountRows`.
    pub fn resultPortable(self: *const PreparedTokenBind) bool {
        std.debug.assert(self.state == .prepared or self.state == .committed);
        return self.result_portable;
    }

    /// Preview the exact bounded local-channel image that commit will install on
    /// the target token. Callers use this while the ticket retains the exclusive
    /// lock so World/output restore plans cannot be built from a stale detached
    /// snapshot that the no-fail commit would immediately override.
    pub fn mergedLocalChannelProjectionsInto(
        self: *const PreparedTokenBind,
        out: []LocalChannelProjection,
    ) []const LocalChannelProjection {
        std.debug.assert(self.state == .prepared);
        const source = self.merged_local_projections.slice();
        std.debug.assert(out.len >= source.len);
        if (out.len < source.len) return out[0..0];
        @memcpy(out[0..source.len], source);
        return out[0..source.len];
    }

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
            claimant.replica_projection_dirty != self.expected_projection_dirty or
            localProjectionSetRevision(claimant.local_channel_projections) != self.expected_local_projection_revision)
        {
            return false;
        }

        const current_target_account = self.store.tokenGroupStateForAccountLocked(
            self.account,
            self.target_token,
        ) orelse return false;
        if (self.kind == .join_existing and
            (!current_target_account.found or current_target_account.portable != self.target_portable))
        {
            return false;
        }
        const current_target = self.store.tokenGroupStateLocked(self.target_token);
        if (current_target.dirty != self.target_dirty or
            current_target.projection_dirty != self.target_projection_dirty or
            current_target.local_projections.revision != self.target_local_projection_revision)
        {
            return false;
        }

        var staged_index: usize = 0;
        if (!self.merged_local_projections.isEmpty()) {
            var accounts = self.store.accounts.iterator();
            while (accounts.next()) |entry| {
                for (entry.value_ptr.items.items) |*session| {
                    if (!std.crypto.timing_safe.eql(Token, session.token, self.target_token)) continue;
                    if (session.local_channel_projections != null) continue;
                    session.local_channel_projections = self.staged_local_projection_sets.?[staged_index];
                    staged_index += 1;
                }
            }
            if (!std.crypto.timing_safe.eql(Token, claimant.token, self.target_token) and
                claimant.local_channel_projections == null)
            {
                claimant.local_channel_projections = self.staged_local_projection_sets.?[staged_index];
                staged_index += 1;
            }
        }
        if (self.staged_local_projection_sets) |staged| {
            std.debug.assert(staged_index == staged.len);
            self.store.allocator.free(staged);
            self.staged_local_projection_sets = null;
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
        // A token bind merges both bounded channel sets. Distinct channels are
        // retained; a case-insensitive collision keeps the newer generation.
        // Preparation already proved the union fits, so commit cannot fail.
        if (!self.merged_local_projections.isEmpty())
            self.merged_local_projections.revision = self.store.nextLocalProjectionGenerationLocked();
        self.store.setTokenGroupLocalProjectionsLocked(
            self.target_token,
            &self.merged_local_projections,
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
        self.destroyLockedAccountRows();
        self.state = .finished;
        self.store.lock.unlockExclusive();
    }

    /// Discard an uncommitted plan and release the exclusive lock. Calling this
    /// after commit is a lifecycle bug; committed plans require `finish`.
    pub fn abort(self: *PreparedTokenBind) void {
        if (self.state == .aborted or self.state == .finished) return;
        std.debug.assert(self.state == .prepared);
        if (self.state != .prepared) return;
        self.destroyStagedLocalProjectionSets();
        self.destroyLockedAccountRows();
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
                self.destroyLockedAccountRows();
                self.state = .finished;
                self.store.lock.unlockExclusive();
                std.debug.assert(false);
            },
            .aborted, .finished => {},
        }
    }

    fn destroyStagedLocalProjectionSets(self: *PreparedTokenBind) void {
        const staged = self.staged_local_projection_sets orelse return;
        for (staged) |set| self.store.allocator.destroy(set);
        self.store.allocator.free(staged);
        self.staged_local_projection_sets = null;
    }

    fn destroyLockedAccountRows(self: *PreparedTokenBind) void {
        if (self.locked_account_rows.len == 0) return;
        self.store.allocator.free(self.locked_account_rows);
        self.locked_account_rows = &.{};
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
    /// Local exact-token channel projection is a third, independent retry lane.
    /// It is row-backed so removing one sibling cannot erase pending work while
    /// another exact attachment remains.
    dirty_local_projection_rows: usize = 0,
    /// Value cursor for the last returned (token, folded channel) work item.
    /// Keeping the full owned channel makes removal and re-arm safe without a
    /// pointer into the account map.
    local_projection_scan_cursor: ?LocalChannelProjectionWork = null,
    /// Generation zero is reserved for "never armed". Wrap is practically
    /// unreachable, but skipping zero keeps the invariant total even under a
    /// synthetic overflow test.
    next_local_projection_generation: u64 = 0,

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

        // An exact reusable token is a global capability. Bind it to exactly one
        // ASCII-casefolded account before ensureAccount can allocate/publish an
        // empty map entry or replacement can merge dirty/journal state.
        const inherited = self.tokenGroupStateForAccountLocked(account, token) orelse
            return error.TokenAccountMismatch;
        const list = try self.ensureAccount(account);
        if (list.indexOfClient(client)) |idx| {
            const displaced = list.items.items[idx];
            const old_projection_storage = list.items.items[idx].local_channel_projections;
            var projection_storage = old_projection_storage;
            if (!inherited.local_projections.isEmpty() and projection_storage == null) {
                projection_storage = try self.allocator.create(LocalChannelProjectionSet);
            }
            if (projection_storage) |storage| {
                if (inherited.local_projections.isEmpty()) {
                    projection_storage = null;
                } else {
                    storage.* = inherited.local_projections;
                }
            }
            self.removeDirtyRowLocked(&list.items.items[idx]);
            if (projection_storage == null) {
                if (old_projection_storage) |storage| self.allocator.destroy(storage);
            }
            freeSnapshot(self.allocator, &list.items.items[idx]);
            list.items.items[idx] = .{
                .client = client,
                .token = token,
                .signon_ms = signon_ms,
                .attached = true,
                .replica_dirty = inherited.dirty,
                .replica_projection_dirty = inherited.projection_dirty,
                .local_channel_projections = projection_storage,
            };
            if (inherited.dirty) self.dirty_replica_rows += 1;
            if (inherited.projection_dirty) self.dirty_projection_rows += 1;
            if (projection_storage != null) self.dirty_local_projection_rows += 1;
            self.setTokenGroupDirtyLocked(token, inherited.dirty);
            self.setTokenGroupProjectionDirtyLocked(token, inherited.projection_dirty);
            self.setTokenGroupLocalProjectionsLocked(token, &inherited.local_projections);
            return .{
                .session = list.items.items[idx],
                .evicted = .{ .token = displaced.token, .portable = displaced.portable_resume },
            };
        }
        // Capture destination retry state before capacity eviction: if the new
        // attachment replaces the only detached row of this same exact token,
        // its pending publish/projection work must move with the logical group.
        const projection_storage = if (!inherited.local_projections.isEmpty()) blk: {
            const storage = try self.allocator.create(LocalChannelProjectionSet);
            storage.* = inherited.local_projections;
            break :blk storage;
        } else null;
        errdefer if (projection_storage) |storage| self.allocator.destroy(storage);
        var evicted: ?ResumeHandle = null;
        if (list.items.items.len >= self.cfg.max_sessions_per_account) {
            // At cap: evict the oldest *detached* ghost to make room for the live
            // session. Never evict an attached session (that would drop a peer).
            if (oldestDetached(list)) |evict| {
                const displaced = list.items.items[evict];
                evicted = .{ .token = displaced.token, .portable = displaced.portable_resume };
                self.removeDirtyRowLocked(&list.items.items[evict]);
                freeSessionOwned(self.allocator, &list.items.items[evict]);
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
            .local_channel_projections = projection_storage,
        };
        try list.items.append(self.allocator, session);
        if (inherited.dirty) self.dirty_replica_rows += 1;
        if (inherited.projection_dirty) self.dirty_projection_rows += 1;
        if (projection_storage != null) self.dirty_local_projection_rows += 1;
        self.setTokenGroupDirtyLocked(token, inherited.dirty);
        self.setTokenGroupProjectionDirtyLocked(token, inherited.projection_dirty);
        self.setTokenGroupLocalProjectionsLocked(token, &inherited.local_projections);
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
        if (tokenIsSentinel(list.items.items[idx].token)) return false;
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
        if (tokenIsSentinel(list.items.items[idx].token)) {
            list.items.items[idx].portable_resume = false;
            return !issued;
        }
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
        // Issuance remains an exact-row audit fact, but the credential authorizes
        // the whole reusable token group. A sibling must therefore stay portable
        // after the issuing attachment detaches or disappears.
        return .{
            .token = session.token,
            .portable = self.tokenGroupStateLocked(session.token).portable,
        };
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
    /// through its later commit/abort boundary. Missing destination journals are
    /// staged here and freed on abort, so `commit` remains allocation-free. A
    /// daemon restore transaction prepares this ticket first, previews the exact
    /// merged local-channel image while its lock excludes stale snapshot races,
    /// then prepares World/output and commits with no error path remaining.
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

        const account_entry = self.accounts.getEntry(account) orelse return null;
        const account_key = account_entry.key_ptr.*;
        const list = account_entry.value_ptr;
        const index = list.indexOfClient(client) orelse return null;
        const claimant = list.items.items[index];
        if (tokenIsSentinel(token)) return null;

        // `adopt_verified` proves possession, not permission to relabel another
        // account's exact capability. Case variants remain one account, and
        // join_existing may therefore find its target in an equivalent key.
        const target = self.tokenGroupStateForAccountLocked(account_key, token) orelse return null;
        if (kind == .join_existing and !target.found) return null;
        const claimant_set = if (claimant.local_channel_projections) |set| set.* else LocalChannelProjectionSet{};
        const target_set = target.local_projections;
        var merged_local_projections: LocalChannelProjectionSet = .{};
        // A bind that would exceed the fixed retry budget is refused before the
        // caller stages World changes. No pending channel may be discarded.
        if (!mergeLocalProjectionSets(&merged_local_projections, &claimant_set, &target_set)) return null;

        // Capture every row under every ASCII-fold-equivalent account key, not
        // merely `account_entry`'s exact spelling. Account maps intentionally
        // retain display casing, while reusable-token authority is folded; a
        // restore plan built from only one spelling can otherwise miss a live
        // attachment that joins or leaves immediately before this ticket.
        var locked_row_count: usize = 0;
        var count_it = self.accounts.iterator();
        while (count_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account_key)) continue;
            locked_row_count = std.math.add(
                usize,
                locked_row_count,
                entry.value_ptr.items.items.len,
            ) catch return null;
        }
        std.debug.assert(locked_row_count != 0);
        const locked_account_rows = self.allocator.alloc(
            TokenBindRowSnapshot,
            locked_row_count,
        ) catch return null;
        var rows_transferred = false;
        defer if (!rows_transferred) self.allocator.free(locked_account_rows);
        var locked_row_index: usize = 0;
        var rows_it = self.accounts.iterator();
        while (rows_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account_key)) continue;
            for (entry.value_ptr.items.items) |session| {
                locked_account_rows[locked_row_index] = .{
                    .client = session.client,
                    .token = session.token,
                    .attached = session.attached,
                    .portable_resume = session.portable_resume,
                };
                locked_row_index += 1;
            }
        }
        std.debug.assert(locked_row_index == locked_account_rows.len);
        const RowOrder = struct {
            fn lessThan(_: void, a: TokenBindRowSnapshot, b: TokenBindRowSnapshot) bool {
                return a.client < b.client;
            }
        };
        std.mem.sort(
            TokenBindRowSnapshot,
            locked_account_rows,
            {},
            RowOrder.lessThan,
        );
        // Exact-case account lists enforce unique clients internally, but
        // independently-created case variants can contain the same packed id
        // with conflicting authority. Sorting makes the fail-closed duplicate
        // check linear even if many case spellings reach their individual caps.
        for (locked_account_rows[1..], 1..) |row, row_index| {
            if (locked_account_rows[row_index - 1].client == row.client) return null;
        }

        var staged_local_projection_sets: ?[]*LocalChannelProjectionSet = null;
        if (!merged_local_projections.isEmpty()) {
            var missing: usize = 0;
            var accounts = self.accounts.iterator();
            while (accounts.next()) |entry| {
                for (entry.value_ptr.items.items) |session| {
                    if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                    if (session.local_channel_projections == null) missing += 1;
                }
            }
            if (!std.crypto.timing_safe.eql(Token, claimant.token, token) and
                claimant.local_channel_projections == null)
            {
                missing += 1;
            }
            if (missing != 0) {
                const staged = self.allocator.alloc(*LocalChannelProjectionSet, missing) catch return null;
                var created: usize = 0;
                while (created < missing) : (created += 1) {
                    staged[created] = self.allocator.create(LocalChannelProjectionSet) catch {
                        for (staged[0..created]) |set| self.allocator.destroy(set);
                        self.allocator.free(staged);
                        return null;
                    };
                    staged[created].* = .{};
                }
                staged_local_projection_sets = staged;
            }
        }
        const result_portable = switch (kind) {
            .join_existing => claimant.portable_resume or target.portable,
            .adopt_verified => |portable| portable,
        };
        keep_locked = true;
        rows_transferred = true;
        return .{
            .store = self,
            .account = account_key,
            .list = list,
            .index = index,
            .client = client,
            .expected_token = claimant.token,
            .expected_portable = claimant.portable_resume,
            .expected_dirty = claimant.replica_dirty,
            .expected_projection_dirty = claimant.replica_projection_dirty,
            .expected_local_projection_revision = claimant_set.revision,
            .target_token = token,
            .kind = kind,
            .target_portable = target.portable,
            .target_dirty = target.dirty,
            .target_projection_dirty = target.projection_dirty,
            .target_local_projection_revision = target_set.revision,
            .merged_local_projections = merged_local_projections,
            .locked_account_rows = locked_account_rows,
            .staged_local_projection_sets = staged_local_projection_sets,
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

    /// Arm or replace one desired local channel image for every row bearing
    /// `token`. This accepts non-portable groups: same-node multi-client
    /// convergence must not depend on a mesh-sealed credential.
    ///
    /// Missing per-row journals are allocated transactionally. Invalid input,
    /// OOM, or a ninth distinct unresolved channel leaves every row, generation,
    /// and counter unchanged. A case-insensitive replacement always succeeds at
    /// capacity once the journals exist.
    pub fn armTokenLocalChannelProjection(
        self: *SessionStore,
        token: Token,
        channel: []const u8,
        present: bool,
        member_mode_bits: u8,
    ) LocalProjectionArmError!LocalChannelProjection {
        return (try self.armTokenLocalChannelProjectionWithPrevious(
            token,
            channel,
            present,
            member_mode_bits,
        )).intent;
    }

    /// Arm exactly like `armTokenLocalChannelProjection`, atomically returning
    /// the prior same-channel intent for allocation-free pre-mutation rollback.
    pub fn armTokenLocalChannelProjectionWithPrevious(
        self: *SessionStore,
        token: Token,
        channel: []const u8,
        present: bool,
        member_mode_bits: u8,
    ) LocalProjectionArmError!LocalChannelProjectionArm {
        if (channel.len == 0 or channel.len > local_channel_name_capacity)
            return error.InvalidChannel;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return error.NoSuchToken;
        var next = state.local_projections;
        const existing_index = localProjectionIndex(&next, channel);
        const previous = if (existing_index) |index| next.items[index] else null;
        if (existing_index == null and next.len == local_channel_projection_capacity)
            return error.TooManyPendingChannels;

        var missing: usize = 0;
        var accounts = self.accounts.iterator();
        while (accounts.next()) |entry| {
            for (entry.value_ptr.items.items) |session| {
                if (std.crypto.timing_safe.eql(Token, session.token, token) and
                    session.local_channel_projections == null)
                {
                    missing += 1;
                }
            }
        }

        var staged: ?[]*LocalChannelProjectionSet = null;
        var staged_transferred = false;
        defer if (staged) |sets| {
            if (!staged_transferred) for (sets) |set| self.allocator.destroy(set);
            self.allocator.free(sets);
        };
        if (missing != 0) {
            const sets = try self.allocator.alloc(*LocalChannelProjectionSet, missing);
            errdefer self.allocator.free(sets);
            var created: usize = 0;
            errdefer for (sets[0..created]) |set| self.allocator.destroy(set);
            while (created < missing) : (created += 1) {
                sets[created] = try self.allocator.create(LocalChannelProjectionSet);
                sets[created].* = .{};
            }
            staged = sets;
        }

        const generation = self.nextLocalProjectionGenerationLocked();
        var intent = LocalChannelProjection{
            .generation = generation,
            .channel_len = @intCast(channel.len),
            .channel_bytes = @splat(0),
            .present = present,
            .member_mode_bits = member_mode_bits,
        };
        @memcpy(intent.channel_bytes[0..channel.len], channel);
        localProjectionUpsert(&next, intent) catch unreachable;
        next.revision = generation;

        if (staged) |sets| {
            var staged_index: usize = 0;
            accounts = self.accounts.iterator();
            while (accounts.next()) |entry| {
                for (entry.value_ptr.items.items) |*session| {
                    if (!std.crypto.timing_safe.eql(Token, session.token, token) or
                        session.local_channel_projections != null) continue;
                    session.local_channel_projections = sets[staged_index];
                    staged_index += 1;
                }
            }
            std.debug.assert(staged_index == sets.len);
            staged_transferred = true;
        }
        self.setTokenGroupLocalProjectionsLocked(token, &next);
        return .{ .intent = intent, .previous = previous };
    }

    /// Copy one pending channel image. Matching uses the daemon's current ASCII
    /// case-insensitive channel semantics; the returned value owns its bytes.
    pub fn tokenLocalChannelProjection(
        self: *const SessionStore,
        token: Token,
        channel: []const u8,
    ) ?LocalChannelProjection {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        const set = self.tokenGroupStateLocked(token).local_projections;
        const index = localProjectionIndex(&set, channel) orelse return null;
        return set.items[index];
    }

    /// Copy every pending image for one token into caller-owned storage.
    pub fn tokenLocalChannelProjectionsInto(
        self: *const SessionStore,
        token: Token,
        out: []LocalChannelProjection,
    ) []const LocalChannelProjection {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        const set = self.tokenGroupStateLocked(token).local_projections;
        const count = @min(out.len, set.len);
        @memcpy(out[0..count], set.items[0..count]);
        return out[0..count];
    }

    /// Compare-and-clear a completed local projection. A stale retry cannot
    /// erase a newer replacement or another channel's pending intent.
    pub fn clearTokenLocalChannelProjection(
        self: *SessionStore,
        token: Token,
        channel: []const u8,
        generation: u64,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var next = self.tokenGroupStateLocked(token).local_projections;
        const index = localProjectionIndex(&next, channel) orelse return false;
        if (next.items[index].generation != generation) return false;
        localProjectionRemoveAt(&next, index);
        next.revision = self.nextLocalProjectionGenerationLocked();
        self.setTokenGroupLocalProjectionsLocked(token, &next);
        return true;
    }

    /// Undo one still-current arm before its producer mutates live state. The
    /// generation CAS prevents a failed older producer from overwriting newer
    /// accepted work. Arm already allocated every row journal, so restoring a
    /// previous value (or removing a newly-added channel) cannot allocate.
    pub fn rollbackTokenLocalChannelProjectionArm(
        self: *SessionStore,
        token: Token,
        armed_generation: u64,
        previous: ?LocalChannelProjection,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var next = self.tokenGroupStateLocked(token).local_projections;
        const armed_channel = if (previous) |prior| prior.channel() else blk: {
            for (next.slice()) |projection| {
                if (projection.generation == armed_generation) break :blk projection.channel();
            }
            return false;
        };
        const index = localProjectionIndex(&next, armed_channel) orelse return false;
        if (next.items[index].generation != armed_generation) return false;
        if (previous) |prior| {
            std.debug.assert(std.ascii.eqlIgnoreCase(prior.channel(), next.items[index].channel()));
            next.items[index] = prior;
        } else {
            localProjectionRemoveAt(&next, index);
        }
        next.revision = self.nextLocalProjectionGenerationLocked();
        self.setTokenGroupLocalProjectionsLocked(token, &next);
        return true;
    }

    /// Fair, bounded, allocation-free collection of exact (token, channel)
    /// work. Its value cursor is independent from both signed-replica lanes.
    pub fn dirtyLocalProjectionsInto(
        self: *SessionStore,
        out: []LocalChannelProjectionWork,
    ) []const LocalChannelProjectionWork {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.dirty_local_projection_rows == 0 or out.len == 0) return out[0..0];

        var n: usize = 0;
        const original_cursor = self.local_projection_scan_cursor;
        var wrapped = original_cursor == null;
        var lower_bound = original_cursor;
        while (n < out.len) {
            var candidate: ?LocalChannelProjectionWork = null;
            var accounts = self.accounts.iterator();
            while (accounts.next()) |entry| {
                for (entry.value_ptr.items.items) |session| {
                    const set = session.local_channel_projections orelse continue;
                    for (set.slice()) |projection| {
                        const work = LocalChannelProjectionWork{ .token = session.token, .projection = projection };
                        if (localWorkInSlice(out[0..n], work)) continue;
                        if (lower_bound) |lower| {
                            if (localWorkOrder(work, lower) != .gt) continue;
                        }
                        if (wrapped) {
                            if (original_cursor) |upper| {
                                if (localWorkOrder(work, upper) == .gt) continue;
                            }
                        }
                        if (candidate == null or localWorkOrder(work, candidate.?) == .lt)
                            candidate = work;
                    }
                }
            }
            if (candidate) |work| {
                out[n] = work;
                n += 1;
                lower_bound = work;
                continue;
            }
            if (wrapped) break;
            wrapped = true;
            lower_bound = null;
        }
        if (n != 0) self.local_projection_scan_cursor = out[n - 1];
        return out[0..n];
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

    pub fn dirtyLocalProjectionRowCount(self: *const SessionStore) usize {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.dirty_local_projection_rows;
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

    /// Whether any live attachment currently holds this exact logical token.
    /// Positive mesh attachment leases must cross this allocation-free boundary
    /// instead of trusting a caller that may already have detached its row.
    pub fn tokenHasAttachedPortable(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        var has_attached = false;
        var has_portable = false;
        var it = self.accounts.valueIterator();
        while (it.next()) |list| {
            for (list.items.items) |session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                has_attached = has_attached or session.attached;
                has_portable = has_portable or session.portable_resume;
                if (has_attached and has_portable) return true;
            }
        }
        return false;
    }

    /// Whether any attached or detached row still owns this exact token.
    /// The daemon uses this allocation-free probe to retry a local-origin REVOKE
    /// after the final row has already been deleted and can no longer carry a
    /// row-backed dirty bit.
    pub fn containsToken(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        var it = self.accounts.valueIterator();
        while (it.next()) |list| {
            for (list.items.items) |session| {
                if (std.crypto.timing_safe.eql(Token, session.token, token)) return true;
            }
        }
        return false;
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
        freeSessionOwned(self.allocator, &entry.value_ptr.items.items[idx]);
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
                freeSessionOwned(self.allocator, &entry.value_ptr.items.items[idx]);
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

    /// Deep-copy one canonical detached snapshot per portable exact-token group.
    /// Used when a secured peer (re)establishes after missing the detach-time
    /// broadcast. Group portability is the OR of per-row issuance; selection is
    /// newest signon, then highest client id, so insertion/hash iteration order
    /// cannot make anti-entropy sign an arbitrary older ghost. The returned
    /// records and outer slice are caller-owned.
    pub fn copyPortableDetachedSnapshots(self: *const SessionStore, allocator: std.mem.Allocator) std.mem.Allocator.Error![]PortableDetachedSnapshot {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const Selection = struct {
            account: []const u8,
            session: ?*const Session = null,
            portable: bool = false,
        };
        var selections: std.AutoHashMapUnmanaged(Token, Selection) = .empty;
        defer selections.deinit(allocator);
        var row_count: usize = 0;
        var count_it = self.accounts.valueIterator();
        while (count_it.next()) |list| row_count += list.items.items.len;
        const selection_capacity = std.math.cast(u32, row_count) orelse return error.OutOfMemory;
        try selections.ensureTotalCapacity(allocator, selection_capacity);

        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |*session| {
                const selected = selections.getOrPutAssumeCapacity(session.token);
                if (!selected.found_existing) selected.value_ptr.* = .{ .account = entry.key_ptr.* };
                selected.value_ptr.portable = selected.value_ptr.portable or session.portable_resume;
                if (session.attached or session.snapshot == null) continue;
                const current = selected.value_ptr.session;
                if (current == null or session.signon_ms > current.?.signon_ms or
                    (session.signon_ms == current.?.signon_ms and session.client > current.?.client))
                {
                    selected.value_ptr.account = entry.key_ptr.*;
                    selected.value_ptr.session = session;
                }
            }
        }

        var count: usize = 0;
        var selected_count = selections.valueIterator();
        while (selected_count.next()) |selection| {
            if (selection.portable and selection.session != null) count += 1;
        }

        const out = try allocator.alloc(PortableDetachedSnapshot, count);
        errdefer allocator.free(out);
        var n: usize = 0;
        errdefer for (out[0..n]) |*record| record.deinit(allocator);
        var selected_it = selections.iterator();
        while (selected_it.next()) |entry| {
            const selection = entry.value_ptr;
            if (!selection.portable) continue;
            const session = selection.session orelse continue;
            const account = try allocator.dupe(u8, selection.account);
            errdefer allocator.free(account);
            const copied = try allocator.dupe(u8, session.snapshot.?);
            out[n] = .{ .account = account, .token = entry.key_ptr.*, .snapshot = copied };
            n += 1;
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
        local_projections: LocalChannelProjectionSet = .{},
    };

    /// Caller holds `lock` exclusively or shared for the duration of the scan.
    fn tokenGroupStateLocked(self: *const SessionStore, token: Token) TokenGroupState {
        var state: TokenGroupState = .{};
        if (tokenIsSentinel(token)) return state;
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                state.found = true;
                state.portable = state.portable or session.portable_resume;
                state.dirty = state.dirty or session.replica_dirty;
                state.projection_dirty = state.projection_dirty or session.replica_projection_dirty;
                if (session.local_channel_projections) |set| {
                    if (set.revision >= state.local_projections.revision)
                        state.local_projections = set.*;
                }
            }
        }
        return state;
    }

    /// Return exact-token group state only when every matching row belongs to
    /// `account` under ASCII case-folding. `null` is a fail-closed ownership
    /// conflict; an empty non-null state means the token is currently rowless.
    /// Caller holds the store lock for the complete scan.
    fn tokenGroupStateForAccountLocked(
        self: *const SessionStore,
        account: []const u8,
        token: Token,
    ) ?TokenGroupState {
        var state: TokenGroupState = .{};
        // The sentinel is a per-row absence marker, not a bearer capability.
        // Returning an empty non-conflicting state lets independent accounts be
        // tracked without merging their retry/portable state or authorizing a
        // later token-group bind.
        if (tokenIsSentinel(token)) return state;
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) return null;
                state.found = true;
                state.portable = state.portable or session.portable_resume;
                state.dirty = state.dirty or session.replica_dirty;
                state.projection_dirty = state.projection_dirty or session.replica_projection_dirty;
                if (session.local_channel_projections) |set| {
                    if (set.revision >= state.local_projections.revision)
                        state.local_projections = set.*;
                }
            }
        }
        return state;
    }

    /// Apply token-group dirty state and keep `dirty_replica_rows` exact. Caller
    /// holds `lock` exclusively. Portability remains a per-row issuance fact;
    /// token-group eligibility is computed by OR in `tokenGroupStateLocked`.
    fn setTokenGroupDirtyLocked(self: *SessionStore, token: Token, dirty: bool) void {
        if (tokenIsSentinel(token)) return;
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |*session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                self.setReplicaDirtyLocked(session, dirty);
            }
        }
    }

    fn setTokenGroupProjectionDirtyLocked(self: *SessionStore, token: Token, dirty: bool) void {
        if (tokenIsSentinel(token)) return;
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |*session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                self.setReplicaProjectionDirtyLocked(session, dirty);
            }
        }
    }

    fn setTokenGroupLocalProjectionsLocked(
        self: *SessionStore,
        token: Token,
        projections: *const LocalChannelProjectionSet,
    ) void {
        if (tokenIsSentinel(token)) return;
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |*session| {
                if (!std.crypto.timing_safe.eql(Token, session.token, token)) continue;
                self.setLocalProjectionsLocked(session, projections);
            }
        }
    }

    fn nextLocalProjectionGenerationLocked(self: *SessionStore) u64 {
        self.next_local_projection_generation +%= 1;
        if (self.next_local_projection_generation == 0)
            self.next_local_projection_generation = 1;
        return self.next_local_projection_generation;
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
        if (session.local_channel_projections) |set| {
            if (set.isEmpty()) return;
            std.debug.assert(self.dirty_local_projection_rows != 0);
            self.dirty_local_projection_rows -= 1;
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

    fn setLocalProjectionsLocked(
        self: *SessionStore,
        session: *Session,
        projections: *const LocalChannelProjectionSet,
    ) void {
        const was_dirty = if (session.local_channel_projections) |set| !set.isEmpty() else false;
        const now_dirty = !projections.isEmpty();
        if (now_dirty) {
            const storage = session.local_channel_projections orelse unreachable;
            storage.* = projections.*;
        } else if (session.local_channel_projections) |storage| {
            self.allocator.destroy(storage);
            session.local_channel_projections = null;
        }
        if (was_dirty == now_dirty) return;
        if (now_dirty) {
            self.dirty_local_projection_rows += 1;
        } else {
            std.debug.assert(self.dirty_local_projection_rows != 0);
            self.dirty_local_projection_rows -= 1;
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

fn localProjectionSetRevision(set: ?*const LocalChannelProjectionSet) u64 {
    return if (set) |value| value.revision else 0;
}

fn localChannelOrder(a: []const u8, b: []const u8) std.math.Order {
    const shared = @min(a.len, b.len);
    for (a[0..shared], b[0..shared]) |a_byte, b_byte| {
        const a_folded = std.ascii.toLower(a_byte);
        const b_folded = std.ascii.toLower(b_byte);
        if (a_folded < b_folded) return .lt;
        if (a_folded > b_folded) return .gt;
    }
    return std.math.order(a.len, b.len);
}

fn localProjectionIndex(set: *const LocalChannelProjectionSet, channel: []const u8) ?usize {
    for (set.slice(), 0..) |projection, index| {
        if (std.ascii.eqlIgnoreCase(projection.channel(), channel)) return index;
    }
    return null;
}

fn localProjectionUpsert(
    set: *LocalChannelProjectionSet,
    projection: LocalChannelProjection,
) error{TooManyPendingChannels}!void {
    if (localProjectionIndex(set, projection.channel())) |index| {
        set.items[index] = projection;
        return;
    }
    if (set.len == local_channel_projection_capacity) return error.TooManyPendingChannels;

    var insert_at: usize = 0;
    while (insert_at < set.len and
        localChannelOrder(set.items[insert_at].channel(), projection.channel()) == .lt)
    {
        insert_at += 1;
    }
    var cursor: usize = set.len;
    while (cursor > insert_at) : (cursor -= 1)
        set.items[cursor] = set.items[cursor - 1];
    set.items[insert_at] = projection;
    set.len += 1;
}

fn localProjectionRemoveAt(set: *LocalChannelProjectionSet, index: usize) void {
    std.debug.assert(index < set.len);
    var cursor = index;
    while (cursor + 1 < set.len) : (cursor += 1)
        set.items[cursor] = set.items[cursor + 1];
    set.len -= 1;
    set.items[set.len] = .{};
}

fn mergeLocalProjectionSets(
    out: *LocalChannelProjectionSet,
    a: *const LocalChannelProjectionSet,
    b: *const LocalChannelProjectionSet,
) bool {
    out.* = .{};
    for (a.slice()) |projection|
        localProjectionUpsert(out, projection) catch return false;
    for (b.slice()) |projection| {
        if (localProjectionIndex(out, projection.channel())) |index| {
            if (projection.generation > out.items[index].generation)
                out.items[index] = projection;
            continue;
        }
        localProjectionUpsert(out, projection) catch return false;
    }
    out.revision = @max(a.revision, b.revision);
    return true;
}

fn localWorkOrder(a: LocalChannelProjectionWork, b: LocalChannelProjectionWork) std.math.Order {
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order;
    return localChannelOrder(a.projection.channel(), b.projection.channel());
}

fn localWorkInSlice(
    work: []const LocalChannelProjectionWork,
    needle: LocalChannelProjectionWork,
) bool {
    for (work) |candidate| {
        if (std.crypto.timing_safe.eql(Token, candidate.token, needle.token) and
            std.ascii.eqlIgnoreCase(candidate.projection.channel(), needle.projection.channel()))
        {
            return true;
        }
    }
    return false;
}

fn freeSnapshot(allocator: std.mem.Allocator, session: *Session) void {
    if (session.snapshot) |bytes| allocator.free(bytes);
    session.snapshot = null;
}

fn freeSessionOwned(allocator: std.mem.Allocator, session: *Session) void {
    freeSnapshot(allocator, session);
    if (session.local_channel_projections) |set| allocator.destroy(set);
    session.local_channel_projections = null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn tok(b: u8) Token {
    return @as([16]u8, @splat(b));
}

test "local channel projection journals overlapping channels and CAS clears independently" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x31);
    const too_long: [local_channel_name_capacity + 1]u8 = @splat('x');
    try testing.expectError(error.InvalidChannel, s.armTokenLocalChannelProjection(token, &too_long, true, 0));
    try testing.expectError(error.NoSuchToken, s.armTokenLocalChannelProjection(token, "#missing", true, 0));
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    const a = try s.armTokenLocalChannelProjection(token, "#a", true, 0x0D);
    const b = try s.armTokenLocalChannelProjection(token, "#b", false, 0x02);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(a.generation, s.tokenLocalChannelProjection(token, "#A").?.generation);
    try testing.expectEqual(b.generation, s.tokenLocalChannelProjection(token, "#b").?.generation);

    var all: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    try testing.expectEqual(@as(usize, 2), s.tokenLocalChannelProjectionsInto(token, &all).len);
    try testing.expect(!s.clearTokenLocalChannelProjection(token, "#a", b.generation));
    try testing.expect(s.clearTokenLocalChannelProjection(token, "#A", a.generation));
    try testing.expect(s.tokenLocalChannelProjection(token, "#a") == null);
    try testing.expect(s.tokenLocalChannelProjection(token, "#b") != null);
    try testing.expect(s.clearTokenLocalChannelProjection(token, "#b", b.generation));
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
}

test "local channel projection rejected arm restores prior intent without erasing newer work" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x30);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    _ = try s.attach("alice", 3, token, 3);
    const prior = try s.armTokenLocalChannelProjection(token, "#keep", true, 0x0D);
    const replacement = try s.armTokenLocalChannelProjectionWithPrevious(token, "#KEEP", false, 0);
    try testing.expectEqual(prior.generation, replacement.previous.?.generation);
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
        token,
        replacement.intent.generation,
        replacement.previous,
    ));
    const restored = s.tokenLocalChannelProjection(token, "#keep").?;
    try testing.expectEqual(prior.generation, restored.generation);
    try testing.expect(restored.present);
    try testing.expectEqual(@as(u8, 0x0D), restored.member_mode_bits);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
    var rows: [3]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |row| {
        const set = row.local_channel_projections orelse return error.TestUnexpectedResult;
        const index = localProjectionIndex(set, "#keep") orelse return error.TestUnexpectedResult;
        try testing.expectEqual(prior.generation, set.items[index].generation);
        try testing.expect(set.items[index].present);
        try testing.expectEqual(@as(u8, 0x0D), set.items[index].member_mode_bits);
    }

    const prior_absent = try s.armTokenLocalChannelProjection(token, "#absent", false, 0x06);
    const replacement_present = try s.armTokenLocalChannelProjectionWithPrevious(token, "#ABSENT", true, 0x03);
    try testing.expectEqual(prior_absent.generation, replacement_present.previous.?.generation);
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
        token,
        replacement_present.intent.generation,
        replacement_present.previous,
    ));
    const restored_absent = s.tokenLocalChannelProjection(token, "#absent").?;
    try testing.expectEqual(prior_absent.generation, restored_absent.generation);
    try testing.expect(!restored_absent.present);
    try testing.expectEqual(@as(u8, 0x06), restored_absent.member_mode_bits);

    const stale = try s.armTokenLocalChannelProjectionWithPrevious(token, "#keep", false, 0);
    const newest = try s.armTokenLocalChannelProjection(token, "#keep", true, 0x03);
    try testing.expect(!s.rollbackTokenLocalChannelProjectionArm(token, stale.intent.generation, stale.previous));
    try testing.expectEqual(newest.generation, s.tokenLocalChannelProjection(token, "#keep").?.generation);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "local channel projection prior-null rollback removes every exact row and preserves CAS" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x2F);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    _ = try s.attach("alice", 3, token, 3);
    const newly_added = try s.armTokenLocalChannelProjectionWithPrevious(token, "#new", true, 1);
    try testing.expect(newly_added.previous == null);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(token, newly_added.intent.generation, null));
    try testing.expect(s.tokenLocalChannelProjection(token, "#new") == null);
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
    var rows: [3]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |row|
        try testing.expect(row.local_channel_projections == null);
    try testing.expect(!s.rollbackTokenLocalChannelProjectionArm(token, newly_added.intent.generation, null));

    const stale = try s.armTokenLocalChannelProjectionWithPrevious(token, "#new", false, 2);
    const newest = try s.armTokenLocalChannelProjection(token, "#NEW", true, 7);
    try testing.expect(!s.rollbackTokenLocalChannelProjectionArm(token, stale.intent.generation, null));
    const retained = s.tokenLocalChannelProjection(token, "#new").?;
    try testing.expectEqual(newest.generation, retained.generation);
    try testing.expect(retained.present);
    try testing.expectEqual(@as(u8, 7), retained.member_mode_bits);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "local channel projection arm OOM is transactional and retryable" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const token = tok(0x32);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    const generation_before = s.next_local_projection_generation;
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, s.armTokenLocalChannelProjection(token, "#oom", true, 1));
    try testing.expectEqual(generation_before, s.next_local_projection_generation);
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
    try testing.expect(s.tokenLocalChannelProjection(token, "#oom") == null);

    failing.fail_index = std.math.maxInt(usize);
    const armed = try s.armTokenLocalChannelProjection(token, "#oom", true, 1);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    // Once journals exist, same-channel replacement/read/scan/clear allocate nothing.
    failing.has_induced_failure = false;
    failing.fail_index = failing.alloc_index;
    const replaced = try s.armTokenLocalChannelProjection(token, "#OOM", false, 3);
    try testing.expect(replaced.generation > armed.generation);
    var work_buf: [2]LocalChannelProjectionWork = undefined;
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionsInto(&work_buf).len);
    try testing.expect(s.clearTokenLocalChannelProjection(token, "#oom", replaced.generation));
    try testing.expect(!failing.has_induced_failure);
}

test "local channel projection capacity fails closed and full same-channel arm coalesces" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const token = tok(0x33);
    _ = try s.attach("alice", 1, token, 1);

    var first_generation: u64 = 0;
    for (0..local_channel_projection_capacity) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#c{d}", .{index});
        const intent = try s.armTokenLocalChannelProjection(token, channel, true, @intCast(index));
        if (index == 0) first_generation = intent.generation;
    }
    const generation_before = s.next_local_projection_generation;
    try testing.expectError(
        error.TooManyPendingChannels,
        s.armTokenLocalChannelProjection(token, "#overflow", true, 0),
    );
    try testing.expectEqual(generation_before, s.next_local_projection_generation);

    failing.fail_index = failing.alloc_index;
    const replacement = try s.armTokenLocalChannelProjection(token, "#C0", false, 7);
    try testing.expect(replacement.generation > first_generation);
    try testing.expect(!s.tokenLocalChannelProjection(token, "#c0").?.present);
    try testing.expect(!failing.has_induced_failure);
    var all: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    try testing.expectEqual(local_channel_projection_capacity, s.tokenLocalChannelProjectionsInto(token, &all).len);
}

test "local channel projection reversible replacement remains allocation-free at capacity" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const token = tok(0x2E);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);

    var edge_generation: u64 = 0;
    for (0..local_channel_projection_capacity) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#r{d}", .{index});
        const intent = try s.armTokenLocalChannelProjection(token, channel, true, @intCast(index));
        if (index == local_channel_projection_capacity - 1) edge_generation = intent.generation;
    }
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

    failing.fail_index = failing.alloc_index;
    const replacement = try s.armTokenLocalChannelProjectionWithPrevious(token, "#R7", false, 0x7F);
    try testing.expectEqual(edge_generation, replacement.previous.?.generation);
    try testing.expect(!failing.has_induced_failure);
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
        token,
        replacement.intent.generation,
        replacement.previous,
    ));
    try testing.expect(!failing.has_induced_failure);
    const restored = s.tokenLocalChannelProjection(token, "#r7").?;
    try testing.expectEqual(edge_generation, restored.generation);
    try testing.expect(restored.present);
    try testing.expectEqual(@as(u8, 7), restored.member_mode_bits);
    var all: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    try testing.expectEqual(local_channel_projection_capacity, s.tokenLocalChannelProjectionsInto(token, &all).len);
    try testing.expectError(
        error.TooManyPendingChannels,
        s.armTokenLocalChannelProjectionWithPrevious(token, "#overflow", true, 0),
    );
    try testing.expect(!failing.has_induced_failure);
}

test "local channel projection survives detach and sibling removal until final row" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const token = tok(0x34);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    const intent = try s.armTokenLocalChannelProjection(token, "#durable", true, 3);
    try testing.expect(s.markDetached("alice", 1));
    try testing.expect(s.remove("alice", 1));
    try testing.expectEqual(intent.generation, s.tokenLocalChannelProjection(token, "#durable").?.generation);
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(@as(usize, 1), s.removeClient(2));
    try testing.expect(s.tokenLocalChannelProjection(token, "#durable") == null);
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
}

test "attach inheritance stages lazy journals before append or replacement mutation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const target = tok(0x35);
    const clean = tok(0x36);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, clean, 2);
    const intent = try s.armTokenLocalChannelProjection(target, "#inherit", true, 1);

    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, s.attach("alice", 3, target, 3));
    try testing.expect(!s.containsClient("alice", 3));
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionRowCount());

    failing.fail_index = std.math.maxInt(usize);
    _ = try s.attach("alice", 3, target, 3);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(intent.generation, s.tokenLocalChannelProjection(target, "#inherit").?.generation);

    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, s.attach("alice", 2, target, 4));
    try testing.expect(s.clientHasToken("alice", 2, clean));
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind preserves channel union and newest case-insensitive collision" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x41);
    const source = tok(0x42);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, source, 2);
    _ = try s.attach("alice", 3, source, 3);
    _ = try s.armTokenLocalChannelProjection(target, "#a", true, 1);
    const target_same = try s.armTokenLocalChannelProjection(target, "#same", true, 1);
    _ = try s.armTokenLocalChannelProjection(source, "#b", false, 2);
    const newest = try s.armTokenLocalChannelProjection(source, "#SAME", false, 7);

    // Aborting a prepared merge must not rewrite either token group's source
    // image or consume the staged target rows.
    var aborted = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    aborted.abort();
    aborted.deinit();
    try testing.expectEqual(target_same.generation, s.tokenLocalChannelProjection(target, "#same").?.generation);
    try testing.expectEqual(newest.generation, s.tokenLocalChannelProjection(source, "#same").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(target, "#b") == null);
    try testing.expect(s.tokenLocalChannelProjection(source, "#a") == null);

    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    var preview_buf: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    const preview = prepared.mergedLocalChannelProjectionsInto(&preview_buf);
    try testing.expectEqual(@as(usize, 3), preview.len);
    try testing.expect(std.ascii.eqlIgnoreCase(preview[0].channel(), "#a"));
    try testing.expect(std.ascii.eqlIgnoreCase(preview[1].channel(), "#b"));
    try testing.expect(std.ascii.eqlIgnoreCase(preview[2].channel(), "#same"));
    try testing.expectEqual(newest.generation, preview[2].generation);
    try testing.expect(!preview[2].present);
    try testing.expect(prepared.commit());
    prepared.finish();
    try testing.expect(s.tokenLocalChannelProjection(target, "#a") != null);
    try testing.expect(s.tokenLocalChannelProjection(target, "#b") != null);
    try testing.expectEqual(newest.generation, s.tokenLocalChannelProjection(target, "#same").?.generation);
    // The surviving source sibling retains its source-token journal only.
    try testing.expect(s.tokenLocalChannelProjection(source, "#a") == null);
    try testing.expect(s.tokenLocalChannelProjection(source, "#b") != null);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind preview is complete at capacity and keeps newest target collision" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x3C);
    const source = tok(0x3D);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, source, 2);

    const older_collision = try s.armTokenLocalChannelProjection(source, "#case", false, 1);
    for (0..3) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#s{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(source, channel, index % 2 == 0, @intCast(index));
    }
    const newer_collision = try s.armTokenLocalChannelProjection(target, "#CASE", true, 0x7F);
    try testing.expect(newer_collision.generation > older_collision.generation);
    for (0..4) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#t{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(target, channel, index % 2 != 0, @intCast(index + 8));
    }

    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    var preview_buf: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    const preview = prepared.mergedLocalChannelProjectionsInto(&preview_buf);
    try testing.expectEqual(local_channel_projection_capacity, preview.len);
    for (preview[1..], 1..) |projection, index|
        try testing.expect(localChannelOrder(preview[index - 1].channel(), projection.channel()) == .lt);
    var collision_count: usize = 0;
    for (preview) |projection| {
        if (!std.ascii.eqlIgnoreCase(projection.channel(), "#case")) continue;
        collision_count += 1;
        try testing.expectEqualStrings("#CASE", projection.channel());
        try testing.expectEqual(newer_collision.generation, projection.generation);
        try testing.expect(projection.present);
        try testing.expectEqual(@as(u8, 0x7F), projection.member_mode_bits);
    }
    try testing.expectEqual(@as(usize, 1), collision_count);

    try testing.expect(prepared.commit());
    prepared.finish();
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    var rows: [2]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |row| {
        try testing.expect(std.crypto.timing_safe.eql(Token, row.token, target));
        const set = row.local_channel_projections orelse return error.TestUnexpectedResult;
        try testing.expectEqual(local_channel_projection_capacity, set.slice().len);
        const index = localProjectionIndex(set, "#case") orelse return error.TestUnexpectedResult;
        try testing.expectEqual(newer_collision.generation, set.items[index].generation);
    }
}

test "prepared token bind row snapshot supersedes stale exact-case copy and freezes folded account" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x3A);
    const generated = tok(0x3B);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, generated, 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));

    const stale = try s.copySessionsAlloc(testing.allocator, "alice");
    defer testing.allocator.free(stale);
    try testing.expectEqual(@as(usize, 2), stale.len);
    try testing.expect(stale[0].attached);

    // Deterministically model the old race window between copySessionsAlloc and
    // prepareTokenBind: one target row detaches and another attaches under a
    // case-variant spelling before the retained ticket acquires its lock.
    try testing.expect(s.markDetached("alice", 1));
    _ = try s.attach("ALICE", 3, target, 3);

    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    const rows = prepared.accountRows();
    try testing.expectEqual(@as(usize, 3), rows.len);
    try testing.expectEqual(@as(ClientId, 1), rows[0].client);
    try testing.expectEqual(@as(ClientId, 2), rows[1].client);
    try testing.expectEqual(@as(ClientId, 3), rows[2].client);
    try testing.expect(!rows[0].attached);
    try testing.expect(rows[0].portable_resume);
    try testing.expectEqual(target, rows[0].token);
    try testing.expect(rows[1].attached);
    try testing.expectEqual(generated, rows[1].token);
    try testing.expect(rows[2].attached);
    try testing.expectEqual(target, rows[2].token);
    try testing.expect(prepared.resultPortable());
    try testing.expect(!s.lock.tryLockExclusive());

    // The stale exact-case copy cannot see C3 and still reports C1 attached;
    // only the ticket snapshot is complete/current enough for World planning.
    try testing.expect(stale[0].attached);
    for (stale) |row| try testing.expect(row.client != 3);

    try testing.expect(prepared.commit());
    try testing.expectEqual(@as(usize, 3), prepared.accountRows().len);
    prepared.finish();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, target));
    try testing.expect(s.clientHasToken("ALICE", 3, target));
}

test "prepared token bind rejects duplicate client ids across folded account keys" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x38);
    const generated = tok(0x39);
    const conflicting = tok(0x37);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, generated, 2);
    _ = try s.attach("ALICE", 1, conflicting, 3);

    try testing.expect(s.prepareTokenBind("alice", 2, target, .join_existing) == null);
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 1, target));
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(s.clientHasToken("ALICE", 1, conflicting));
    try testing.expect(!s.clientHasToken("alice", 2, target));
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind locked row allocation OOM is transactional and retryable" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const target = tok(0x35);
    const generated = tok(0x36);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, generated, 2);

    failing.fail_index = failing.alloc_index;
    try testing.expect(s.prepareTokenBind("alice", 2, target, .join_existing) == null);
    try testing.expect(failing.has_induced_failure);
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(!s.clientHasToken("alice", 2, target));

    failing.fail_index = std.math.maxInt(usize);
    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expectEqual(@as(usize, 2), prepared.accountRows().len);
    prepared.abort();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, generated));
}

test "prepared token bind folded row and staged journal tickets are leak-clean on every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const target = tok(0x33);
            _ = try s.attach("alice", 1, target, 1);
            const intent = try s.armTokenLocalChannelProjection(target, "#locked", true, 3);
            _ = try s.attach("ALICE", 3, target, 3);
            _ = try s.attach("alice", 2, tok(0x34), 2);

            // Implicit prepared deinit and explicit abort must both release the
            // row snapshot plus the claimant's staged lazy journal unchanged.
            var implicit = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            try testing.expectEqual(@as(usize, 3), implicit.accountRows().len);
            implicit.deinit();
            var aborted = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            try testing.expectEqual(@as(usize, 3), aborted.accountRows().len);
            aborted.abort();
            aborted.deinit();
            try testing.expect(s.lock.tryLockExclusive());
            s.lock.unlockExclusive();
            try testing.expect(s.clientHasToken("alice", 2, tok(0x34)));
            try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

            // Success commits the same prepared resources without allocating,
            // then finish frees the locked rows before releasing the lock.
            var committed = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            defer committed.deinit();
            try testing.expect(committed.commit());
            committed.finish();
            try testing.expect(s.clientHasToken("alice", 2, target));
            try testing.expectEqual(intent.generation, s.tokenLocalChannelProjection(target, "#locked").?.generation);
            try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "prepared token adopt carries the journal and abort frees staged rows" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x45);
    const source = tok(0x46);
    _ = try s.attach("alice", 1, source, 1);
    _ = try s.attach("alice", 2, source, 2);
    const a = try s.armTokenLocalChannelProjection(source, "#a", true, 1);
    const b = try s.armTokenLocalChannelProjection(source, "#b", false, 2);

    var adopt = s.prepareTokenBind("alice", 1, target, .{ .adopt_verified = false }) orelse
        return error.TestUnexpectedResult;
    defer adopt.deinit();
    try testing.expect(adopt.commit());
    adopt.finish();
    try testing.expectEqual(a.generation, s.tokenLocalChannelProjection(target, "#a").?.generation);
    try testing.expectEqual(b.generation, s.tokenLocalChannelProjection(target, "#b").?.generation);
    try testing.expectEqual(a.generation, s.tokenLocalChannelProjection(source, "#a").?.generation);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

    // A clean claimant joining the dirty target requires a staged journal. An
    // abort must destroy it and leave the claimant/token/count untouched.
    const clean = tok(0x47);
    _ = try s.attach("alice", 3, clean, 3);
    var aborted = s.prepareTokenBind("alice", 3, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    aborted.abort();
    aborted.deinit();
    try testing.expect(s.clientHasToken("alice", 3, clean));
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind rejects an over-capacity union without mutation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x43);
    const source = tok(0x44);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, source, 2);
    for (0..5) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#t{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(target, channel, true, 0);
    }
    for (0..4) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#s{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(source, channel, true, 0);
    }
    try testing.expect(s.prepareTokenBind("alice", 2, target, .join_existing) == null);
    try testing.expect(s.clientHasToken("alice", 2, source));
    try testing.expect(s.tokenLocalChannelProjection(target, "#t0") != null);
    try testing.expect(s.tokenLocalChannelProjection(source, "#s0") != null);
}

test "bounded local projection work scan rotates across channels and tokens" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const a = tok(0x50);
    const b = tok(0x51);
    _ = try s.attach("a", 1, a, 1);
    _ = try s.attach("b", 2, b, 2);
    _ = try s.armTokenLocalChannelProjection(a, "#a", true, 0);
    _ = try s.armTokenLocalChannelProjection(a, "#b", true, 0);
    _ = try s.armTokenLocalChannelProjection(b, "#a", true, 0);

    var first_buf: [2]LocalChannelProjectionWork = undefined;
    const first = s.dirtyLocalProjectionsInto(&first_buf);
    try testing.expectEqual(@as(usize, 2), first.len);
    var second_buf: [2]LocalChannelProjectionWork = undefined;
    const second = s.dirtyLocalProjectionsInto(&second_buf);
    try testing.expectEqual(@as(usize, 2), second.len);
    try testing.expect(!localWorkInSlice(first, second[0]));
    try testing.expect(localWorkInSlice(first, second[1])); // wrapped fairly
}

test "local projection arm and prepared bind allocation failures are leak-clean" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const target = tok(0x71);
            _ = try s.attach("sweep", 1, target, 1);
            _ = try s.attach("sweep", 2, tok(0x72), 2);
            const intent = try s.armTokenLocalChannelProjection(target, "#sweep", true, 0x0F);
            var prepared = s.prepareTokenBind("sweep", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            defer prepared.deinit();
            try testing.expect(prepared.commit());
            prepared.finish();
            try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
            try testing.expect(s.clearTokenLocalChannelProjection(target, "#sweep", intent.generation));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "reversible local projection arm and rollback are leak-clean across every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const token = tok(0x70);
            _ = try s.attach("rollback-sweep", 1, token, 1);
            _ = try s.attach("rollback-sweep", 2, token, 2);
            _ = try s.attach("rollback-sweep", 3, token, 3);

            const prior = try s.armTokenLocalChannelProjection(token, "#prior", false, 0x06);
            const replacement = try s.armTokenLocalChannelProjectionWithPrevious(token, "#PRIOR", true, 0x03);
            try testing.expectEqual(prior.generation, replacement.previous.?.generation);
            try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
                token,
                replacement.intent.generation,
                replacement.previous,
            ));
            const restored = s.tokenLocalChannelProjection(token, "#prior").?;
            try testing.expectEqual(prior.generation, restored.generation);
            try testing.expect(!restored.present);
            try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());

            const added = try s.armTokenLocalChannelProjectionWithPrevious(token, "#new", true, 1);
            try testing.expect(added.previous == null);
            try testing.expect(s.rollbackTokenLocalChannelProjectionArm(token, added.intent.generation, null));
            try testing.expect(s.tokenLocalChannelProjection(token, "#new") == null);
            try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "local projection arm rolls back every lazy journal allocation boundary" {
    for (0..3) |failure_offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.init(failing.allocator());
        defer s.deinit();
        const token = tok(@intCast(0x78 + failure_offset));
        _ = try s.attach("rollback", 1, token, 1);
        _ = try s.attach("rollback", 2, token, 2);

        failing.fail_index = failing.alloc_index + failure_offset;
        try testing.expectError(
            error.OutOfMemory,
            s.armTokenLocalChannelProjection(token, "#rollback", true, 1),
        );
        try testing.expectEqual(@as(u64, 0), s.next_local_projection_generation);
        try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
        try testing.expect(s.tokenLocalChannelProjection(token, "#rollback") == null);

        failing.fail_index = std.math.maxInt(usize);
        _ = try s.armTokenLocalChannelProjection(token, "#rollback", true, 1);
        try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    }
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

test "portable detached anti-entropy selects one newest snapshot independent of insertion order" {
    const token = tok(0x2a);
    var stores = [_]SessionStore{
        SessionStore.init(testing.allocator),
        SessionStore.init(testing.allocator),
    };
    defer for (&stores) |*store| store.deinit();

    // Same logical rows, reversed insertion order. Only the older row receives
    // the credential, proving portability is group-wide while snapshot choice
    // remains newest signon rather than "portable row" or hash order.
    _ = try stores[0].attach("Alice", 10, token, 100);
    _ = try stores[0].attach("aLiCe", 20, token, 200);
    _ = try stores[1].attach("aLiCe", 20, token, 200);
    _ = try stores[1].attach("Alice", 10, token, 100);
    for (&stores) |*store| {
        try testing.expect(store.markPortableResumeIssued("Alice", 10));
        try testing.expect(store.markDetachedWithSnapshot("Alice", 10, "older"));
        try testing.expect(store.markDetachedWithSnapshot("aLiCe", 20, "newest"));
        const copies = try store.copyPortableDetachedSnapshots(testing.allocator);
        defer {
            for (copies) |*copy| copy.deinit(testing.allocator);
            testing.allocator.free(copies);
        }
        try testing.expectEqual(@as(usize, 1), copies.len);
        try testing.expectEqualSlices(u8, &token, &copies[0].token);
        try testing.expectEqualStrings("aLiCe", copies[0].account);
        try testing.expectEqualStrings("newest", copies[0].snapshot);
    }
}

test "portable detached canonical copy is leak-clean at every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const token = tok(0x2b);
            _ = try s.attach("alice", 1, token, 10);
            _ = try s.attach("alice", 2, token, 20);
            try testing.expect(s.markPortableResumeIssued("alice", 1));
            if (!s.markDetachedWithSnapshot("alice", 1, "old")) return error.OutOfMemory;
            if (!s.markDetachedWithSnapshot("alice", 2, "new")) return error.OutOfMemory;
            const copies = try s.copyPortableDetachedSnapshots(allocator);
            defer {
                for (copies) |*copy| copy.deinit(allocator);
                allocator.free(copies);
            }
            try testing.expectEqual(@as(usize, 1), copies.len);
            try testing.expectEqualStrings("new", copies[0].snapshot);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
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

test "tokenHasAttachedPortable distinguishes live siblings from final detached token" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(0x21), 1);
    _ = try s.attach("alice", 2, tok(0x21), 2);
    _ = try s.attach("bob", 3, tok(0x22), 3);
    try testing.expect(!s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markPortableResumeIssued("alice", 2));
    try testing.expect(s.markPortableResumeIssued("bob", 3));
    try testing.expect(s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "one"));
    try testing.expect(s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "two"));
    try testing.expect(!s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.tokenHasAttachedPortable(tok(0x22)));
    try testing.expect(!s.tokenHasAttachedPortable(tok(0xff)));
    try testing.expect(s.containsToken(tok(0x21)));
    try testing.expect(s.containsToken(tok(0x22)));
    try testing.expect(!s.containsToken(tok(0xff)));
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

test "token group stays portable when issuing sibling detaches" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0xac);
    _ = try s.attach("alice", 1, token, 10);
    _ = try s.attach("alice", 2, token, 20);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetached("alice", 1));

    // Per-row issuance remains exact for checkpoint/audit purposes.
    var rows: [2]Session = undefined;
    const sessions = s.sessionsInto("alice", &rows);
    try testing.expectEqual(@as(usize, 2), sessions.len);
    for (sessions) |session| {
        try testing.expectEqual(session.client == 1, session.portable_resume);
    }

    // Group-facing APIs combine "any portable" with "any attached". Client B
    // can therefore renew the lease and detach into mesh resume state even
    // though client A was the attachment that received the credential.
    const b = s.resumeHandleForClient("alice", 2) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &token, &b.token);
    try testing.expect(b.portable);
    try testing.expect(s.tokenHasAttachedPortable(token));

    try testing.expect(s.markDetached("alice", 2));
    try testing.expect(!s.tokenHasAttachedPortable(token));
    try testing.expect(s.resumeHandleForClient("alice", 2).?.portable);
}

test "prepared token join aborts cleanly then prepared commit needs no allocation" {
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

    // Preparation intentionally allocates the complete folded-account snapshot
    // and any missing projection journals while holding the lock. Once that
    // plan exists, fail the allocator's very next request: commit itself must
    // remain allocation-free and publish the exact group transition in one step.
    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    failing.fail_index = failing.alloc_index;
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

test "prepared verified adopt rejects cross-account tokens and preserves rowless retry state" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const generated = tok(0x11);
    const foreign = tok(0x99);
    const verified = tok(0x98);
    _ = try s.attach("alice", 1, generated, 10);
    _ = try s.attach("bob", 2, foreign, 20);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(generated));
    try testing.expect(s.markTokenReplicaProjectionDirty(generated));

    // A row in another account never authorizes join_existing.
    try testing.expect(s.prepareTokenBind("alice", 1, foreign, .join_existing) == null);
    // External verification cannot relabel a token already owned by a different
    // account either. The chosen token must remain globally account-bound.
    try testing.expect(s.prepareTokenBind("alice", 1, foreign, .{ .adopt_verified = false }) == null);
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
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
}

test "attach rejects cross-account token collision before dirty journal mutation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const target = tok(0x9a);
    const source = tok(0x9b);
    _ = try s.attach("Alice", 1, target, 10);
    _ = try s.attach("bob", 2, source, 20);
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markTokenReplicaDirty(target));
    try testing.expect(s.markTokenReplicaProjectionDirty(target));
    const target_intent = try s.armTokenLocalChannelProjection(target, "#target", true, 3);
    const source_intent = try s.armTokenLocalChannelProjection(source, "#source", false, 7);
    const dirty_rows = s.dirtyReplicaRowCount();
    const projection_rows = s.dirtyReplicaProjectionRowCount();
    const local_rows = s.dirtyLocalProjectionRowCount();

    // Collision detection is allocation-free and precedes replacement, dirty
    // propagation, and journal union. Even an allocator armed to fail remains
    // untouched because the chosen token already belongs to another account.
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.TokenAccountMismatch, s.attach("bob", 2, target, 30));
    try testing.expect(!failing.has_induced_failure);
    try testing.expect(s.clientHasToken("bob", 2, source));
    try testing.expect(!s.clientHasToken("bob", 2, target));
    try testing.expectEqual(dirty_rows, s.dirtyReplicaRowCount());
    try testing.expectEqual(projection_rows, s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(local_rows, s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(target_intent.generation, s.tokenLocalChannelProjection(target, "#target").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(target, "#source") == null);
    try testing.expectEqual(source_intent.generation, s.tokenLocalChannelProjection(source, "#source").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(source, "#target") == null);

    // ASCII case variants are the same account boundary and may share the
    // exact token. The new row inherits the target group's durable retry state.
    failing.fail_index = std.math.maxInt(usize);
    _ = try s.attach("aLiCe", 3, target, 40);
    try testing.expect(s.clientHasToken("aLiCe", 3, target));
    try testing.expect(s.tokenReplicaDirty(target));
    try testing.expect(s.tokenReplicaProjectionDirty(target));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "sentinel tracks independent accounts without becoming a token group" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const sentinel: Token = @splat(0);
    _ = try s.attach("alice", 1, sentinel, 10);
    _ = try s.attach("bob", 2, sentinel, 20);
    _ = try s.attach("alice", 3, sentinel, 30);

    const alice = s.resumeHandleForClient("alice", 1) orelse
        return error.TestUnexpectedResult;
    const bob = s.resumeHandleForClient("bob", 2) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(sentinel, alice.token);
    try testing.expectEqual(sentinel, bob.token);
    try testing.expect(!alice.portable);
    try testing.expect(!bob.portable);

    // The absence marker cannot be issued, joined, adopted, dirtied, or given
    // a channel-projection journal as though it were a reusable credential.
    try testing.expect(!s.markPortableResumeIssued("alice", 1));
    try testing.expect(!s.restorePortableResumeIssued("bob", 2, true));
    try testing.expect(s.prepareTokenBind("alice", 3, sentinel, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("alice", 3, sentinel, .{ .adopt_verified = true }) == null);
    try testing.expect(!s.markTokenReplicaDirty(sentinel));
    try testing.expectError(
        error.NoSuchToken,
        s.armTokenLocalChannelProjection(sentinel, "#sentinel", true, 0),
    );
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
}

test "prepared bind enforces folded token account and rolls back staged case-variant journal OOM" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const target = tok(0xa8);
    const same_account_source = tok(0xa9);
    const foreign_source = tok(0xaa);
    _ = try s.attach("Alice", 1, target, 10);
    _ = try s.attach("ALICE", 2, same_account_source, 20);
    _ = try s.attach("bob", 3, foreign_source, 30);
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markTokenReplicaDirty(target));
    try testing.expect(s.markTokenReplicaProjectionDirty(target));
    const target_intent = try s.armTokenLocalChannelProjection(target, "#target", true, 1);
    const foreign_intent = try s.armTokenLocalChannelProjection(foreign_source, "#foreign", false, 2);

    // Both join and externally verified adoption reject a chosen token already
    // owned by a non-equivalent account, without merging either retry journal.
    failing.fail_index = failing.alloc_index;
    try testing.expect(s.prepareTokenBind("bob", 3, target, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("bob", 3, target, .{ .adopt_verified = true }) == null);
    try testing.expect(!failing.has_induced_failure);
    try testing.expect(s.clientHasToken("bob", 3, foreign_source));
    try testing.expectEqual(target_intent.generation, s.tokenLocalChannelProjection(target, "#target").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(target, "#foreign") == null);
    try testing.expectEqual(foreign_intent.generation, s.tokenLocalChannelProjection(foreign_source, "#foreign").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(foreign_source, "#target") == null);

    // Joining through a case-variant account is valid, but the clean claimant
    // needs a staged journal allocation. Injected OOM aborts before mutation.
    failing.fail_index = failing.alloc_index;
    try testing.expect(s.prepareTokenBind("ALICE", 2, target, .join_existing) == null);
    try testing.expect(failing.has_induced_failure);
    try testing.expect(s.clientHasToken("ALICE", 2, same_account_source));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

    failing.fail_index = std.math.maxInt(usize);
    var prepared = s.prepareTokenBind("ALICE", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expect(prepared.commit());
    prepared.finish();
    try testing.expect(s.clientHasToken("ALICE", 2, target));
    try testing.expect(s.tokenReplicaDirty(target));
    try testing.expect(s.tokenReplicaProjectionDirty(target));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
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

test "prepared token bind commit remains no-allocation after exhaustive preparation failures" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();

            const target = tok(0x71);
            _ = try s.attach("sweep", 1, target, 1);
            _ = try s.attach("sweep", 2, tok(0x72), 2);
            try testing.expect(s.markPortableResumeIssued("sweep", 1));

            var prepared = s.prepareTokenBind("sweep", 2, target, .join_existing) orelse
                return error.OutOfMemory;
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

    fn token(writer_id: usize, i: usize, lane: u8) Token {
        var value: Token = @splat(0);
        value[0] = @intCast(writer_id + 1);
        value[1] = @intCast(i);
        value[2] = lane;
        return value;
    }

    fn writer(ctx: *SessionMtCtx) void {
        var acct_buf: [16]u8 = undefined;
        var tmp_buf: [24]u8 = undefined;
        const acct = account(&acct_buf, ctx.writer_id);
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const cid = client(ctx.writer_id, i);
            _ = ctx.store.attach(acct, cid, token(ctx.writer_id, i, 1), @intCast(i)) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if ((i & 1) == 0) {
                if (!ctx.store.markDetached(acct, cid)) {
                    _ = ctx.failures.fetchAdd(1, .monotonic);
                    return;
                }
                _ = ctx.store.attach(acct, cid, token(ctx.writer_id, i, 2), @intCast(i + 1000)) catch {
                    _ = ctx.failures.fetchAdd(1, .monotonic);
                    return;
                };
            }

            const tmp = tempAccount(&tmp_buf, ctx.writer_id, i);
            const tmp_cid = tempClient(ctx.writer_id, i);
            _ = ctx.store.attach(tmp, tmp_cid, token(ctx.writer_id, i, 3), @intCast(i)) catch {
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
    // Prevent the error cleanup from joining already-consumed thread handles if
    // a post-join invariant fails; double-join obscures the actual assertion.
    spawned = 0;

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
