// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! S2S session replication — the capsule a node ships to a peer so clients can
//! attach to the same logical session across the mesh, plus the receiving node's
//! bounded holding area.
//!
//! Unlike a hot UPGRADE (same machine, the socket fd is inherited), an S2S
//! replica crosses processes/machines: the fd CANNOT move, so a client attaches
//! on the target node with the same reusable token. This module is the data layer
//! for that:
//!
//!   * `Capsule` — token + account + a `session_snapshot` blob (nick/account/
//!     hosts/away/oper/channels). The `fd` inside the snapshot is meaningless
//!     across machines and ignored on reclaim.
//!   * `PendingMigrations` — the target node's holding area: token -> (account,
//!     snapshot), inserted when the capsule arrives and borrowed by every client
//!     attaching with that token until bounded TTL expiry. Pairs with
//!     `sessions.SessionStore`, which tracks local logical-session attachments.
//!
//! Transport-agnostic: the capsule rides whatever carries it (S2S relay frame,
//! conduit, ...). Wiring it onto the live S2S link + the reclaim path are later
//! slices.
const std = @import("std");

pub const Token = [16]u8;
pub const Error = error{ Truncated, TooLong };

/// A migrated session in flight: who it is + its serialized state.
pub const Capsule = struct {
    token: Token,
    account: []const u8,
    /// A `session_snapshot.encode` blob (borrowed on decode).
    snapshot: []const u8,
};

/// Wire: [16 token][u16 account_len][account][u32 snap_len][snapshot]
pub fn encode(allocator: std.mem.Allocator, cap: Capsule) (Error || std.mem.Allocator.Error)![]u8 {
    if (cap.account.len > std.math.maxInt(u16)) return error.TooLong;
    if (cap.snapshot.len > std.math.maxInt(u32)) return error.TooLong;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &cap.token);
    var alen: [2]u8 = undefined;
    std.mem.writeInt(u16, &alen, @intCast(cap.account.len), .little);
    try out.appendSlice(allocator, &alen);
    try out.appendSlice(allocator, cap.account);
    var slen: [4]u8 = undefined;
    std.mem.writeInt(u32, &slen, @intCast(cap.snapshot.len), .little);
    try out.appendSlice(allocator, &slen);
    try out.appendSlice(allocator, cap.snapshot);
    return out.toOwnedSlice(allocator);
}

/// Decode a capsule, returning views that borrow `bytes`.
pub fn decode(bytes: []const u8) Error!Capsule {
    if (bytes.len < 16 + 2) return error.Truncated;
    var token: Token = undefined;
    @memcpy(&token, bytes[0..16]);
    var pos: usize = 16;
    const alen = std.mem.readInt(u16, bytes[pos..][0..2], .little);
    pos += 2;
    if (pos + alen + 4 > bytes.len) return error.Truncated;
    const account = bytes[pos .. pos + alen];
    pos += alen;
    const slen = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;
    if (pos + slen > bytes.len) return error.Truncated;
    const snapshot = bytes[pos .. pos + slen];
    return .{ .token = token, .account = account, .snapshot = snapshot };
}

pub const Tombstone = struct {
    token: Token,
    consumed_at_ms: i64,
};

pub const tombstone_wire_len: usize = @sizeOf(Token) + @sizeOf(i64);

pub fn encodeTombstone(tombstone: Tombstone, out: *[tombstone_wire_len]u8) []const u8 {
    @memcpy(out[0..16], &tombstone.token);
    std.mem.writeInt(i64, out[16..24], tombstone.consumed_at_ms, .big);
    return out;
}

pub fn decodeTombstone(bytes: []const u8) Error!Tombstone {
    if (bytes.len != tombstone_wire_len) return error.Truncated;
    var token: Token = undefined;
    @memcpy(&token, bytes[0..16]);
    return .{ .token = token, .consumed_at_ms = std.mem.readInt(i64, bytes[16..24], .big) };
}

/// Target-node holding area: migrated sessions awaiting the client's reconnect.
/// Bounded two ways — a hard entry cap enforced in `put` and a TTL enforced by
/// the server's periodic `sweep` — so a signed-but-hostile (or buggy) peer
/// streaming capsules can never grow this map without bound.
pub const PendingMigrations = struct {
    allocator: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged(Token, Entry) = .empty,
    /// Compatibility tombstones received/carried from legacy one-shot peers.
    /// Modern reusable-session attachment never creates one; a fresh verified
    /// signed offer supersedes one during a rolling upgrade.
    consumed: std.AutoHashMapUnmanaged(Token, i64) = .empty,
    cfg: Config,

    /// Hard ceiling on staged entries. A staged entry is one reusable logical
    /// session replica; even a large mesh stages far fewer than this. On a
    /// full map `put` fails closed (the client's reclaim then falls back to the
    /// legacy redirect path) rather than evicting a legitimate pending entry.
    pub const default_max_entries: usize = 4096;

    pub const Config = struct {
        max_entries: usize = default_max_entries,
        max_per_account: usize = 64,
    };

    pub const PutError = error{ PendingFull, AlreadyConsumed, StaleOffer, TokenAccountMismatch } || std.mem.Allocator.Error;

    pub const Entry = struct {
        account: []u8,
        snapshot: []u8,
        /// Monotonic-ms staging time; `sweep` evicts entries older than the TTL.
        staged_at_ms: i64,
        /// Signed relay epoch for this exact session token. Zero denotes legacy
        /// or locally-seeded state without ordering metadata.
        offer_epoch: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) PendingMigrations {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) PendingMigrations {
        return .{ .allocator = allocator, .cfg = cfg };
    }

    pub fn deinit(self: *PendingMigrations) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            self.allocator.free(e.account);
            self.allocator.free(e.snapshot);
        }
        self.map.deinit(self.allocator);
        self.consumed.deinit(self.allocator);
    }

    /// Store a freshly-arrived capsule (copies the account + snapshot), stamped
    /// `now_ms` for TTL eviction. Replaces any existing entry for the same token
    /// (freeing the old). Fails closed with `PendingFull` when inserting a NEW
    /// token into a map already at `max_entries` (a replacement always succeeds).
    pub fn put(self: *PendingMigrations, cap: Capsule, now_ms: i64) PutError!void {
        return self.putAtEpoch(cap, now_ms, 0);
    }

    /// Stage a signed offer with token-scoped ordering. The pending map is the
    /// bounded lifecycle authority: a replayed or reordered offer cannot replace
    /// a newer snapshot for the same resume token, while different authenticated
    /// origin peers never collide merely because their local nonce counters match.
    pub fn putAtEpoch(self: *PendingMigrations, cap: Capsule, now_ms: i64, offer_epoch: u64) PutError!void {
        // Legacy one-shot peers may have converged a consume tombstone during a
        // rolling upgrade. An unsigned/legacy restage must still respect it;
        // only a newly verified, ordered relay offer proves that the reusable
        // logical session is live again and may reactivate the replica.
        if (self.consumed.contains(cap.token) and offer_epoch == 0) return error.AlreadyConsumed;
        const replacing = self.map.contains(cap.token);
        if (replacing) {
            const current = self.map.getPtr(cap.token).?;
            if (!std.ascii.eqlIgnoreCase(current.account, cap.account)) return error.TokenAccountMismatch;
            if (offer_epoch != 0 and current.offer_epoch != 0 and offer_epoch <= current.offer_epoch) return error.StaleOffer;
        }
        if (!replacing and self.map.count() >= self.cfg.max_entries) {
            return error.PendingFull;
        }
        if (!replacing and self.countForAccount(cap.account) >= self.cfg.max_per_account) {
            return error.PendingFull;
        }
        const account = try self.allocator.dupe(u8, cap.account);
        errdefer self.allocator.free(account);
        const snapshot = try self.allocator.dupe(u8, cap.snapshot);
        errdefer self.allocator.free(snapshot);
        // v3+ session credentials are reusable multi-attachment capabilities.
        // A freshly verified signed offer reactivates a token tombstoned by an
        // older one-shot peer during a rolling upgrade. Do this only after all
        // bounds/allocation checks pass so a failed stage preserves old state.
        if (offer_epoch != 0) _ = self.consumed.remove(cap.token);
        const gop = try self.map.getOrPut(self.allocator, cap.token);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.account);
            self.allocator.free(gop.value_ptr.snapshot);
        }
        gop.value_ptr.* = .{ .account = account, .snapshot = snapshot, .staged_at_ms = now_ms, .offer_epoch = offer_epoch };
    }

    /// Evict every entry staged at least `ttl_ms` before `now_ms` (freeing its
    /// copies). Returns the count evicted. Best-effort: if the scratch key list
    /// cannot be allocated nothing is evicted this round — the next sweep
    /// retries. Called periodically by the server (reactor 0's timer tick).
    pub fn sweep(self: *PendingMigrations, now_ms: i64, ttl_ms: u64) usize {
        var expired: std.ArrayList(Token) = .empty;
        defer expired.deinit(self.allocator);
        var it = self.map.iterator();
        while (it.next()) |e| {
            const age = now_ms -| e.value_ptr.staged_at_ms;
            if (age >= 0 and @as(u64, @intCast(age)) >= ttl_ms) {
                expired.append(self.allocator, e.key_ptr.*) catch return 0;
            }
        }
        for (expired.items) |token| {
            const kv = self.map.fetchRemove(token) orelse continue;
            self.allocator.free(kv.value.account);
            self.allocator.free(kv.value.snapshot);
        }
        const pending_evicted = expired.items.len;
        expired.clearRetainingCapacity();
        var consumed_it = self.consumed.iterator();
        while (consumed_it.next()) |entry| {
            const age = now_ms -| entry.value_ptr.*;
            if (age >= 0 and @as(u64, @intCast(age)) >= ttl_ms) {
                expired.append(self.allocator, entry.key_ptr.*) catch return pending_evicted;
            }
        }
        for (expired.items) |token| _ = self.consumed.remove(token);
        return pending_evicted + expired.items.len;
    }

    /// Whether a migrated session is waiting for `token`.
    pub fn has(self: *const PendingMigrations, token: Token) bool {
        return self.map.contains(token);
    }

    /// Borrow a staged reusable replica without consuming it. Multiple clients
    /// may restore from this view until its bounded TTL expires.
    pub fn get(self: *const PendingMigrations, token: Token) ?*const Entry {
        return self.map.getPtr(token);
    }

    pub fn isConsumed(self: *const PendingMigrations, token: Token) bool {
        return self.consumed.contains(token);
    }

    /// Legacy one-shot compatibility: remove a staged copy and retain a bounded
    /// token tombstone. Modern successful attachment deliberately does not call
    /// this because the signed replica is reusable by concurrent clients.
    pub fn markConsumed(self: *PendingMigrations, token: Token, now_ms: i64) std.mem.Allocator.Error!void {
        // Remove the live copy first even if allocating the tombstone fails: a
        // memory-pressure event must not leave an immediately double-consumable
        // snapshot in place.
        if (self.map.fetchRemove(token)) |kv| {
            self.allocator.free(kv.value.account);
            self.allocator.free(kv.value.snapshot);
        }
        if (self.consumed.contains(token)) return;
        if (self.consumed.count() >= self.cfg.max_entries) self.evictOldestConsumed();
        try self.consumed.put(self.allocator, token, now_ms);
    }

    /// Legacy destructive access used by compatibility tests/capsule adoption.
    /// Modern attachment borrows with `get`. Caller owns the returned slices and
    /// releases them with `freeEntry`.
    pub fn take(self: *PendingMigrations, token: Token) ?Entry {
        const e = self.map.fetchRemove(token) orelse return null;
        return e.value;
    }

    pub fn freeEntry(self: *PendingMigrations, e: Entry) void {
        self.allocator.free(e.account);
        self.allocator.free(e.snapshot);
    }

    pub fn count(self: *const PendingMigrations) usize {
        return self.map.count();
    }

    pub fn consumedCount(self: *const PendingMigrations) usize {
        return self.consumed.count();
    }

    fn evictOldestConsumed(self: *PendingMigrations) void {
        var oldest_token: ?Token = null;
        var oldest_at: i64 = std.math.maxInt(i64);
        var it = self.consumed.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* < oldest_at) {
                oldest_at = entry.value_ptr.*;
                oldest_token = entry.key_ptr.*;
            }
        }
        if (oldest_token) |token| _ = self.consumed.remove(token);
    }

    fn countForAccount(self: *const PendingMigrations, account: []const u8) usize {
        var matches: usize = 0;
        var it = @constCast(&self.map).valueIterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.account, account)) matches += 1;
        }
        return matches;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const migration_relay = @import("migration_relay.zig");

test "migration capsule encode/decode round-trips" {
    const allocator = testing.allocator;
    const token: Token = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const cap = Capsule{ .token = token, .account = "alice", .snapshot = "snap-bytes-here" };
    const bytes = try encode(allocator, cap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, &token, &got.token);
    try testing.expectEqualStrings("alice", got.account);
    try testing.expectEqualStrings("snap-bytes-here", got.snapshot);
}

test "consumption tombstone wire round-trips exactly" {
    const original = Tombstone{ .token = @splat(0x5A), .consumed_at_ms = 123_456 };
    var buf: [tombstone_wire_len]u8 = undefined;
    const got = try decodeTombstone(encodeTombstone(original, &buf));
    try testing.expectEqualSlices(u8, &original.token, &got.token);
    try testing.expectEqual(original.consumed_at_ms, got.consumed_at_ms);
    try testing.expectError(error.Truncated, decodeTombstone(buf[0 .. buf.len - 1]));
}

test "decode rejects truncated input" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 2, 3 }));
    // valid token + account-len claiming more than present
    var buf: [20]u8 = @splat(0);
    buf[16] = 50; // account_len = 50, but no bytes follow
    try testing.expectError(error.Truncated, decode(&buf));
}

test "PendingMigrations stores, finds, and consumes by token" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    const t1: Token = @as([15]u8, @splat(0)) ++ .{1};
    const t2: Token = @as([15]u8, @splat(0)) ++ .{2};
    try pm.put(.{ .token = t1, .account = "alice", .snapshot = "A" }, 1000);
    try pm.put(.{ .token = t2, .account = "bob", .snapshot = "BB" }, 1000);
    try testing.expectEqual(@as(usize, 2), pm.count());
    try testing.expect(pm.has(t1));

    const e = pm.take(t1) orelse return error.TestUnexpectedResult;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("alice", e.account);
    try testing.expectEqualStrings("A", e.snapshot);
    try testing.expect(!pm.has(t1)); // consumed
    try testing.expect(pm.take(t1) == null);
    try testing.expectEqual(@as(usize, 1), pm.count()); // bob remains
}

test "put replaces an existing token snapshot without leaking" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    const t: Token = @splat(9);
    try pm.put(.{ .token = t, .account = "alice", .snapshot = "x" }, 1000);
    try pm.put(.{ .token = t, .account = "ALICE", .snapshot = "yy" }, 1000);
    try testing.expectEqual(@as(usize, 1), pm.count());
    const e = pm.take(t).?;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("ALICE", e.account);
    try testing.expectEqualStrings("yy", e.snapshot);
}

test "signed offer epoch rejects replay and stale replacement per token" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    const token: Token = @splat(7);

    try pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "new" }, 100, 42);
    try testing.expectError(
        error.StaleOffer,
        pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "replay" }, 101, 42),
    );
    try testing.expectError(
        error.StaleOffer,
        pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "old" }, 102, 41),
    );
    try testing.expectError(
        error.TokenAccountMismatch,
        pm.putAtEpoch(.{ .token = token, .account = "mallory", .snapshot = "splice" }, 103, 43),
    );
    try pm.putAtEpoch(.{ .token = token, .account = "alice", .snapshot = "newer" }, 103, 43);

    const entry = pm.get(token).?;
    try testing.expectEqual(@as(u64, 43), entry.offer_epoch);
    try testing.expectEqualStrings("newer", entry.snapshot);
}

test "put fails closed at max_entries; a replacement of an existing token still succeeds" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.initWithConfig(allocator, .{
        .max_entries = PendingMigrations.default_max_entries,
        .max_per_account = PendingMigrations.default_max_entries,
    });
    defer pm.deinit();

    // Fill to the cap (distinct tokens derived from the loop index).
    var i: usize = 0;
    while (i < PendingMigrations.default_max_entries) : (i += 1) {
        var t: Token = @splat(0);
        std.mem.writeInt(u64, t[0..8], i, .little);
        try pm.put(.{ .token = t, .account = "acct", .snapshot = "s" }, 1);
    }
    try testing.expectEqual(PendingMigrations.default_max_entries, pm.count());

    // A NEW token is rejected — the map never grows past the cap.
    const fresh: Token = @splat(0xFF);
    try testing.expectError(
        error.PendingFull,
        pm.put(.{ .token = fresh, .account = "evil", .snapshot = "x" }, 2),
    );
    try testing.expectEqual(PendingMigrations.default_max_entries, pm.count());
    try testing.expect(!pm.has(fresh));

    // Replacing an EXISTING token at the cap succeeds (count unchanged).
    const t0: Token = @splat(0);
    try pm.put(.{ .token = t0, .account = "acct", .snapshot = "zz" }, 3);
    try testing.expectEqual(PendingMigrations.default_max_entries, pm.count());
    const e = pm.take(t0).?;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("acct", e.account);

    // Consuming an entry frees a slot; a new token is admitted again.
    try pm.put(.{ .token = fresh, .account = "ok", .snapshot = "y" }, 4);
    try testing.expect(pm.has(fresh));
}

test "per-account staging cap cannot evict another account" {
    var pm = PendingMigrations.initWithConfig(testing.allocator, .{
        .max_entries = 4,
        .max_per_account = 1,
    });
    defer pm.deinit();

    const alice_1: Token = @as([15]u8, @splat(0)) ++ .{1};
    const alice_2: Token = @as([15]u8, @splat(0)) ++ .{2};
    const bob: Token = @as([15]u8, @splat(0)) ++ .{3};
    try pm.put(.{ .token = alice_1, .account = "alice", .snapshot = "a" }, 1);
    try testing.expectError(error.PendingFull, pm.put(.{ .token = alice_2, .account = "ALICE", .snapshot = "b" }, 2));
    try pm.put(.{ .token = bob, .account = "bob", .snapshot = "c" }, 3);
    try testing.expect(pm.has(alice_1));
    try testing.expect(pm.has(bob));
}

test "consumption tombstone blocks late migration resurrection and expires" {
    var pm = PendingMigrations.initWithConfig(testing.allocator, .{
        .max_entries = 4,
        .max_per_account = 4,
    });
    defer pm.deinit();

    const token: Token = @splat(0xAC);
    try pm.put(.{ .token = token, .account = "alice", .snapshot = "state" }, 10);
    try pm.markConsumed(token, 20);
    try testing.expect(!pm.has(token));
    try testing.expect(pm.isConsumed(token));
    try testing.expectError(error.AlreadyConsumed, pm.put(.{ .token = token, .account = "alice", .snapshot = "late" }, 21));

    try testing.expectEqual(@as(usize, 1), pm.sweep(120, 100));
    try testing.expect(!pm.isConsumed(token));
    try pm.put(.{ .token = token, .account = "alice", .snapshot = "new-generation" }, 121);
    try testing.expect(pm.has(token));
}

test "verified reusable-session offer supersedes a legacy consumption tombstone" {
    var pm = PendingMigrations.init(testing.allocator);
    defer pm.deinit();

    const token: Token = @splat(0xAD);
    try pm.markConsumed(token, 20);
    try testing.expect(pm.isConsumed(token));

    try pm.putAtEpoch(.{
        .token = token,
        .account = "alice",
        .snapshot = "fresh-signed-state",
    }, 21, 7);
    try testing.expect(pm.has(token));
    try testing.expect(!pm.isConsumed(token));
    try testing.expectEqualStrings("fresh-signed-state", pm.get(token).?.snapshot);
}

test "sweep evicts entries past the TTL and keeps fresh ones" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    const stale: Token = @as([15]u8, @splat(0)) ++ .{1};
    const fresh: Token = @as([15]u8, @splat(0)) ++ .{2};
    try pm.put(.{ .token = stale, .account = "old", .snapshot = "a" }, 1_000);
    try pm.put(.{ .token = fresh, .account = "new", .snapshot = "b" }, 9_000);

    // Nothing lapsed yet: age(stale)=4000 < ttl.
    try testing.expectEqual(@as(usize, 0), pm.sweep(5_000, 5_000));
    try testing.expectEqual(@as(usize, 2), pm.count());

    // stale's age hits the TTL exactly (>= evicts); fresh survives.
    try testing.expectEqual(@as(usize, 1), pm.sweep(6_000, 5_000));
    try testing.expect(!pm.has(stale));
    try testing.expect(pm.has(fresh));

    // A re-staged token's clock restarts from its new staged_at.
    try pm.put(.{ .token = stale, .account = "old2", .snapshot = "c" }, 10_000);
    try testing.expectEqual(@as(usize, 0), pm.sweep(11_000, 5_000));
    try testing.expect(pm.has(stale));
}

test "end-to-end: origin prepare -> session_migrate wrap -> target accept -> PendingMigrations -> reclaim consume" {
    // Exercises exactly the server seam: the origin mints a signed migration
    // capsule, wraps it in a session_migrate.Capsule keyed by the 16-byte session
    // token, the target verifies it (MigrationTarget.accept) and stages it under
    // that key, then a reclaim by the matching token takes + decodes the full
    // restored snapshot (nick/umodes/channels/away/account/host/is_oper).
    const allocator = testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7E)));

    // ORIGIN: build the full session snapshot and mint the relay frame.
    const channels = [_][]const u8{ "#orochi", "#helix", "#ops" };
    const snapshot = migration_relay.Snapshot{
        .nick = "kain",
        .umodes = "+iwx",
        .channels = channels[0..],
        .realname = "Kain Example",
        .host = "cloak-ab12.orochi",
        .account = "kain",
        .away = "migrating",
        .is_oper = true,
    };
    var origin = migration_relay.MigrationOrigin.init(allocator, kp);
    defer origin.deinit();
    var prepared = try origin.prepare("kain", snapshot, 0xCAFEBABE, 7);
    defer prepared.deinit(allocator);

    // ORIGIN: wrap the relay frame in a session_migrate capsule keyed by the
    // 16-byte session token (the reclaim-side lookup key) and serialize for S2S.
    const session_token: Token = .{ 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const wire = try encode(allocator, .{
        .token = session_token,
        .account = "kain",
        .snapshot = prepared.frame_bytes,
    });
    defer allocator.free(wire);

    // TARGET: decode the outer capsule, verify+decode the relay frame, then stage
    // the re-encoded snapshot under the session-token key.
    const outer = try decode(wire);
    try testing.expectEqualSlices(u8, &session_token, &outer.token);

    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    {
        var target = migration_relay.MigrationTarget.init(allocator, kp.public_key.toBytes());
        defer target.deinit();
        var capsule = try target.accept(outer.snapshot);
        defer capsule.deinit(allocator);
        try testing.expectEqualStrings("kain", capsule.account);

        const snap_bytes = try capsule.snapshot.encode(allocator);
        defer allocator.free(snap_bytes);
        try pm.put(.{ .token = outer.token, .account = outer.account, .snapshot = snap_bytes }, 1000);
    }
    try testing.expect(pm.has(session_token));

    // RECLAIM: the client reconnects + presents the matching token; consume.
    const entry = pm.take(session_token) orelse return error.TestUnexpectedResult;
    defer pm.freeEntry(entry);
    try testing.expectEqualStrings("kain", entry.account);
    try testing.expect(!pm.has(session_token)); // consumed

    var restored = try migration_relay.Snapshot.decode(allocator, entry.snapshot);
    defer restored.deinit(allocator);
    try testing.expectEqualStrings("kain", restored.nick);
    try testing.expectEqualStrings("+iwx", restored.umodes);
    try testing.expectEqual(@as(usize, 3), restored.channels.len);
    try testing.expectEqualStrings("#orochi", restored.channels[0]);
    try testing.expectEqualStrings("#ops", restored.channels[2]);
    try testing.expectEqualStrings("Kain Example", restored.realname);
    try testing.expectEqualStrings("cloak-ab12.orochi", restored.host);
    try testing.expectEqualStrings("kain", restored.account);
    try testing.expectEqualStrings("migrating", restored.away);
    try testing.expect(restored.is_oper);
}

test "end-to-end: target rejects a capsule signed by the wrong key (no staging)" {
    const allocator = testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const real = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x01)));
    const attacker = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x02)));

    const channels = [_][]const u8{"#orochi"};
    const snapshot = migration_relay.Snapshot{ .nick = "kain", .umodes = "+i", .channels = channels[0..] };
    var origin = migration_relay.MigrationOrigin.init(allocator, attacker); // signs with attacker key
    defer origin.deinit();
    var prepared = try origin.prepare("kain", snapshot, 0x1, 1);
    defer prepared.deinit(allocator);

    const session_token: Token = @splat(1);
    const wire = try encode(allocator, .{ .token = session_token, .account = "kain", .snapshot = prepared.frame_bytes });
    defer allocator.free(wire);
    const outer = try decode(wire);

    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    var target = migration_relay.MigrationTarget.init(allocator, real.public_key.toBytes()); // pins the REAL key
    defer target.deinit();
    // Verification fails: nothing is staged.
    try testing.expectError(error.BadSignature, target.accept(outer.snapshot));
    try testing.expect(!pm.has(session_token));
    try testing.expectEqual(@as(usize, 0), pm.count());
}

test "a staged entry rides a Helix .pending_migration capsule across USR2 (round-trip)" {
    // The seal side wraps each PendingMigrations entry as a session_migrate wire
    // blob inside a `.pending_migration` Helix capsule (ordinal 1, exactly how
    // helix_live.prepare frames every StatePiece); the adopt side decodes the
    // capsule field and re-stages it. Prove the full byte path round-trips.
    const allocator = testing.allocator;
    const helix_capsule = @import("capsule.zig");

    const token: Token = @as([15]u8, @splat(7)) ++ .{1};
    const wire = try encode(allocator, .{ .token = token, .account = "kain", .snapshot = "verified-snapshot-bytes" });
    defer allocator.free(wire);

    var fields = [_]helix_capsule.Field{.{ .ordinal = 1, .bytes = wire }};
    const sealed = try helix_capsule.encode(allocator, helix_capsule.make(.pending_migration, fields[0..]));
    defer allocator.free(sealed);

    var adopted = try helix_capsule.decode(allocator, sealed);
    defer adopted.deinit(allocator);
    try testing.expectEqual(helix_capsule.CapsuleKind.pending_migration, adopted.header.kind);
    try testing.expectEqual(@as(u16, 1), adopted.header.version);
    try testing.expectEqual(@as(usize, 1), adopted.fields.len);

    const got = try decode(adopted.fields[0].bytes);
    try testing.expectEqualSlices(u8, &token, &got.token);
    try testing.expectEqualStrings("kain", got.account);
    try testing.expectEqualStrings("verified-snapshot-bytes", got.snapshot);

    // Re-staging on the successor works and is consumable by token.
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    try pm.put(got, 42);
    try testing.expect(pm.has(token));
}

test "adopting a truncated .pending_migration payload fails closed (tolerant decode)" {
    // A corrupt inner blob must be a clean skip on the successor, never a crash
    // and never a partially-staged entry.
    const allocator = testing.allocator;
    const token: Token = @splat(3);
    const wire = try encode(allocator, .{ .token = token, .account = "kain", .snapshot = "snapshot" });
    defer allocator.free(wire);

    // Truncate mid-snapshot and mid-header: both reject with Truncated.
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 3]));
    try testing.expectError(error.Truncated, decode(wire[0..10]));
}
