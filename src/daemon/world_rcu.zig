// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lock-free, RCU-backed core registries for the live IRC world.
//!
//! These are the hot-path lookup/delivery substrates. Readers traverse a
//! published immutable snapshot under an EBR pin with **no lock and no
//! allocation**; writers serialize on a per-registry spinlock, copy-on-write
//! the backing HAMT, atomically publish the new root, and retire the old root
//! (and any displaced owned key storage) for epoch-deferred free.
//!
//! Built directly on two committed substrates:
//!   * `../substrate/persistent_map.zig` — `PersistentMap(K,V,Context)`, an
//!     immutable, structurally-shared, reference-counted HAMT. A "root" here is
//!     a whole `PersistentMap` value (a `?*Node` + cached `len`).
//!   * `../substrate/ebr.zig` — epoch-based reclamation. A `Domain` (borrowed,
//!     caller-owned, shared) governs *when* retired memory is freed; each reader
//!     thread holds its own `Participant`.
//!
//! ## RCU model (the read/write shapes)
//!
//! Each registry holds:
//!   * a borrowed `*ebr.Domain` (shared; the caller owns and `deinit`s it),
//!   * the backing allocator (used for HAMT nodes and owned key storage),
//!   * an atomically-published `Published(...)` pointer holding the live HAMT
//!     snapshot, and
//!   * a writer spinlock serializing all mutators.
//!
//! READ (lock-free): pin the EBR participant, `.acquire`-load the published
//! `Published` box, call the pure HAMT `get`/`contains` on its snapshot, unpin.
//! The pin guarantees the snapshot box and every node it references stay alive
//! for the duration of the critical section — a concurrent writer that replaces
//! the box only *retires* the old one, and EBR defers the free until every
//! reader pinned at-or-before the swap has unpinned and two epochs have elapsed.
//!
//! WRITE (serialized): take the spinlock, derive a new HAMT snapshot via the
//! HAMT's pure `put`/`remove` (structural sharing — only the touched root-to-leaf
//! path is freshly allocated), allocate a fresh `Published` box wrapping the new
//! snapshot, `.release`-store it as the new published pointer, then retire the
//! OLD `Published` box. Retiring (not freeing) is mandatory: a reader may still
//! be traversing the old snapshot. The retire closure, when finally run after
//! the grace period, `release`s the old HAMT snapshot — which drops exactly the
//! nodes unique to that version (the displaced path) and frees them.
//!
//! ## Key-string ownership / retire discipline
//!
//! String-keyed registries (`NickRegistry`, `ChannelRegistry`) own their key
//! bytes: every insert `dupe`s the caller's key into a heap buffer, and the HAMT
//! stores a slice into that buffer. The HAMT frees its `*Node` storage when a
//! root is released, but it does NOT know about the key *bytes* — those are ours.
//!
//! With structural sharing, a key buffer must be freed only when no published
//! version still references it. The discipline:
//!   * On a brand-new insert, the duped buffer lives on in the new (and all
//!     future) versions — never retired here.
//!   * On **overwrite**, the new version duplicates a fresh buffer for the key;
//!     the OLD buffer is now referenced only by the old root, so we retire it
//!     alongside the old `Published` box. After the grace period no reader can
//!     still be reading either, so both free together.
//!   * On **remove**, the entry leaves the new version entirely; its buffer is
//!     referenced only by the old root, so it too is retired alongside the old
//!     box.
//! Retiring the displaced buffer (rather than freeing it immediately) is what
//! makes this safe: a lock-free reader pinned before the swap may still hold a
//! `[]const u8` into that buffer.
//!
//! `MembershipSet` keys on `ClientId` (a 64-bit value), so it carries no owned
//! string storage — only the HAMT snapshot box is retired per write.
//!
//! ## Bounded loops
//!
//! Every loop here is bounded: writer spinlock acquisition is a finite CAS spin
//! with backoff (it only contends with other writers, which always make
//! progress), and all traversal is delegated to the HAMT, whose depth is bounded
//! by `max_depth`. There is no unbounded `while (true)` on the read or write
//! path.

const std = @import("std");
const ebr = @import("../substrate/ebr.zig");
const persistent_map = @import("../substrate/persistent_map.zig");
const client_mod = @import("client.zig");

const Allocator = std.mem.Allocator;
const PersistentMap = persistent_map.PersistentMap;

pub const ClientId = client_mod.ClientId;

// ===========================================================================
// Shared helpers
// ===========================================================================

/// ASCII case-insensitive context for `[]const u8` keys. v1 casemapping is
/// plain ASCII lowercase; RFC1459 casemapping (`{}|^` ~ `[]\~`) is a later
/// refinement that only changes `lowerByte`.
const CaseInsensitiveBytesContext = struct {
    fn lowerByte(c: u8) u8 {
        return std.ascii.toLower(c);
    }

    pub fn hash(_: CaseInsensitiveBytesContext, key: []const u8) u64 {
        var h = std.hash.Wyhash.init(0);
        // Bounded by key length; feed lowercased bytes so equal-ignoring-case
        // keys hash identically.
        for (key) |c| {
            const lc = lowerByte(c);
            h.update(std.mem.asBytes(&lc));
        }
        return h.final();
    }

    pub fn eql(_: CaseInsensitiveBytesContext, a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |ca, cb| {
            if (lowerByte(ca) != lowerByte(cb)) return false;
        }
        return true;
    }
};

/// Context for `ClientId` value keys: hash the packed 64-bit representation.
const ClientIdContext = struct {
    pub fn hash(_: ClientIdContext, key: ClientId) u64 {
        const bits: u64 = @bitCast(key);
        return std.hash.Wyhash.hash(0, std.mem.asBytes(&bits));
    }
    pub fn eql(_: ClientIdContext, a: ClientId, b: ClientId) bool {
        return a.eql(b);
    }
};

/// A minimal test-and-test-and-set spinlock. Only writers contend on it, and
/// every writer completes a bounded amount of work, so the spin always
/// terminates. Acquisition is a finite CAS loop with a spin hint.
const WriterLock = struct {
    flag: std.atomic.Value(bool) = .init(false),

    fn lock(self: *WriterLock) void {
        while (true) {
            // Fast path: try to claim.
            if (self.flag.cmpxchgWeak(false, true, .acquire, .monotonic) == null) return;
            // Back off: spin reading the relaxed flag until it looks free, then
            // retry the CAS. Bounded progress: held only across one CoW write.
            while (self.flag.load(.monotonic)) std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *WriterLock) void {
        self.flag.store(false, .release);
    }
};

// ===========================================================================
// NickRegistry — case-insensitive nick → ClientId
// ===========================================================================

/// Case-insensitive nick (`[]const u8`) → `ClientId`. Owns its key bytes
/// (duped on insert, retired on displacement). Reads are lock-free.
pub const NickRegistry = StringKeyedRegistry(ClientId);

// ===========================================================================
// ChannelRegistry(V) — case-insensitive channel name → V
// ===========================================================================

/// Case-insensitive channel name (`[]const u8`) → caller-chosen value `V`
/// (e.g. a channel-record pointer). Owns its key bytes. Reads are lock-free.
pub fn ChannelRegistry(comptime V: type) type {
    return StringKeyedRegistry(V);
}

/// Shared implementation for the two string-keyed registries. `V` is the value
/// type stored against each owned, case-insensitive string key.
fn StringKeyedRegistry(comptime V: type) type {
    return struct {
        const Self = @This();
        const Map = PersistentMap([]const u8, V, CaseInsensitiveBytesContext);

        /// The atomically-published snapshot: a heap box holding one immutable
        /// HAMT version. Swapped wholesale on every write; the old box is
        /// retired (its `release` runs after the grace period).
        const Published = struct {
            map: Map,
        };

        /// A displaced owned key buffer awaiting epoch-deferred free. Retired
        /// alongside the old `Published` box so it outlives any reader still
        /// holding a slice into it.
        const RetiredKey = struct {
            bytes: []u8,
        };

        const RetiredKeysBatch = struct {
            box: *Published,
            keys: [][]u8,

            fn reclaim(ptr: *anyopaque, allocator: Allocator) void {
                const batch: *@This() = @ptrCast(@alignCast(ptr));
                batch.box.map.release(allocator);
                allocator.destroy(batch.box);
                for (batch.keys) |bytes| allocator.free(bytes);
                allocator.free(batch.keys);
                allocator.destroy(batch);
            }
        };

        domain: *ebr.Domain,
        allocator: Allocator,
        published: std.atomic.Value(*Published),
        writer_lock: WriterLock = .{},

        pub fn init(allocator: Allocator, domain: *ebr.Domain) !Self {
            const box = try allocator.create(Published);
            box.* = .{ .map = Map.empty() };
            return .{
                .domain = domain,
                .allocator = allocator,
                .published = std.atomic.Value(*Published).init(box),
            };
        }

        /// Tear down. Caller must ensure no readers are pinned and the EBR
        /// domain has been drained/quiesced so all retired boxes/keys are freed.
        /// Frees the currently-published snapshot and its key storage directly.
        pub fn deinit(self: *Self) void {
            const box = self.published.load(.acquire);
            // Free every owned key buffer still live in the published version.
            var it = box.map.iterator();
            while (it.next()) |entry| {
                self.allocator.free(@constCast(entry.key));
            }
            box.map.release(self.allocator);
            self.allocator.destroy(box);
        }

        // ---- reads (lock-free) ------------------------------------------

        /// Lock-free lookup. Pins the participant, reads the published
        /// snapshot, returns a copy of the value. No allocation, no lock.
        pub fn lookup(self: *Self, p: *ebr.Participant, key: []const u8) ?V {
            var guard = p.pin();
            defer guard.unpin();
            const box = self.published.load(.acquire);
            return box.map.get(key);
        }

        /// O(1) live key count from the published snapshot (pinned read).
        pub fn count(self: *Self, p: *ebr.Participant) usize {
            var guard = p.pin();
            defer guard.unpin();
            const box = self.published.load(.acquire);
            return box.map.count();
        }

        // ---- writes (serialized, CoW, publish, retire) ------------------

        /// Insert or overwrite `key` → `id`. Dupes the key into owned storage.
        /// On overwrite, the displaced old key buffer is retired for deferred
        /// free (a lock-free reader may still hold a slice into it).
        pub fn set(self: *Self, p: *ebr.Participant, key: []const u8, value: V) !void {
            self.writer_lock.lock();
            defer self.writer_lock.unlock();

            const old_box = self.published.load(.acquire);

            // Find any existing owned key buffer (case-insensitive) so we can
            // retire it after publishing the new version.
            const displaced = findOwnedKey(old_box.map, key);

            // Publication must not be followed by a limbo-bag allocation panic.
            // Unique insert retires one box; overwrite also retires one key.
            var reservation = try p.reserveRetireCapacity(if (displaced == null) 1 else 2);
            defer reservation.finish();

            const retired_key = if (displaced) |old_key| blk: {
                const rk = try self.allocator.create(RetiredKey);
                rk.* = .{ .bytes = old_key };
                break :blk rk;
            } else null;
            errdefer if (retired_key) |rk| self.allocator.destroy(rk);

            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);

            const new_map = try old_box.map.put(self.allocator, owned_key, value);
            errdefer new_map.release(self.allocator);

            const new_box = try self.allocator.create(Published);
            new_box.* = .{ .map = new_map };

            self.published.store(new_box, .release);

            // The old box (and its unique nodes) plus the displaced key buffer
            // are now referenced only by the old version — retire both.
            self.retireBoxReserved(&reservation, old_box);
            if (retired_key) |rk| self.retireKeyReserved(&reservation, rk);
        }

        /// Remove `key` if present. The entry's owned key buffer is retired for
        /// deferred free.
        pub fn remove(self: *Self, p: *ebr.Participant, key: []const u8) !void {
            self.writer_lock.lock();
            defer self.writer_lock.unlock();

            const old_box = self.published.load(.acquire);
            const displaced = findOwnedKey(old_box.map, key);
            if (displaced == null) return; // absent: nothing to do

            // Publication retires both the old box and its owned key buffer.
            // Reserve both limbo entries before the release-store so neither
            // retire call can allocate (and panic) after readers can see the
            // replacement snapshot.
            var reservation = try p.reserveRetireCapacity(2);
            defer reservation.finish();
            const retired_key = try self.allocator.create(RetiredKey);
            errdefer self.allocator.destroy(retired_key);
            retired_key.* = .{ .bytes = displaced.? };

            const new_map = try old_box.map.remove(self.allocator, key);
            errdefer new_map.release(self.allocator);

            const new_box = try self.allocator.create(Published);
            new_box.* = .{ .map = new_map };

            self.published.store(new_box, .release);

            self.retireBoxReserved(&reservation, old_box);
            self.retireKeyReserved(&reservation, retired_key);
        }

        /// Prepared case-insensitive key removal. The registry writer lock is
        /// held until commit or abort and every allocation happens before the
        /// release-store, allowing World to combine an existence removal with
        /// other RCU publications under one retire reservation.
        pub const StagedRemove = struct {
            registry: *Self,
            reservation: *ebr.Participant.RetireReservation,
            old_box: *Published,
            new_box: *Published,
            retired_key: *RetiredKey,
            active: bool = true,

            pub fn commit(self: *StagedRemove) void {
                std.debug.assert(self.active);
                self.registry.published.store(self.new_box, .release);
                self.registry.retireBoxReserved(self.reservation, self.old_box);
                self.registry.retireKeyReserved(self.reservation, self.retired_key);
                self.active = false;
                self.registry.writer_lock.unlock();
            }

            pub fn abort(self: *StagedRemove) void {
                std.debug.assert(self.active);
                self.new_box.map.release(self.registry.allocator);
                self.registry.allocator.destroy(self.new_box);
                // The old published map still owns the key bytes.
                self.registry.allocator.destroy(self.retired_key);
                self.active = false;
                self.registry.writer_lock.unlock();
            }
        };

        /// Stage one key removal using a caller-owned retire reservation.
        /// Returns null when the key is already absent. A returned stage must
        /// be committed or aborted.
        pub fn stageRemoveReserved(
            self: *Self,
            reservation: *ebr.Participant.RetireReservation,
            key: []const u8,
        ) !?StagedRemove {
            self.writer_lock.lock();
            const old_box = self.published.load(.acquire);
            const displaced = findOwnedKey(old_box.map, key) orelse {
                self.writer_lock.unlock();
                return null;
            };

            std.debug.assert(reservation.active);
            std.debug.assert(reservation.remaining >= 2);
            const retired_key = self.allocator.create(RetiredKey) catch |err| {
                self.writer_lock.unlock();
                return err;
            };
            retired_key.* = .{ .bytes = displaced };
            const new_map = old_box.map.remove(self.allocator, key) catch |err| {
                self.allocator.destroy(retired_key);
                self.writer_lock.unlock();
                return err;
            };
            const new_box = self.allocator.create(Published) catch |err| {
                new_map.release(self.allocator);
                self.allocator.destroy(retired_key);
                self.writer_lock.unlock();
                return err;
            };
            new_box.* = .{ .map = new_map };
            return .{
                .registry = self,
                .reservation = reservation,
                .old_box = old_box,
                .new_box = new_box,
                .retired_key = retired_key,
            };
        }

        /// One key/value insertion used by `stageInsertAbsentBatch`.
        pub const Insert = struct {
            key: []const u8,
            value: V,
        };

        /// Prepared insertion of a batch of previously-absent keys. The
        /// registry writer lock remains held until commit or abort. Commit is a
        /// single release-store plus a pre-reserved retire and cannot allocate.
        pub const StagedInsertAbsentBatch = struct {
            registry: *Self,
            reservation: *ebr.Participant.RetireReservation,
            new_box: *Published,
            owned_keys: [][]u8,
            active: bool = true,

            pub fn commit(self: *StagedInsertAbsentBatch) void {
                std.debug.assert(self.active);
                const old_box = self.registry.published.load(.acquire);
                self.registry.published.store(self.new_box, .release);
                self.registry.retireBoxReserved(self.reservation, old_box);
                // The byte buffers are now owned by the live registry. Only
                // the temporary slice-of-slices container remains ours.
                self.registry.allocator.free(self.owned_keys);
                self.active = false;
                self.registry.writer_lock.unlock();
            }

            pub fn abort(self: *StagedInsertAbsentBatch) void {
                std.debug.assert(self.active);
                self.new_box.map.release(self.registry.allocator);
                self.registry.allocator.destroy(self.new_box);
                for (self.owned_keys) |key| self.registry.allocator.free(key);
                self.registry.allocator.free(self.owned_keys);
                self.active = false;
                self.registry.writer_lock.unlock();
            }
        };

        /// Build one immutable registry snapshot containing every insertion,
        /// without publishing any of them. Returns null if any key already
        /// exists or if two requested keys collide case-insensitively. The
        /// caller must commit or abort the returned value.
        pub fn stageInsertAbsentBatchReserved(
            self: *Self,
            reservation: *ebr.Participant.RetireReservation,
            inserts: []const Insert,
        ) !?StagedInsertAbsentBatch {
            std.debug.assert(inserts.len != 0);
            self.writer_lock.lock();
            errdefer self.writer_lock.unlock();

            const old_box = self.published.load(.acquire);
            const ctx: CaseInsensitiveBytesContext = undefined;
            for (inserts, 0..) |insert, i| {
                if (old_box.map.get(insert.key) != null) {
                    self.writer_lock.unlock();
                    return null;
                }
                for (inserts[0..i]) |prior| {
                    if (ctx.eql(prior.key, insert.key)) {
                        self.writer_lock.unlock();
                        return null;
                    }
                }
            }

            std.debug.assert(reservation.active);
            std.debug.assert(reservation.remaining != 0);
            const owned_keys = try self.allocator.alloc([]u8, inserts.len);
            var owned_count: usize = 0;
            errdefer {
                for (owned_keys[0..owned_count]) |key| self.allocator.free(key);
                self.allocator.free(owned_keys);
            }

            var new_map = old_box.map;
            new_map.retain();
            errdefer new_map.release(self.allocator);
            for (inserts) |insert| {
                const owned_key = try self.allocator.dupe(u8, insert.key);
                owned_keys[owned_count] = owned_key;
                owned_count += 1;
                const next = try new_map.put(self.allocator, owned_key, insert.value);
                new_map.release(self.allocator);
                new_map = next;
            }

            const new_box = try self.allocator.create(Published);
            new_box.* = .{ .map = new_map };
            return .{
                .registry = self,
                .reservation = reservation,
                .new_box = new_box,
                .owned_keys = owned_keys,
            };
        }

        /// Prepared exact-value replacement. The registry writer lock remains
        /// held until commit or abort; commit is allocation-free.
        pub const StagedReplaceRemovingValues = struct {
            registry: *Self,
            reservation: ebr.Participant.RetireReservation,
            new_box: *Published,
            owned_key: []u8,
            removed_keys: [][]u8,
            retired: *RetiredKeysBatch,
            active: bool = true,

            pub fn commit(self: *StagedReplaceRemovingValues) void {
                std.debug.assert(self.active);
                self.registry.published.store(self.new_box, .release);
                self.reservation.retireErased(
                    @ptrCast(self.retired),
                    RetiredKeysBatch.reclaim,
                    self.registry.allocator,
                );
                self.reservation.finish();
                self.active = false;
                self.registry.writer_lock.unlock();
            }

            pub fn abort(self: *StagedReplaceRemovingValues) void {
                std.debug.assert(self.active);
                self.new_box.map.release(self.registry.allocator);
                self.registry.allocator.destroy(self.new_box);
                self.registry.allocator.free(self.owned_key);
                self.registry.allocator.free(self.removed_keys);
                self.registry.allocator.destroy(self.retired);
                self.reservation.finish();
                self.active = false;
                self.registry.writer_lock.unlock();
            }
        };

        /// Build, but do not publish, one immutable snapshot that removes every
        /// entry whose value belongs to `removed_values`, then binds `key` to
        /// `value`. Null is a foreign-owner collision. The returned transaction
        /// owns every allocation and holds the writer lock until commit/abort.
        pub fn stageReplaceRemovingValues(
            self: *Self,
            p: *ebr.Participant,
            key: []const u8,
            value: V,
            removed_values: []const V,
        ) !?StagedReplaceRemovingValues {
            self.writer_lock.lock();
            errdefer self.writer_lock.unlock();

            const old_box = self.published.load(.acquire);
            if (old_box.map.get(key)) |existing| {
                if (!valueInSet(existing, removed_values)) {
                    self.writer_lock.unlock();
                    return null;
                }
            }

            var removed_count: usize = 0;
            var count_it = old_box.map.iterator();
            while (count_it.next()) |entry| {
                if (valueInSet(entry.value, removed_values)) removed_count += 1;
            }
            const removed_keys = try self.allocator.alloc([]u8, removed_count);
            errdefer self.allocator.free(removed_keys);
            var next_removed: usize = 0;
            var key_it = old_box.map.iterator();
            while (key_it.next()) |entry| {
                if (!valueInSet(entry.value, removed_values)) continue;
                removed_keys[next_removed] = @constCast(entry.key);
                next_removed += 1;
            }
            std.debug.assert(next_removed == removed_count);

            var reservation = try p.reserveRetireCapacity(1);
            errdefer reservation.finish();
            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);

            var new_map = old_box.map;
            new_map.retain();
            errdefer new_map.release(self.allocator);
            for (removed_keys) |removed_key| {
                const without_alias = try new_map.remove(self.allocator, removed_key);
                new_map.release(self.allocator);
                new_map = without_alias;
            }
            const with_target = try new_map.put(self.allocator, owned_key, value);
            new_map.release(self.allocator);
            new_map = with_target;

            const new_box = try self.allocator.create(Published);
            errdefer self.allocator.destroy(new_box);
            new_box.* = .{ .map = new_map };
            const retired = try self.allocator.create(RetiredKeysBatch);
            errdefer self.allocator.destroy(retired);
            retired.* = .{ .box = old_box, .keys = removed_keys };
            return .{
                .registry = self,
                .reservation = reservation,
                .new_box = new_box,
                .owned_key = owned_key,
                .removed_keys = removed_keys,
                .retired = retired,
            };
        }

        /// Publish one immutable exact-value replacement. All allocations are
        /// staged before the release store, so OOM cannot expose partial aliases.
        pub fn replaceRemovingValues(
            self: *Self,
            p: *ebr.Participant,
            key: []const u8,
            value: V,
            removed_values: []const V,
        ) !bool {
            var staged = (try self.stageReplaceRemovingValues(p, key, value, removed_values)) orelse return false;
            staged.commit();
            return true;
        }

        /// Prepared removal of every alias owned by `removed_values` while a
        /// caller-authorized foreign `preserved_key`/`preserved_value` remains
        /// untouched. Null means the preserved binding did not match exactly.
        /// A valid no-alias case still returns a staged snapshot so validation
        /// and publication remain one serialized transaction.
        pub const StagedRemoveValuesPreservingKey = struct {
            registry: *Self,
            reservation: ebr.Participant.RetireReservation,
            new_box: *Published,
            removed_keys: [][]u8,
            retired: *RetiredKeysBatch,
            active: bool = true,

            pub fn commit(self: *StagedRemoveValuesPreservingKey) void {
                std.debug.assert(self.active);
                self.registry.published.store(self.new_box, .release);
                self.reservation.retireErased(
                    @ptrCast(self.retired),
                    RetiredKeysBatch.reclaim,
                    self.registry.allocator,
                );
                self.reservation.finish();
                self.active = false;
                self.registry.writer_lock.unlock();
            }

            pub fn abort(self: *StagedRemoveValuesPreservingKey) void {
                std.debug.assert(self.active);
                self.new_box.map.release(self.registry.allocator);
                self.registry.allocator.destroy(self.new_box);
                self.registry.allocator.free(self.removed_keys);
                self.registry.allocator.destroy(self.retired);
                self.reservation.finish();
                self.active = false;
                self.registry.writer_lock.unlock();
            }
        };

        pub fn stageRemoveValuesPreservingKey(
            self: *Self,
            p: *ebr.Participant,
            preserved_key: []const u8,
            preserved_value: V,
            removed_values: []const V,
        ) !?StagedRemoveValuesPreservingKey {
            self.writer_lock.lock();
            errdefer self.writer_lock.unlock();

            const old_box = self.published.load(.acquire);
            const current = old_box.map.get(preserved_key) orelse {
                self.writer_lock.unlock();
                return null;
            };
            if (!std.meta.eql(current, preserved_value) or valueInSet(current, removed_values)) {
                self.writer_lock.unlock();
                return null;
            }

            var removed_count: usize = 0;
            var count_it = old_box.map.iterator();
            while (count_it.next()) |entry| {
                if (valueInSet(entry.value, removed_values)) removed_count += 1;
            }
            const removed_keys = try self.allocator.alloc([]u8, removed_count);
            errdefer self.allocator.free(removed_keys);
            var next_removed: usize = 0;
            var key_it = old_box.map.iterator();
            while (key_it.next()) |entry| {
                if (!valueInSet(entry.value, removed_values)) continue;
                removed_keys[next_removed] = @constCast(entry.key);
                next_removed += 1;
            }
            std.debug.assert(next_removed == removed_count);

            var reservation = try p.reserveRetireCapacity(1);
            errdefer reservation.finish();
            var new_map = old_box.map;
            new_map.retain();
            errdefer new_map.release(self.allocator);
            for (removed_keys) |removed_key| {
                const next = try new_map.remove(self.allocator, removed_key);
                new_map.release(self.allocator);
                new_map = next;
            }
            const new_box = try self.allocator.create(Published);
            errdefer self.allocator.destroy(new_box);
            new_box.* = .{ .map = new_map };
            const retired = try self.allocator.create(RetiredKeysBatch);
            errdefer self.allocator.destroy(retired);
            retired.* = .{ .box = old_box, .keys = removed_keys };
            return .{
                .registry = self,
                .reservation = reservation,
                .new_box = new_box,
                .removed_keys = removed_keys,
                .retired = retired,
            };
        }

        /// Atomically remove all aliases owned by `removed_values` while
        /// requiring `preserved_key` to remain owned by `preserved_value`.
        /// Used when another independently-authorized logical session already
        /// owns a shared display nick: the attaching token sheds every stale
        /// World alias without stealing or briefly removing the foreign owner.
        pub fn removeValuesPreservingKey(
            self: *Self,
            p: *ebr.Participant,
            preserved_key: []const u8,
            preserved_value: V,
            removed_values: []const V,
        ) !bool {
            self.writer_lock.lock();
            defer self.writer_lock.unlock();

            const old_box = self.published.load(.acquire);
            const current = old_box.map.get(preserved_key) orelse return false;
            if (!std.meta.eql(current, preserved_value) or valueInSet(current, removed_values)) return false;

            var removed_count: usize = 0;
            var count_it = old_box.map.iterator();
            while (count_it.next()) |entry| {
                if (valueInSet(entry.value, removed_values)) removed_count += 1;
            }
            if (removed_count == 0) return false;
            const removed_keys = try self.allocator.alloc([]u8, removed_count);
            var removed_keys_transferred = false;
            defer if (!removed_keys_transferred) self.allocator.free(removed_keys);
            var next_removed: usize = 0;
            var key_it = old_box.map.iterator();
            while (key_it.next()) |entry| {
                if (!valueInSet(entry.value, removed_values)) continue;
                removed_keys[next_removed] = @constCast(entry.key);
                next_removed += 1;
            }
            std.debug.assert(next_removed == removed_count);

            var reservation = try p.reserveRetireCapacity(1);
            defer reservation.finish();
            var new_map = old_box.map;
            new_map.retain();
            errdefer new_map.release(self.allocator);
            for (removed_keys) |removed_key| {
                const without_alias = try new_map.remove(self.allocator, removed_key);
                new_map.release(self.allocator);
                new_map = without_alias;
            }

            const new_box = try self.allocator.create(Published);
            errdefer self.allocator.destroy(new_box);
            new_box.* = .{ .map = new_map };

            const RetiredBatch = struct {
                box: *Published,
                keys: [][]u8,

                fn reclaim(ptr: *anyopaque, allocator: Allocator) void {
                    const batch: *@This() = @ptrCast(@alignCast(ptr));
                    batch.box.map.release(allocator);
                    allocator.destroy(batch.box);
                    for (batch.keys) |bytes| allocator.free(bytes);
                    allocator.free(batch.keys);
                    allocator.destroy(batch);
                }
            };
            const retired = try self.allocator.create(RetiredBatch);
            errdefer self.allocator.destroy(retired);
            retired.* = .{ .box = old_box, .keys = removed_keys };

            self.published.store(new_box, .release);
            removed_keys_transferred = true;
            reservation.retireErased(@ptrCast(retired), RetiredBatch.reclaim, self.allocator);
            return true;
        }

        // ---- internal retire helpers ------------------------------------

        /// Locate the owned key slice currently stored for `key` (case-
        /// insensitive). Returns the buffer the OLD version owns so it can be
        /// retired after being displaced. Bounded by HAMT depth via `get`-style
        /// traversal in the iterator? No — we scan via a targeted lookup using
        /// the iterator only as a fallback. Here we use a direct find.
        fn findOwnedKey(map: Map, key: []const u8) ?[]u8 {
            // The HAMT stores the owned slice as the Entry key. We need the
            // stored slice itself (not the caller's `key`). Walk to the entry.
            // `get` returns only the value, so iterate the (bounded-depth) trie
            // for the matching key. To stay O(depth) rather than O(n) we reuse
            // the same traversal the map uses internally via a small probe:
            // since PersistentMap exposes only get/iterator, and we must return
            // the *stored* slice, we iterate. The iterator is bounded by the
            // live set; writers are serialized and infrequent on the hot path.
            const ctx: CaseInsensitiveBytesContext = undefined;
            var it = map.iterator();
            while (it.next()) |entry| {
                if (ctx.eql(entry.key, key)) return @constCast(entry.key);
            }
            return null;
        }

        fn valueInSet(value: V, values: []const V) bool {
            for (values) |candidate| {
                if (std.meta.eql(value, candidate)) return true;
            }
            return false;
        }

        fn retireBoxReserved(
            self: *Self,
            reservation: *ebr.Participant.RetireReservation,
            box: *Published,
        ) void {
            const Closure = struct {
                fn free(ptr: *anyopaque, a: Allocator) void {
                    const b: *Published = @ptrCast(@alignCast(ptr));
                    b.map.release(a);
                    a.destroy(b);
                }
            };
            reservation.retireErased(@ptrCast(box), Closure.free, self.allocator);
        }

        fn retireKeyReserved(
            self: *Self,
            reservation: *ebr.Participant.RetireReservation,
            rk: *RetiredKey,
        ) void {
            const Closure = struct {
                fn free(ptr: *anyopaque, a: Allocator) void {
                    const r: *RetiredKey = @ptrCast(@alignCast(ptr));
                    a.free(r.bytes);
                    a.destroy(r);
                }
            };
            reservation.retireErased(@ptrCast(rk), Closure.free, self.allocator);
        }
    };
}

// ===========================================================================
// MembershipSet — RCU set of ClientId for one channel
// ===========================================================================

/// An RCU membership set for ONE channel: a lock-free set of `ClientId`.
/// Backed by `PersistentMap(ClientId, void, ...)`. Reads (`contains`,
/// `iterate`, `count`) are lock-free under an EBR pin; writers serialize and
/// copy-on-write.
pub const MembershipSet = struct {
    const Self = @This();
    const Map = PersistentMap(ClientId, void, ClientIdContext);

    const Published = struct {
        map: Map,
    };

    domain: *ebr.Domain,
    allocator: Allocator,
    published: std.atomic.Value(*Published),
    writer_lock: WriterLock = .{},

    pub fn init(allocator: Allocator, domain: *ebr.Domain) !Self {
        const box = try allocator.create(Published);
        box.* = .{ .map = Map.empty() };
        return .{
            .domain = domain,
            .allocator = allocator,
            .published = std.atomic.Value(*Published).init(box),
        };
    }

    /// Construct an unpublished membership set whose initial snapshot already
    /// contains `id`. This is used for off-map channel preparation: no empty
    /// snapshot is ever published or retired, and the resulting set can be
    /// installed with an allocation-free pointer move.
    pub fn initWithOne(allocator: Allocator, domain: *ebr.Domain, id: ClientId) !Self {
        return initFromSlice(allocator, domain, &.{id});
    }

    /// Construct an unpublished membership set from a complete caller image.
    /// No intermediate snapshot is published or retired, making this suitable
    /// for rebuilding a missing RCU set from World's fallback membership map.
    pub fn initFromSlice(allocator: Allocator, domain: *ebr.Domain, ids: []const ClientId) !Self {
        var map = Map.empty();
        errdefer map.release(allocator);
        for (ids) |id| {
            const next = try map.put(allocator, id, {});
            map.release(allocator);
            map = next;
        }
        const box = try allocator.create(Published);
        box.* = .{ .map = map };
        return .{
            .domain = domain,
            .allocator = allocator,
            .published = std.atomic.Value(*Published).init(box),
        };
    }

    /// Tear down. Requires the EBR domain drained/quiesced.
    pub fn deinit(self: *Self) void {
        const box = self.published.load(.acquire);
        box.map.release(self.allocator);
        self.allocator.destroy(box);
    }

    // ---- reads (lock-free) ----------------------------------------------

    /// Lock-free membership test.
    pub fn contains(self: *Self, p: *ebr.Participant, id: ClientId) bool {
        var guard = p.pin();
        defer guard.unpin();
        const box = self.published.load(.acquire);
        return box.map.get(id) != null;
    }

    /// O(1) member count from the published snapshot (pinned read).
    pub fn count(self: *Self, p: *ebr.Participant) usize {
        var guard = p.pin();
        defer guard.unpin();
        const box = self.published.load(.acquire);
        return box.map.count();
    }

    /// Snapshot the members under a single read guard and invoke `func` for
    /// each. The snapshot is the published version at pin time, so it is a
    /// stable point-in-time view even if writers mutate concurrently — exactly
    /// what message fan-out needs. `func` is bounded by the live member count;
    /// traversal depth is HAMT-bounded.
    pub fn iterate(
        self: *Self,
        p: *ebr.Participant,
        ctx: anytype,
        comptime func: fn (@TypeOf(ctx), ClientId) void,
    ) void {
        var guard = p.pin();
        defer guard.unpin();
        const box = self.published.load(.acquire);
        var it = box.map.iterator();
        while (it.next()) |entry| {
            func(ctx, entry.key);
        }
    }

    // ---- writes (serialized, CoW, publish, retire) ----------------------

    /// Prepared membership insertion. `stageAdd` holds the set's writer lock
    /// until exactly one of `commit` or `abort` is called. The new immutable
    /// snapshot and its publication box are fully allocated up front, making
    /// commit allocation-free. World uses this to prepare every channel in a
    /// logical-session handoff before publishing any of them.
    pub const StagedAdd = struct {
        set: *Self,
        reservation: *ebr.Participant.RetireReservation,
        old_box: *Published,
        new_box: *Published,
        active: bool = true,

        pub fn commit(self: *StagedAdd) void {
            std.debug.assert(self.active);
            self.set.published.store(self.new_box, .release);
            self.set.retireBoxReserved(self.reservation, self.old_box);
            self.active = false;
            self.set.writer_lock.unlock();
        }

        pub fn abort(self: *StagedAdd) void {
            std.debug.assert(self.active);
            self.new_box.map.release(self.set.allocator);
            self.set.allocator.destroy(self.new_box);
            self.active = false;
            self.set.writer_lock.unlock();
        }
    };

    /// Prepared membership removal. Like `StagedAdd`, this holds the writer
    /// lock and publishes allocation-free through a caller-owned reservation.
    pub const StagedRemove = struct {
        set: *Self,
        reservation: *ebr.Participant.RetireReservation,
        old_box: *Published,
        new_box: *Published,
        active: bool = true,

        pub fn commit(self: *StagedRemove) void {
            std.debug.assert(self.active);
            self.set.published.store(self.new_box, .release);
            self.set.retireBoxReserved(self.reservation, self.old_box);
            self.active = false;
            self.set.writer_lock.unlock();
        }

        pub fn abort(self: *StagedRemove) void {
            std.debug.assert(self.active);
            self.new_box.map.release(self.set.allocator);
            self.set.allocator.destroy(self.new_box);
            self.active = false;
            self.set.writer_lock.unlock();
        }
    };

    /// Stage one absent id without publishing it. Returns null when already
    /// present. The caller must commit or abort a returned value.
    pub fn stageAddReserved(
        self: *Self,
        reservation: *ebr.Participant.RetireReservation,
        id: ClientId,
    ) !?StagedAdd {
        self.writer_lock.lock();
        const old_box = self.published.load(.acquire);
        if (old_box.map.get(id) != null) {
            self.writer_lock.unlock();
            return null;
        }

        std.debug.assert(reservation.active);
        std.debug.assert(reservation.remaining != 0);
        const new_map = old_box.map.put(self.allocator, id, {}) catch |err| {
            self.writer_lock.unlock();
            return err;
        };
        const new_box = self.allocator.create(Published) catch |err| {
            new_map.release(self.allocator);
            self.writer_lock.unlock();
            return err;
        };
        new_box.* = .{ .map = new_map };
        return .{
            .set = self,
            .reservation = reservation,
            .old_box = old_box,
            .new_box = new_box,
        };
    }

    /// Stage one present id for removal without publishing it. Returns null
    /// when already absent. The caller must commit or abort a returned value.
    pub fn stageRemoveReserved(
        self: *Self,
        reservation: *ebr.Participant.RetireReservation,
        id: ClientId,
    ) !?StagedRemove {
        self.writer_lock.lock();
        const old_box = self.published.load(.acquire);
        if (old_box.map.get(id) == null) {
            self.writer_lock.unlock();
            return null;
        }

        std.debug.assert(reservation.active);
        std.debug.assert(reservation.remaining != 0);
        const new_map = old_box.map.remove(self.allocator, id) catch |err| {
            self.writer_lock.unlock();
            return err;
        };
        const new_box = self.allocator.create(Published) catch |err| {
            new_map.release(self.allocator);
            self.writer_lock.unlock();
            return err;
        };
        new_box.* = .{ .map = new_map };
        return .{
            .set = self,
            .reservation = reservation,
            .old_box = old_box,
            .new_box = new_box,
        };
    }

    /// Add `id` to the set (idempotent). Value keys carry no owned storage, so
    /// only the old snapshot box is retired.
    pub fn add(self: *Self, p: *ebr.Participant, id: ClientId) !void {
        self.writer_lock.lock();
        defer self.writer_lock.unlock();

        const old_box = self.published.load(.acquire);
        if (old_box.map.get(id) != null) return;
        var reservation = try p.reserveRetireCapacity(1);
        defer reservation.finish();
        const new_map = try old_box.map.put(self.allocator, id, {});
        errdefer new_map.release(self.allocator);

        const new_box = try self.allocator.create(Published);
        new_box.* = .{ .map = new_map };

        self.published.store(new_box, .release);
        self.retireBoxReserved(&reservation, old_box);
    }

    /// Remove `id` from the set if present.
    pub fn remove(self: *Self, p: *ebr.Participant, id: ClientId) !void {
        self.writer_lock.lock();
        defer self.writer_lock.unlock();

        const old_box = self.published.load(.acquire);
        if (old_box.map.get(id) == null) return; // absent
        var reservation = try p.reserveRetireCapacity(1);
        defer reservation.finish();

        const new_map = try old_box.map.remove(self.allocator, id);
        errdefer new_map.release(self.allocator);

        const new_box = try self.allocator.create(Published);
        new_box.* = .{ .map = new_map };

        self.published.store(new_box, .release);
        self.retireBoxReserved(&reservation, old_box);
    }

    fn retireBoxReserved(
        self: *Self,
        reservation: *ebr.Participant.RetireReservation,
        box: *Published,
    ) void {
        const Closure = struct {
            fn free(ptr: *anyopaque, a: Allocator) void {
                const b: *Published = @ptrCast(@alignCast(ptr));
                b.map.release(a);
                a.destroy(b);
            }
        };
        reservation.retireErased(@ptrCast(box), Closure.free, self.allocator);
    }
};

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn cid(shard: u12, slot: u20, gen: u32) ClientId {
    return .{ .shard = shard, .slot = slot, .gen = gen };
}

/// Bring an EBR domain to full quiescence so `deinit` succeeds: no participant
/// pinned, then drain every limbo bag.
fn quiesce(domain: *ebr.Domain) void {
    domain.drainAll();
}

test "NickRegistry: set/lookup/remove, case-insensitive, overwrite, miss" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();
    const p = domain.register() catch unreachable;
    defer p.unregister();

    var reg = try NickRegistry.init(a, &domain);
    defer {
        reg.deinit();
        quiesce(&domain);
    }

    // Absent miss.
    try testing.expectEqual(@as(?ClientId, null), reg.lookup(p, "nobody"));

    // Insert + lookup.
    try reg.set(p, "Alice", cid(1, 2, 3));
    try testing.expectEqual(@as(usize, 1), reg.count(p));
    try testing.expect(reg.lookup(p, "Alice").?.eql(cid(1, 2, 3)));

    // Case-insensitive hit.
    try testing.expect(reg.lookup(p, "alice").?.eql(cid(1, 2, 3)));
    try testing.expect(reg.lookup(p, "ALICE").?.eql(cid(1, 2, 3)));

    // Overwrite (different case key) keeps count, updates value.
    try reg.set(p, "ALICE", cid(4, 5, 6));
    try testing.expectEqual(@as(usize, 1), reg.count(p));
    try testing.expect(reg.lookup(p, "alice").?.eql(cid(4, 5, 6)));

    // Second distinct nick.
    try reg.set(p, "Bob", cid(7, 8, 9));
    try testing.expectEqual(@as(usize, 2), reg.count(p));

    // Remove.
    try reg.remove(p, "alice");
    try testing.expectEqual(@as(usize, 1), reg.count(p));
    try testing.expectEqual(@as(?ClientId, null), reg.lookup(p, "Alice"));
    try testing.expect(reg.lookup(p, "BOB").?.eql(cid(7, 8, 9)));

    // Remove absent: no-op.
    try reg.remove(p, "ghost");
    try testing.expectEqual(@as(usize, 1), reg.count(p));
}

const Dummy = struct { tag: u32 };

test "ChannelRegistry(*Dummy): set/lookup/remove with pointer value" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();
    const p = domain.register() catch unreachable;
    defer p.unregister();

    var d1 = Dummy{ .tag = 11 };
    var d2 = Dummy{ .tag = 22 };

    var reg = try ChannelRegistry(*Dummy).init(a, &domain);
    defer {
        reg.deinit();
        quiesce(&domain);
    }

    try testing.expectEqual(@as(?*Dummy, null), reg.lookup(p, "#none"));

    try reg.set(p, "#General", &d1);
    try testing.expectEqual(@as(?*Dummy, &d1), reg.lookup(p, "#general"));
    try testing.expectEqual(@as(u32, 11), reg.lookup(p, "#GENERAL").?.tag);

    // Overwrite with a different pointer.
    try reg.set(p, "#general", &d2);
    try testing.expectEqual(@as(?*Dummy, &d2), reg.lookup(p, "#General"));
    try testing.expectEqual(@as(usize, 1), reg.count(p));

    try reg.remove(p, "#GENERAL");
    try testing.expectEqual(@as(?*Dummy, null), reg.lookup(p, "#general"));
    try testing.expectEqual(@as(usize, 0), reg.count(p));
}

const Collector = struct {
    seen: *std.AutoHashMap(u64, void),
    fn visit(self: Collector, id: ClientId) void {
        const bits: u64 = @bitCast(id);
        self.seen.put(bits, {}) catch unreachable;
    }
};

test "MembershipSet: add/contains/remove/iterate/count" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();
    const p = domain.register() catch unreachable;
    defer p.unregister();

    var set = try MembershipSet.init(a, &domain);
    defer {
        set.deinit();
        quiesce(&domain);
    }

    const members = [_]ClientId{
        cid(0, 1, 1), cid(0, 2, 1), cid(1, 3, 2), cid(2, 4, 7),
    };
    for (members) |m| try set.add(p, m);
    // Idempotent re-add.
    try set.add(p, members[0]);
    try testing.expectEqual(@as(usize, 4), set.count(p));

    for (members) |m| try testing.expect(set.contains(p, m));
    try testing.expect(!set.contains(p, cid(9, 9, 9)));

    // Remove one.
    try set.remove(p, members[1]);
    try testing.expectEqual(@as(usize, 3), set.count(p));
    try testing.expect(!set.contains(p, members[1]));

    // iterate visits exactly the live members.
    var seen = std.AutoHashMap(u64, void).init(a);
    defer seen.deinit();
    set.iterate(p, Collector{ .seen = &seen }, Collector.visit);
    try testing.expectEqual(@as(usize, 3), seen.count());
    try testing.expect(seen.contains(@bitCast(members[0])));
    try testing.expect(!seen.contains(@bitCast(members[1])));
    try testing.expect(seen.contains(@bitCast(members[2])));
    try testing.expect(seen.contains(@bitCast(members[3])));
}

test "snapshot stability: held guard sees pre-mutation state" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();
    const reader = domain.register() catch unreachable;
    defer reader.unregister();
    const writer = domain.register() catch unreachable;
    defer writer.unregister();

    var set = try MembershipSet.init(a, &domain);
    defer {
        set.deinit();
        quiesce(&domain);
    }

    try set.add(writer, cid(0, 1, 1));
    try set.add(writer, cid(0, 2, 1));

    // Reader pins and captures the published snapshot box directly so it can
    // assert stability against later mutation.
    var guard = reader.pin();
    const snap = set.published.load(.acquire);
    try testing.expectEqual(@as(usize, 2), snap.map.count());
    try testing.expect(snap.map.get(cid(0, 1, 1)) != null);

    // Writer mutates (publishes a new box, retires the old). EBR cannot free
    // the old box while the reader is pinned.
    try set.add(writer, cid(5, 5, 5));
    try set.remove(writer, cid(0, 1, 1));

    // The held snapshot still reflects the pre-mutation state.
    try testing.expectEqual(@as(usize, 2), snap.map.count());
    try testing.expect(snap.map.get(cid(0, 1, 1)) != null);
    try testing.expect(snap.map.get(cid(5, 5, 5)) == null);

    guard.unpin();

    // After unpin, the new published version reflects the writes.
    try testing.expectEqual(@as(usize, 2), set.count(reader));
    try testing.expect(set.contains(reader, cid(5, 5, 5)));
    try testing.expect(!set.contains(reader, cid(0, 1, 1)));
}

test "THREADED: concurrent readers vs writer, no UAF, no leak, correct final" {
    const a = testing.allocator;
    var domain = ebr.Domain.init(a);
    defer domain.deinit();

    var nicks = try NickRegistry.init(a, &domain);
    var set = try MembershipSet.init(a, &domain);
    defer {
        nicks.deinit();
        set.deinit();
        quiesce(&domain);
    }

    const Shared = struct {
        nicks: *NickRegistry,
        set: *MembershipSet,
        domain: *ebr.Domain,
        stop: *std.atomic.Value(bool),

        fn readerLoop(ctx: @This(), part: *ebr.Participant) void {
            var iters: usize = 0;
            // Bounded by `stop`; the writer guarantees it flips after a finite
            // number of rounds, so this terminates.
            while (!ctx.stop.load(.acquire)) : (iters += 1) {
                // Lookups under their own pins; values may or may not be
                // present mid-flight — we only require no UAF / no crash.
                _ = ctx.nicks.lookup(part, "alice");
                _ = ctx.nicks.lookup(part, "bob");
                _ = ctx.set.contains(part, cid(0, 1, 1));
                _ = ctx.set.count(part);
                if (iters % 64 == 0) std.atomic.spinLoopHint();
            }
        }
    };

    var stop = std.atomic.Value(bool).init(false);
    const shared = Shared{ .nicks = &nicks, .set = &set, .domain = &domain, .stop = &stop };

    const reader_count = 4;
    var reader_parts: [reader_count]*ebr.Participant = undefined;
    var threads: [reader_count]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        stop.store(true, .release);
        for (0..spawned) |i| threads[i].join();
    }
    for (0..reader_count) |i| {
        reader_parts[i] = domain.register() catch unreachable;
        threads[i] = std.Thread.spawn(.{}, Shared.readerLoop, .{ shared, reader_parts[i] }) catch return error.SkipZigTest;
        spawned += 1;
    }

    // Writer runs on this thread, its own participant, bounded round count.
    const writer = domain.register() catch unreachable;
    const rounds: usize = 40_000;
    var r: usize = 0;
    while (r < rounds) : (r += 1) {
        try nicks.set(writer, "alice", cid(@intCast(r % 4096), @intCast(r % 1000), @intCast(r)));
        try nicks.set(writer, "bob", cid(0, 0, @intCast(r)));
        try set.add(writer, cid(0, 1, 1));
        try set.add(writer, cid(1, 2, @intCast(r % 64)));
        try set.remove(writer, cid(1, 2, @intCast((r +% 1) % 64)));
        try nicks.remove(writer, "bob");
        // Drive the epoch so retired boxes/keys actually get reclaimed during
        // the run (not just at the end), exercising the grace-period path.
        _ = domain.advance();
        _ = domain.advance();
    }

    stop.store(true, .release);
    for (0..spawned) |i| threads[i].join();

    // Final state check (single-threaded now).
    try testing.expect(nicks.lookup(writer, "alice") != null);
    try testing.expectEqual(@as(?ClientId, null), nicks.lookup(writer, "bob"));
    try testing.expect(set.contains(writer, cid(0, 1, 1)));

    // Cleanup participants. The defer chain drains the domain and frees the
    // currently-published snapshots; std.testing.allocator asserts no leak.
    writer.unregister();
    for (0..reader_count) |i| reader_parts[i].unregister();
}
