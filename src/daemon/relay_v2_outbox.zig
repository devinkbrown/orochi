// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded durable per-hop MESSAGE_V2 retransmission authority.
//!
//! Each row is keyed by the authenticated immediate peer node and RelayId and
//! retains the exact origin-signed wire until that peer authenticates an ACK.
//! A row is a durable obligation to exactly that peer: it is never retargeted,
//! failed over, merged, or deleted merely because the peer is unavailable or
//! because another peer owns the same RelayId. An exact duplicate (same peer,
//! same RelayId) coalesces only at admission; binding an unbound row never
//! consumes it in favor of an existing obligation. Batch insertion allocates
//! every wire copy and list slot before publication, so RVG2/Lotus callers can
//! reserve propagation before their no-fail commit.
//!
//! Unbound rows (peer == `unbound_peer`) are future-hop obligations that have
//! not yet selected a peer. Every unbound obligation persists a nonzero
//! `excluded_peer` — the ingress hop (or the reserved local-origin exclusion
//! for authored traffic) — so that binding can never bounce the message back
//! to the peer that delivered it, including across checkpoint restore.

const std = @import("std");
const message_relay_v2 = @import("../substrate/undertow/message_relay_v2.zig");

pub const RelayId = message_relay_v2.RelayId;
pub const unbound_peer: u64 = 0;
/// Reserved exclusion recorded on unbound obligations that were authored
/// locally and therefore have no ingress hop to exclude. Nonzero by
/// construction so the `excluded_peer != unbound_peer` invariant holds for
/// every unbound row; a real peer colliding with this value would merely be
/// skipped by `bindUnbound` (the row remains for any other peer), never
/// dropped or bounced.
pub const local_origin_exclusion: u64 = std.math.maxInt(u64);
pub const default_max_entries: usize = 8192;
pub const hard_max_entries: usize = 65_536;
pub const hard_max_receipts: usize = 65_536;
pub const hard_max_wire_bytes: usize = 1024 * 1024;
/// Instance-aggregate cap on the encoded checkpoint (header + every entry row
/// including per-entry overhead and exact wire + every 36-byte receipt row +
/// checksum). Enforced at admission so every admitted state seals.
pub const hard_max_checkpoint_bytes: usize = 64 * 1024 * 1024;

pub const Entry = struct {
    peer: u64,
    relay_id: RelayId,
    retry_after_ms: u64,
    attempts: u32 = 0,
    /// Persisted visited/ingress constraint. Unbound rows require a nonzero
    /// exclusion; `bindUnbound` never selects the excluded peer. Rows bound at
    /// admission carry 0; rows bound by `bindUnbound` deliberately retain
    /// their original exclusion as a visited constraint. `excluded_peer ==
    /// peer` is invalid in every state (covers unbound-with-zero as well as a
    /// bound row excluding itself).
    excluded_peer: u64 = 0,
    wire: []u8,
};

/// Durable proof that one immediate peer's exact MESSAGE_V2 was admitted. The
/// receiver retransmits the ACK until that peer returns an ACK confirmation;
/// unlike the former global FIFO, an unconfirmed proof is never evicted or
/// expired merely because unrelated traffic advances — only `confirmReceipt`
/// from the bound peer retires it, and admission fails closed at capacity.
/// The bound peer is always a real peer: a receipt with `peer ==
/// unbound_peer` could never be confirmed and would pin receipt capacity
/// forever, so it is rejected at live admission and by strict checkpoint
/// validation/restore.
pub const Receipt = struct {
    peer: u64,
    relay_id: RelayId,
    retry_after_ms: u64,
    attempts: u32 = 0,
};

pub const Error = std.mem.Allocator.Error || error{
    CapacityExceeded,
    BadMagic,
    UnsupportedVersion,
    InvalidConfig,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    DuplicateEntry,
    NonCanonicalOrder,
    InvalidWire,
    InvalidExclusion,
    InvalidReceiptPeer,
    CheckpointTooLarge,
};

pub const Outbox = struct {
    allocator: std.mem.Allocator,
    max_entries: usize,
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    receipts: std.ArrayListUnmanaged(Receipt) = .empty,
    /// In-memory, non-authoritative resume-fair sweep positions. Never
    /// checkpointed; a restored instance restarts both at 0. Repaired across
    /// every ordered removal so pending rows are neither skipped nor served
    /// twice within a round.
    entry_retry_cursor: usize = 0,
    receipt_retry_cursor: usize = 0,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) error{InvalidConfig}!Outbox {
        if (max_entries == 0 or max_entries > hard_max_entries) return error.InvalidConfig;
        return .{ .allocator = allocator, .max_entries = max_entries };
    }

    pub fn deinit(self: *Outbox) void {
        for (self.entries.items) |entry| self.allocator.free(entry.wire);
        self.entries.deinit(self.allocator);
        self.receipts.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const Outbox) usize {
        return self.entries.items.len;
    }

    pub fn items(self: *const Outbox) []const Entry {
        return self.entries.items;
    }

    pub fn mutableItems(self: *Outbox) []Entry {
        return self.entries.items;
    }

    pub fn contains(self: *const Outbox, peer: u64, relay_id: RelayId) bool {
        for (self.entries.items) |entry| {
            if (entry.peer == peer and std.mem.eql(u8, &entry.relay_id, &relay_id)) return true;
        }
        return false;
    }

    pub fn receiptItems(self: *const Outbox) []const Receipt {
        return self.receipts.items;
    }

    pub fn mutableReceiptItems(self: *Outbox) []Receipt {
        return self.receipts.items;
    }

    pub fn containsReceipt(self: *const Outbox, peer: u64, relay_id: RelayId) bool {
        for (self.receipts.items) |receipt| {
            if (receipt.peer == peer and std.mem.eql(u8, &receipt.relay_id, &relay_id)) return true;
        }
        return false;
    }

    /// Compatibility entry point: derives the unbound exclusion from the
    /// admission context. On the relayed path `receipt_peer` is the
    /// authenticated ingress hop, so any unbound future-hop row it creates is
    /// excluded from bouncing back to that ingress; authored traffic
    /// (`receipt_peer == null`) records the reserved local-origin exclusion.
    /// New callers should pass the exclusion explicitly via
    /// `putBatchExcluding`.
    pub fn putBatch(
        self: *Outbox,
        peers: []const u64,
        receipt_peer: ?u64,
        relay_id: RelayId,
        wire: []const u8,
        retry_after_ms: u64,
    ) Error!void {
        return self.putBatchExcluding(
            peers,
            receipt_peer,
            relay_id,
            wire,
            retry_after_ms,
            receipt_peer orelse local_origin_exclusion,
        );
    }

    /// Atomically retain one exact wire for every distinct peer not already
    /// holding this RelayId, plus at most one admission receipt. Entry and
    /// receipt publication is a single allocation/capacity/byte-cap
    /// transaction: on any failure `self` is byte-for-byte unchanged. Any
    /// unbound peer in `peers` requires a nonzero `unbound_excluded_peer`,
    /// which is persisted on the unbound row; bound rows are admitted with
    /// `excluded_peer == 0`. A `receipt_peer` equal to `unbound_peer` would
    /// create an unconfirmable receipt that pins capacity forever, so it is
    /// rejected before any allocation or mutation. Admission also enforces
    /// the instance-aggregate encoded-checkpoint cap so every admitted state
    /// seals.
    pub fn putBatchExcluding(
        self: *Outbox,
        peers: []const u64,
        receipt_peer: ?u64,
        relay_id: RelayId,
        wire: []const u8,
        retry_after_ms: u64,
        unbound_excluded_peer: u64,
    ) Error!void {
        if (wire.len == 0 or wire.len > hard_max_wire_bytes) return error.InvalidWire;
        if (receipt_peer) |peer| if (peer == unbound_peer) return error.InvalidReceiptPeer;
        for (peers) |peer| {
            if (peer == unbound_peer and unbound_excluded_peer == unbound_peer)
                return error.InvalidExclusion;
        }
        var needed: usize = 0;
        for (peers, 0..) |peer, index| {
            var duplicate_input = false;
            for (peers[0..index]) |prior| if (prior == peer) {
                duplicate_input = true;
                break;
            };
            if (!duplicate_input and !self.contains(peer, relay_id)) needed += 1;
        }
        const needs_receipt = if (receipt_peer) |peer|
            !self.containsReceipt(peer, relay_id)
        else
            false;
        if (needed == 0 and !needs_receipt) return;
        if (needed > self.max_entries - self.entries.items.len) return error.CapacityExceeded;
        if (needs_receipt and self.receipts.items.len == self.maxReceiptEntries())
            return error.CapacityExceeded;
        var retained_body_bytes = std.math.mul(
            usize,
            self.receipts.items.len,
            receipt_prefix_len,
        ) catch return error.CapacityExceeded;
        for (self.entries.items) |entry| {
            retained_body_bytes = std.math.add(
                usize,
                retained_body_bytes,
                entry_prefix_len + entry.wire.len,
            ) catch return error.CapacityExceeded;
        }
        const added_bytes = std.math.mul(usize, needed, entry_prefix_len + wire.len) catch
            return error.CapacityExceeded;
        var prospective_body = std.math.add(usize, retained_body_bytes, added_bytes) catch
            return error.CapacityExceeded;
        if (needs_receipt)
            prospective_body = std.math.add(usize, prospective_body, receipt_prefix_len) catch
                return error.CapacityExceeded;
        if (prospective_body > hard_max_checkpoint_bytes - header_len - checksum_len)
            return error.CapacityExceeded;

        const staged = try self.allocator.alloc(Entry, needed);
        defer self.allocator.free(staged);
        var staged_len: usize = 0;
        errdefer for (staged[0..staged_len]) |entry| self.allocator.free(entry.wire);
        for (peers, 0..) |peer, index| {
            var duplicate_input = false;
            for (peers[0..index]) |prior| if (prior == peer) {
                duplicate_input = true;
                break;
            };
            if (duplicate_input or self.contains(peer, relay_id)) continue;
            staged[staged_len] = .{
                .peer = peer,
                .relay_id = relay_id,
                .retry_after_ms = retry_after_ms,
                .excluded_peer = if (peer == unbound_peer) unbound_excluded_peer else 0,
                .wire = try self.allocator.dupe(u8, wire),
            };
            staged_len += 1;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, staged_len);
        if (needs_receipt)
            try self.receipts.ensureUnusedCapacity(self.allocator, 1);
        for (staged[0..staged_len]) |entry| self.entries.appendAssumeCapacity(entry);
        if (needs_receipt) self.receipts.appendAssumeCapacity(.{
            .peer = receipt_peer.?,
            .relay_id = relay_id,
            .retry_after_ms = retry_after_ms,
        });
    }

    /// Remove only the row authenticated by this immediate peer.
    pub fn acknowledge(self: *Outbox, peer: u64, relay_id: RelayId) bool {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.peer != peer or !std.mem.eql(u8, &entry.relay_id, &relay_id)) continue;
            const removed = self.entries.orderedRemove(index);
            self.allocator.free(removed.wire);
            self.repairEntryCursor(index);
            return true;
        }
        return false;
    }

    pub fn removeAt(self: *Outbox, index: usize) void {
        const removed = self.entries.orderedRemove(index);
        self.allocator.free(removed.wire);
        self.repairEntryCursor(index);
    }

    /// Remove only the accepted-message receipt confirmed by its authenticated
    /// immediate peer. A confirmation from another peer cannot retire it.
    pub fn confirmReceipt(self: *Outbox, peer: u64, relay_id: RelayId) bool {
        for (self.receipts.items, 0..) |receipt, index| {
            if (receipt.peer != peer or !std.mem.eql(u8, &receipt.relay_id, &relay_id)) continue;
            _ = self.receipts.orderedRemove(index);
            self.repairReceiptCursor(index);
            return true;
        }
        return false;
    }

    /// Bind unbound future-hop rows to `peer`. Rows whose persisted
    /// `excluded_peer` equals `peer` are skipped untouched — never deleted or
    /// altered — so an obligation can never bounce back to its ingress, even
    /// immediately after checkpoint restore. Rows whose RelayId `peer` already
    /// owns are likewise skipped byte-identically — never consumed, deleted,
    /// or retargeted — so a reconnecting already-served peer cannot absorb a
    /// future-hop obligation that must remain reserved for a genuinely
    /// different future peer. All other rows bind to `peer` and deliberately
    /// retain their exclusion as a visited constraint.
    pub fn bindUnbound(self: *Outbox, peer: u64) usize {
        if (peer == unbound_peer) return 0;
        var bound: usize = 0;
        for (self.entries.items) |*entry| {
            if (entry.peer != unbound_peer) continue;
            if (entry.excluded_peer == peer) continue;
            if (self.contains(peer, entry.relay_id)) continue;
            entry.peer = peer;
            bound += 1;
        }
        return bound;
    }

    /// Resume-fair page collection of due bound entries. Copies up to
    /// `out.len` rows whose retry deadline has passed, skipping unbound rows,
    /// and advances the non-authoritative cursor past every scanned row at
    /// collection time — so a caller that later drops part of the page under
    /// encoded-byte or SendQ pressure still starts the next sweep after the
    /// rows already served (a budget of 32 serves row 33 next sweep even when
    /// every row is due). Never mutates `retry_after_ms` or `attempts`.
    /// Returned entries alias live internal state (including `wire`); callers
    /// must copy what they need before releasing their lock or mutating the
    /// outbox.
    pub fn collectDueEntries(self: *Outbox, now_ms: u64, out: []Entry) usize {
        const total = self.entries.items.len;
        if (total == 0) {
            self.entry_retry_cursor = 0;
            return 0;
        }
        if (out.len == 0) return 0;
        var index = self.entry_retry_cursor % total;
        var scanned: usize = 0;
        var collected: usize = 0;
        while (scanned < total and collected < out.len) : (scanned += 1) {
            const entry = self.entries.items[index];
            index = (index + 1) % total;
            if (entry.peer == unbound_peer) continue;
            if (now_ms < entry.retry_after_ms) continue;
            out[collected] = entry;
            collected += 1;
        }
        self.entry_retry_cursor = index;
        return collected;
    }

    /// Resume-fair page collection of due admission receipts, with the same
    /// cursor semantics as `collectDueEntries`. Never mutates rows.
    pub fn collectDueReceipts(self: *Outbox, now_ms: u64, out: []Receipt) usize {
        const total = self.receipts.items.len;
        if (total == 0) {
            self.receipt_retry_cursor = 0;
            return 0;
        }
        if (out.len == 0) return 0;
        var index = self.receipt_retry_cursor % total;
        var scanned: usize = 0;
        var collected: usize = 0;
        while (scanned < total and collected < out.len) : (scanned += 1) {
            const receipt = self.receipts.items[index];
            index = (index + 1) % total;
            if (now_ms < receipt.retry_after_ms) continue;
            out[collected] = receipt;
            collected += 1;
        }
        self.receipt_retry_cursor = index;
        return collected;
    }

    fn repairEntryCursor(self: *Outbox, removed_index: usize) void {
        if (removed_index < self.entry_retry_cursor) self.entry_retry_cursor -= 1;
        if (self.entries.items.len == 0) self.entry_retry_cursor = 0;
    }

    fn repairReceiptCursor(self: *Outbox, removed_index: usize) void {
        if (removed_index < self.receipt_retry_cursor) self.receipt_retry_cursor -= 1;
        if (self.receipts.items.len == 0) self.receipt_retry_cursor = 0;
    }

    fn maxReceiptEntries(self: *const Outbox) usize {
        return @min(self.max_entries * 8, hard_max_receipts);
    }

    pub fn encodeCheckpoint(self: *const Outbox, allocator: std.mem.Allocator) Error![]u8 {
        if (self.entries.items.len > self.max_entries or
            self.receipts.items.len > self.maxReceiptEntries())
            return error.CapacityExceeded;
        var body_len = std.math.mul(usize, self.receipts.items.len, receipt_prefix_len) catch
            return error.CheckpointTooLarge;
        for (self.entries.items) |entry| {
            if (entry.wire.len == 0 or entry.wire.len > hard_max_wire_bytes) return error.InvalidWire;
            if (entry.excluded_peer == entry.peer) return error.InvalidExclusion;
            body_len = std.math.add(usize, body_len, entry_prefix_len + entry.wire.len) catch
                return error.CheckpointTooLarge;
        }
        for (self.receipts.items) |receipt| {
            if (receipt.peer == unbound_peer) return error.InvalidReceiptPeer;
        }
        const prefix_len = std.math.add(usize, header_len, body_len) catch return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch return error.CheckpointTooLarge;
        if (total_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        @memcpy(out[0..magic.len], &magic);
        out[4] = version;
        writeU32(out[5..9], @intCast(self.max_entries));
        writeU32(out[9..13], @intCast(self.entries.items.len));
        writeU32(out[13..17], @intCast(self.receipts.items.len));
        writeU32(out[17..21], @intCast(body_len));
        var pos: usize = header_len;
        for (self.entries.items) |entry| {
            writeU64(out[pos..][0..8], entry.peer);
            pos += 8;
            writeU64(out[pos..][0..8], entry.excluded_peer);
            pos += 8;
            @memcpy(out[pos..][0..@sizeOf(RelayId)], &entry.relay_id);
            pos += @sizeOf(RelayId);
            writeU64(out[pos..][0..8], entry.retry_after_ms);
            pos += 8;
            writeU32(out[pos..][0..4], entry.attempts);
            pos += 4;
            writeU32(out[pos..][0..4], @intCast(entry.wire.len));
            pos += 4;
            @memcpy(out[pos..][0..entry.wire.len], entry.wire);
            pos += entry.wire.len;
        }
        for (self.receipts.items) |receipt| {
            writeU64(out[pos..][0..8], receipt.peer);
            pos += 8;
            @memcpy(out[pos..][0..@sizeOf(RelayId)], &receipt.relay_id);
            pos += @sizeOf(RelayId);
            writeU64(out[pos..][0..8], receipt.retry_after_ms);
            pos += 8;
            writeU32(out[pos..][0..4], receipt.attempts);
            pos += 4;
        }
        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_max_entries: usize,
        bytes: []const u8,
    ) Error!Outbox {
        const meta = try validateCheckpoint(bytes);
        if (meta.max_entries != expected_max_entries) return error.InvalidConfig;
        var out = try Outbox.init(allocator, expected_max_entries);
        errdefer out.deinit();
        try out.entries.ensureTotalCapacity(allocator, meta.count);
        var pos: usize = header_len;
        for (0..meta.count) |_| {
            const peer = readU64(bytes[pos..][0..8]);
            pos += 8;
            const excluded_peer = readU64(bytes[pos..][0..8]);
            pos += 8;
            const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
            pos += @sizeOf(RelayId);
            const retry_after_ms = readU64(bytes[pos..][0..8]);
            pos += 8;
            const attempts = readU32(bytes[pos..][0..4]);
            pos += 4;
            const wire_len: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const wire = try allocator.dupe(u8, bytes[pos..][0..wire_len]);
            pos += wire_len;
            var owned = message_relay_v2.decode(allocator, wire) catch |err| {
                allocator.free(wire);
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.InvalidWire,
                };
            };
            defer owned.deinit(allocator);
            const derived = switch (message_relay_v2.verifyAndRelayId(allocator, owned.msg) catch |err| {
                allocator.free(wire);
                return err;
            }) {
                .verified => |id| id,
                else => {
                    allocator.free(wire);
                    return error.InvalidWire;
                },
            };
            if (!std.mem.eql(u8, &derived, &relay_id)) {
                allocator.free(wire);
                return error.InvalidWire;
            }
            out.entries.appendAssumeCapacity(.{
                .peer = peer,
                .relay_id = relay_id,
                .retry_after_ms = retry_after_ms,
                .attempts = attempts,
                .excluded_peer = excluded_peer,
                .wire = wire,
            });
        }
        try out.receipts.ensureTotalCapacity(allocator, meta.receipt_count);
        for (0..meta.receipt_count) |_| {
            const peer = readU64(bytes[pos..][0..8]);
            pos += 8;
            const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
            pos += @sizeOf(RelayId);
            const retry_after_ms = readU64(bytes[pos..][0..8]);
            pos += 8;
            const attempts = readU32(bytes[pos..][0..4]);
            pos += 4;
            out.receipts.appendAssumeCapacity(.{
                .peer = peer,
                .relay_id = relay_id,
                .retry_after_ms = retry_after_ms,
                .attempts = attempts,
            });
        }
        return out;
    }
};

pub const CheckpointMeta = struct { max_entries: usize, count: usize, receipt_count: usize };

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub fn validateCheckpoint(bytes: []const u8) Error!CheckpointMeta {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != version) return error.UnsupportedVersion;
    const max_entries: usize = readU32(bytes[5..9]);
    const count: usize = readU32(bytes[9..13]);
    const receipt_count: usize = readU32(bytes[13..17]);
    const body_len: usize = readU32(bytes[17..21]);
    if (max_entries == 0 or max_entries > hard_max_entries) return error.InvalidConfig;
    if (count > max_entries) return error.CapacityExceeded;
    if (receipt_count > @min(max_entries * 8, hard_max_receipts)) return error.CapacityExceeded;
    const prefix_len = std.math.add(usize, header_len, body_len) catch return error.CheckpointTooLarge;
    const total_len = std.math.add(usize, prefix_len, checksum_len) catch return error.CheckpointTooLarge;
    if (total_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < total_len) return error.Truncated;
    if (bytes.len > total_len) return error.TrailingBytes;
    var sum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &sum);
    if (!std.mem.eql(u8, &sum, bytes[prefix_len..])) return error.ChecksumMismatch;
    var pos: usize = header_len;
    for (0..count) |_| {
        if (pos > prefix_len or prefix_len - pos < entry_prefix_len) return error.Truncated;
        const row_start = pos;
        const peer = readU64(bytes[pos..][0..8]);
        pos += 8;
        const excluded_peer = readU64(bytes[pos..][0..8]);
        pos += 8;
        const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
        pos += @sizeOf(RelayId);
        pos += 8 + 4; // retry_after_ms + attempts
        const wire_len: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        // One rule covers both invalid shapes: an unbound row with no
        // persisted exclusion (0 == 0) and a bound row excluding itself.
        if (excluded_peer == peer) return error.InvalidExclusion;
        if (wire_len == 0 or wire_len > hard_max_wire_bytes or wire_len > prefix_len - pos)
            return error.InvalidWire;
        var prior_pos: usize = header_len;
        while (prior_pos < row_start) {
            const prior_peer = readU64(bytes[prior_pos..][0..8]);
            const prior_id: RelayId = bytes[prior_pos + 16 ..][0..@sizeOf(RelayId)].*;
            const prior_wire_len: usize = readU32(bytes[prior_pos + entry_prefix_len - 4 ..][0..4]);
            if (prior_peer == peer and std.mem.eql(u8, &prior_id, &relay_id))
                return error.DuplicateEntry;
            prior_pos += entry_prefix_len + prior_wire_len;
        }
        pos += wire_len;
    }
    const receipts_start = pos;
    for (0..receipt_count) |receipt_index| {
        if (pos > prefix_len or prefix_len - pos < receipt_prefix_len) return error.Truncated;
        const peer = readU64(bytes[pos..][0..8]);
        // A receipt bound to peer 0 could never be confirmed and would pin
        // receipt capacity forever; restore fails closed instead.
        if (peer == unbound_peer) return error.InvalidReceiptPeer;
        const receipt: RelayId = bytes[pos + 8 ..][0..@sizeOf(RelayId)].*;
        for (0..receipt_index) |prior_index| {
            const prior_off = receipts_start + prior_index * receipt_prefix_len;
            const prior_peer = readU64(bytes[prior_off..][0..8]);
            const prior: RelayId = bytes[prior_off + 8 ..][0..@sizeOf(RelayId)].*;
            if (prior_peer == peer and std.mem.eql(u8, &prior, &receipt))
                return error.DuplicateEntry;
        }
        pos += receipt_prefix_len;
    }
    if (pos != prefix_len) return if (pos < prefix_len) error.TrailingBytes else error.Truncated;
    return .{ .max_entries = max_entries, .count = count, .receipt_count = receipt_count };
}

const magic = [_]u8{ 'R', 'V', 'O', '2' };
const version: u8 = 2;
const header_len: usize = 21;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const entry_prefix_len: usize = 8 + 8 + @sizeOf(RelayId) + 8 + 4 + 4;
const receipt_prefix_len: usize = 8 + @sizeOf(RelayId) + 8 + 4;
// Unreleased-format revision: entry rows gained a persisted excluded_peer, so
// the domain rotates and any pre-revision blob fails closed (ChecksumMismatch)
// instead of misparsing under the old row stride.
const checksum_domain = "orochi-relay-v2-outbox-checkpoint-v2-excluded";

comptime {
    std.debug.assert(entry_prefix_len == 48);
    std.debug.assert(receipt_prefix_len == 36);
}

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(checksum_domain);
    h.update(prefix);
    h.final(out);
}
fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}
fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}
fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}
fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .big);
}

const TestSigned = struct { wire: []u8, id: RelayId };

fn makeTestSigned(
    allocator: std.mem.Allocator,
    seed: u8,
    hlc: u64,
    text: []const u8,
) !TestSigned {
    const sign = @import("../crypto/sign.zig");
    const signed_frame = @import("../substrate/undertow/signed_frame.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed)));
    defer kp.deinit();
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    var msg = message_relay_v2.RelayMessage{
        .verb = .privmsg,
        .target = "#mesh",
        .source_prefix = "alice!u@mesh.test",
        .text = text,
        .scope_kind = .channel,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try message_relay_v2.stampOrigin(allocator, &msg, &kp, &pubkey, &signature);
    const wire = try message_relay_v2.encode(allocator, msg);
    errdefer allocator.free(wire);
    const id = switch (try message_relay_v2.verifyAndRelayId(allocator, msg)) {
        .verified => |verified| verified,
        else => return error.TestUnexpectedResult,
    };
    return .{ .wire = wire, .id = id };
}

fn resealTestCheckpoint(buf: []u8) void {
    const prefix = buf.len - checksum_len;
    checkpointChecksum(buf[0..prefix], buf[prefix..][0..checksum_len]);
}

fn testRelayId(seed: u8) RelayId {
    var id: RelayId = @splat(0);
    id[0] = seed;
    return id;
}

test "relay v2 outbox batch reservation ack scope and checkpoint are exact" {
    const allocator = std.testing.allocator;
    const signed = try makeTestSigned(allocator, 0x31, 7, "exact-wire");
    defer allocator.free(signed.wire);
    const wire = signed.wire;
    const id = signed.id;
    var outbox = try Outbox.init(allocator, 4);
    defer outbox.deinit();
    try outbox.putBatch(&.{ 7, 8, 7 }, 9, id, wire, 1234);
    try std.testing.expectEqual(@as(usize, 2), outbox.len());
    try std.testing.expect(!outbox.acknowledge(9, id));
    try std.testing.expect(outbox.acknowledge(7, id));
    try std.testing.expect(outbox.contains(8, id));
    try std.testing.expectEqual(@as(u64, 0), outbox.items()[0].excluded_peer);

    const checkpoint = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(checkpoint);
    var restored = try Outbox.decodeCheckpoint(allocator, 4, checkpoint);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 1), restored.len());
    try std.testing.expect(restored.contains(8, id));
    try std.testing.expect(restored.containsReceipt(9, id));
    try std.testing.expectEqualStrings(wire, restored.items()[0].wire);

    // Byte-identical re-encode of the restored authority.
    const resealed = try restored.encodeCheckpoint(allocator);
    defer allocator.free(resealed);
    try std.testing.expectEqualSlices(u8, checkpoint, resealed);

    const PutSweep = struct {
        fn run(failing: std.mem.Allocator, signed_wire: []const u8, relay_id: RelayId) !void {
            var candidate = try Outbox.init(failing, 4);
            defer candidate.deinit();
            try candidate.putBatchExcluding(&.{ 7, 8, unbound_peer }, 9, relay_id, signed_wire, 99, 9);
            try std.testing.expectEqual(@as(usize, 3), candidate.len());
            try std.testing.expect(candidate.contains(unbound_peer, relay_id));
            try std.testing.expect(candidate.containsReceipt(9, relay_id));
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, PutSweep.run, .{ wire, id });

    const DecodeSweep = struct {
        fn run(failing: std.mem.Allocator, encoded: []const u8) !void {
            var candidate = try Outbox.decodeCheckpoint(failing, 4, encoded);
            defer candidate.deinit();
            try std.testing.expectEqual(@as(usize, 1), candidate.len());
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, DecodeSweep.run, .{checkpoint});
}

test "relay v2 outbox capacity failure leaves prior authority unchanged" {
    const allocator = std.testing.allocator;
    var outbox = try Outbox.init(allocator, 1);
    defer outbox.deinit();
    const first: RelayId = @splat(1);
    const second: RelayId = @splat(2);
    try outbox.putBatch(&.{7}, null, first, "one", 100);
    const before = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(before);
    try std.testing.expectError(error.CapacityExceeded, outbox.putBatch(&.{8}, null, second, "two", 100));
    const after = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "relay v2 outbox receipt authority fails closed at capacity and survives long partitions" {
    const allocator = std.testing.allocator;
    var outbox = try Outbox.init(allocator, 1);
    defer outbox.deinit();
    // max_entries=1 bounds receipts at 8 proofs.
    for (0..8) |index| {
        const seed: u8 = @intCast(index + 1);
        try outbox.putBatch(&.{}, @as(u64, 40 + seed), testRelayId(seed), "w", 5);
    }
    try std.testing.expectEqual(@as(usize, 8), outbox.receiptItems().len);

    // Cap + 1 fails closed and is atomic across entry+receipt publication:
    // the entry half of the batch must not publish either.
    const before = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(before);
    try std.testing.expectError(
        error.CapacityExceeded,
        outbox.putBatch(&.{7}, 60, testRelayId(9), "w", 5),
    );
    try std.testing.expectEqual(@as(usize, 0), outbox.len());
    const after = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);

    // Long partition: the peer-41 proof survives arbitrary retry aging and
    // arbitrary unrelated confirmations; only its bound peer retires it.
    const target = testRelayId(1);
    for (outbox.mutableReceiptItems()) |*receipt| {
        receipt.attempts = 100_000;
        receipt.retry_after_ms = std.math.maxInt(u64);
    }
    for (2..9) |index| {
        const seed: u8 = @intCast(index);
        try std.testing.expect(outbox.confirmReceipt(@as(u64, 40 + seed), testRelayId(seed)));
    }
    try std.testing.expect(!outbox.confirmReceipt(99, target)); // foreign peer
    try std.testing.expect(!outbox.confirmReceipt(42, target)); // wrong bound peer
    try std.testing.expect(outbox.containsReceipt(41, target));
    try std.testing.expect(outbox.confirmReceipt(41, target));
    try std.testing.expectEqual(@as(usize, 0), outbox.receiptItems().len);
}

test "relay v2 outbox retry collectors stay resume-fair across budgets removals and unbound rows" {
    const allocator = std.testing.allocator;
    var outbox = try Outbox.init(allocator, 64);
    defer outbox.deinit();
    for (0..33) |index| {
        try outbox.putBatch(&.{7}, null, testRelayId(@intCast(index + 1)), "w", 0);
    }
    var page: [32]Entry = undefined;
    // Every row is due; a 32 budget must still serve row 33 next sweep.
    try std.testing.expectEqual(@as(usize, 32), outbox.collectDueEntries(1, &page));
    try std.testing.expectEqual(@as(u8, 1), page[0].relay_id[0]);
    try std.testing.expectEqual(@as(u8, 32), page[31].relay_id[0]);
    // The collector never mutates retry state.
    for (outbox.items()) |entry| {
        try std.testing.expectEqual(@as(u32, 0), entry.attempts);
        try std.testing.expectEqual(@as(u64, 0), entry.retry_after_ms);
    }
    try std.testing.expectEqual(@as(usize, 32), outbox.collectDueEntries(1, &page));
    try std.testing.expectEqual(@as(u8, 33), page[0].relay_id[0]);
    try std.testing.expectEqual(@as(u8, 1), page[1].relay_id[0]);

    // Ordered removal repairs the cursor: rows behind it are neither skipped
    // nor double-served within the round.
    var small = try Outbox.init(allocator, 8);
    defer small.deinit();
    for (0..4) |index| {
        try small.putBatch(&.{7}, null, testRelayId(@intCast(index + 1)), "w", 0);
    }
    var duo: [2]Entry = undefined;
    try std.testing.expectEqual(@as(usize, 2), small.collectDueEntries(1, &duo));
    try std.testing.expectEqual(@as(u8, 1), duo[0].relay_id[0]);
    try std.testing.expectEqual(@as(u8, 2), duo[1].relay_id[0]);
    try std.testing.expect(small.acknowledge(7, testRelayId(1)));
    try std.testing.expectEqual(@as(usize, 2), small.collectDueEntries(1, &duo));
    try std.testing.expectEqual(@as(u8, 3), duo[0].relay_id[0]);
    try std.testing.expectEqual(@as(u8, 4), duo[1].relay_id[0]);
    try std.testing.expectEqual(@as(usize, 2), small.collectDueEntries(1, &duo));
    try std.testing.expectEqual(@as(u8, 2), duo[0].relay_id[0]);
    try std.testing.expectEqual(@as(u8, 3), duo[1].relay_id[0]);

    // Unbound rows are skipped by collection but never deleted.
    var mixed = try Outbox.init(allocator, 8);
    defer mixed.deinit();
    try mixed.putBatchExcluding(&.{unbound_peer}, null, testRelayId(1), "w", 0, 9);
    try mixed.putBatch(&.{5}, null, testRelayId(2), "w", 0);
    var solo: [4]Entry = undefined;
    try std.testing.expectEqual(@as(usize, 1), mixed.collectDueEntries(1, &solo));
    try std.testing.expectEqual(@as(u64, 5), solo[0].peer);
    try std.testing.expect(mixed.contains(unbound_peer, testRelayId(1)));

    // Receipt collector shares the same resume-fair and repair semantics.
    var proofs = try Outbox.init(allocator, 8);
    defer proofs.deinit();
    for (0..3) |index| {
        const seed: u8 = @intCast(index + 1);
        try proofs.putBatch(&.{}, @as(u64, 40 + seed), testRelayId(seed), "w", 0);
    }
    var rpage: [2]Receipt = undefined;
    try std.testing.expectEqual(@as(usize, 2), proofs.collectDueReceipts(1, &rpage));
    try std.testing.expectEqual(@as(u8, 1), rpage[0].relay_id[0]);
    try std.testing.expect(proofs.confirmReceipt(41, testRelayId(1)));
    try std.testing.expectEqual(@as(usize, 2), proofs.collectDueReceipts(1, &rpage));
    try std.testing.expectEqual(@as(u8, 3), rpage[0].relay_id[0]);
    for (proofs.receiptItems()) |receipt| {
        try std.testing.expectEqual(@as(u32, 0), receipt.attempts);
    }
}

test "relay v2 outbox aggregate checkpoint cap admits exactly the boundary and every admitted state seals" {
    const allocator = std.testing.allocator;
    const body_budget = hard_max_checkpoint_bytes - header_len - checksum_len;
    const per_full_row = entry_prefix_len + hard_max_wire_bytes;
    const full_rows = body_budget / per_full_row;
    const tail_total = body_budget - full_rows * per_full_row;
    comptime {
        std.debug.assert(tail_total > entry_prefix_len);
        std.debug.assert(tail_total - entry_prefix_len <= hard_max_wire_bytes);
    }
    const tail_wire_len = tail_total - entry_prefix_len;

    var outbox = try Outbox.init(allocator, full_rows + 2);
    defer outbox.deinit();
    const full_wire = try allocator.alloc(u8, hard_max_wire_bytes);
    defer allocator.free(full_wire);
    @memset(full_wire, 0xAB);
    for (0..full_rows) |index| {
        try outbox.putBatch(&.{7}, null, testRelayId(@intCast(index + 1)), full_wire, 0);
    }

    // One byte over the exact boundary fails closed and changes nothing.
    const over_id = testRelayId(200);
    try std.testing.expectError(
        error.CapacityExceeded,
        outbox.putBatch(&.{7}, null, over_id, full_wire[0 .. tail_wire_len + 1], 0),
    );
    try std.testing.expectEqual(full_rows, outbox.len());

    // The exact boundary admits and the admitted state seals at the cap.
    try outbox.putBatch(&.{7}, null, testRelayId(201), full_wire[0..tail_wire_len], 0);
    const sealed = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(sealed);
    try std.testing.expectEqual(hard_max_checkpoint_bytes, sealed.len);
    const meta = try validateCheckpoint(sealed);
    try std.testing.expectEqual(full_rows + 1, meta.count);

    // Nothing further fits: neither a minimal entry row nor a 36-byte receipt.
    try std.testing.expectError(
        error.CapacityExceeded,
        outbox.putBatch(&.{7}, null, testRelayId(202), "x", 0),
    );
    try std.testing.expectError(
        error.CapacityExceeded,
        outbox.putBatch(&.{}, 9, testRelayId(203), "x", 0),
    );
    try std.testing.expectEqual(full_rows + 1, outbox.len());
}

test "relay v2 outbox checkpoint decode is strict and fails closed" {
    const allocator = std.testing.allocator;
    const signed = try makeTestSigned(allocator, 0x51, 21, "strict");
    defer allocator.free(signed.wire);
    var outbox = try Outbox.init(allocator, 4);
    defer outbox.deinit();
    try outbox.putBatch(&.{7}, null, signed.id, signed.wire, 55);
    const base = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(base);

    // Unsupported version is rejected before any payload interpretation.
    {
        const mutated = try allocator.dupe(u8, base);
        defer allocator.free(mutated);
        mutated[4] = version + 1;
        try std.testing.expectError(error.UnsupportedVersion, validateCheckpoint(mutated));
    }
    // Any unresealed corruption is a checksum failure.
    {
        const mutated = try allocator.dupe(u8, base);
        defer allocator.free(mutated);
        mutated[header_len] ^= 0x01;
        try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(mutated));
    }
    // Truncated and trailing byte streams fail closed.
    try std.testing.expectError(error.Truncated, validateCheckpoint(base[0 .. base.len - 1]));
    {
        const trailing = try allocator.alloc(u8, base.len + 1);
        defer allocator.free(trailing);
        @memcpy(trailing[0..base.len], base);
        trailing[base.len] = 0;
        try std.testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));
    }
    // A resealed duplicate (same peer, same RelayId) row is rejected.
    {
        const row_len = entry_prefix_len + signed.wire.len;
        const dup = try allocator.alloc(u8, base.len + row_len);
        defer allocator.free(dup);
        @memcpy(dup[0 .. header_len + row_len], base[0 .. header_len + row_len]);
        @memcpy(dup[header_len + row_len ..][0..row_len], base[header_len..][0..row_len]);
        @memcpy(
            dup[header_len + 2 * row_len ..][0..checksum_len],
            base[header_len + row_len ..][0..checksum_len],
        );
        writeU32(dup[9..13], 2);
        writeU32(dup[17..21], @intCast(2 * row_len));
        resealTestCheckpoint(dup);
        try std.testing.expectError(error.DuplicateEntry, validateCheckpoint(dup));
    }
    // A resealed derived-RelayId mismatch passes structural validation but the
    // strict decoder refuses to adopt it.
    {
        const mutated = try allocator.dupe(u8, base);
        defer allocator.free(mutated);
        mutated[header_len + 16] ^= 0xFF; // stored relay_id byte
        resealTestCheckpoint(mutated);
        _ = try validateCheckpoint(mutated);
        try std.testing.expectError(
            error.InvalidWire,
            Outbox.decodeCheckpoint(allocator, 4, mutated),
        );
    }
    // A resealed tampered wire is rejected: the retained bytes must remain the
    // exact origin-signed frame.
    {
        const mutated = try allocator.dupe(u8, base);
        defer allocator.free(mutated);
        mutated[header_len + entry_prefix_len] ^= 0x01;
        resealTestCheckpoint(mutated);
        try std.testing.expectError(
            error.InvalidWire,
            Outbox.decodeCheckpoint(allocator, 4, mutated),
        );
    }
    // A resealed unbound row without a persisted exclusion is invalid, as is
    // a bound row excluding itself.
    {
        const mutated = try allocator.dupe(u8, base);
        defer allocator.free(mutated);
        writeU64(mutated[header_len..][0..8], unbound_peer); // peer=0, excluded=0
        resealTestCheckpoint(mutated);
        try std.testing.expectError(error.InvalidExclusion, validateCheckpoint(mutated));
    }
    {
        const mutated = try allocator.dupe(u8, base);
        defer allocator.free(mutated);
        writeU64(mutated[header_len + 8 ..][0..8], 7); // excluded == bound peer
        resealTestCheckpoint(mutated);
        try std.testing.expectError(error.InvalidExclusion, validateCheckpoint(mutated));
    }
}

test "relay v2 outbox persisted ingress exclusion survives restore and never bounces" {
    const allocator = std.testing.allocator;
    const signed = try makeTestSigned(allocator, 0x42, 11, "restore");
    defer allocator.free(signed.wire);
    var outbox = try Outbox.init(allocator, 4);
    defer outbox.deinit();

    // Relayed traffic with no eligible bound peer: the compatibility API
    // derives the exclusion from the ingress receipt peer.
    try outbox.putBatch(&.{unbound_peer}, 9, signed.id, signed.wire, 100);
    try std.testing.expect(outbox.contains(unbound_peer, signed.id));
    try std.testing.expectEqual(@as(u64, 9), outbox.items()[0].excluded_peer);
    try std.testing.expect(outbox.containsReceipt(9, signed.id));

    const checkpoint = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(checkpoint);
    var restored = try Outbox.decodeCheckpoint(allocator, 4, checkpoint);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u64, 9), restored.items()[0].excluded_peer);

    // The ingress can never re-acquire the obligation, even after restore,
    // and the skipped row is neither deleted nor altered.
    try std.testing.expectEqual(@as(usize, 0), restored.bindUnbound(9));
    try std.testing.expect(restored.contains(unbound_peer, signed.id));
    try std.testing.expectEqual(@as(u64, 9), restored.items()[0].excluded_peer);
    try std.testing.expectEqualStrings(signed.wire, restored.items()[0].wire);

    // A different peer binds; the exclusion is retained as a visited
    // constraint on the now-bound row.
    try std.testing.expectEqual(@as(usize, 1), restored.bindUnbound(11));
    try std.testing.expect(restored.contains(11, signed.id));
    try std.testing.expectEqual(@as(u64, 9), restored.items()[0].excluded_peer);

    const DecodeSweep = struct {
        fn run(failing: std.mem.Allocator, encoded: []const u8) !void {
            var candidate = try Outbox.decodeCheckpoint(failing, 4, encoded);
            defer candidate.deinit();
            try std.testing.expectEqual(@as(usize, 1), candidate.len());
            try std.testing.expectEqual(@as(u64, 9), candidate.items()[0].excluded_peer);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, DecodeSweep.run, .{checkpoint});

    // Authored traffic has no ingress: the reserved local-origin exclusion
    // keeps the invariant nonzero and any real peer may bind.
    var authored = try Outbox.init(allocator, 4);
    defer authored.deinit();
    try authored.putBatch(&.{unbound_peer}, null, testRelayId(3), "w", 0);
    try std.testing.expectEqual(local_origin_exclusion, authored.items()[0].excluded_peer);
    try std.testing.expectEqual(@as(usize, 1), authored.bindUnbound(9));
    try std.testing.expect(authored.contains(9, testRelayId(3)));

    // The explicit API fails closed on an unbound row with no exclusion.
    try std.testing.expectError(
        error.InvalidExclusion,
        authored.putBatchExcluding(&.{unbound_peer}, null, testRelayId(4), "w", 0, unbound_peer),
    );
    try std.testing.expectEqual(@as(usize, 1), authored.len());

    // Binding never consumes an unbound row for a peer that already owns the
    // RelayId: the future-hop obligation is skipped untouched and remains
    // reserved for a genuinely different peer.
    var dup = try Outbox.init(allocator, 4);
    defer dup.deinit();
    try dup.putBatch(&.{5}, null, testRelayId(6), "w", 0);
    try dup.putBatchExcluding(&.{unbound_peer}, null, testRelayId(6), "w", 0, 9);
    try std.testing.expectEqual(@as(usize, 2), dup.len());
    try std.testing.expectEqual(@as(usize, 0), dup.bindUnbound(5));
    try std.testing.expectEqual(@as(usize, 2), dup.len());
    try std.testing.expect(dup.contains(5, testRelayId(6)));
    try std.testing.expect(dup.contains(unbound_peer, testRelayId(6)));
    try std.testing.expectEqual(@as(u64, 9), dup.items()[1].excluded_peer);
    // A genuinely different future peer still receives the obligation.
    try std.testing.expectEqual(@as(usize, 1), dup.bindUnbound(12));
    try std.testing.expect(dup.contains(12, testRelayId(6)));
    try std.testing.expect(dup.contains(5, testRelayId(6)));
}

test "relay v2 outbox reconnecting served peer never consumes a future-hop obligation" {
    const allocator = std.testing.allocator;
    const signed = try makeTestSigned(allocator, 0x66, 33, "future-hop");
    defer allocator.free(signed.wire);
    var outbox = try Outbox.init(allocator, 4);
    defer outbox.deinit();

    // bound(C=7, id) plus unbound(0, id, exclude=B=9) from ingress B.
    try outbox.putBatchExcluding(&.{ 7, unbound_peer }, 9, signed.id, signed.wire, 100, 9);
    try std.testing.expectEqual(@as(usize, 2), outbox.len());

    const checkpoint = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(checkpoint);
    var restored = try Outbox.decodeCheckpoint(allocator, 4, checkpoint);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 2), restored.len());

    // C reconnects after restore: it already owns the RelayId, so binding
    // must leave the whole authority byte-identical — the unbound row is
    // neither consumed, deleted, nor retargeted.
    try std.testing.expectEqual(@as(usize, 0), restored.bindUnbound(7));
    const after_reconnect = try restored.encodeCheckpoint(allocator);
    defer allocator.free(after_reconnect);
    try std.testing.expectEqualSlices(u8, checkpoint, after_reconnect);

    // The ingress exclusion still holds on the preserved row.
    try std.testing.expectEqual(@as(usize, 0), restored.bindUnbound(9));
    try std.testing.expect(restored.contains(unbound_peer, signed.id));

    // A later, genuinely different peer D receives the exact wire.
    try std.testing.expectEqual(@as(usize, 1), restored.bindUnbound(11));
    try std.testing.expect(restored.contains(11, signed.id));
    try std.testing.expect(restored.contains(7, signed.id));
    for (restored.items()) |entry| {
        try std.testing.expectEqualStrings(signed.wire, entry.wire);
    }
}

test "relay v2 outbox rejects zero receipt peer live and in resealed checkpoints" {
    const allocator = std.testing.allocator;
    var outbox = try Outbox.init(allocator, 4);
    defer outbox.deinit();
    try outbox.putBatch(&.{7}, 9, testRelayId(1), "w", 5);
    const before = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(before);

    // Live admission rejects an unconfirmable peer-0 receipt before any
    // allocation or mutation, through both entry points; the entry half of
    // the batch must not publish either.
    try std.testing.expectError(
        error.InvalidReceiptPeer,
        outbox.putBatch(&.{8}, unbound_peer, testRelayId(2), "w", 5),
    );
    try std.testing.expectError(
        error.InvalidReceiptPeer,
        outbox.putBatchExcluding(&.{unbound_peer}, unbound_peer, testRelayId(2), "w", 5, 9),
    );
    try std.testing.expectEqual(@as(usize, 1), outbox.len());
    try std.testing.expectEqual(@as(usize, 1), outbox.receiptItems().len);
    const after = try outbox.encodeCheckpoint(allocator);
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);

    // Internal retry bookkeeping exposes mutable rows, so sealing revalidates
    // the confirmable-peer invariant instead of emitting a checkpoint that the
    // successor would reject only after exec.
    outbox.mutableReceiptItems()[0].peer = unbound_peer;
    try std.testing.expectError(error.InvalidReceiptPeer, outbox.encodeCheckpoint(allocator));
    outbox.mutableReceiptItems()[0].peer = 9;

    // A resealed checkpoint carrying a peer-0 receipt row fails strict
    // validation and can never be restored.
    const mutated = try allocator.dupe(u8, before);
    defer allocator.free(mutated);
    const receipt_off = header_len + entry_prefix_len + 1; // single 1-byte wire
    writeU64(mutated[receipt_off..][0..8], unbound_peer);
    resealTestCheckpoint(mutated);
    try std.testing.expectError(error.InvalidReceiptPeer, validateCheckpoint(mutated));
    try std.testing.expectError(
        error.InvalidReceiptPeer,
        Outbox.decodeCheckpoint(allocator, 4, mutated),
    );
}
