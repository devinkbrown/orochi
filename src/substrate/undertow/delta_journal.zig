// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable journal for signed CRDT deltas.
//!
//! Composes the write-ahead log (`wal`) with the canonical signed-delta wire
//! codec (`signed_delta`): every Concord-Sync mutation is appended as a CRC-framed,
//! signature-verifiable record, so a node recovers its converged channel state
//! after a crash by replaying the journal (verifying each delta) on top of the
//! last snapshot. The relay/disk is not trusted — replay re-verifies signatures,
//! and a torn tail record is detected by CRC and dropped, not applied.
//!
//! The journal owns the delta log; snapshots carry an opaque serialized CRDT
//! state (produced by the caller, e.g. `burst.serialize`) plus the log
//! truncation point, so the log can be compacted after a snapshot.
const std = @import("std");

const wal = @import("../wal.zig");
const signed_delta = @import("../../proto/signed_delta.zig");

const SignedDelta = signed_delta.SignedDelta;

pub const DeltaJournal = struct {
    allocator: std.mem.Allocator,
    log: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) DeltaJournal {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *DeltaJournal) void {
        self.log.deinit(self.allocator);
        self.* = undefined;
    }

    /// Append a signed delta to the journal; returns its log offset.
    pub fn append(self: *DeltaJournal, signed: SignedDelta) !usize {
        const need = signed_delta.signedWireLen(signed.env);
        const buf = try self.allocator.alloc(u8, need);
        defer self.allocator.free(buf);
        const wire = try signed_delta.encodeSigned(signed, buf);
        return wal.append(self.allocator, &self.log, wire);
    }

    pub fn logBytes(self: *const DeltaJournal) []const u8 {
        return self.log.items;
    }

    /// Replayed journal: owned record bytes plus decoded delta views into them.
    /// The deltas borrow `result`'s record buffers — keep this alive while using
    /// them, then `deinit`.
    pub const Replayed = struct {
        result: wal.ReplayResult,
        deltas: []SignedDelta,
        stop_reason: wal.StopReason,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *Replayed) void {
            self.allocator.free(self.deltas);
            self.result.deinit(self.allocator);
            self.* = undefined;
        }
    };

    /// Replay valid records and decode each into a SignedDelta (callers should
    /// re-verify signatures via `signed_delta.verifyOne` before applying).
    pub fn replay(self: *DeltaJournal) !Replayed {
        var result = try wal.replay(self.allocator, self.log.items);
        errdefer result.deinit(self.allocator);
        const deltas = try self.allocator.alloc(SignedDelta, result.records.len);
        errdefer self.allocator.free(deltas);
        for (result.records, 0..) |rec, i| {
            deltas[i] = try signed_delta.decodeSigned(rec);
        }
        const reason = result.stop_reason;
        return .{ .result = result, .deltas = deltas, .stop_reason = reason, .allocator = self.allocator };
    }

    /// Produce a snapshot capturing `state_bytes` (the serialized converged CRDT)
    /// and the current log length as the truncation point.
    pub fn snapshot(self: *DeltaJournal, state_bytes: []const u8) !wal.Snapshot {
        return wal.snapshot(self.allocator, state_bytes, self.log.items.len);
    }

    /// Compact the log: drop the prefix already captured by a snapshot.
    pub fn truncateTo(self: *DeltaJournal, offset: usize) void {
        const n = @min(offset, self.log.items.len);
        const rest = self.log.items.len - n;
        std.mem.copyForwards(u8, self.log.items[0..rest], self.log.items[n..]);
        self.log.shrinkRetainingCapacity(rest);
    }
};

/// Recover the latest state from a snapshot blob plus the live log tail.
pub fn recover(allocator: std.mem.Allocator, snapshot_blob: []const u8, log_tail: []const u8) !wal.Recovery {
    return wal.recover(allocator, snapshot_blob, log_tail);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makeSigned(kp: *const signed_delta.KeyPair, hlc: u64, op: []const u8) !SignedDelta {
    return signed_delta.sign(.{
        .origin_node = signed_delta.nodeIdFromPublicKey(kp.public_key.toBytes()),
        .hlc = hlc,
        .family = 1,
        .scope = "#chan",
        .op_bytes = op,
    }, kp);
}

test "append then replay decodes and re-verifies every delta" {
    const allocator = testing.allocator;
    const kp = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x31)));
    const pub_key = kp.public_key.toBytes();

    var j = DeltaJournal.init(allocator);
    defer j.deinit();

    _ = try j.append(try makeSigned(&kp, 100, "join:1"));
    _ = try j.append(try makeSigned(&kp, 101, "join:2"));
    _ = try j.append(try makeSigned(&kp, 102, "part:1"));

    var r = try j.replay();
    defer r.deinit();
    try testing.expectEqual(@as(usize, 3), r.deltas.len);
    try testing.expectEqual(wal.StopReason.end, r.stop_reason);
    for (r.deltas) |d| try testing.expect(signed_delta.verifyOne(d, pub_key));
    try testing.expectEqual(@as(u64, 100), r.deltas[0].env.hlc);
    try testing.expectEqualStrings("part:1", r.deltas[2].env.op_bytes);
}

test "a torn tail record is detected by CRC and dropped, not applied" {
    const allocator = testing.allocator;
    const kp = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x32)));

    var j = DeltaJournal.init(allocator);
    defer j.deinit();
    _ = try j.append(try makeSigned(&kp, 1, "good-1"));
    _ = try j.append(try makeSigned(&kp, 2, "good-2"));
    // Corrupt the last byte of the log (the second record's tail).
    j.log.items[j.log.items.len - 1] ^= 0xff;

    var r = try j.replay();
    defer r.deinit();
    // Only the first, intact record replays; the corrupt frame stops replay.
    try testing.expectEqual(@as(usize, 1), r.deltas.len);
    try testing.expect(r.stop_reason != .end);
    try testing.expectEqualStrings("good-1", r.deltas[0].env.op_bytes);
}

test "snapshot + truncate + recover reconstructs state plus tail" {
    const allocator = testing.allocator;
    const kp = try signed_delta.KeyPair.generateDeterministic(@as([signed_delta.seed_len]u8, @splat(0x33)));

    var j = DeltaJournal.init(allocator);
    defer j.deinit();
    _ = try j.append(try makeSigned(&kp, 10, "a"));
    _ = try j.append(try makeSigned(&kp, 11, "b"));

    // Snapshot the converged state (opaque bytes here) at the current log point.
    const converged = "CRDT-STATE-BLOB";
    var snap = try j.snapshot(converged);
    defer snap.deinit(allocator);
    j.truncateTo(snap.truncate_at);
    try testing.expectEqual(@as(usize, 0), j.logBytes().len); // log compacted

    // More deltas land after the snapshot.
    _ = try j.append(try makeSigned(&kp, 12, "c"));

    var rec = try recover(allocator, snap.blob, j.logBytes());
    defer rec.deinit(allocator);
    try testing.expectEqualStrings(converged, rec.snapshot_state);
    try testing.expectEqual(@as(usize, 1), rec.records.len); // the post-snapshot tail delta
    const tail = try signed_delta.decodeSigned(rec.records[0]);
    try testing.expectEqualStrings("c", tail.env.op_bytes);
}
