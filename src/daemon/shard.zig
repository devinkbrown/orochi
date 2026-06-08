//! Sharding foundation for the multi-reactor daemon.
//!
//! The target architecture runs N worker threads, each owning its own io_uring
//! reactor and a disjoint slice of the connection table; a connection is pinned
//! to one shard for its whole lifetime (its `ClientId.shard`). Work that must
//! cross shards — chiefly delivering a channel message to members living on
//! other reactors — is handed off over lock-free MPMC mailboxes rather than by
//! touching another reactor's connection state directly.
//!
//! This module is the pure, thread-agnostic core of that design: deterministic
//! shard assignment + a typed per-shard mailbox set built on the lock-free
//! `substrate/queue.BoundedMpmc`. The live reactor wiring (SO_REUSEPORT
//! listeners, per-shard rings, and a thread-safe world projection) builds on
//! this; see docs/planning/24-multithreading.md. Keeping the primitives here
//! lets them be unit-tested without spinning real threads.

const std = @import("std");
const queue = @import("../substrate/queue.zig");
const client = @import("client.zig");

pub const ClientId = client.ClientId;

/// Hard cap on reactor shards — matches the 12-bit `ClientId.shard` field, and
/// is plenty for current many-core hardware.
pub const max_shards: usize = 4096;

/// Round-robin shard for the Nth accepted connection. Accept order is the only
/// input the accept path has before a slot is allocated, and round-robin keeps
/// the reactors evenly loaded without shared state. `num_shards` must be >= 1.
pub fn assignShard(accept_seq: u64, num_shards: usize) u12 {
    std.debug.assert(num_shards >= 1 and num_shards <= max_shards);
    return @intCast(accept_seq % num_shards);
}

/// The shard a connection is pinned to (its `ClientId.shard`).
pub fn shardOf(id: ClientId) u12 {
    return id.shard;
}

/// Whether `id` belongs to the reactor running `shard`.
pub fn isLocal(id: ClientId, shard: u12) bool {
    return id.shard == shard;
}

/// Stable shard for a channel name (FNV-1a → shard), so a future channel-owning
/// reactor model has a single deterministic home per channel. Independent of
/// connection assignment; used for routing channel-scoped work.
pub fn shardForChannel(name: []const u8, num_shards: usize) u12 {
    std.debug.assert(num_shards >= 1 and num_shards <= max_shards);
    var h: u64 = 0xcbf29ce484222325;
    for (name) |b| {
        h ^= b;
        h *%= 0x100000001b3;
    }
    return @intCast(h % num_shards);
}

/// A fixed set of per-shard lock-free inboxes carrying `Msg` between reactors.
/// `sendTo(shard, msg)` is callable from any thread (MPMC); each reactor drains
/// only its own inbox. `Msg` must be trivially copyable across threads (no
/// borrowed slices into another shard's memory — carry owned/handle types).
pub fn Mailboxes(comptime Msg: type, comptime num_shards: usize, comptime capacity: usize) type {
    comptime std.debug.assert(num_shards >= 1 and num_shards <= max_shards);
    return struct {
        const Self = @This();
        const Inbox = queue.BoundedMpmc(Msg, capacity);

        inboxes: [num_shards]Inbox = blk: {
            var arr: [num_shards]Inbox = undefined;
            for (&arr) |*ib| ib.* = Inbox.init();
            break :blk arr;
        },

        pub fn init() Self {
            return .{};
        }

        /// Enqueue `msg` for the reactor owning `shard`. Returns false if that
        /// inbox is full (caller decides: drop, retry, or back-pressure).
        pub fn sendTo(self: *Self, shard: u12, msg: Msg) bool {
            return self.inboxes[shard].push(msg);
        }

        /// Drain up to `out.len` messages from `shard`'s inbox (called only by
        /// that shard's reactor). Returns the count written to `out`.
        pub fn drain(self: *Self, shard: u12, out: []Msg) usize {
            return self.inboxes[shard].popBatch(out);
        }
    };
}

test "assignShard round-robins across shards" {
    try std.testing.expectEqual(@as(u12, 0), assignShard(0, 4));
    try std.testing.expectEqual(@as(u12, 1), assignShard(1, 4));
    try std.testing.expectEqual(@as(u12, 3), assignShard(3, 4));
    try std.testing.expectEqual(@as(u12, 0), assignShard(4, 4));
    // A single shard always yields 0 (degenerate single-reactor mode).
    try std.testing.expectEqual(@as(u12, 0), assignShard(123, 1));
}

test "shardOf / isLocal reflect the pinned shard" {
    const id = ClientId{ .shard = 2, .slot = 7, .gen = 1 };
    try std.testing.expectEqual(@as(u12, 2), shardOf(id));
    try std.testing.expect(isLocal(id, 2));
    try std.testing.expect(!isLocal(id, 0));
}

test "shardForChannel is deterministic and bounded" {
    const a = shardForChannel("#zig", 8);
    try std.testing.expectEqual(a, shardForChannel("#zig", 8));
    try std.testing.expect(a < 8);
    // Distinct names generally land on distinct homes (not guaranteed, but these do).
    try std.testing.expect(shardForChannel("#a", 8) != shardForChannel("#bbbb", 8));
}

test "Mailboxes route messages to the addressed shard only" {
    const Msg = struct { to: ClientId, tag: u32 };
    var boxes = Mailboxes(Msg, 4, 16).init();

    try std.testing.expect(boxes.sendTo(1, .{ .to = .{ .shard = 1, .slot = 5, .gen = 1 }, .tag = 42 }));
    try std.testing.expect(boxes.sendTo(3, .{ .to = .{ .shard = 3, .slot = 6, .gen = 1 }, .tag = 99 }));

    var out: [8]Msg = undefined;
    // Shard 0 and 2 are empty; 1 and 3 hold one each.
    try std.testing.expectEqual(@as(usize, 0), boxes.drain(0, &out));
    try std.testing.expectEqual(@as(usize, 1), boxes.drain(1, &out));
    try std.testing.expectEqual(@as(u32, 42), out[0].tag);
    try std.testing.expectEqual(@as(usize, 1), boxes.drain(3, &out));
    try std.testing.expectEqual(@as(u32, 99), out[0].tag);
}

test "Mailboxes report back-pressure when an inbox is full" {
    var boxes = Mailboxes(u32, 2, 2).init();
    try std.testing.expect(boxes.sendTo(0, 1));
    try std.testing.expect(boxes.sendTo(0, 2));
    try std.testing.expect(!boxes.sendTo(0, 3)); // capacity 2 reached
    var out: [4]u32 = undefined;
    try std.testing.expectEqual(@as(usize, 2), boxes.drain(0, &out));
}
