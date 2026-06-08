//! Pure S2S migration target selection and drain batching.
//!
//! This module intentionally has no daemon dependencies. It provides the small
//! deterministic policy surface needed to choose a migration target from peer
//! load data and to plan a bounded batch of local sessions to drain.

const std = @import("std");

/// Current load snapshot for a peer node.
pub const PeerLoad = struct {
    node_id: u64,
    clients: u32,
    capacity: u32,
};

/// Returns the available client slots for `peer`.
///
/// At-capacity and over-capacity peers have zero headroom.
pub fn headroom(peer: PeerLoad) u32 {
    if (peer.capacity <= peer.clients) return 0;
    return peer.capacity - peer.clients;
}

/// Selects the eligible peer with the largest headroom.
///
/// `exclude_node` is skipped, as are peers with no remaining capacity. Ties are
/// resolved by keeping the first peer in the input slice, making the policy
/// stable for already-prioritized peer lists.
pub fn selectTarget(peers: []const PeerLoad, exclude_node: u64) ?u64 {
    var best_node: ?u64 = null;
    var best_headroom: u32 = 0;

    for (peers) |peer| {
        if (peer.node_id == exclude_node) continue;

        const available = headroom(peer);
        if (available == 0) continue;

        if (best_node == null or available > best_headroom) {
            best_node = peer.node_id;
            best_headroom = available;
        }
    }

    return best_node;
}

/// Writes a simple bounded drain plan into `out`.
///
/// The returned count is `min(total_sessions, max_batch, out.len)`, and the
/// written entries are the corresponding session indices starting at zero.
pub fn drainBatch(total_sessions: usize, max_batch: usize, out: []usize) usize {
    const count = @min(@min(total_sessions, max_batch), out.len);
    for (out[0..count], 0..) |*slot, index| {
        slot.* = index;
    }
    return count;
}

test "headroom returns available slots and clamps saturated peers" {
    try std.testing.expectEqual(@as(u32, 7), headroom(.{
        .node_id = 1,
        .clients = 3,
        .capacity = 10,
    }));

    try std.testing.expectEqual(@as(u32, 0), headroom(.{
        .node_id = 2,
        .clients = 10,
        .capacity = 10,
    }));

    try std.testing.expectEqual(@as(u32, 0), headroom(.{
        .node_id = 3,
        .clients = 11,
        .capacity = 10,
    }));
}

test "selectTarget picks peer with most headroom" {
    const peers = [_]PeerLoad{
        .{ .node_id = 10, .clients = 8, .capacity = 10 },
        .{ .node_id = 20, .clients = 3, .capacity = 10 },
        .{ .node_id = 30, .clients = 1, .capacity = 5 },
    };

    try std.testing.expectEqual(@as(?u64, 20), selectTarget(&peers, 99));
}

test "selectTarget skips full and over-capacity peers" {
    const peers = [_]PeerLoad{
        .{ .node_id = 10, .clients = 10, .capacity = 10 },
        .{ .node_id = 20, .clients = 12, .capacity = 10 },
        .{ .node_id = 30, .clients = 9, .capacity = 10 },
    };

    try std.testing.expectEqual(@as(?u64, 30), selectTarget(&peers, 99));
}

test "selectTarget excludes self" {
    const peers = [_]PeerLoad{
        .{ .node_id = 10, .clients = 0, .capacity = 100 },
        .{ .node_id = 20, .clients = 9, .capacity = 10 },
    };

    try std.testing.expectEqual(@as(?u64, 20), selectTarget(&peers, 10));
}

test "selectTarget returns null when no eligible peer exists" {
    const empty = [_]PeerLoad{};
    try std.testing.expectEqual(@as(?u64, null), selectTarget(&empty, 1));

    const peers = [_]PeerLoad{
        .{ .node_id = 10, .clients = 0, .capacity = 10 },
        .{ .node_id = 20, .clients = 4, .capacity = 4 },
        .{ .node_id = 30, .clients = 6, .capacity = 5 },
    };

    try std.testing.expectEqual(@as(?u64, null), selectTarget(&peers, 10));
}

test "selectTarget keeps first peer on equal headroom" {
    const peers = [_]PeerLoad{
        .{ .node_id = 10, .clients = 5, .capacity = 10 },
        .{ .node_id = 20, .clients = 15, .capacity = 20 },
    };

    try std.testing.expectEqual(@as(?u64, 10), selectTarget(&peers, 99));
}

test "drainBatch writes sequential indices up to total sessions" {
    var out = [_]usize{ 99, 99, 99, 99, 99 };

    const count = drainBatch(3, 10, &out);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, out[0..count]);
    try std.testing.expectEqual(@as(usize, 99), out[3]);
    try std.testing.expectEqual(@as(usize, 99), out[4]);
}

test "drainBatch caps at max batch" {
    var out = [_]usize{ 99, 99, 99, 99, 99 };

    const count = drainBatch(10, 3, &out);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, out[0..count]);
    try std.testing.expectEqual(@as(usize, 99), out[3]);
}

test "drainBatch caps at output length" {
    var out = [_]usize{ 99, 99 };

    const count = drainBatch(10, 10, &out);

    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1 }, out[0..count]);
}

test "drainBatch handles zero limits without writing" {
    var out = [_]usize{ 99, 99 };

    try std.testing.expectEqual(@as(usize, 0), drainBatch(0, 10, &out));
    try std.testing.expectEqualSlices(usize, &.{ 99, 99 }, &out);

    try std.testing.expectEqual(@as(usize, 0), drainBatch(10, 0, &out));
    try std.testing.expectEqualSlices(usize, &.{ 99, 99 }, &out);

    try std.testing.expectEqual(@as(usize, 0), drainBatch(10, 10, out[0..0]));
    try std.testing.expectEqualSlices(usize, &.{ 99, 99 }, &out);
}
