// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic cross-node NICK collision resolution for the live mesh path.
//!
//! The network-wide NICK claim CRDT (`nick_claim.zig` / `state.zig`) keys claims
//! by UID and tiebreaks `(HLC, node)` so every replica converges on the same
//! winner without delivery-order sensitivity, renaming losers to their own UID
//! rather than killing them. The LIVE wire path (`membership_event` /
//! `nick_event`), however, is nick-keyed and carries no UID — only the claimant's
//! `(node_id, hlc)`. This module factors out the SAME deterministic tiebreak so
//! the route table (the per-link remote-nick mirror) resolves collisions exactly
//! the way the CRDT would, and derives the stable fallback UID a loser is renamed
//! to so it is collision-free and reproducible on every node.
//!
//! Resolution policy (identical ordering to `state.nickClaimWins`, minus the
//! authority/UID terms the wire path does not carry):
//!   * higher `hlc` wins;
//!   * on an `hlc` tie, the higher `node_id` wins;
//!   * a claim from the SAME node is never a self-collision (a node renaming its
//!     own user is an ordinary NICK change, not a contest).
//! The loser is renamed to its stable mesh UID; we NEVER signal a kill.
const std = @import("std");

const uid_alloc = @import("uid_alloc.zig");

pub const NodeId = u64;
pub const Uid = uid_alloc.Uid;

/// One side of a nick contest: the claimant's owning node and the logical clock
/// of its claim. `node_id` 0 is reserved (the route table rejects it upstream),
/// so a zero node never wins a contest here either.
pub const Claim = struct {
    node_id: NodeId,
    hlc: u64,
};

/// Whether `candidate` beats `incumbent` for the same nick. A candidate from the
/// same node as the incumbent is treated as the same owner re-asserting (returns
/// false: keep the incumbent slot, the caller updates it in place), so only a
/// genuinely different node can wrest a nick away.
pub fn candidateWins(candidate: Claim, incumbent: Claim) bool {
    if (candidate.node_id == incumbent.node_id) return false;
    if (candidate.hlc != incumbent.hlc) return candidate.hlc > incumbent.hlc;
    return candidate.node_id > incumbent.node_id;
}

/// Derive the stable fallback nick a collision loser is renamed to. The mesh UID
/// is canonical base-36 over `(node_id<<64 | counter)` (see `uid_alloc`); we use
/// the OWNING node's id and a deterministic per-nick counter so the result is
/// reproducible on every node and never collides with another node's fallback.
/// `node_id` here is the mesh SHORT id (fits the u16 UID node field via low bits;
/// the high bits of a 64-bit short id are masked, matching how short ids are
/// derived). The counter folds the contested nick so two different nicks losing
/// on the same node still get distinct fallbacks.
pub fn loserUid(node_id: NodeId, nick: []const u8) uid_alloc.Uid {
    const node16: u16 = @truncate(node_id);
    const counter = fnv1a64(nick);
    return uid_alloc.generate(node16, counter);
}

fn fnv1a64(bytes: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (bytes) |b| {
        hash ^= b;
        hash *%= 0x100000001b3;
    }
    return hash;
}

const testing = std.testing;

test "candidateWins: higher hlc wins" {
    try testing.expect(candidateWins(.{ .node_id = 1, .hlc = 20 }, .{ .node_id = 2, .hlc = 10 }));
    try testing.expect(!candidateWins(.{ .node_id = 1, .hlc = 5 }, .{ .node_id = 2, .hlc = 10 }));
}

test "candidateWins: hlc tie breaks by higher node id" {
    try testing.expect(candidateWins(.{ .node_id = 9, .hlc = 7 }, .{ .node_id = 3, .hlc = 7 }));
    try testing.expect(!candidateWins(.{ .node_id = 3, .hlc = 7 }, .{ .node_id = 9, .hlc = 7 }));
}

test "candidateWins: same node is never a self-collision" {
    try testing.expect(!candidateWins(.{ .node_id = 5, .hlc = 100 }, .{ .node_id = 5, .hlc = 1 }));
}

test "loserUid: stable, node-scoped, and per-nick distinct" {
    const a = loserUid(0x1234, "alice");
    const b = loserUid(0x1234, "alice");
    try testing.expectEqualSlices(u8, a[0..], b[0..]); // reproducible

    const c = loserUid(0x1234, "bob");
    try testing.expect(!std.mem.eql(u8, a[0..], c[0..])); // per-nick distinct

    const d = loserUid(0x5678, "alice");
    try testing.expect(!std.mem.eql(u8, a[0..], d[0..])); // node-scoped distinct

    // The fallback is a canonical mesh UID (parses + validates).
    try testing.expect(uid_alloc.validate(a[0..]));
    const parts = try uid_alloc.parse(a[0..]);
    try testing.expectEqual(@as(u16, 0x1234), parts.node);
}
