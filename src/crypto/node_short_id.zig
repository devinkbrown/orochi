// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity bridge: canonical 20-byte node id  ->  u64 mesh routing handle.
//!
//! Onyx Server's SOLE identity is the 20-byte `BLAKE3-160(Ed25519 public key)` node
//! id (no SID/TS6). The Undertow CRDT/gossip layer (`s2s_peer`, `gossip_round`,
//! `route_table`) keys peers by a compact `u64` for cheap hashing and wire
//! economy. This module derives that u64 *from* the canonical id so the two
//! never disagree:
//!
//!   * The 20-byte id is canonical and authenticated (it comes out of the
//!     Mooring handshake as `peer_node_id`). The u64 is a derived, lossy
//!     *routing handle* — never an identity in its own right, never trusted for
//!     authorization.
//!   * Derivation is a keyed BLAKE3 squeeze (domain-separated), so the handle is
//!     uniformly distributed regardless of key structure and reveals nothing
//!     exploitable about the 20-byte id.
//!   * `0` is reserved by `s2s_peer` as the "unknown peer" sentinel, so a derived
//!     `0` is bumped to `1`. (Astronomically unlikely; handled for totality.)
const std = @import("std");

const Blake3 = std.crypto.hash.Blake3;

pub const NodeId = [20]u8;

/// Domain-separation label so this derivation can never collide with any other
/// use of BLAKE3 over a node id elsewhere in the system.
const domain = "MZ-S2S-SHORTID-v1";

/// Derive the u64 mesh routing handle for a canonical 20-byte node id.
/// Deterministic and stable across processes/architectures (big-endian read).
pub fn shortId(node_id: NodeId) u64 {
    var h = Blake3.init(.{});
    h.update(domain);
    h.update(&node_id);
    var out: [8]u8 = undefined;
    h.final(&out);
    const handle = std.mem.readInt(u64, &out, .big);
    return if (handle == 0) 1 else handle; // avoid the s2s_peer "unknown" sentinel
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "shortId is deterministic for the same node id" {
    const id: NodeId = @splat(0xAB);
    try testing.expectEqual(shortId(id), shortId(id));
}

test "distinct node ids yield distinct handles (no trivial collision)" {
    const a: NodeId = @splat(0x01);
    var b: NodeId = @splat(0x01);
    b[19] = 0x02; // flip one byte
    try testing.expect(shortId(a) != shortId(b));
}

test "handle is never the zero sentinel" {
    // Sweep many ids; none should derive to 0 (and the bump guarantees it even
    // if the hash ever produced one).
    var i: u32 = 0;
    while (i < 2048) : (i += 1) {
        var id: NodeId = @splat(0);
        std.mem.writeInt(u32, id[0..4], i, .little);
        try testing.expect(shortId(id) != 0);
    }
}

test "derivation diffuses: a single-bit input change flips many output bits" {
    const a: NodeId = @splat(0x55);
    var b = a;
    b[0] ^= 0x01;
    const da = shortId(a);
    const db = shortId(b);
    const diff = @popCount(da ^ db);
    // A good hash flips ~32 of 64 bits; require a generous lower bound.
    try testing.expect(diff >= 16);
}
