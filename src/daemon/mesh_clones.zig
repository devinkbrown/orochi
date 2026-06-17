//! Network-wide clone aggregation, IP-keyed via a salted hash.
//!
//! Each node tracks its LOCAL concurrent-connection count per salted-IP-hash and
//! learns peers' per-hash counts through gossip. The network-wide count for a
//! hash is `local + Σ remote[node]`, maintained incrementally so the hot-path
//! lookup at registration is O(1).
//!
//! Raw client IPs NEVER appear here or on the wire: callers pass a precomputed
//! `u64` produced by `hashIp` (a keyed SipHash over the address bytes using a key
//! derived from the shared mesh secret, so the same IP maps to the same hash on
//! every node). This keeps a true per-IP network clone cap without gossiping
//! addresses. Pure: no clock, no I/O.

const std = @import("std");

/// Hash an address's raw bytes with the mesh-wide `key` (16 bytes). Stable across
/// nodes that share the secret, so a given IP collapses to one hash network-wide.
pub fn hashIp(key: [16]u8, ip_bytes: []const u8) u64 {
    return std.hash.SipHash64(1, 3).toInt(ip_bytes, &key);
}

pub const MeshClones = struct {
    allocator: std.mem.Allocator,
    /// iphash -> this node's live connection count.
    local: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// {node, iphash} -> that peer's last-gossiped count.
    remote: std.AutoHashMapUnmanaged(RemoteKey, u32) = .empty,
    /// iphash -> Σ over peers of `remote`, kept in step with `remote` so
    /// `networkCount` is O(1).
    remote_total: std.AutoHashMapUnmanaged(u64, u32) = .empty,

    pub const RemoteKey = struct { node: u64, hash: u64 };

    pub fn init(allocator: std.mem.Allocator) MeshClones {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MeshClones) void {
        self.local.deinit(self.allocator);
        self.remote.deinit(self.allocator);
        self.remote_total.deinit(self.allocator);
        self.* = undefined;
    }

    /// Record one new local connection for `hash`; returns the new local count.
    pub fn addLocal(self: *MeshClones, hash: u64) std.mem.Allocator.Error!u32 {
        const gop = try self.local.getOrPut(self.allocator, hash);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
        return gop.value_ptr.*;
    }

    /// Release one local connection for `hash`; returns the remaining local count.
    /// A zero count removes the entry. Releasing an untracked hash is a no-op.
    pub fn removeLocal(self: *MeshClones, hash: u64) u32 {
        const e = self.local.getPtr(hash) orelse return 0;
        if (e.* <= 1) {
            _ = self.local.remove(hash);
            return 0;
        }
        e.* -= 1;
        return e.*;
    }

    pub fn localCount(self: *const MeshClones, hash: u64) u32 {
        return self.local.get(hash) orelse 0;
    }

    /// Apply a peer's authoritative count for `(node, hash)`. A `0` count clears
    /// the entry. `remote_total` is updated by the delta so it stays consistent.
    pub fn setRemote(self: *MeshClones, node: u64, hash: u64, count: u32) std.mem.Allocator.Error!void {
        const key = RemoteKey{ .node = node, .hash = hash };
        const old: u32 = self.remote.get(key) orelse 0;
        if (count == old) return;

        if (count == 0) {
            _ = self.remote.remove(key);
        } else {
            try self.remote.put(self.allocator, key, count);
        }
        try self.applyTotalDelta(hash, old, count);
    }

    /// Drop every contribution from `node` (on link-down / SQUIT) so a vanished
    /// peer's connections stop counting toward the network total.
    pub fn dropNode(self: *MeshClones, node: u64) void {
        // Collect this node's keys first (removing during iteration is unsafe),
        // then unwind each from `remote` and `remote_total`.
        var it = self.remote.iterator();
        var batch: [256]RemoteKey = undefined;
        while (true) {
            var n: usize = 0;
            it = self.remote.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.node != node) continue;
                batch[n] = entry.key_ptr.*;
                n += 1;
                if (n == batch.len) break;
            }
            if (n == 0) break;
            for (batch[0..n]) |k| {
                const old = self.remote.get(k) orelse continue;
                _ = self.remote.remove(k);
                self.applyTotalDelta(k.hash, old, 0) catch {};
            }
        }
    }

    /// Network-wide live count for `hash`: this node plus every peer's last
    /// gossiped count. O(1).
    pub fn networkCount(self: *const MeshClones, hash: u64) u32 {
        return (self.local.get(hash) orelse 0) +| (self.remote_total.get(hash) orelse 0);
    }

    /// Iterate this node's local (hash, count) pairs — for an anti-entropy burst
    /// to a freshly linked peer.
    pub fn localIterator(self: *const MeshClones) std.AutoHashMapUnmanaged(u64, u32).Iterator {
        return self.local.iterator();
    }

    /// Adjust `remote_total[hash]` by `new - old` (saturating; a drained entry is
    /// removed). `remote_total` only ever shrinks to what the per-node entries
    /// sum to, so it never underflows in practice; saturation guards regardless.
    fn applyTotalDelta(self: *MeshClones, hash: u64, old: u32, new: u32) std.mem.Allocator.Error!void {
        const gop = try self.remote_total.getOrPut(self.allocator, hash);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        if (new >= old) {
            gop.value_ptr.* +|= (new - old);
        } else {
            gop.value_ptr.* -|= (old - new);
        }
        if (gop.value_ptr.* == 0) _ = self.remote_total.remove(hash);
    }
};

// -- Tests -------------------------------------------------------------------

test "hashIp is stable and IP-distinct under a shared key" {
    const key = [_]u8{0x5a} ** 16;
    const a = hashIp(key, &[_]u8{ 192, 0, 2, 1 });
    const b = hashIp(key, &[_]u8{ 192, 0, 2, 1 });
    const c = hashIp(key, &[_]u8{ 192, 0, 2, 2 });
    try std.testing.expectEqual(a, b); // same IP, same key -> same hash
    try std.testing.expect(a != c); // different IP -> (almost surely) different hash
    // A different key yields a different hash for the same IP (salting works).
    const key2 = [_]u8{0x17} ** 16;
    try std.testing.expect(hashIp(key2, &[_]u8{ 192, 0, 2, 1 }) != a);
}

test "local add/remove counts and removal at zero" {
    var mc = MeshClones.init(std.testing.allocator);
    defer mc.deinit();

    try std.testing.expectEqual(@as(u32, 1), try mc.addLocal(7));
    try std.testing.expectEqual(@as(u32, 2), try mc.addLocal(7));
    try std.testing.expectEqual(@as(u32, 2), mc.localCount(7));
    try std.testing.expectEqual(@as(u32, 1), mc.removeLocal(7));
    try std.testing.expectEqual(@as(u32, 0), mc.removeLocal(7));
    try std.testing.expectEqual(@as(u32, 0), mc.localCount(7));
    try std.testing.expectEqual(@as(u32, 0), mc.removeLocal(7)); // untracked no-op
}

test "networkCount aggregates local plus all peer contributions" {
    var mc = MeshClones.init(std.testing.allocator);
    defer mc.deinit();

    _ = try mc.addLocal(99); // local = 1
    try mc.setRemote(1001, 99, 2); // node 1001 -> 2
    try mc.setRemote(1002, 99, 3); // node 1002 -> 3
    try std.testing.expectEqual(@as(u32, 6), mc.networkCount(99));

    // A peer revising its count down updates the total by the delta.
    try mc.setRemote(1001, 99, 0); // node 1001 leaves this hash
    try std.testing.expectEqual(@as(u32, 4), mc.networkCount(99));
    // An unrelated hash is independent.
    try std.testing.expectEqual(@as(u32, 0), mc.networkCount(12345));
}

test "dropNode removes exactly that node's contributions" {
    var mc = MeshClones.init(std.testing.allocator);
    defer mc.deinit();

    _ = try mc.addLocal(5);
    try mc.setRemote(1, 5, 4);
    try mc.setRemote(2, 5, 1);
    try mc.setRemote(1, 8, 9); // node 1 also contributes to a different hash
    try std.testing.expectEqual(@as(u32, 6), mc.networkCount(5));
    try std.testing.expectEqual(@as(u32, 9), mc.networkCount(8));

    mc.dropNode(1); // node 1 vanishes
    try std.testing.expectEqual(@as(u32, 2), mc.networkCount(5)); // local 1 + node2 1
    try std.testing.expectEqual(@as(u32, 0), mc.networkCount(8)); // only node 1 was here
}
