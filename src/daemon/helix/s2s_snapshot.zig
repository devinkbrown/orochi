// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-mesh-link resume snapshot — the wire format carried across a Helix UPGRADE
//! so an ESTABLISHED secured s2s (mesh) link keeps its encrypted record stream
//! flowing on the successor WITHOUT re-dialing or re-running the AKE. The socket
//! fd survives execve (CLOEXEC cleared); this carries the crypto + framing state
//! that pairs with it so the PEER never sees a drop (no netsplit, no +Y churn).
//!
//! One snapshot is sealed into a `.s2s_link` capsule per carried secured link.
//! `fd` re-attaches the inherited socket. The converged CRDT roster is DELIBERATELY
//! not carried — the successor stands the inner link up established with a fresh
//! empty replica and sends a RESYNC frame; the peer answers with a full state burst
//! (the same one a fresh establishment sends), reconverging within one round-trip.
//!
//! SECURITY: the encoded bytes contain the live Tsumugi directional record keys.
//! They only ever live inside the sealed memfd arena inherited by the successor —
//! never on disk.
//!
//! Wire format (all integers little-endian):
//!   [i32 fd]
//!   [u8 role]            0 = initiator, 1 = responder (outer Tsumugi role)
//!   [u8 s2s_initiator]   1 if THIS node dialed the link (collision resolution)
//!   [N established]      Established.serialized_len bytes: record keys + peer id
//!   [u64 send_counter][u64 recv_counter][u64 feed_seq]
//!   inner peer_link header:
//!     [u64 local_epoch][u64 remote_epoch][u32 send_credit][u32 pending_credit]
//!     [u64 next_out_seq][u64 next_in_seq][u64 last_acked]
//!   inner identity/caps:
//!     [u64 remote_node_id][u64 remote_epoch_ms][u8 caps]  (bit0 signing, bit1
//!                                                          account, bit2 oper_info,
//!                                                          bit3 repair_frames)
//!   [u16 len][remote_name]
//!   [u16 len][connect_addr] raw sockaddr.in6 of the dial target (initiator only)
//!   [u32 len][rec_inbuf]    partial inbound record buffered at export
//!   [u32 len][pending_out]  sealed records queued but not yet on the wire
const std = @import("std");

const hs = @import("../../crypto/tsumugi_handshake.zig");

pub const Error = error{ Truncated, TooLong };

pub const est_len = hs.Established.serialized_len;

pub const cap_signing: u8 = 1 << 0;
pub const cap_account: u8 = 1 << 1;
pub const cap_oper_info: u8 = 1 << 2;
pub const cap_repair: u8 = 1 << 3;

/// A plain view of one carried secured link. `remote_name`/`rec_inbuf`/`pending_out`
/// borrow the source (encode input) or the decoded buffer (decode output); the
/// fixed-size fields are owned copies.
pub const Snapshot = struct {
    fd: i32 = -1,
    role: u8 = 0,
    s2s_initiator: bool = false,
    /// Serialized `hs.Established` (record keys + base nonces + peer identity).
    established: [est_len]u8 = @splat(0),
    send_counter: u64 = 0,
    recv_counter: u64 = 0,
    feed_seq: u64 = 0,

    // Inner peer_link transport header (seq/ack/credit/epoch continuity).
    pl_local_epoch_ms: u64 = 0,
    pl_remote_epoch_ms: u64 = 0,
    pl_send_credit: u32 = 0,
    pl_pending_credit: u32 = 0,
    pl_next_out_seq: u64 = 0,
    pl_next_in_seq: u64 = 0,
    pl_last_acked: u64 = 0,

    // Inner peer identity/caps.
    remote_node_id: u64 = 0,
    remote_epoch_ms: u64 = 0,
    caps: u8 = 0,
    remote_name: []const u8 = &.{},
    /// Raw `posix.sockaddr.in6` bytes of the dial target (initiator links only),
    /// so the successor's `[mesh].connect` sweep recognizes the preserved link and
    /// does NOT dial a duplicate. Empty on responder (accepted) links.
    connect_addr: []const u8 = &.{},

    rec_inbuf: []const u8 = &.{},
    pending_out: []const u8 = &.{},
};

/// Encode `snap` into a freshly-allocated buffer the caller owns. The result
/// contains live record keys — seal it into the arena and never persist it.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    if (snap.remote_name.len > std.math.maxInt(u16)) return error.TooLong;
    if (snap.connect_addr.len > std.math.maxInt(u16)) return error.TooLong;
    if (snap.rec_inbuf.len > std.math.maxInt(u32)) return error.TooLong;
    if (snap.pending_out.len > std.math.maxInt(u32)) return error.TooLong;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendInt(&out, allocator, i32, snap.fd);
    try out.append(allocator, snap.role);
    try out.append(allocator, @intFromBool(snap.s2s_initiator));
    try out.appendSlice(allocator, &snap.established);
    try appendInt(&out, allocator, u64, snap.send_counter);
    try appendInt(&out, allocator, u64, snap.recv_counter);
    try appendInt(&out, allocator, u64, snap.feed_seq);

    try appendInt(&out, allocator, u64, snap.pl_local_epoch_ms);
    try appendInt(&out, allocator, u64, snap.pl_remote_epoch_ms);
    try appendInt(&out, allocator, u32, snap.pl_send_credit);
    try appendInt(&out, allocator, u32, snap.pl_pending_credit);
    try appendInt(&out, allocator, u64, snap.pl_next_out_seq);
    try appendInt(&out, allocator, u64, snap.pl_next_in_seq);
    try appendInt(&out, allocator, u64, snap.pl_last_acked);

    try appendInt(&out, allocator, u64, snap.remote_node_id);
    try appendInt(&out, allocator, u64, snap.remote_epoch_ms);
    try out.append(allocator, snap.caps);

    try appendInt(&out, allocator, u16, @intCast(snap.remote_name.len));
    try out.appendSlice(allocator, snap.remote_name);
    try appendInt(&out, allocator, u16, @intCast(snap.connect_addr.len));
    try out.appendSlice(allocator, snap.connect_addr);
    try appendInt(&out, allocator, u32, @intCast(snap.rec_inbuf.len));
    try out.appendSlice(allocator, snap.rec_inbuf);
    try appendInt(&out, allocator, u32, @intCast(snap.pending_out.len));
    try out.appendSlice(allocator, snap.pending_out);

    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot; byte-slice fields borrow `bytes`.
pub fn decode(bytes: []const u8) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    var snap = Snapshot{};
    snap.fd = try r.int(i32);
    snap.role = try r.byte();
    snap.s2s_initiator = (try r.byte()) != 0;
    @memcpy(&snap.established, try r.take(est_len));
    snap.send_counter = try r.int(u64);
    snap.recv_counter = try r.int(u64);
    snap.feed_seq = try r.int(u64);

    snap.pl_local_epoch_ms = try r.int(u64);
    snap.pl_remote_epoch_ms = try r.int(u64);
    snap.pl_send_credit = try r.int(u32);
    snap.pl_pending_credit = try r.int(u32);
    snap.pl_next_out_seq = try r.int(u64);
    snap.pl_next_in_seq = try r.int(u64);
    snap.pl_last_acked = try r.int(u64);

    snap.remote_node_id = try r.int(u64);
    snap.remote_epoch_ms = try r.int(u64);
    snap.caps = try r.byte();

    snap.remote_name = try r.take(try r.int(u16));
    snap.connect_addr = try r.take(try r.int(u16));
    snap.rec_inbuf = try r.take(try r.int(u32));
    snap.pending_out = try r.take(try r.int(u32));
    return snap;
}

fn appendInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        defer self.pos += 1;
        return self.buf[self.pos];
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        if (self.pos + @sizeOf(T) > self.buf.len) return error.Truncated;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        defer self.pos += n;
        return self.buf[self.pos .. self.pos + n];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "s2s link snapshot round-trips fd, keys, counters, framing header + buffers" {
    const allocator = testing.allocator;
    var snap = Snapshot{
        .fd = 41,
        .role = 1,
        .s2s_initiator = true,
        .send_counter = 12345,
        .recv_counter = 6789,
        .feed_seq = 42,
        .pl_local_epoch_ms = 1000,
        .pl_remote_epoch_ms = 2000,
        .pl_send_credit = 60000,
        .pl_pending_credit = 512,
        .pl_next_out_seq = 88,
        .pl_next_in_seq = 77,
        .pl_last_acked = 66,
        .remote_node_id = 0xDEADBEEFCAFEF00D,
        .remote_epoch_ms = 2000,
        .caps = cap_signing | cap_oper_info | cap_repair,
        .remote_name = "ircx.us",
        .connect_addr = &@as([28]u8, @splat('\x0a')),
        .rec_inbuf = "\x04\x00\x00\x00partial",
        .pending_out = "sealed-record-bytes",
    };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i * 3 + 1);

    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqual(@as(i32, 41), got.fd);
    try testing.expectEqual(@as(u8, 1), got.role);
    try testing.expect(got.s2s_initiator);
    try testing.expectEqualSlices(u8, &snap.established, &got.established);
    try testing.expectEqual(@as(u64, 12345), got.send_counter);
    try testing.expectEqual(@as(u64, 6789), got.recv_counter);
    try testing.expectEqual(@as(u64, 42), got.feed_seq);
    try testing.expectEqual(@as(u64, 1000), got.pl_local_epoch_ms);
    try testing.expectEqual(@as(u32, 60000), got.pl_send_credit);
    try testing.expectEqual(@as(u64, 88), got.pl_next_out_seq);
    try testing.expectEqual(@as(u64, 77), got.pl_next_in_seq);
    try testing.expectEqual(@as(u64, 66), got.pl_last_acked);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFEF00D), got.remote_node_id);
    try testing.expectEqual(cap_signing | cap_oper_info | cap_repair, got.caps);
    try testing.expectEqualStrings("ircx.us", got.remote_name);
    try testing.expectEqualStrings(&@as([28]u8, @splat('\x0a')), got.connect_addr);
    try testing.expectEqualStrings("\x04\x00\x00\x00partial", got.rec_inbuf);
    try testing.expectEqualStrings("sealed-record-bytes", got.pending_out);
}

test "s2s link snapshot decode rejects truncation" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0 }));
}
