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
//!                        (schema v1 blobs are 4 bytes shorter here — they predate
//!                         the trailing `admitted_frame_families`; see `decode`)
//!   [u64 send_counter][u64 recv_counter][u64 feed_seq]
//!   inner peer_link header:
//!     [u64 local_epoch][u64 remote_epoch][u32 send_credit][u32 pending_credit]
//!     [u64 next_out_seq][u64 next_in_seq][u64 last_acked]
//!   inner identity/caps:
//!     [u64 remote_node_id][u64 remote_epoch_ms][u8 caps][u8 caps_ext]
//!                                                        (caps bit0 signing, bit1
//!                                                          account, bit2 oper_info,
//!                                                          bit3 repair_frames,
//!                                                          bit4 session_replica_v2,
//!                                                          bit5 secure_relay_v2,
//!                                                          bit6 attachment_lease_v2,
//!                                                          bit7 event_spine_v2;
//!                                                         caps_ext bit0 relay-v2.1
//!                                                                  bit1 ACK confirm
//!                                                         schema + ACK support)
//!   [u16 len][remote_name]
//!   [u16 len][connect_addr] raw sockaddr.in6 of the dial target (initiator only)
//!   [u32 len][rec_inbuf]    partial inbound record buffered at export
//!   [u32 len][pending_out]  sealed records queued but not yet on the wire
const std = @import("std");

const hs = @import("../../crypto/tsumugi_handshake.zig");
const s2s_frame = @import("../../proto/s2s_frame.zig");

pub const Error = error{
    Truncated,
    TooLong,
    UnsupportedVersion,
    InvalidRole,
    InvalidBoolean,
    UnknownCaps,
    TrailingBytes,
};

pub const est_len = hs.Established.serialized_len;

/// Current `.s2s_link` capsule schema version whose blob layout `encode` writes.
/// The blob carries no inline version — it rides the capsule header — so this
/// MIRRORS the descriptor in `capsule.zig`; bump both together.
pub const schema_version: u16 = 3;

/// Length of the embedded `Established` blob in schema v1 capsules. v2 appended a
/// trailing `admitted_frame_families` (u32) to `Established.serialize`, so a v1
/// blob is exactly a v2 blob minus its last 4 bytes; legacy decode reconstructs
/// `admitted_frame_families = 0` (the correct legacy/open default).
pub const est_len_v1 = est_len - @sizeOf(u32);

pub const cap_signing: u8 = s2s_frame.cap_frame_signing;
pub const cap_account: u8 = s2s_frame.cap_member_account;
pub const cap_oper_info: u8 = s2s_frame.cap_member_oper_info;
pub const cap_repair: u8 = s2s_frame.cap_repair_frames;
pub const cap_session_replica_v2: u8 = s2s_frame.cap_session_replica_v2;
pub const cap_secure_relay_v2: u8 = s2s_frame.cap_secure_relay_v2;
pub const cap_session_attachment_lease_v2: u8 = s2s_frame.cap_session_attachment_lease_v2;
pub const cap_event_spine_v2: u8 = s2s_frame.cap_event_spine_v2;
pub const cap_ext_relay_v2_current: u8 = 1 << 0;
pub const cap_ext_relay_v2_ack_confirm: u8 = 1 << 1;

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
    caps_ext: u8 = 0,
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
    try out.append(allocator, snap.caps_ext);

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

/// Decode a snapshot; byte-slice fields borrow `bytes`. `version` is the sealing
/// capsule's schema version (`capsule.Header.version`). A v1 blob predates the
/// trailing `admitted_frame_families` in the embedded `Established` region, so it
/// is 4 bytes shorter there and decodes with `admitted_frame_families = 0`;
/// because the field is appended at the END of `Established.serialize`, a v1 blob
/// is byte-for-byte a v2 blob minus that trailing u32, so every FOLLOWING field
/// still lands at its correct offset. Any version other than 1 or the current
/// schema version is rejected fail-closed (a too-new blob may have grown the
/// `Established` region again and cannot be parsed here).
pub fn decode(bytes: []const u8, version: u16) Error!Snapshot {
    // Every supported predecessor layout is still an authority-bearing Helix
    // image. Version tolerance must not imply tolerance for non-boolean flags,
    // reserved roles, or trailing bytes.
    return decodeInternal(bytes, version, true);
}

/// Decode exactly the current schema emitted by `encode`. Current-generation
/// whole handoffs must not accept reserved roles/capabilities, non-boolean
/// flags, legacy layouts, or bytes after the final bounded field.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    return decodeInternal(bytes, schema_version, true);
}

fn decodeInternal(bytes: []const u8, version: u16, strict_current: bool) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    var snap = Snapshot{};
    snap.fd = try r.int(i32);
    snap.role = try r.byte();
    if (strict_current and snap.role > 1) return error.InvalidRole;
    const initiator = try r.byte();
    if (strict_current and initiator > 1) return error.InvalidBoolean;
    snap.s2s_initiator = initiator != 0;
    switch (version) {
        1 => {
            @memcpy(snap.established[0..est_len_v1], try r.take(est_len_v1));
            @memset(snap.established[est_len_v1..], 0); // admitted_frame_families = 0
        },
        2, schema_version => @memcpy(&snap.established, try r.take(est_len)),
        // Fail-closed: only v1 and the current schema are parseable here. MAINTENANCE
        // TRAP — each future schema bump that keeps `min_supported = 1` in the capsule
        // descriptor MUST add an explicit legacy arm above for EVERY still-accepted
        // version (not just the newest), or that version's links silently drop across
        // the upgrade (the exact field-shift bug this switch was introduced to fix).
        else => return error.UnsupportedVersion,
    }
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
    if (version >= 3) snap.caps_ext = try r.byte();
    const known_caps = cap_signing | cap_account | cap_oper_info | cap_repair |
        cap_session_replica_v2 | cap_secure_relay_v2 |
        cap_session_attachment_lease_v2 | cap_event_spine_v2;
    if (strict_current and snap.caps & ~known_caps != 0) return error.UnknownCaps;
    if (strict_current and snap.caps_ext &
        ~(cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm) != 0)
        return error.UnknownCaps;
    if (strict_current and snap.caps_ext & cap_ext_relay_v2_ack_confirm != 0 and
        snap.caps_ext & cap_ext_relay_v2_current == 0) return error.UnknownCaps;
    if (strict_current and snap.caps_ext & cap_ext_relay_v2_current != 0 and
        (snap.caps & (cap_signing | cap_secure_relay_v2)) !=
            (cap_signing | cap_secure_relay_v2)) return error.UnknownCaps;

    snap.remote_name = try r.take(try r.int(u16));
    snap.connect_addr = try r.take(try r.int(u16));
    snap.rec_inbuf = try r.take(try r.int(u32));
    snap.pending_out = try r.take(try r.int(u32));
    if (strict_current and r.pos != bytes.len) return error.TrailingBytes;
    return snap;
}

/// Best-effort recovery of the inherited socket fd from a snapshot blob whose
/// full `decode` failed. The fd is always the fixed leading little-endian i32, so
/// the adoption path can still `close()` it — a decode failure then drops the link
/// cleanly instead of leaking the fd (the fd lives ONLY inside this blob). Returns
/// null if the blob is too short to hold the fd.
pub fn peekFd(bytes: []const u8) ?i32 {
    if (bytes.len < @sizeOf(i32)) return null;
    return std.mem.readInt(i32, bytes[0..@sizeOf(i32)], .little);
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
        .caps = cap_signing | cap_oper_info | cap_repair | cap_session_replica_v2 | cap_secure_relay_v2 | cap_session_attachment_lease_v2 | cap_event_spine_v2,
        .caps_ext = cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm,
        .remote_name = "ircx.us",
        .connect_addr = &@as([28]u8, @splat('\x0a')),
        .rec_inbuf = "\x04\x00\x00\x00partial",
        .pending_out = "sealed-record-bytes",
    };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i * 3 + 1);

    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    const got = try decode(bytes, schema_version);
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
    try testing.expectEqual(cap_signing | cap_oper_info | cap_repair | cap_session_replica_v2 | cap_secure_relay_v2 | cap_session_attachment_lease_v2 | cap_event_spine_v2, got.caps);
    try testing.expectEqual(cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm, got.caps_ext);
    try testing.expectEqualStrings("ircx.us", got.remote_name);
    try testing.expectEqualStrings(&@as([28]u8, @splat('\x0a')), got.connect_addr);
    try testing.expectEqualStrings("\x04\x00\x00\x00partial", got.rec_inbuf);
    try testing.expectEqualStrings("sealed-record-bytes", got.pending_out);
}

test "s2s link snapshot decode rejects truncation" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0 }, schema_version));
}

test "current s2s decode rejects noncanonical flags capabilities legacy and trailing bytes" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 41, .remote_node_id = 9 });
    defer allocator.free(bytes);
    _ = try decodeCurrent(bytes);

    const bad_role = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_role);
    bad_role[4] = 2;
    try testing.expectError(error.InvalidRole, decodeCurrent(bad_role));
    const bad_bool = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_bool);
    bad_bool[5] = 2;
    try testing.expectError(error.InvalidBoolean, decodeCurrent(bad_bool));

    const trailing = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(trailing));
    try testing.expectError(error.Truncated, decodeCurrent(bytes[0 .. bytes.len - 1]));
}

/// Byte offset of the embedded `Established` region: `fd`(i32) + `role`(u8) +
/// `s2s_initiator`(u8). The trailing `admitted_frame_families`(u32) that v2 added
/// lives at the END of that region.
const est_field_off: usize = @sizeOf(i32) + 1 + 1;
const caps_ext_field_off_v2: usize = est_field_off + est_len +
    8 + 8 + 8 +
    8 + 8 + 4 + 4 + 8 + 8 + 8 +
    8 + 8 + 1;

test "current s2s decode rejects inconsistent relay-v2 capability combinations" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{
        .fd = 41,
        .remote_node_id = 9,
        .caps = cap_signing | cap_secure_relay_v2,
        .caps_ext = cap_ext_relay_v2_current | cap_ext_relay_v2_ack_confirm,
    });
    defer allocator.free(bytes);
    _ = try decodeCurrent(bytes);

    const confirm_without_current = try allocator.dupe(u8, bytes);
    defer allocator.free(confirm_without_current);
    confirm_without_current[caps_ext_field_off_v2] = cap_ext_relay_v2_ack_confirm;
    try testing.expectError(error.UnknownCaps, decodeCurrent(confirm_without_current));

    const current_without_secure_relay = try allocator.dupe(u8, bytes);
    defer allocator.free(current_without_secure_relay);
    current_without_secure_relay[caps_ext_field_off_v2 - 1] = cap_signing;
    try testing.expectError(error.UnknownCaps, decodeCurrent(current_without_secure_relay));

    const current_without_signing = try allocator.dupe(u8, bytes);
    defer allocator.free(current_without_signing);
    current_without_signing[caps_ext_field_off_v2 - 1] = cap_secure_relay_v2;
    try testing.expectError(error.UnknownCaps, decodeCurrent(current_without_signing));
}

test "s2s link snapshot v2 round-trip preserves admitted_frame_families" {
    const allocator = testing.allocator;
    var snap = Snapshot{
        .fd = 7,
        .send_counter = 900,
        .recv_counter = 800,
        .caps = cap_signing,
        .remote_name = "peer.example",
        .rec_inbuf = "inbuf",
        .pending_out = "pending",
    };
    // Fill the Established blob with a recognizable pattern and stamp a NON-ZERO
    // admitted_frame_families into its trailing u32 (the v2-only field).
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i + 5);
    std.mem.writeInt(u32, snap.established[est_len - 4 ..][0..4], 0x1122_3344, .little);

    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    var legacy_v2 = try allocator.alloc(u8, bytes.len - 1);
    defer allocator.free(legacy_v2);
    @memcpy(legacy_v2[0..caps_ext_field_off_v2], bytes[0..caps_ext_field_off_v2]);
    @memcpy(legacy_v2[caps_ext_field_off_v2..], bytes[caps_ext_field_off_v2 + 1 ..]);

    const got = try decode(legacy_v2, 2);
    try testing.expectEqualSlices(u8, &snap.established, &got.established);
    try testing.expectEqual(
        @as(u32, 0x1122_3344),
        std.mem.readInt(u32, got.established[est_len - 4 ..][0..4], .little),
    );
    try testing.expectEqual(@as(u64, 900), got.send_counter);
    try testing.expectEqual(@as(u64, 800), got.recv_counter);
    try testing.expectEqualStrings("peer.example", got.remote_name);
    try testing.expectEqualStrings("inbuf", got.rec_inbuf);
    try testing.expectEqualStrings("pending", got.pending_out);
    try testing.expectEqual(@as(u8, 0), got.caps_ext);

    const trailing = try allocator.alloc(u8, legacy_v2.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..legacy_v2.len], legacy_v2);
    trailing[legacy_v2.len] = 0;
    try testing.expectError(error.TrailingBytes, decode(trailing, 2));

    const bad_bool = try allocator.dupe(u8, legacy_v2);
    defer allocator.free(bad_bool);
    bad_bool[5] = 2;
    try testing.expectError(error.InvalidBoolean, decode(bad_bool, 2));
}

test "s2s link snapshot v1 blob decodes with admitted_frame_families=0 and all following fields intact" {
    const allocator = testing.allocator;
    var snap = Snapshot{
        .fd = 33,
        .role = 1,
        .s2s_initiator = true,
        .send_counter = 0xAABBCCDD_00112233,
        .recv_counter = 0x0102030405060708,
        .feed_seq = 4242,
        .pl_local_epoch_ms = 111,
        .pl_remote_epoch_ms = 222,
        .pl_send_credit = 65000,
        .pl_pending_credit = 4096,
        .pl_next_out_seq = 91,
        .pl_next_in_seq = 82,
        .pl_last_acked = 73,
        .remote_node_id = 0xFEEDFACECAFEBEEF,
        .remote_epoch_ms = 3333,
        .caps = cap_signing | cap_account | cap_repair,
        .remote_name = "legacy.peer",
        .connect_addr = &@as([28]u8, @splat('\x0b')),
        .rec_inbuf = "half-record",
        .pending_out = "queued-sealed",
    };
    // Give the Established region a distinct pattern and a non-zero trailing
    // admitted_frame_families so we can prove v1 decode zeroes exactly it.
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
    std.mem.writeInt(u32, snap.established[est_len - 4 ..][0..4], 0x7F00_00FF, .little);

    // Encode at v2, then synthesize the v1 wire format by SPLICING OUT the trailing
    // admitted_frame_families(u32) at the end of the Established region — exactly
    // what a pre-bump binary would have produced.
    const current = try encode(allocator, snap);
    defer allocator.free(current);
    var v2 = try allocator.alloc(u8, current.len - 1);
    defer allocator.free(v2);
    @memcpy(v2[0..caps_ext_field_off_v2], current[0..caps_ext_field_off_v2]);
    @memcpy(v2[caps_ext_field_off_v2..], current[caps_ext_field_off_v2 + 1 ..]);
    const cut_at = est_field_off + est_len - 4;
    var v1: std.ArrayList(u8) = .empty;
    defer v1.deinit(allocator);
    try v1.appendSlice(allocator, v2[0..cut_at]);
    try v1.appendSlice(allocator, v2[cut_at + 4 ..]);
    try testing.expectEqual(v2.len - 4, v1.items.len);

    const got = try decode(v1.items, 1);

    // The Established prefix (everything before admitted_frame_families) survives
    // verbatim; the trailing u32 is reconstructed as the legacy/open default 0.
    try testing.expectEqualSlices(u8, snap.established[0..est_len_v1], got.established[0..est_len_v1]);
    try testing.expectEqual(
        @as(u32, 0),
        std.mem.readInt(u32, got.established[est_len - 4 ..][0..4], .little),
    );

    // Every field FOLLOWING the Established region must land at its correct offset.
    try testing.expectEqual(@as(i32, 33), got.fd);
    try testing.expectEqual(@as(u8, 1), got.role);
    try testing.expect(got.s2s_initiator);
    try testing.expectEqual(@as(u64, 0xAABBCCDD_00112233), got.send_counter);
    try testing.expectEqual(@as(u64, 0x0102030405060708), got.recv_counter);
    try testing.expectEqual(@as(u64, 4242), got.feed_seq);
    try testing.expectEqual(@as(u64, 111), got.pl_local_epoch_ms);
    try testing.expectEqual(@as(u64, 222), got.pl_remote_epoch_ms);
    try testing.expectEqual(@as(u32, 65000), got.pl_send_credit);
    try testing.expectEqual(@as(u32, 4096), got.pl_pending_credit);
    try testing.expectEqual(@as(u64, 91), got.pl_next_out_seq);
    try testing.expectEqual(@as(u64, 82), got.pl_next_in_seq);
    try testing.expectEqual(@as(u64, 73), got.pl_last_acked);
    try testing.expectEqual(@as(u64, 0xFEEDFACECAFEBEEF), got.remote_node_id);
    try testing.expectEqual(@as(u64, 3333), got.remote_epoch_ms);
    try testing.expectEqual(cap_signing | cap_account | cap_repair, got.caps);
    try testing.expectEqualStrings("legacy.peer", got.remote_name);
    try testing.expectEqualStrings(&@as([28]u8, @splat('\x0b')), got.connect_addr);
    try testing.expectEqualStrings("half-record", got.rec_inbuf);
    try testing.expectEqualStrings("queued-sealed", got.pending_out);
}

test "s2s link snapshot decode rejects an unknown too-new version fail-closed" {
    const allocator = testing.allocator;
    var snap = Snapshot{ .fd = 5 };
    for (&snap.established, 0..) |*b, i| b.* = @truncate(i);
    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);
    try testing.expectError(error.UnsupportedVersion, decode(bytes, schema_version + 1));
}

test "peekFd recovers the leading fd even from an otherwise-unparseable blob" {
    // A blob far too short to decode still yields its fd for cleanup.
    var buf: [4]u8 = undefined;
    std.mem.writeInt(i32, &buf, 49, .little);
    try testing.expectEqual(@as(?i32, 49), peekFd(&buf));
    try testing.expectError(error.Truncated, decode(&buf, schema_version));
    // Too short to even hold the fd → null (no bogus close).
    try testing.expectEqual(@as(?i32, null), peekFd(&[_]u8{ 1, 2, 3 }));
}
