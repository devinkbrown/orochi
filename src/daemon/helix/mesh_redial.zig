// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mesh re-dial hints carried across a Helix UPGRADE.
//!
//! S2S peer sockets are deliberately NOT preserved across the execve: the
//! secured Mooring link's post-AKE stream cannot be re-entered mid-connection,
//! so the predecessor lets the socket close at exec (the peer sees the drop
//! instantly) and instead seals one of these hints per initiator-side link.
//! The successor dials every hint as soon as it boots, shrinking the netsplit
//! window to roughly one connect+handshake round-trip.
//!
//! Config-managed `[mesh].connect` dials are NOT encoded here — the successor's
//! mesh boot pass already re-dials those in its first loop iteration; hints
//! cover the links an operator opened by hand (CONNECT <host> <port>).
//!
//! Wire format (version-tagged, integers little-endian):
//!   v2: [u8 ver=2][16 bytes IPv6, network byte order][u16 port, host order]
//!   v1 (legacy, decode-only): [u8 ver=1][4 bytes IPv4][u16 port] — decoded as
//!       the IPv4-mapped IPv6 address ::ffff:a.b.c.d so a successor still honors
//!       hints sealed by a predecessor that predates dual-stack mesh dials.
const std = @import("std");

pub const Error = error{ Truncated, BadVersion, TrailingBytes, InvalidPeer };

const version: u8 = 2;
const legacy_v4_version: u8 = 1;
pub const encoded_len: usize = 1 + 16 + 2;
const legacy_v4_len: usize = 1 + 4 + 2;

/// One peer to re-dial: the 16 address bytes exactly as they sat in the
/// predecessor's `sockaddr.in6` (network byte order) plus the host-order port.
/// IPv4 peers are stored in their IPv4-mapped form (::ffff:a.b.c.d).
pub const Peer = struct {
    addr: [16]u8,
    port: u16,
};

/// Encode one re-dial hint into a fixed-size buffer.
pub fn encode(peer: Peer) [encoded_len]u8 {
    var out: [encoded_len]u8 = undefined;
    out[0] = version;
    @memcpy(out[1..17], &peer.addr);
    std.mem.writeInt(u16, out[17..19], peer.port, .little);
    return out;
}

/// Decode one re-dial hint. Accepts both the v2 IPv6 format and the legacy v1
/// IPv4 format (returned as an IPv4-mapped address).
pub fn decode(bytes: []const u8) Error!Peer {
    if (bytes.len < 1) return error.Truncated;
    switch (bytes[0]) {
        version => {
            if (bytes.len < encoded_len) return error.Truncated;
            var peer = Peer{ .addr = undefined, .port = std.mem.readInt(u16, bytes[17..19], .little) };
            @memcpy(&peer.addr, bytes[1..17]);
            return peer;
        },
        legacy_v4_version => {
            if (bytes.len < legacy_v4_len) return error.Truncated;
            var peer = Peer{ .addr = @as([16]u8, @splat(0)), .port = std.mem.readInt(u16, bytes[5..7], .little) };
            peer.addr[10] = 0xff;
            peer.addr[11] = 0xff;
            @memcpy(peer.addr[12..16], bytes[1..5]);
            return peer;
        },
        else => return error.BadVersion,
    }
}

/// True only for the current v2 discriminator. Used by the exact handoff
/// relation validator to distinguish a redial row from the magic-prefixed
/// process-global mesh checkpoints that share the outer capsule family.
pub fn isCurrent(bytes: []const u8) bool {
    return bytes.len != 0 and bytes[0] == version;
}

/// Decode the exact current representation. A zero port cannot be dialed and
/// any trailing byte would make the row noncanonical under the handoff digest.
pub fn decodeCurrent(bytes: []const u8) Error!Peer {
    if (bytes.len < encoded_len) return error.Truncated;
    if (bytes.len > encoded_len) return error.TrailingBytes;
    if (!isCurrent(bytes)) return error.BadVersion;
    const peer = try decode(bytes);
    if (peer.port == 0) return error.InvalidPeer;
    return peer;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "redial hint round-trips IPv6 address and port" {
    const peer = Peer{ .addr = .{ 0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 6697 };
    const bytes = encode(peer);
    const got = try decode(&bytes);
    try testing.expectEqualSlices(u8, &peer.addr, &got.addr);
    try testing.expectEqual(@as(u16, 6697), got.port);
}

test "decodes a legacy v1 IPv4 hint as an IPv4-mapped address" {
    // [ver=1][127,0,0,1][port=6697 LE]
    const legacy = [_]u8{ 1, 127, 0, 0, 1, 0x29, 0x1a };
    const got = try decode(&legacy);
    const want = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
    try testing.expectEqualSlices(u8, &want, &got.addr);
    try testing.expectEqual(@as(u16, 6697), got.port);
}

test "decode rejects short buffers and unknown versions" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 2, 127, 0 }));
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 127, 0 }));
    var bad = encode(.{ .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1 }, .port = 1 });
    bad[0] = 0xFF;
    try testing.expectError(error.BadVersion, decode(&bad));
}

test "current redial decode rejects legacy zero-port and trailing rows" {
    const peer = Peer{ .addr = @splat(0x11), .port = 6697 };
    const bytes = encode(peer);
    try testing.expectEqual(peer, try decodeCurrent(&bytes));

    var zero_port = bytes;
    @memset(zero_port[17..19], 0);
    try testing.expectError(error.InvalidPeer, decodeCurrent(&zero_port));
    const legacy = [_]u8{ 1, 127, 0, 0, 1, 0x29, 0x1a };
    try testing.expectError(error.Truncated, decodeCurrent(&legacy));
    var trailing: [encoded_len + 1]u8 = undefined;
    @memcpy(trailing[0..encoded_len], &bytes);
    trailing[encoded_len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCurrent(&trailing));
}
