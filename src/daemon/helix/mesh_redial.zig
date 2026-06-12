//! Mesh re-dial hints carried across a Helix UPGRADE.
//!
//! S2S peer sockets are deliberately NOT preserved across the execve: the
//! secured Tsumugi link's post-AKE stream cannot be re-entered mid-connection,
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
//!   [u8 ver=1][4 bytes IPv4, network byte order][u16 port, host order]
const std = @import("std");

pub const Error = error{ Truncated, BadVersion };

const version: u8 = 1;
pub const encoded_len: usize = 1 + 4 + 2;

/// One peer to re-dial: the IPv4 address bytes exactly as they sat in the
/// predecessor's `sockaddr.in` (network byte order) plus the host-order port.
pub const Peer = struct {
    addr4: [4]u8,
    port: u16,
};

/// Encode one re-dial hint into a fixed-size buffer.
pub fn encode(peer: Peer) [encoded_len]u8 {
    var out: [encoded_len]u8 = undefined;
    out[0] = version;
    @memcpy(out[1..5], &peer.addr4);
    std.mem.writeInt(u16, out[5..7], peer.port, .little);
    return out;
}

/// Decode one re-dial hint.
pub fn decode(bytes: []const u8) Error!Peer {
    if (bytes.len < encoded_len) return error.Truncated;
    if (bytes[0] != version) return error.BadVersion;
    var peer = Peer{ .addr4 = undefined, .port = std.mem.readInt(u16, bytes[5..7], .little) };
    @memcpy(&peer.addr4, bytes[1..5]);
    return peer;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "redial hint round-trips address and port" {
    const peer = Peer{ .addr4 = .{ 127, 0, 0, 1 }, .port = 6697 };
    const bytes = encode(peer);
    const got = try decode(&bytes);
    try testing.expectEqualSlices(u8, &peer.addr4, &got.addr4);
    try testing.expectEqual(@as(u16, 6697), got.port);
}

test "decode rejects short buffers and unknown versions" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 127, 0 }));
    var bad = encode(.{ .addr4 = .{ 10, 0, 0, 1 }, .port = 1 });
    bad[0] = 0xFF;
    try testing.expectError(error.BadVersion, decode(&bad));
}
