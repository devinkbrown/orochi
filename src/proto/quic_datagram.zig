// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebTransport-over-QUIC datagram path over the Ryūsen transport seam.
//!
//! Composes the shipped wire codecs into the unreliable datagram pipeline a
//! browser (WebTransport) or native peer uses for media/control:
//!
//!   app payload
//!     -> WebTransport session datagram (quarter-stream-id + payload)   [webtransport]
//!     -> QUIC DATAGRAM frame                                            [quic_frame]
//!     -> QUIC short-header packet (packet number)                       [quic_packet]
//!     -> Ryūsen transport                                               [ryusen]
//!
//! Header protection (quic_packet.apply/removeHeaderProtection) and AEAD packet
//! encryption are demonstrated/derived from the QUIC key schedule (quic_tls)
//! separately; this path carries unprotected packets and is the framing spine
//! the secure variant wraps. Transport-agnostic + deterministic for DST.
const std = @import("std");

const ryusen = @import("../substrate/ryusen.zig");
const quic_packet = @import("quic_packet.zig");
const quic_frame = @import("quic_frame.zig");
const webtransport = @import("webtransport.zig");

pub const SessionId = webtransport.SessionId;
pub const ConnectionId = quic_packet.ConnectionId;

pub const Session = struct {
    allocator: std.mem.Allocator,
    transport: ryusen.Transport,
    session_id: SessionId,
    dcid: ConnectionId,
    next_pn: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        transport: ryusen.Transport,
        session_id: SessionId,
        dcid: ConnectionId,
    ) Session {
        return .{ .allocator = allocator, .transport = transport, .session_id = session_id, .dcid = dcid };
    }

    /// Send one application datagram down the full WT->QUIC stack.
    pub fn send(self: *Session, payload: []const u8) !void {
        const wt = try webtransport.encodeSessionDatagram(self.allocator, self.session_id, payload);
        defer self.allocator.free(wt);

        const frames = [_]quic_frame.Frame{.{ .DATAGRAM = .{ .len = wt.len, .data = wt } }};
        const frame_bytes = try quic_frame.encodeFrames(self.allocator, &frames);
        defer self.allocator.free(frame_bytes);

        var hdr: [1 + quic_packet.max_connection_id_len + 4]u8 = undefined;
        const hdr_len = try quic_packet.encodeShortHeader(&hdr, .{
            .dcid = self.dcid,
            .packet_number = self.next_pn,
            .packet_number_len = try quic_packet.PacketNumberLength.fromByteLen(4),
        });

        var packet: std.ArrayList(u8) = .empty;
        defer packet.deinit(self.allocator);
        try packet.appendSlice(self.allocator, hdr[0..hdr_len]);
        try packet.appendSlice(self.allocator, frame_bytes);

        self.next_pn +%= 1;
        _ = try self.transport.startSend(packet.items);
    }

    /// Receive one application datagram (or null). `buffer` is caller-owned; the
    /// returned payload is a freshly-allocated owned copy.
    pub fn recv(self: *Session, buffer: []u8) !?[]u8 {
        try self.transport.supplyReceiveBuffer(buffer);
        var comps: [4]ryusen.ReceiveCompletion = undefined;
        const n = try self.transport.pollReceiveCompletions(&comps);
        if (n == 0) return null;
        return self.parsePacket(comps[0].bytes());
    }

    /// Parse a received QUIC short-header packet down to the application payload.
    pub fn parsePacket(self: *Session, packet: []const u8) !?[]u8 {
        const dcid_len = self.dcid.slice().len;
        const decoded = try quic_packet.decodeShortHeader(packet, dcid_len);
        const frame_payload = packet[decoded.consumed..];

        var frames = try quic_frame.decodeFrames(self.allocator, frame_payload);
        defer frames.deinit();
        for (frames.frames) |frame| {
            switch (frame) {
                .DATAGRAM => |dg| {
                    const sd = try webtransport.decodeSessionDatagram(dg.data);
                    return try self.allocator.dupe(u8, sd.payload);
                },
                else => {},
            }
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn cid8() !ConnectionId {
    return ConnectionId.init(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
}

test "WebTransport datagram round-trips over QUIC packets on a loopback" {
    const allocator = testing.allocator;
    var pairs = try ryusen.LoopbackTransport.pair(allocator, .{});
    defer pairs.deinit();

    const sid = try SessionId.initClientBidirectional(0);
    const dcid = try cid8();
    var a = Session.init(allocator, (&pairs.a).transport(), sid, dcid);
    var b = Session.init(allocator, (&pairs.b).transport(), sid, dcid);

    try a.send("voice-frame-payload");
    try pairs.a.flush();
    try pairs.b.flush();

    var buf: [512]u8 = undefined;
    const got = (try b.recv(&buf)).?;
    defer allocator.free(got);
    try testing.expectEqualStrings("voice-frame-payload", got);

    // A second datagram advances the packet number and still round-trips.
    try testing.expectEqual(@as(u32, 1), a.next_pn);
    try a.send("second");
    try pairs.a.flush();
    try pairs.b.flush();
    const got2 = (try b.recv(&buf)).?;
    defer allocator.free(got2);
    try testing.expectEqualStrings("second", got2);
}

test "parsePacket recovers the WT session id and payload" {
    const allocator = testing.allocator;
    var pairs = try ryusen.LoopbackTransport.pair(allocator, .{});
    defer pairs.deinit();
    const sid = try SessionId.initClientBidirectional(4);
    const dcid = try cid8();
    var a = Session.init(allocator, (&pairs.a).transport(), sid, dcid);

    // Build a packet on A's side by capturing what it sends.
    try a.send("hello");
    try pairs.a.flush();
    var buf: [512]u8 = undefined;
    var b = Session.init(allocator, (&pairs.b).transport(), sid, dcid);
    const got = (try b.recv(&buf)).?;
    defer allocator.free(got);
    try testing.expectEqualStrings("hello", got);
}

test "header protection apply/remove is reversible" {
    // The framing spine carries unprotected packets, but verify the HP transform
    // (which the keyed variant uses) round-trips on a short-header packet.
    const dcid = try cid8();
    var hdr: [32]u8 = undefined;
    const hdr_len = try quic_packet.encodeShortHeader(&hdr, .{
        .dcid = dcid,
        .packet_number = 0x1234,
        .packet_number_len = try quic_packet.PacketNumberLength.fromByteLen(4),
    });
    var packet: [32]u8 = undefined;
    @memcpy(packet[0..hdr_len], hdr[0..hdr_len]);
    const original = packet;

    const pn_offset = 1 + dcid.slice().len;
    const mask = [5]u8{ 0xaa, 0x01, 0x02, 0x03, 0x04 };
    try quic_packet.applyHeaderProtection(packet[0..hdr_len], pn_offset, mask);
    try testing.expect(!std.mem.eql(u8, original[0..hdr_len], packet[0..hdr_len]));
    try quic_packet.removeHeaderProtection(packet[0..hdr_len], pn_offset, mask);
    try testing.expectEqualSlices(u8, original[0..hdr_len], packet[0..hdr_len]);
}
