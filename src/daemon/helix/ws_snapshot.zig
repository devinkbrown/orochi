// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client WebSocket resume snapshot — carried across a Helix UPGRADE so an
//! ESTABLISHED wss browser client keeps its socket instead
//! of being dropped and forced to reconnect on every hot upgrade.
//!
//! A wss client is layered TLS-then-WebSocket. The TLS crypto state rides its
//! own `.tls_session` capsule (see tls_snapshot.zig); THIS capsule carries the
//! WebSocket-adapter state that pairs with it. `fd` is the join key back to
//! the matching `.clients` session snapshot and `.tls_session`.
//!
//! v1 (historical) carried only `[i32 fd][u8 flags]` and the predecessor sealed
//! it ONLY at a clean framing boundary (handshake open, empty deframer, empty
//! tx accumulator). An active browser client is almost never at that boundary —
//! its deframer usually holds the first bytes of the next inbound frame — so in
//! practice every busy wss client was dropped on every upgrade (the live
//! "browsers reconnect on each deploy" symptom).
//!
//! v2 therefore ALSO serializes the adapter's partial framing state so the
//! successor rebuilds the adapter mid-frame with no lost bytes:
//!   * the deframer's buffered partial inbound frame wire bytes,
//!   * the deframer's cross-frame fragmentation state (fragmented + msg_binary),
//!   * the tx accumulator's partial outbound line.
//! A popped-but-unconsumed deframer event (or latent error) exists only
//! transiently INSIDE one drive turn, never between reactor turns, so it is not
//! serialized — the seal path refuses to carry that (pathological) state.
//!
//! v3 appends the selected WebSocket application protocol and the bounded
//! reassembly state for an in-flight fragmented binary application message.
//! The latter is distinct from the Deframer's wire-byte prefix: it is the
//! already-decoded payload from completed fragments awaiting the final
//! continuation. This is an
//! enforcement boundary: `text.ircv3.net` must remain text-only after Helix,
//! while `onyx.irc-media.v1` admits Cadence binary datagrams. A zero byte is
//! the explicit compatibility state for legacy clients which offered no
//! subprotocol; it preserves their pre-negotiation media behavior.
//!
//! Wire format (all integers little-endian):
//!   v1: [i32 fd][u8 flags]
//!   v2: [i32 fd][u8 flags][u32 dlen][dlen deframer bytes][u32 tlen][tlen tx bytes]
//!   v3: [v2 fields][u8 selected_subprotocol][u8 binary_active]
//!       [u32 binary_len][binary_len binary payload bytes]
//! flags: bit0 = phase_open (required to adopt), bit1 = deframer fragmented,
//! bit2 = in-flight fragmented message is binary. A v1 capsule decodes with
//! empty partial state (it was sealed at a clean boundary by construction).
const std = @import("std");
const websocket = @import("../../proto/websocket.zig");

pub const Error = error{ Truncated, TrailingBytes, InvalidFlags, InvalidSubprotocol, InvalidDeframerState, InvalidBinaryState, InvalidTxState, TooLong, UnsupportedVersion };

/// Must equal the live adapter's Deframer payload ceiling. Keeping it here lets
/// allocation-free current-state validation reject an oversize declared frame
/// exactly as the successor's 4 MiB Deframer would.
pub const max_frame_payload: usize = 4 * 1024 * 1024;
const max_frame_overhead: usize = 14;
/// Exact live WebSocket outbound-line accumulator capacity.
pub const max_tx_bytes: usize = 8192;

/// flags bit0: the carried adapter had completed its HTTP Upgrade (phase=open).
/// A capsule without it is ignored on adopt (a handshake-phase WS is never
/// carried; it reconnects). Reserved higher bits stay zero for forward capsules.
pub const flag_phase_open: u8 = 1 << 0;
/// flags bit1: a fragmented DATA message was open at seal time (a non-FIN
/// text/binary frame was seen; its closing FIN continuation had not arrived).
pub const flag_fragmented: u8 = 1 << 1;
/// flags bit2: the in-flight fragmented DATA message's opcode was binary.
pub const flag_msg_binary: u8 = 1 << 2;

/// A plain view of one carried WebSocket adapter. Decoded slices borrow the
/// input buffer; the caller copies them into the rebuilt adapter immediately.
pub const Snapshot = struct {
    /// The client's socket fd (inherited across execve) — joins this WS snapshot
    /// to its `.clients` session snapshot and `.tls_session` capsule.
    fd: i32 = -1,
    /// The adapter had finished its Upgrade handshake and was framing IRC lines.
    /// Only an open adapter is ever sealed.
    phase_open: bool = true,
    /// Cross-frame fragmentation state (RFC 6455 §5.4) at seal time.
    fragmented: bool = false,
    msg_binary: bool = false,
    /// Buffered wire bytes of the (partial) next inbound frame in the deframer.
    deframer: []const u8 = &.{},
    /// Partial outbound IRC line accumulated in the tx seam (no CRLF seen yet).
    tx: []const u8 = &.{},
    /// Exact application protocol selected in the opening handshake. Null is
    /// the intentional legacy/no-offer compatibility state.
    subprotocol: ?websocket.Subprotocol = null,
    /// Decoded payload accumulated from completed fragments of an in-flight
    /// binary application message. `binary_message_active` distinguishes an
    /// empty opening fragment from no fragmented binary message.
    binary_message_active: bool = false,
    binary_message: []const u8 = &.{},
};

/// Encode `snap` (current version, v3) into a freshly-allocated buffer the
/// caller owns.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    if (snap.deframer.len > std.math.maxInt(u32) or snap.tx.len > std.math.maxInt(u32) or
        snap.binary_message.len > std.math.maxInt(u32))
        return error.TooLong;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var le: [4]u8 = undefined;
    std.mem.writeInt(i32, &le, snap.fd, .little);
    try out.appendSlice(allocator, &le);
    var flags: u8 = 0;
    if (snap.phase_open) flags |= flag_phase_open;
    if (snap.fragmented) flags |= flag_fragmented;
    if (snap.msg_binary) flags |= flag_msg_binary;
    try out.append(allocator, flags);
    inline for (.{ snap.deframer, snap.tx }) |bytes| {
        std.mem.writeInt(u32, &le, @intCast(bytes.len), .little);
        try out.appendSlice(allocator, &le);
        try out.appendSlice(allocator, bytes);
    }
    try out.append(allocator, encodeSubprotocol(snap.subprotocol));
    try out.append(allocator, @intFromBool(snap.binary_message_active));
    std.mem.writeInt(u32, &le, @intCast(snap.binary_message.len), .little);
    try out.appendSlice(allocator, &le);
    try out.appendSlice(allocator, snap.binary_message);
    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot sealed at capsule `version` (the `.ws_session` capsule
/// header version). v1 carries no partial state — it was sealed at a clean
/// framing boundary by construction, so the partials decode empty. Unknown
/// versions fail closed. Returned slices borrow `bytes`.
pub fn decode(bytes: []const u8, version: u16) Error!Snapshot {
    if (bytes.len < 5) return error.Truncated;
    const fd = std.mem.readInt(i32, bytes[0..4], .little);
    const flags = bytes[4];
    if ((flags & ~(flag_phase_open | flag_fragmented | flag_msg_binary)) != 0)
        return error.InvalidFlags;
    var snap = Snapshot{
        .fd = fd,
        .phase_open = (flags & flag_phase_open) != 0,
        .fragmented = (flags & flag_fragmented) != 0,
        .msg_binary = (flags & flag_msg_binary) != 0,
    };
    switch (version) {
        1 => {
            // Clean-boundary seal: no partial state on the wire.
            if (bytes.len != 5) return error.TrailingBytes;
        },
        2, 3 => {
            var p: usize = 5;
            inline for (.{ &snap.deframer, &snap.tx }) |dst| {
                if (bytes.len - p < 4) return error.Truncated;
                const n = std.mem.readInt(u32, bytes[p..][0..4], .little);
                p += 4;
                if (bytes.len - p < n) return error.Truncated;
                dst.* = bytes[p .. p + n];
                p += n;
            }
            if (version == 3) {
                if (p == bytes.len) return error.Truncated;
                snap.subprotocol = try decodeSubprotocol(bytes[p]);
                p += 1;
                if (p == bytes.len) return error.Truncated;
                snap.binary_message_active = switch (bytes[p]) {
                    0 => false,
                    1 => true,
                    else => return error.InvalidBinaryState,
                };
                p += 1;
                if (bytes.len - p < 4) return error.Truncated;
                const n = std.mem.readInt(u32, bytes[p..][0..4], .little);
                p += 4;
                if (bytes.len - p < n) return error.Truncated;
                snap.binary_message = bytes[p .. p + n];
                p += n;
            }
            if (p != bytes.len) return error.TrailingBytes;
        },
        else => return error.UnsupportedVersion,
    }
    return snap;
}

/// Decode the exact current v3 adapter state.
///
/// Current sealing only carries an open WebSocket adapter. The version-aware
/// `decode` remains available for explicit v1/v2 cold-migration fixtures;
/// authoritative current adoption must use this semantic gate.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    const snap = try decode(bytes, 3);
    if (!snap.phase_open) return error.InvalidFlags;
    // The text-only contract never accepts a binary application message, so
    // the Deframer's sticky opcode bit can never become true on that protocol.
    if (snap.subprotocol == .ircv3_text and snap.msg_binary)
        return error.InvalidDeframerState;
    const fragmented_binary = snap.fragmented and snap.msg_binary;
    if (snap.binary_message_active != fragmented_binary or
        (!snap.binary_message_active and snap.binary_message.len != 0) or
        snap.binary_message.len > max_frame_payload)
        return error.InvalidBinaryState;
    if (snap.binary_message_active and snap.subprotocol == .ircv3_text)
        return error.InvalidBinaryState;
    try validatePartialDeframer(snap);
    // wsAppendToConn drains every segment through and including LF before the
    // reactor can seal. A trailing CR remains canonical while its LF arrives in
    // a later append, but any retained LF proves the accumulator was not at an
    // honest between-turn cut.
    const cr = std.mem.indexOfScalar(u8, snap.tx, '\r');
    if (snap.tx.len > max_tx_bytes or std.mem.indexOfScalar(u8, snap.tx, '\n') != null or
        (cr != null and cr.? != snap.tx.len - 1))
        return error.InvalidTxState;
    return snap;
}

/// Validate the exact between-turn state of `websocket.Deframer(4 MiB)` without
/// allocating its multi-megabyte scratch buffers. An honest drive loop drains
/// every complete frame and surfaces every fatal parser/fragmentation error, so
/// a non-empty retained buffer must be a strict prefix for which the next
/// Deframer call would return null. Complete, invalid, or oversize first frames
/// are noncanonical current state even when followed by another partial frame.
fn validatePartialDeframer(snap: Snapshot) Error!void {
    const input = snap.deframer;
    if (input.len == 0) return;
    if (input.len > max_frame_payload + max_frame_overhead)
        return error.InvalidDeframerState;
    // decodeFrame returns Truncated before inspecting a lone first byte.
    if (input.len < 2) return;

    const first = input[0];
    const second = input[1];
    if ((first & 0x70) != 0) return error.InvalidDeframerState;
    const fin = (first & 0x80) != 0;
    const opcode = std.enums.fromInt(websocket.Opcode, @as(u4, @truncate(first & 0x0f))) orelse
        return error.InvalidDeframerState;
    const len_tag = second & 0x7f;
    if (opcode.isControl()) {
        if (!fin or len_tag > 125) return error.InvalidDeframerState;
    }
    // All client-to-server frames are masked.
    if ((second & 0x80) == 0) return error.InvalidDeframerState;

    var cursor: usize = 2;
    var payload_len: u64 = len_tag;
    if (len_tag == 126) {
        if (input.len < cursor + 2) return;
        payload_len = std.mem.readInt(u16, input[cursor..][0..2], .big);
        if (payload_len < 126) return error.InvalidDeframerState;
        cursor += 2;
    } else if (len_tag == 127) {
        if (input.len < cursor + 8) return;
        payload_len = std.mem.readInt(u64, input[cursor..][0..8], .big);
        if ((payload_len & (@as(u64, 1) << 63)) != 0 or payload_len <= 0xffff)
            return error.InvalidDeframerState;
        cursor += 8;
    }
    if (payload_len > max_frame_payload) return error.InvalidDeframerState;

    if (input.len < cursor + 4) return; // partial client mask key
    cursor += 4;
    const payload_size: usize = @intCast(payload_len);
    if (input.len >= cursor + payload_size)
        return error.InvalidDeframerState; // complete first frame (or beyond)
}

fn encodeSubprotocol(subprotocol: ?websocket.Subprotocol) u8 {
    const selected = subprotocol orelse return 0;
    return switch (selected) {
        .ircv3_text => 1,
        .onyx_irc_media => 2,
    };
}

fn decodeSubprotocol(byte: u8) Error!?websocket.Subprotocol {
    return switch (byte) {
        0 => null,
        1 => .ircv3_text,
        2 => .onyx_irc_media,
        else => error.InvalidSubprotocol,
    };
}

const testing = std.testing;

test "ws snapshot v3 round-trips fd flags partial state and subprotocol" {
    const allocator = testing.allocator;
    const partial_frame = [_]u8{ 0x81, 0x8a, 1, 2, 3, 4, 'p' }; // masked frame head + 1 byte
    const partial_line = "@time=2026 PRIVMSG #root :hel";
    const binary_prefix = "cadence-prefix";
    const bytes = try encode(allocator, .{
        .fd = 31,
        .phase_open = true,
        .fragmented = true,
        .msg_binary = true,
        .deframer = &partial_frame,
        .tx = partial_line,
        .subprotocol = .onyx_irc_media,
        .binary_message_active = true,
        .binary_message = binary_prefix,
    });
    defer allocator.free(bytes);
    const got = try decode(bytes, 3);
    try testing.expectEqual(@as(i32, 31), got.fd);
    try testing.expect(got.phase_open and got.fragmented and got.msg_binary);
    try testing.expectEqualSlices(u8, &partial_frame, got.deframer);
    try testing.expectEqualStrings(partial_line, got.tx);
    try testing.expectEqual(websocket.Subprotocol.onyx_irc_media, got.subprotocol.?);
    try testing.expect(got.binary_message_active);
    try testing.expectEqualStrings(binary_prefix, got.binary_message);
}

test "ws snapshot v3 with empty partials and legacy protocol round-trips" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 7, .phase_open = true });
    defer allocator.free(bytes);
    const got = try decode(bytes, 3);
    try testing.expectEqual(@as(i32, 7), got.fd);
    try testing.expect(got.phase_open and !got.fragmented and !got.msg_binary);
    try testing.expectEqual(@as(usize, 0), got.deframer.len);
    try testing.expectEqual(@as(usize, 0), got.tx.len);
    try testing.expectEqual(@as(?websocket.Subprotocol, null), got.subprotocol);
}

test "cross-version: a v1 capsule decodes with empty partial state" {
    // A v1 blob is exactly [i32 fd][u8 flags] — sealed only at a clean boundary,
    // so decoding it as v1 must yield an open adapter with NO partial state.
    var v1: [5]u8 = undefined;
    std.mem.writeInt(i32, v1[0..4], 42, .little);
    v1[4] = flag_phase_open;
    const got = try decode(&v1, 1);
    try testing.expectEqual(@as(i32, 42), got.fd);
    try testing.expect(got.phase_open);
    try testing.expect(!got.fragmented and !got.msg_binary);
    try testing.expectEqual(@as(usize, 0), got.deframer.len);
    try testing.expectEqual(@as(usize, 0), got.tx.len);
}

test "ws snapshot carries a not-open marker distinctly" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 7, .phase_open = false });
    defer allocator.free(bytes);
    const got = try decode(bytes, 3);
    try testing.expectEqual(@as(i32, 7), got.fd);
    try testing.expect(!got.phase_open);
}

test "decode rejects truncation and unknown versions" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0, 0 }, 2));
    // v2 prefix without its length-prefixed tails is truncated.
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0, 0, 1 }, 2));
    // Declared deframer length overrunning the buffer is truncated.
    var bad: [13]u8 = @splat(0);
    bad[4] = flag_phase_open;
    std.mem.writeInt(u32, bad[5..9], 100, .little);
    try testing.expectError(error.Truncated, decode(&bad, 2));
    // Unknown future version fails closed.
    try testing.expectError(error.UnsupportedVersion, decode(&[_]u8{ 1, 0, 0, 0, 1 }, 4));
}

test "decode rejects reserved flags and trailing bytes" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 7, .phase_open = true });
    defer allocator.free(bytes);

    const trailing = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try testing.expectError(error.TrailingBytes, decode(trailing, 3));

    const bad_flags = try allocator.dupe(u8, bytes);
    defer allocator.free(bad_flags);
    bad_flags[4] |= 0x80;
    try testing.expectError(error.InvalidFlags, decode(bad_flags, 3));
}

test "ws decodeCurrent requires an open v3 adapter" {
    const allocator = testing.allocator;
    const partial_frame = [_]u8{ 0x81, 0x85, 1, 2, 3, 4, 'x' };
    const bytes = try encode(allocator, .{
        .fd = 17,
        .phase_open = true,
        .fragmented = false,
        .msg_binary = true,
        .deframer = &partial_frame,
        .tx = "line",
        .subprotocol = .onyx_irc_media,
    });
    defer allocator.free(bytes);
    const got = try decodeCurrent(bytes);
    try testing.expect(got.phase_open and !got.fragmented and got.msg_binary);

    const closed = try encode(allocator, .{ .fd = 17, .phase_open = false });
    defer allocator.free(closed);
    try testing.expectError(error.InvalidFlags, decodeCurrent(closed));

    // The deframer intentionally retains the last data frame's opcode after a
    // completed message, so binary=true while fragmented=false is canonical.
    const completed_binary = try encode(allocator, .{
        .fd = 17,
        .phase_open = true,
        .fragmented = false,
        .msg_binary = true,
    });
    defer allocator.free(completed_binary);
    const completed = try decodeCurrent(completed_binary);
    try testing.expect(!completed.fragmented and completed.msg_binary);
}

test "cross-version v2 cold decode defaults to legacy no subprotocol" {
    const allocator = testing.allocator;
    const current = try encode(allocator, .{
        .fd = 22,
        .phase_open = true,
        .deframer = "partial",
        .tx = "line",
        .subprotocol = .ircv3_text,
    });
    defer allocator.free(current);

    // Strip the complete v3 tail: protocol + active + binary length (empty).
    const legacy = current[0 .. current.len - 6];
    const got = try decode(legacy, 2);
    try testing.expectEqual(@as(i32, 22), got.fd);
    try testing.expectEqualStrings("partial", got.deframer);
    try testing.expectEqualStrings("line", got.tx);
    try testing.expectEqual(@as(?websocket.Subprotocol, null), got.subprotocol);
    try testing.expectError(error.Truncated, decodeCurrent(legacy));
}

test "ws snapshot v3 rejects invalid subprotocol discriminator" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 7, .subprotocol = .ircv3_text });
    defer allocator.free(bytes);
    bytes[bytes.len - 6] = 3;
    try testing.expectError(error.InvalidSubprotocol, decode(bytes, 3));
    try testing.expectError(error.InvalidSubprotocol, decodeCurrent(bytes));
}

test "ws decodeCurrent accepts strict partial frames and canonical state relations" {
    const allocator = testing.allocator;
    var text_buf: [128]u8 = undefined;
    const text = try websocket.encodeFrame(64, .{
        .opcode = .text,
        .mask_key = .{ 1, 2, 3, 4 },
    }, "hello", &text_buf);

    // Every strict prefix, including an empty buffer and a lone first byte, is
    // exactly a state in which Deframer.next() returns null.
    for (0..text.len) |end| {
        const bytes = try encode(allocator, .{
            .fd = 30,
            .deframer = text[0..end],
            .subprotocol = .ircv3_text,
        });
        defer allocator.free(bytes);
        _ = try decodeCurrent(bytes);
    }

    // A control frame may be partially buffered while a fragmented text
    // message is open; it does not disturb the message opcode state.
    var ping_buf: [128]u8 = undefined;
    const ping = try websocket.encodeFrame(64, .{
        .opcode = .ping,
        .mask_key = .{ 5, 6, 7, 8 },
    }, "p", &ping_buf);
    const control = try encode(allocator, .{
        .fd = 31,
        .fragmented = true,
        .msg_binary = false,
        .deframer = ping[0 .. ping.len - 1],
        .subprotocol = .ircv3_text,
    });
    defer allocator.free(control);
    _ = try decodeCurrent(control);

    // A continuation prefix with an active text message is canonical.
    var continuation_buf: [128]u8 = undefined;
    const continuation = try websocket.encodeFrame(64, .{
        .opcode = .continuation,
        .mask_key = .{ 9, 10, 11, 12 },
    }, "tail", &continuation_buf);
    const continued = try encode(allocator, .{
        .fd = 32,
        .fragmented = true,
        .msg_binary = false,
        .deframer = continuation[0 .. continuation.len - 1],
        .subprotocol = .onyx_irc_media,
    });
    defer allocator.free(continued);
    _ = try decodeCurrent(continued);

    // Deframer evaluates UnexpectedContinuation/NestedFragmentation only after
    // the frame becomes complete. Their strict partial prefixes are reachable
    // between recv turns and must survive the upgrade for the successor to
    // surface the same eventual error.
    const unexpected_partial = try encode(allocator, .{
        .fd = 34,
        .fragmented = false,
        .deframer = continuation[0 .. continuation.len - 1],
    });
    defer allocator.free(unexpected_partial);
    _ = try decodeCurrent(unexpected_partial);

    const nested_partial = try encode(allocator, .{
        .fd = 35,
        .fragmented = true,
        .msg_binary = false,
        .deframer = text[0 .. text.len - 1],
    });
    defer allocator.free(nested_partial);
    _ = try decodeCurrent(nested_partial);

    // Custom/legacy connections retain sticky binary=true after an accepted
    // complete single-frame datagram. A partial next text frame is independent.
    const sticky = try encode(allocator, .{
        .fd = 33,
        .fragmented = false,
        .msg_binary = true,
        .deframer = text[0 .. text.len - 1],
        .subprotocol = .onyx_irc_media,
    });
    defer allocator.free(sticky);
    _ = try decodeCurrent(sticky);
}

test "ws decodeCurrent rejects complete invalid and impossible deframer state" {
    const allocator = testing.allocator;
    var frame_buf: [128]u8 = undefined;
    const text = try websocket.encodeFrame(64, .{
        .opcode = .text,
        .mask_key = .{ 1, 2, 3, 4 },
    }, "hello", &frame_buf);

    const complete = try encode(allocator, .{ .fd = 40, .deframer = text });
    defer allocator.free(complete);
    try testing.expectError(error.InvalidDeframerState, decodeCurrent(complete));

    var complete_plus: [128]u8 = undefined;
    @memcpy(complete_plus[0..text.len], text);
    complete_plus[text.len] = 0x81;
    const beyond = try encode(allocator, .{ .fd = 41, .deframer = complete_plus[0 .. text.len + 1] });
    defer allocator.free(beyond);
    try testing.expectError(error.InvalidDeframerState, decodeCurrent(beyond));

    const unmasked = [_]u8{ 0x81, 0x05 };
    const invalid = try encode(allocator, .{ .fd = 42, .deframer = &unmasked });
    defer allocator.free(invalid);
    try testing.expectError(error.InvalidDeframerState, decodeCurrent(invalid));

    var oversize = [_]u8{ 0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u64, oversize[2..10], max_frame_payload + 1, .big);
    const too_large = try encode(allocator, .{ .fd = 43, .deframer = &oversize });
    defer allocator.free(too_large);
    try testing.expectError(error.InvalidDeframerState, decodeCurrent(too_large));

    const text_sticky_binary = try encode(allocator, .{
        .fd = 44,
        .msg_binary = true,
        .subprotocol = .ircv3_text,
    });
    defer allocator.free(text_sticky_binary);
    try testing.expectError(error.InvalidDeframerState, decodeCurrent(text_sticky_binary));

    const active_binary = try encode(allocator, .{
        .fd = 45,
        .fragmented = true,
        .msg_binary = true,
        .subprotocol = .onyx_irc_media,
        .binary_message_active = true,
        .binary_message = "opening-fragment",
    });
    defer allocator.free(active_binary);
    const active = try decodeCurrent(active_binary);
    try testing.expect(active.binary_message_active);
    try testing.expectEqualStrings("opening-fragment", active.binary_message);

    // An empty opening fragment is still an active binary message.
    const empty_active = try encode(allocator, .{
        .fd = 46,
        .fragmented = true,
        .msg_binary = true,
        .subprotocol = .onyx_irc_media,
        .binary_message_active = true,
    });
    defer allocator.free(empty_active);
    _ = try decodeCurrent(empty_active);

    const missing_accumulator = try encode(allocator, .{
        .fd = 47,
        .fragmented = true,
        .msg_binary = true,
        .subprotocol = .onyx_irc_media,
    });
    defer allocator.free(missing_accumulator);
    try testing.expectError(error.InvalidBinaryState, decodeCurrent(missing_accumulator));

    const stray_accumulator = try encode(allocator, .{
        .fd = 48,
        .subprotocol = .onyx_irc_media,
        .binary_message = "stray",
    });
    defer allocator.free(stray_accumulator);
    try testing.expectError(error.InvalidBinaryState, decodeCurrent(stray_accumulator));

    const text_accumulator = try encode(allocator, .{
        .fd = 49,
        .fragmented = true,
        .msg_binary = true,
        .subprotocol = .ircv3_text,
        .binary_message_active = true,
    });
    defer allocator.free(text_accumulator);
    try testing.expectError(error.InvalidDeframerState, decodeCurrent(text_accumulator));

    const oversized_binary = try allocator.alloc(u8, max_frame_payload + 1);
    defer allocator.free(oversized_binary);
    @memset(oversized_binary, 0xa5);
    const oversized_accumulator = try encode(allocator, .{
        .fd = 54,
        .fragmented = true,
        .msg_binary = true,
        .subprotocol = .onyx_irc_media,
        .binary_message_active = true,
        .binary_message = oversized_binary,
    });
    defer allocator.free(oversized_accumulator);
    try testing.expectError(error.InvalidBinaryState, decodeCurrent(oversized_accumulator));
}

test "ws decodeCurrent rejects drained LF in tx while preserving trailing CR" {
    const allocator = testing.allocator;

    const trailing_cr = try encode(allocator, .{
        .fd = 50,
        .tx = "PING :split\r",
        .subprotocol = .ircv3_text,
    });
    defer allocator.free(trailing_cr);
    const canonical = try decodeCurrent(trailing_cr);
    try testing.expectEqualStrings("PING :split\r", canonical.tx);

    const drained_lf = try encode(allocator, .{
        .fd = 51,
        .tx = "PING :one\r\nPRIVMSG #root :retained",
        .subprotocol = .ircv3_text,
    });
    defer allocator.free(drained_lf);
    try testing.expectError(error.InvalidTxState, decodeCurrent(drained_lf));

    const internal_cr = try encode(allocator, .{
        .fd = 53,
        .tx = "PING :one\rPRIVMSG #root :retained",
        .subprotocol = .ircv3_text,
    });
    defer allocator.free(internal_cr);
    try testing.expectError(error.InvalidTxState, decodeCurrent(internal_cr));

    const oversized_tx = try allocator.alloc(u8, max_tx_bytes + 1);
    defer allocator.free(oversized_tx);
    @memset(oversized_tx, 'x');
    const oversized = try encode(allocator, .{
        .fd = 52,
        .tx = oversized_tx,
        .subprotocol = .onyx_irc_media,
    });
    defer allocator.free(oversized);
    try testing.expectError(error.InvalidTxState, decodeCurrent(oversized));
}

test "ws decodeCurrent rejects every prefix and is allocation-free" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 17, .phase_open = true });
    defer allocator.free(bytes);
    for (0..bytes.len) |end| {
        try testing.expectError(error.Truncated, decodeCurrent(bytes[0..end]));
    }

    const fn_info = @typeInfo(@TypeOf(decodeCurrent)).@"fn";
    comptime {
        const return_type = fn_info.return_type orelse @compileError("decodeCurrent must return a value");
        const decode_errors = @typeInfo(return_type).error_union.error_set;
        for (@typeInfo(decode_errors).error_set.error_names.?) |name| {
            if (std.mem.eql(u8, name, "OutOfMemory"))
                @compileError("decodeCurrent must remain allocation-free");
        }
    }
    _ = try decodeCurrent(bytes);
}
