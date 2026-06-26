// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Length-prefixed S2S wire frames for Suimyaku mesh links.
//!
//! The frame header is exactly five bytes:
//!   * u8 frame type tag
//!   * u32 little-endian payload length
//! followed by `length` payload bytes.
const std = @import("std");

pub const header_len: usize = 5;
pub const length_len: usize = 4;
pub const default_max_frame_size: usize = 1024 * 1024;

const endian = .little;

pub const EncodeError = error{
    BufferTooSmall,
    PayloadTooLarge,
};

pub const DecodeError = std.mem.Allocator.Error || error{
    MalformedFrame,
    OversizeFrame,
    Truncated,
};

pub const FrameType = enum(u8) {
    HANDSHAKE = 0x01,
    BURST = 0x02,
    DELTA = 0x03,
    GOSSIP = 0x04,
    PING = 0x05,
    PONG = 0x06,
    QUIT = 0x07,
    MEMBERSHIP = 0x08,
    MESSAGE = 0x09,
    /// Signed cross-mesh operator authorization grant (oper_cred_share bytes),
    /// verified against the sending peer's identity on receipt.
    OPER_GRANT = 0x0A,
    CHANNEL_MODE_FLAGS = 0x0B,
    /// Channel list-mode fact (+b/+e/+I), LWW by payload HLC.
    CHANNEL_LIST = 0x0C,
    /// IRCX channel PROP convergence event (channel/key/value/owner LWW by hlc).
    CHANNEL_PROP = 0x0D,
    /// Channel topic-text fact (channel/topic/setter/set_at), LWW by payload HLC.
    TOPIC = 0x0E,
    /// Remote user nick change (old/new nick + identity) for live `NICK` lines.
    NICKCHANGE = 0x0F,
    /// Parameter/IRCX channel state snapshot (+k/+l/+j/+f/private/hidden/ext).
    CHANNEL_MODE_STATE = 0x10,
    /// Live session-migration capsule (migration_relay frame bytes): a signed
    /// snapshot the origin ships to the owning node so a reconnecting client
    /// lands with its nick/umodes/account/away/channels restored.
    SESSION_MIGRATE = 0x11,
    /// IRCX user/member PROP convergence event (entity_kind/entity/key/value/owner
    /// LWW by hlc). The non-channel counterpart of CHANNEL_PROP: channels ride
    /// CHANNEL_PROP, `user`/`member` entities ride ENTITY_PROP.
    ENTITY_PROP = 0x12,
    /// Network-wide clone counts: a batch of (salted-IP-hash, count) pairs this
    /// node currently holds. Raw IPs never appear — only keyed hashes. Decoded by
    /// the `mesh_clones` binary codec and attributed to the authenticated link.
    CLONE_COUNT = 0x13,
    /// Network-wide operator event: a one-shot Event-Spine alert (raid, spamtrap,
    /// oper action, …) raised on `origin_server`, fanned to every node so opers
    /// anywhere see it, rendered with the origin server name. Carries
    /// {origin_server, category, severity, message}; signed like other facts.
    OPER_EVENT = 0x14,
    /// Network-wide operator OBSERVE feed: a one-shot lifecycle record (connect,
    /// quit, nick, oper-up) for a watched subject raised on `origin_server`, fanned
    /// to every node so a standing `EVENT OBSERVE <mask>` matches network-wide.
    /// Carries {action, origin_server, nick, user, host, account, detail}; signed
    /// (the subject's host is the REAL/uncloaked host — an operator-trust surface).
    OBSERVE_EVENT = 0x15,
    /// Targeted cross-mesh operator KILL: the owning node disconnects its local
    /// `target` on behalf of operator `killer` who issued it on `origin_server`.
    /// A one-shot COMMAND (not stored); the killer's node already enforced the
    /// `client_kill` privilege and signs the frame with its Tsumugi identity.
    /// Carries {origin_server, killer, target, reason}.
    KILL = 0x16,
    /// Network-wide `mesh`-scope WARD (network-ban) convergence: an add or remove
    /// of a Warden entry, fanned to every secured peer so an already-running node
    /// enforces (or forgets) the ban live. Carries a `warden` wire record
    /// {op, match, pattern, action, reason, set_by, created_ms, expires_ms};
    /// signed like other oper-trust facts (the setter is operator authority).
    WARD = 0x17,

    pub fn tag(self: FrameType) u8 {
        return @intFromEnum(self);
    }

    pub fn fromTag(tag_value: u8) ?FrameType {
        return switch (tag_value) {
            @intFromEnum(FrameType.HANDSHAKE) => .HANDSHAKE,
            @intFromEnum(FrameType.BURST) => .BURST,
            @intFromEnum(FrameType.DELTA) => .DELTA,
            @intFromEnum(FrameType.GOSSIP) => .GOSSIP,
            @intFromEnum(FrameType.PING) => .PING,
            @intFromEnum(FrameType.PONG) => .PONG,
            @intFromEnum(FrameType.QUIT) => .QUIT,
            @intFromEnum(FrameType.MEMBERSHIP) => .MEMBERSHIP,
            @intFromEnum(FrameType.MESSAGE) => .MESSAGE,
            @intFromEnum(FrameType.OPER_GRANT) => .OPER_GRANT,
            @intFromEnum(FrameType.CHANNEL_MODE_FLAGS) => .CHANNEL_MODE_FLAGS,
            @intFromEnum(FrameType.CHANNEL_LIST) => .CHANNEL_LIST,
            @intFromEnum(FrameType.CHANNEL_PROP) => .CHANNEL_PROP,
            @intFromEnum(FrameType.TOPIC) => .TOPIC,
            @intFromEnum(FrameType.NICKCHANGE) => .NICKCHANGE,
            @intFromEnum(FrameType.CHANNEL_MODE_STATE) => .CHANNEL_MODE_STATE,
            @intFromEnum(FrameType.SESSION_MIGRATE) => .SESSION_MIGRATE,
            @intFromEnum(FrameType.ENTITY_PROP) => .ENTITY_PROP,
            @intFromEnum(FrameType.CLONE_COUNT) => .CLONE_COUNT,
            @intFromEnum(FrameType.OPER_EVENT) => .OPER_EVENT,
            @intFromEnum(FrameType.OBSERVE_EVENT) => .OBSERVE_EVENT,
            @intFromEnum(FrameType.KILL) => .KILL,
            @intFromEnum(FrameType.WARD) => .WARD,
            else => null,
        };
    }
};

pub const Type = FrameType;

pub const Frame = struct {
    frame_type: FrameType,
    payload: []const u8,
};

pub fn encodedLen(payload_len: usize) EncodeError!usize {
    if (payload_len > std.math.maxInt(u32)) return error.PayloadTooLarge;
    return header_len + payload_len;
}

pub fn encode(frame_type: FrameType, payload: []const u8, out: []u8) EncodeError![]const u8 {
    const total = try encodedLen(payload.len);
    if (out.len < total) return error.BufferTooSmall;

    out[0] = frame_type.tag();
    std.mem.writeInt(u32, out[1..][0..length_len], @intCast(payload.len), endian);
    @memcpy(out[header_len..total], payload);
    return out[0..total];
}

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    max_frame_size: usize,
    accumulator: std.ArrayList(u8) = .empty,
    payload_buf: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, max_frame_size: usize) Decoder {
        return .{
            .allocator = allocator,
            .max_frame_size = max_frame_size,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.accumulator.deinit(self.allocator);
        self.payload_buf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn reset(self: *Decoder) void {
        self.accumulator.clearRetainingCapacity();
        self.payload_buf.clearRetainingCapacity();
    }

    pub fn feed(self: *Decoder, bytes: []const u8) DecodeError!void {
        try self.accumulator.appendSlice(self.allocator, bytes);
    }

    pub fn decode(self: *Decoder, bytes: []const u8) DecodeError!?Frame {
        try self.feed(bytes);
        return try self.next();
    }

    /// Returns null until a complete frame is buffered.
    ///
    /// The returned payload is owned by the decoder and remains valid until the
    /// next successful `next`, `decode`, `reset`, or `deinit` call.
    pub fn next(self: *Decoder) DecodeError!?Frame {
        if (self.accumulator.items.len < header_len) return null;

        const frame_type = FrameType.fromTag(self.accumulator.items[0]) orelse {
            return error.MalformedFrame;
        };
        const payload_len_u32 = std.mem.readInt(u32, self.accumulator.items[1..][0..length_len], endian);
        const payload_len: usize = @intCast(payload_len_u32);
        if (payload_len > std.math.maxInt(usize) - header_len) return error.OversizeFrame;

        const total = header_len + payload_len;
        if (total > self.max_frame_size) return error.OversizeFrame;
        if (self.accumulator.items.len < total) return null;

        try self.payload_buf.resize(self.allocator, payload_len);
        @memcpy(self.payload_buf.items, self.accumulator.items[header_len..total]);
        self.discardPrefix(total);

        return .{
            .frame_type = frame_type,
            .payload = self.payload_buf.items,
        };
    }

    /// Call at EOF when no more bytes are expected.
    pub fn finish(self: *Decoder) DecodeError!void {
        if (self.accumulator.items.len != 0) return error.Truncated;
    }

    fn discardPrefix(self: *Decoder, count: usize) void {
        std.debug.assert(count <= self.accumulator.items.len);
        const remaining = self.accumulator.items.len - count;
        if (remaining != 0) {
            std.mem.copyForwards(u8, self.accumulator.items[0..remaining], self.accumulator.items[count..]);
        }
        self.accumulator.shrinkRetainingCapacity(remaining);
    }
};

const testing = std.testing;

const all_frame_types = [_]FrameType{
    .HANDSHAKE,
    .BURST,
    .DELTA,
    .GOSSIP,
    .PING,
    .PONG,
    .QUIT,
    .MEMBERSHIP,
    .MESSAGE,
    .OPER_GRANT,
    .CHANNEL_MODE_FLAGS,
    .CHANNEL_LIST,
    .CHANNEL_PROP,
    .TOPIC,
    .NICKCHANGE,
    .CHANNEL_MODE_STATE,
    .SESSION_MIGRATE,
    .ENTITY_PROP,
    .KILL,
    .WARD,
};

test "encode/decode round-trip each type" {
    const allocator = testing.allocator;

    inline for (all_frame_types) |frame_type| {
        const payload = "suimyaku s2s payload";
        var encoded: [header_len + payload.len]u8 = undefined;
        const bytes = try encode(frame_type, payload, &encoded);

        try testing.expectEqual(frame_type.tag(), bytes[0]);
        try testing.expectEqual(@as(u32, payload.len), std.mem.readInt(u32, bytes[1..][0..length_len], endian));

        var decoder = Decoder.init(allocator, default_max_frame_size);
        defer decoder.deinit();

        try decoder.feed(bytes);
        const frame = (try decoder.next()).?;
        try testing.expectEqual(frame_type, frame.frame_type);
        try testing.expectEqualSlices(u8, payload, frame.payload);
        try testing.expectEqual(@as(?Frame, null), try decoder.next());
        try decoder.finish();
    }
}

test "partial streamed decode reassembles frames" {
    const allocator = testing.allocator;
    const first_payload = "burst-001";
    const second_payload = "delta-002-with-more-bytes";
    var first_buf: [header_len + first_payload.len]u8 = undefined;
    var second_buf: [header_len + second_payload.len]u8 = undefined;
    const first = try encode(.BURST, first_payload, &first_buf);
    const second = try encode(.DELTA, second_payload, &second_buf);

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(first[0..2]);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try decoder.feed(first[2..header_len]);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try decoder.feed(first[header_len..]);

    const frame1 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.BURST, frame1.frame_type);
    try testing.expectEqualSlices(u8, first_payload, frame1.payload);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());

    var pos: usize = 0;
    while (pos < second.len) {
        const end = @min(pos + 3, second.len);
        try decoder.feed(second[pos..end]);
        pos = end;
    }

    const frame2 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.DELTA, frame2.frame_type);
    try testing.expectEqualSlices(u8, second_payload, frame2.payload);
    try decoder.finish();
}

test "multiple complete frames drain in order" {
    const allocator = testing.allocator;
    const ping_payload = "ping";
    const pong_payload = "pong";
    var ping_buf: [header_len + ping_payload.len]u8 = undefined;
    var pong_buf: [header_len + pong_payload.len]u8 = undefined;
    const ping = try encode(.PING, ping_payload, &ping_buf);
    const pong = try encode(.PONG, pong_payload, &pong_buf);

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(ping);
    try decoder.feed(pong);

    const frame1 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.PING, frame1.frame_type);
    try testing.expectEqualSlices(u8, ping_payload, frame1.payload);

    const frame2 = (try decoder.next()).?;
    try testing.expectEqual(FrameType.PONG, frame2.frame_type);
    try testing.expectEqualSlices(u8, pong_payload, frame2.payload);

    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try decoder.finish();
}

test "oversize rejected" {
    const allocator = testing.allocator;
    const payload = "abcd";
    var encoded: [header_len + payload.len]u8 = undefined;
    const bytes = try encode(.GOSSIP, payload, &encoded);

    var decoder = Decoder.init(allocator, header_len + payload.len - 1);
    defer decoder.deinit();

    try decoder.feed(bytes);
    try testing.expectError(error.OversizeFrame, decoder.next());
}

test "truncated handled" {
    const allocator = testing.allocator;

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(&.{@intFromEnum(FrameType.HANDSHAKE)});
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try testing.expectError(error.Truncated, decoder.finish());

    decoder.reset();
    var header: [header_len]u8 = undefined;
    header[0] = @intFromEnum(FrameType.QUIT);
    std.mem.writeInt(u32, header[1..][0..length_len], 3, endian);
    try decoder.feed(&header);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
    try testing.expectError(error.Truncated, decoder.finish());
}

test "malformed type rejected" {
    const allocator = testing.allocator;
    var encoded = [_]u8{ 0xff, 0, 0, 0, 0 };

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(&encoded);
    try testing.expectError(error.MalformedFrame, decoder.next());
}

test "encode rejects undersized output buffer" {
    var short: [header_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encode(.PING, "", &short));
}

test "no leak when accumulator owns partial bytes" {
    const allocator = testing.allocator;
    const payload = "partial";
    var encoded: [header_len + payload.len]u8 = undefined;
    const bytes = try encode(.HANDSHAKE, payload, &encoded);

    var decoder = Decoder.init(allocator, default_max_frame_size);
    defer decoder.deinit();

    try decoder.feed(bytes[0 .. bytes.len - 1]);
    try testing.expectEqual(@as(?Frame, null), try decoder.next());
}
