//! Pure S2S peer driver for one Suimyaku server-to-server connection.
//!
//! The caller owns sockets, timers, and randomness. This driver consumes
//! inbound bytes, streaming-decodes `s2s_frame` frames, dispatches them into the
//! Suimyaku state modules, and writes encoded outbound bytes to a caller sink.
const std = @import("std");

const link_session = @import("link_session.zig");
const burst = @import("burst.zig");
const server_registry = @import("server_registry.zig");
const route_table = @import("route_table.zig");
const channel_crdt = @import("channel_crdt.zig");
const gossip_round = @import("gossip_round.zig");
const anti_entropy_repair = @import("anti_entropy_repair.zig");
const membership_view = @import("membership_view.zig");
const peer_link = @import("peer_link.zig");
const message_relay = @import("message_relay.zig");
const toml = @import("../../proto/toml.zig");

const Allocator = std.mem.Allocator;

pub const ChannelCrdt = channel_crdt.ChannelCrdt;
pub const NodeId = gossip_round.NodeId;
pub const MemberInfo = route_table.Member;
pub const RelayMessage = message_relay.RelayMessage;
pub const InboundMessage = message_relay.Owned;
pub const RelayVerb = message_relay.Verb;

const handshake_magic = [_]u8{ 'S', '2', 'P', 'H' };
const handshake_version: u8 = 1;

const s2s_frame = @import("../../proto/s2s_frame.zig");
const membership_event = @import("../../proto/membership_event.zig");

pub const ByteSink = struct {
    ptr: *anyopaque,
    write_fn: *const fn (*anyopaque, []const u8) anyerror!void,

    pub fn writeAll(self: ByteSink, bytes: []const u8) !void {
        try self.write_fn(self.ptr, bytes);
    }
};

pub const Config = struct {
    max_frame_size: usize = s2s_frame.default_max_frame_size,
    link: link_session.Config = .{
        .gossip_interval_ms = 1_000,
        .repair_interval_ms = 2_000,
        .gossip_config = .{ .fanout = 1 },
    },
    registry: server_registry.Config = .{},
    routes: route_table.Config = .{},

    /// Consolidated applier for the EFFECTIVE production path
    /// (`s2s_peer` → `link_session` → peer-link/gossip/swim/burst). Overlays
    /// every `[mesh.*]` section this driver owns. Missing keys leave fields at
    /// their defaults, so behavior is unchanged until the orchestrator supplies
    /// a parsed config. The aggregate `[mesh.gossip]`/`[mesh.swim]` sections are
    /// applied to the embedded session sub-configs here (link.applyToml only
    /// handles the `[mesh.link]` per-session overrides + transport + burst).
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        // Apply the broad `[mesh.gossip]`/`[mesh.swim]` sections to the embedded
        // session sub-configs first, then the narrower `[mesh.link]` per-session
        // overrides last so an explicit per-session override always wins.
        cfg.link.gossip_config.applyToml(doc);
        cfg.link.swim_config.applyToml(doc);
        cfg.link.view_config.applyToml(doc);
        cfg.link.applyToml(doc);
        cfg.registry.applyToml(doc);
        cfg.routes.applyToml(doc);
    }
};

pub const Options = struct {
    allocator: Allocator,
    state: *ChannelCrdt,
    clock: peer_link.Clock,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    local_epoch_ms: u64,
    server_name: []const u8,
    description: []const u8 = "",
    channel_name: []const u8 = "#suimyaku",
    initial_send_credit: u32 = peer_link.default_send_credit,
    config: Config = .{},
};

const Handshake = struct {
    node_id: NodeId,
    epoch_ms: u64,
    name: []const u8,
    description: []const u8,
};

pub const S2sPeer = struct {
    allocator: Allocator,
    decoder: s2s_frame.Decoder,
    state: *ChannelCrdt,
    session: link_session.LinkSession,
    registry: server_registry.ServerRegistry,
    routes: route_table.RouteTable,
    local_node_id: NodeId,
    remote_node_id: NodeId,
    local_epoch_ms: u64,
    server_name: []u8,
    description: []u8,
    channel_name: []u8,
    remote_epoch_ms: ?u64 = null,
    remote_name: []u8 = &.{},
    handshake_sent: bool = false,
    established: bool = false,
    burst_sent: bool = false,
    ping_rx_count: usize = 0,
    pong_rx_count: usize = 0,
    config: Config,
    /// Inbound cross-node user messages decoded from MESSAGE frames, awaiting the
    /// daemon to drain + deliver to local clients (the daemon owns delivery; the
    /// peer driver stays substrate-pure). Loop-guarded by `seen`.
    inbound: std.ArrayListUnmanaged(message_relay.Owned) = .empty,
    seen: message_relay.SeenSet,

    pub fn init(options: Options) !S2sPeer {
        const server_name = try options.allocator.dupe(u8, options.server_name);
        errdefer options.allocator.free(server_name);
        const description = try options.allocator.dupe(u8, options.description);
        errdefer options.allocator.free(description);
        const channel_name = try options.allocator.dupe(u8, options.channel_name);
        errdefer options.allocator.free(channel_name);

        var registry = try server_registry.ServerRegistry.init(options.allocator, options.config.registry);
        errdefer registry.deinit();
        try registry.add(.{
            .node_id = options.local_node_id,
            .name = server_name,
            .description = description,
            .last_seen_ms = try i64Ms(options.local_epoch_ms),
        });

        var routes = try route_table.RouteTable.init(options.allocator, options.config.routes);
        errdefer routes.deinit();
        try routes.setNickLocation(server_name, options.local_node_id);

        var session = try link_session.LinkSession.init(options.allocator, options.state, .{
            .clock = options.clock,
            .local_epoch_ms = options.local_epoch_ms,
            .local_node_id = options.local_node_id,
            .remote_node_id = options.remote_node_id,
            .initial_send_credit = options.initial_send_credit,
            .config = options.config.link,
        });
        errdefer session.deinit();

        return .{
            .allocator = options.allocator,
            .decoder = s2s_frame.Decoder.init(options.allocator, options.config.max_frame_size),
            .state = options.state,
            .session = session,
            .registry = registry,
            .routes = routes,
            .local_node_id = options.local_node_id,
            .remote_node_id = options.remote_node_id,
            .local_epoch_ms = options.local_epoch_ms,
            .server_name = server_name,
            .description = description,
            .channel_name = channel_name,
            .config = options.config,
            .seen = message_relay.SeenSet.init(options.allocator, 1024),
        };
    }

    pub fn deinit(self: *S2sPeer) void {
        for (self.inbound.items) |*owned| owned.deinit(self.allocator);
        self.inbound.deinit(self.allocator);
        self.seen.deinit();
        self.allocator.free(self.remote_name);
        self.allocator.free(self.channel_name);
        self.allocator.free(self.description);
        self.allocator.free(self.server_name);
        self.session.deinit();
        self.routes.deinit();
        self.registry.deinit();
        self.decoder.deinit();
        self.* = undefined;
    }

    pub fn startHandshake(self: *S2sPeer, sink: ByteSink) !void {
        if (self.handshake_sent) return;
        if (self.session.link.state == .idle) try self.session.link.beginHandshake();
        try self.emitHandshake(sink);
    }

    pub fn feed(self: *S2sPeer, bytes: []const u8, sink: ByteSink, now_ms: u64, rng_seed: u64) !void {
        try self.decoder.feed(bytes);
        while (try self.decoder.next()) |frame| {
            try self.dispatch(frame, sink, now_ms, rng_seed);
        }
    }

    pub fn finish(self: *S2sPeer) !void {
        try self.decoder.finish();
    }

    pub fn sendDelta(self: *S2sPeer, delta: *const ChannelCrdt, sink: ByteSink) !void {
        if (!self.established) return error.NotEstablished;
        const encoded = try burst.serialize(self.allocator, delta, self.config.link.burst_limits);
        defer self.allocator.free(encoded);
        try emitFrame(self.allocator, sink, .DELTA, encoded);
    }

    pub fn sendPing(self: *S2sPeer, payload: []const u8, sink: ByteSink) !void {
        try emitFrame(self.allocator, sink, .PING, payload);
    }

    pub fn tick(self: *S2sPeer, sink: ByteSink, now_ms: u64, rng_seed: u64, peers: []const NodeId) !void {
        if (self.session.link.tick() == .heartbeat_due) {
            try emitFrame(self.allocator, sink, .PING, "");
        }
        if (!self.established) return;

        var result = try self.session.gossip.run(
            try i64Ms(now_ms),
            rng_seed,
            peers,
            &.{},
            self.config.link.gossip_config,
        );
        defer result.deinit(self.allocator);
        if (!containsNode(result.peers.items, self.remote_node_id)) return;

        const payload = try encodeGossip(self.allocator, &result.payload);
        defer self.allocator.free(payload);
        try emitFrame(self.allocator, sink, .GOSSIP, payload);
    }

    pub fn linkState(self: *const S2sPeer) peer_link.State {
        return self.session.linkState();
    }

    pub fn registryCount(self: *const S2sPeer) usize {
        return self.registry.count();
    }

    /// The remote server's name once learned from the handshake (empty before).
    pub fn remoteName(self: *const S2sPeer) []const u8 {
        return self.remote_name;
    }

    /// The remote node id once learned from the handshake (null before).
    pub fn remoteNodeId(self: *const S2sPeer) ?NodeId {
        if (!self.established or self.remote_node_id == 0) return null;
        return self.remote_node_id;
    }

    pub fn routeNickNode(self: *const S2sPeer, nick: []const u8) ?NodeId {
        return self.routes.nickNode(nick);
    }

    pub fn repairRoot(self: *const S2sPeer) !anti_entropy_repair.Hash {
        var summary = try anti_entropy_repair.summarize(self.allocator, self.state);
        defer summary.deinit();
        return summary.root();
    }

    fn dispatch(self: *S2sPeer, frame: s2s_frame.Frame, sink: ByteSink, now_ms: u64, rng_seed: u64) !void {
        switch (frame.frame_type) {
            .HANDSHAKE => try self.recvHandshake(frame.payload, sink, now_ms, rng_seed),
            .BURST => try burst.apply(self.allocator, self.state, frame.payload, self.config.link.burst_limits),
            .DELTA => try self.mergeDelta(frame.payload),
            .GOSSIP => try self.recvGossip(frame.payload, now_ms, rng_seed),
            .PING => {
                self.ping_rx_count += 1;
                try emitFrame(self.allocator, sink, .PONG, frame.payload);
            },
            .PONG => self.pong_rx_count += 1,
            .QUIT => self.closeRemote(),
            .MEMBERSHIP => try self.recvMembership(frame.payload),
            .MESSAGE => try self.recvMessage(frame.payload),
        }
    }

    /// Decode an inbound cross-node MESSAGE and queue it for the daemon to
    /// deliver locally. Loop-guarded by (origin_node, hlc): a duplicate that has
    /// already traversed this node is dropped (never re-queued/re-forwarded). A
    /// malformed payload is dropped, never fatal to the link.
    fn recvMessage(self: *S2sPeer, payload: []const u8) !void {
        var owned = message_relay.decode(self.allocator, payload) catch return;
        if (self.seen.observe(owned.msg.origin_node, owned.msg.hlc)) {
            owned.deinit(self.allocator); // duplicate — already seen
            return;
        }
        self.inbound.append(self.allocator, owned) catch {
            owned.deinit(self.allocator);
        };
    }

    /// Emit a cross-node user message to this peer. Records it in the loop-guard
    /// so an echo back is dropped. Best-effort; only meaningful once established.
    pub fn sendMessage(self: *S2sPeer, sink: ByteSink, msg: message_relay.RelayMessage) !void {
        _ = self.seen.observe(msg.origin_node, msg.hlc);
        const wire = try message_relay.encode(self.allocator, msg);
        defer self.allocator.free(wire);
        try emitFrame(self.allocator, sink, .MESSAGE, wire);
    }

    /// Transfer ownership of all queued inbound messages to the caller, which
    /// must `deinit` each `Owned` and free the returned slice. Resets the queue.
    pub fn takeInbound(self: *S2sPeer) ![]message_relay.Owned {
        return self.inbound.toOwnedSlice(self.allocator);
    }

    /// Apply an inbound MEMBERSHIP event to the route table (LWW by hlc). A
    /// malformed payload is dropped, never fatal to the link.
    fn recvMembership(self: *S2sPeer, payload: []const u8) !void {
        const ev = membership_event.decode(payload) catch return;
        self.routes.applyMembership(ev.channel, ev.nick, ev.origin_node, ev.status, ev.hlc, ev.present) catch {};
    }

    /// Emit a MEMBERSHIP event to the peer announcing a local member's presence
    /// (or departure) in `channel`. Best-effort; only meaningful once established.
    pub fn sendMembership(
        self: *S2sPeer,
        sink: ByteSink,
        channel: []const u8,
        nick: []const u8,
        status: u4,
        hlc: u64,
        present: bool,
    ) !void {
        const ev = membership_event.MembershipEvent{
            .present = present,
            .status = status,
            .origin_node = self.local_node_id,
            .hlc = hlc,
            .channel = channel,
            .nick = nick,
        };
        var buf: [membership_event.max_channel_len + membership_event.max_nick_len + 32]u8 = undefined;
        const wire = try membership_event.encode(ev, &buf);
        try emitFrame(self.allocator, sink, .MEMBERSHIP, wire);
    }

    /// Remote members the peer has announced for `channel` (borrowed roster).
    pub fn channelMembers(self: *const S2sPeer, channel: []const u8) []const route_table.Member {
        return self.routes.channelMembers(channel);
    }

    fn recvHandshake(self: *S2sPeer, payload: []const u8, sink: ByteSink, now_ms: u64, rng_seed: u64) !void {
        const hs = try decodeHandshake(payload);
        // remote_node_id == 0 means "unknown peer" (an accepting/dialing side that
        // does not know the remote's node id in advance): adopt it from the first
        // handshake. Otherwise enforce the expected identity.
        if (self.remote_node_id == 0) {
            self.remote_node_id = hs.node_id;
        } else if (hs.node_id != self.remote_node_id) {
            return error.UnexpectedRemote;
        }

        try self.rememberRemote(hs, now_ms);
        if (!self.handshake_sent) try self.emitHandshake(sink);
        if (!self.established) {
            try self.session.establish(hs.epoch_ms, now_ms, rng_seed);
            self.session.clearOutbound();
            self.established = true;
            try self.emitBurst(sink);
        }
    }

    fn rememberRemote(self: *S2sPeer, hs: Handshake, now_ms: u64) !void {
        // Run all fallible work first so a registry/route failure cannot leave a
        // dangling self.remote_name. Only after everything succeeds do we swap in
        // the freshly-duped name (transactional: old name freed last).
        const owned_name = try self.allocator.dupe(u8, hs.name);
        errdefer self.allocator.free(owned_name);

        _ = try self.registry.addOrUpdate(.{
            .node_id = hs.node_id,
            .name = hs.name,
            .description = hs.description,
            .hopcount = 1,
            .uplink = self.local_node_id,
            .last_seen_ms = try i64Ms(now_ms),
        });
        try self.routes.setNickLocation(hs.name, hs.node_id);

        self.remote_epoch_ms = hs.epoch_ms;
        self.allocator.free(self.remote_name);
        self.remote_name = owned_name;
    }

    fn emitHandshake(self: *S2sPeer, sink: ByteSink) !void {
        const payload = try encodeHandshake(self.allocator, .{
            .node_id = self.local_node_id,
            .epoch_ms = self.local_epoch_ms,
            .name = self.server_name,
            .description = self.description,
        });
        defer self.allocator.free(payload);
        try emitFrame(self.allocator, sink, .HANDSHAKE, payload);
        self.handshake_sent = true;
    }

    fn emitBurst(self: *S2sPeer, sink: ByteSink) !void {
        if (self.burst_sent) return;
        const encoded = try burst.serialize(self.allocator, self.state, self.config.link.burst_limits);
        defer self.allocator.free(encoded);
        try emitFrame(self.allocator, sink, .BURST, encoded);
        self.burst_sent = true;
    }

    fn mergeDelta(self: *S2sPeer, payload: []const u8) !void {
        var incoming = ChannelCrdt.init(self.allocator, self.state.replica_id);
        defer incoming.deinit();
        try burst.apply(self.allocator, &incoming, payload, self.config.link.burst_limits);
        try self.state.merge(&incoming);
        try self.refreshChannelRoute();
    }

    fn recvGossip(self: *S2sPeer, payload: []const u8, now_ms: u64, rng_seed: u64) !void {
        var gossip_payload = try decodeGossip(self.allocator, payload);
        defer gossip_payload.deinit(self.allocator);
        var rng = membership_view.Rng.init(mixSeed(rng_seed, self.local_node_id, self.remote_node_id));
        try self.session.gossip.applyPayload(&gossip_payload, try i64Ms(now_ms), &rng);
    }

    fn refreshChannelRoute(self: *S2sPeer) !void {
        if (self.channel_name.len == 0) return;
        self.routes.removeNode(self.remote_node_id);
        var live: usize = 0;
        for (self.state.members.items) |entry| {
            if (entry.adds.items.len == 0) continue;
            live += 1;
        }
        if (live == 0) return;
        try self.routes.addChannelMember(self.channel_name, self.remote_node_id);
    }

    fn closeRemote(self: *S2sPeer) void {
        self.established = false;
        if (self.remote_node_id != 0) _ = self.registry.remove(self.remote_node_id) catch false;
        self.routes.removeNode(self.remote_node_id);
        self.session.link.close();
    }
};

pub const Peer = S2sPeer;

fn emitFrame(allocator: Allocator, sink: ByteSink, frame_type: s2s_frame.FrameType, payload: []const u8) !void {
    const total = try s2s_frame.encodedLen(payload.len);
    const out = try allocator.alloc(u8, total);
    defer allocator.free(out);
    const encoded = try s2s_frame.encode(frame_type, payload, out);
    try sink.writeAll(encoded);
}

fn encodeHandshake(allocator: Allocator, hs: Handshake) ![]u8 {
    if (hs.name.len > std.math.maxInt(u16) or hs.description.len > std.math.maxInt(u16)) return error.HandshakeTooLarge;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &handshake_magic);
    try out.append(allocator, handshake_version);
    try writeU64(&out, allocator, hs.node_id);
    try writeU64(&out, allocator, hs.epoch_ms);
    try writeBytes16(&out, allocator, hs.name);
    try writeBytes16(&out, allocator, hs.description);
    return out.toOwnedSlice(allocator);
}

fn decodeHandshake(bytes: []const u8) !Handshake {
    var r = Reader{ .buf = bytes };
    for (handshake_magic) |want| {
        if (try r.readByte() != want) return error.BadHandshake;
    }
    if (try r.readByte() != handshake_version) return error.UnsupportedHandshake;
    const out = Handshake{
        .node_id = try r.readU64(),
        .epoch_ms = try r.readU64(),
        .name = try r.readBytes16(),
        .description = try r.readBytes16(),
    };
    if (!r.done()) return error.TrailingBytes;
    return out;
}

fn encodeGossip(allocator: Allocator, payload: *const gossip_round.GossipPayload) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try writeU64(&out, allocator, payload.origin);
    try writeU64(&out, allocator, payload.origin_incarnation);
    try writeVarint(&out, allocator, payload.member_deltas.items.len);
    for (payload.member_deltas.items) |delta| {
        try writeU64(&out, allocator, delta.id);
        try out.append(allocator, @intFromEnum(delta.state));
        try writeU64(&out, allocator, delta.incarnation);
    }
    try writeVarint(&out, allocator, payload.suspicions.items.len);
    for (payload.suspicions.items) |s| {
        try writeU64(&out, allocator, s.node);
        try writeU64(&out, allocator, s.incarnation);
        try writeU64(&out, allocator, s.witness);
    }
    return out.toOwnedSlice(allocator);
}

fn decodeGossip(allocator: Allocator, bytes: []const u8) !gossip_round.GossipPayload {
    var r = Reader{ .buf = bytes };
    var out = gossip_round.GossipPayload{
        .origin = try r.readU64(),
        .origin_incarnation = try r.readU64(),
    };
    errdefer out.deinit(allocator);
    const deltas = try r.readVarint();
    var i: usize = 0;
    while (i < deltas) : (i += 1) {
        try out.member_deltas.append(allocator, .{
            .id = try r.readU64(),
            .state = try decodeMemberState(try r.readByte()),
            .incarnation = try r.readU64(),
        });
    }
    const suspicions = try r.readVarint();
    i = 0;
    while (i < suspicions) : (i += 1) {
        try out.suspicions.append(allocator, .{
            .node = try r.readU64(),
            .incarnation = try r.readU64(),
            .witness = try r.readU64(),
        });
    }
    if (!r.done()) return error.TrailingBytes;
    return out;
}

fn writeBytes16(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8) !void {
    try writeU16(out, allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

fn writeU16(out: *std.ArrayList(u8), allocator: Allocator, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn writeU64(out: *std.ArrayList(u8), allocator: Allocator, value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn writeVarint(out: *std.ArrayList(u8), allocator: Allocator, value: usize) !void {
    var n: u64 = @intCast(value);
    while (n >= 0x80) {
        try out.append(allocator, @as(u8, @intCast(n & 0x7f)) | 0x80);
        n >>= 7;
    }
    try out.append(allocator, @intCast(n));
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }

    fn readByte(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readU16(self: *Reader) !u16 {
        const bytes = try self.readFixed(2);
        return std.mem.readInt(u16, bytes[0..2], .little);
    }

    fn readU64(self: *Reader) !u64 {
        const bytes = try self.readFixed(8);
        return std.mem.readInt(u64, bytes[0..8], .little);
    }

    fn readVarint(self: *Reader) !usize {
        var shift: u6 = 0;
        var value: u64 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const byte = try self.readByte();
            value |= @as(u64, byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) {
                if (value > std.math.maxInt(usize)) return error.Oversize;
                return @intCast(value);
            }
            shift += 7;
        }
        return error.VarintTooLong;
    }

    fn readBytes16(self: *Reader) ![]const u8 {
        return self.readFixed(try self.readU16());
    }

    fn readFixed(self: *Reader, len: usize) ![]const u8 {
        if (self.pos + len > self.buf.len) return error.Truncated;
        const out = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }
};

fn decodeMemberState(value: u8) !gossip_round.MemberState {
    return switch (value) {
        0 => .alive,
        1 => .suspect,
        2 => .dead,
        3 => .left,
        else => error.UnknownMemberState,
    };
}

fn containsNode(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |candidate| if (candidate == node) return true;
    return false;
}

fn i64Ms(ms: u64) !i64 {
    if (ms > @as(u64, @intCast(std.math.maxInt(i64)))) return error.TimeOutOfRange;
    return @intCast(ms);
}

fn mixSeed(a: u64, b: u64, c: u64) u64 {
    var x = a ^ (b *% 0x9e3779b97f4a7c15) ^ (c *% 0xbf58476d1ce4e5b9);
    x ^= x >> 30;
    x *%= 0xbf58476d1ce4e5b9;
    x ^= x >> 27;
    x *%= 0x94d049bb133111eb;
    return x ^ (x >> 31);
}

const TestClock = struct {
    now_ms: u64,

    fn clock(self: *TestClock) peer_link.Clock {
        return .{ .ptr = self, .now_fn = nowFn };
    }

    fn nowFn(ptr: *anyopaque) u64 {
        const self: *TestClock = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }
};

const BufferSink = struct {
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *BufferSink, allocator: Allocator) void {
        self.bytes.deinit(allocator);
    }

    fn sink(self: *BufferSink) ByteSink {
        return .{ .ptr = self, .write_fn = writeFn };
    }

    fn writeFn(ptr: *anyopaque, bytes: []const u8) !void {
        const self: *BufferSink = @ptrCast(@alignCast(ptr));
        try self.bytes.appendSlice(std.testing.allocator, bytes);
    }

    fn clear(self: *BufferSink) void {
        self.bytes.clearRetainingCapacity();
    }
};

fn discard(delta: anytype) void {
    var owned = delta;
    owned.deinit();
}

fn pump(a: *S2sPeer, b: *S2sPeer, a_to_b: *BufferSink, b_to_a: *BufferSink, now_ms: u64, seed: u64) !void {
    var rounds: usize = 0;
    while (rounds < 128) : (rounds += 1) {
        var moved = false;
        if (a_to_b.bytes.items.len != 0) {
            try b.feed(a_to_b.bytes.items, b_to_a.sink(), now_ms, seed +% @as(u64, @intCast(rounds)));
            a_to_b.clear();
            moved = true;
        }
        if (b_to_a.bytes.items.len != 0) {
            try a.feed(b_to_a.bytes.items, a_to_b.sink(), now_ms, seed +% 0x100 +% @as(u64, @intCast(rounds)));
            b_to_a.clear();
            moved = true;
        }
        if (!moved) return;
    }
    return error.PumpDidNotSettle;
}

fn newPeer(
    allocator: Allocator,
    state: *ChannelCrdt,
    tc: *TestClock,
    local_node: NodeId,
    remote_node: NodeId,
    epoch: u64,
    name: []const u8,
) !S2sPeer {
    return S2sPeer.init(.{
        .allocator = allocator,
        .state = state,
        .clock = tc.clock(),
        .local_node_id = local_node,
        .remote_node_id = remote_node,
        .local_epoch_ms = epoch,
        .server_name = name,
        .description = "test",
        .config = .{
            .link = .{
                .gossip_interval_ms = 10,
                .repair_interval_ms = 20,
                .gossip_config = .{ .fanout = 1 },
            },
        },
    });
}

test "two s2s peer drivers handshake and converge channel CRDT state" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 10 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();

    discard(try a_state.localJoin(10, .{ .op = true }, 10));
    discard(try a_state.localSetMode(.{ .invite_only = true }, 11));
    discard(try b_state.localJoin(20, .{ .voice = true }, 12));
    discard(try b_state.localSetMode(.{ .topic_protected = true }, 13));

    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 1000, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 2000, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.startHandshake(a_to_b.sink());
    try b.startHandshake(b_to_a.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xA11CE);

    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));
    try std.testing.expectEqual(peer_link.State.established, a.linkState());
    try std.testing.expectEqual(peer_link.State.established, b.linkState());
    try std.testing.expectEqual(@as(usize, 2), a.registryCount());
    try std.testing.expectEqual(@as(?NodeId, 2), a.routeNickNode("b.test"));

    var delta = try a_state.localJoin(30, .{ .founder = true }, 30);
    defer delta.deinit();
    try a.sendDelta(&delta, a_to_b.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0xD317A);
    try std.testing.expect(ChannelCrdt.eql(&a_state, &b_state));
}

test "PING emits matching PONG" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 10, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 20, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.sendPing("hello", a_to_b.sink());
    try pump(&a, &b, &a_to_b, &b_to_a, tc.now_ms, 0x51);
    try std.testing.expectEqual(@as(usize, 1), b.ping_rx_count);
    try std.testing.expectEqual(@as(usize, 1), a.pong_rx_count);
}

test "partial inbound bytes are buffered until complete frame" {
    const allocator = std.testing.allocator;
    var tc = TestClock{ .now_ms = 1 };
    var a_state = ChannelCrdt.init(allocator, 1);
    defer a_state.deinit();
    var b_state = ChannelCrdt.init(allocator, 2);
    defer b_state.deinit();
    var a = try newPeer(allocator, &a_state, &tc, 1, 2, 10, "a.test");
    defer a.deinit();
    var b = try newPeer(allocator, &b_state, &tc, 2, 1, 20, "b.test");
    defer b.deinit();
    var a_to_b = BufferSink{};
    defer a_to_b.deinit(allocator);
    var b_to_a = BufferSink{};
    defer b_to_a.deinit(allocator);

    try a.sendPing("split", a_to_b.sink());
    const bytes = a_to_b.bytes.items;
    try b.feed(bytes[0..3], b_to_a.sink(), tc.now_ms, 1);
    try std.testing.expectEqual(@as(usize, 0), b.ping_rx_count);
    try b.feed(bytes[3..], b_to_a.sink(), tc.now_ms, 1);
    try std.testing.expectEqual(@as(usize, 1), b.ping_rx_count);
    try a.feed(b_to_a.bytes.items, a_to_b.sink(), tc.now_ms, 1);
    try std.testing.expectEqual(@as(usize, 1), a.pong_rx_count);
}

test "Config.applyToml consolidated EFFECTIVE prod path overlay" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.gossip]
        \\round_fanout = 5
        \\[mesh.swim]
        \\sazanami_witness_quorum = 3
        \\[mesh.link]
        \\gossip_interval_ms = 1750
        \\idle_timeout_ms = 90000
        \\[mesh.routing]
        \\max_servers = 256
        \\max_nicks = 2048
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    // [mesh.gossip]/[mesh.swim] flow into the session sub-configs.
    try std.testing.expectEqual(@as(usize, 5), cfg.link.gossip_config.fanout);
    try std.testing.expectEqual(@as(u8, 3), cfg.link.swim_config.witness_quorum);
    // [mesh.link] session cadence + transport.
    try std.testing.expectEqual(@as(u64, 1750), cfg.link.gossip_interval_ms);
    try std.testing.expectEqual(@as(u64, 90000), cfg.link.peer_link_config.idle_timeout_ms);
    // [mesh.routing] registry + routes.
    try std.testing.expectEqual(@as(usize, 256), cfg.registry.max_nodes);
    try std.testing.expectEqual(@as(usize, 2048), cfg.routes.max_nicks);
}
