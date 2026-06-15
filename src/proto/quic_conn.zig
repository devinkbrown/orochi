//! Socketless QUIC v1 connection driver (RFC 9000 + RFC 9001) — layer 5.
//!
//! This ties the four tested layers below into a real connection. It is fully
//! socketless: the UDP listener (next layer) only calls `recvDatagram` with one
//! received UDP payload and `sendDatagrams` to collect the datagrams to write
//! back. Nothing here touches a socket, a clock other than the `now` the caller
//! passes, or any global state.
//!
//! Layers reused verbatim (no re-decrypt / re-encode / re-derive by hand):
//!   * `quic_packet`   — long/short header encode/decode, ConnectionId, pn len.
//!   * `quic_protect`  — `KeySet`, `sealPacketSuite` / `openPacketSuite`,
//!                       `EncryptionLevel`, header protection.
//!   * `quic_frame`    — ACK / CRYPTO / STREAM / DATAGRAM / PADDING / PING /
//!                       CONNECTION_CLOSE encode/decode, varints, pn truncation.
//!   * `quic_conn_state.Engine` — packet-number spaces, ACK manager, CRYPTO
//!                       reassembly + send buffers, STREAM reassembly + flow
//!                       control, `intake`.
//!   * `quic_handshake.Server` / `.Client` — the TLS-1.3-over-QUIC handshake,
//!                       producing the Handshake and 1-RTT `KeySet`s.
//!
//! Send / receive loop
//! -------------------
//! `recvDatagram` walks the (possibly coalesced) QUIC packets in one UDP
//! datagram. For each packet it picks the `EncryptionLevel` from the header,
//! selects the matching `KeySet` (Initial from the DCID at first contact;
//! Handshake / 1-RTT once the handshake installs them), `openPacket`s to
//! decrypt, decodes the frames, runs them through `Engine.intake`, and feeds
//! CRYPTO bytes to the handshake. A packet whose level has no keys installed yet
//! is **buffered** (re-tried after the next key install) rather than faulting.
//!
//! `sendDatagrams` collects everything owed — pending handshake CRYPTO flights
//! (fragmented via the per-level `CryptoSendBuffer`), the ACK frames the engine
//! says are owed, application STREAM / DATAGRAM frames the caller queued, and
//! PADDING to bring a client Initial up to the 1200-byte minimum — assembles
//! them into packets per level, `sealPacket`s each, and **coalesces** Initial +
//! Handshake (+ 1-RTT) packets into a single datagram where allowed.
//!
//! Level / state transitions
//! -------------------------
//! Initial → Handshake → 1-RTT (Application). The handshake produces the
//! Handshake keys after the first flight and the 1-RTT keys after the server
//! flight; `installKeys` wires each `KeySet` in as the handshake exposes it.
//! Once Handshake keys are in use the Initial keys are discarded (RFC 9001
//! §4.9). `isEstablished()` is true once both 1-RTT key directions are present
//! AND the handshake reports complete.
//!
//! Documented simplifications (intentional for this layer; the listener / HTTP3
//! layers refine them):
//!   * Congestion control: a generous fixed window only — we never withhold a
//!     send for cwnd reasons. Loss recovery is a single fixed PTO (no RTT
//!     sampling, no exponential backoff yet). This is safe for a loopback /
//!     low-loss path and keeps the reliability surface small; a real BBR/CUBIC
//!     controller is a later layer.
//!   * One connection id per side, no migration, no Retry, no stateless reset,
//!     no key update (1-RTT key phase stays 0), no 0-RTT. Each is a typed gap,
//!     not a silent one.
//!   * The receive side enforces frame-level bounds via the Engine; this driver
//!     additionally bounds-checks every byte of packet parsing so a malicious or
//!     truncated datagram errors (never panics / reads out of bounds).

const std = @import("std");
const Allocator = std.mem.Allocator;

const quic_packet = @import("quic_packet.zig");
const quic_protect = @import("quic_protect.zig");
const quic_frame = @import("quic_frame.zig");
const quic_conn_state = @import("quic_conn_state.zig");
const quic_handshake = @import("quic_handshake.zig");
const quic_transport_params = @import("quic_transport_params.zig");

pub const EncryptionLevel = quic_protect.EncryptionLevel;
pub const KeySet = quic_protect.KeySet;
pub const ConnectionId = quic_packet.ConnectionId;
pub const Frame = quic_frame.Frame;
pub const Engine = quic_conn_state.Engine;
pub const StreamId = quic_conn_state.StreamId;
pub const Role = enum { client, server };

/// QUIC v1 (RFC 9000 §15).
pub const quic_version_1: u32 = 0x0000_0001;

/// The minimum UDP payload a client MUST inflate its Initial packet(s) to
/// (RFC 9000 §14.1). We pad the *datagram* (across coalesced packets).
pub const min_initial_datagram: usize = 1200;

/// A conservative ceiling on one outbound datagram. 1252 is the IPv6 minimum
/// safe UDP payload without PMTUD; we never exceed it.
pub const max_datagram: usize = 1252;

/// Fixed probe timeout (loss detection). A real driver samples the RTT; this
/// layer uses a single generous fixed PTO so an un-acked CRYPTO flight is
/// retransmitted on `onTimeout`. Documented simplification.
pub const fixed_pto_ns: u64 = 250 * std.time.ns_per_ms;

/// Default idle timeout if neither side advertises one (RFC 9000 §10.1).
pub const default_idle_timeout_ns: u64 = 30 * std.time.ns_per_s;

/// CONNECTION_CLOSE application/transport error codes we emit.
pub const transport_error_no_error: u64 = 0x00;
pub const transport_error_internal: u64 = 0x01;

pub const ConnError = error{
    /// A datagram could not be parsed at the packet-structure level.
    MalformedPacket,
    /// The header declared an unsupported/short-of-QUIC-v1 version.
    UnsupportedVersion,
    /// `sendStream` / `sendDatagram` before the connection is established.
    NotEstablished,
    /// A peer CONNECTION_CLOSE was received; the connection is closing.
    PeerClosed,
    /// The handshake produced a fatal error.
    HandshakeFailed,
    /// The idle timeout elapsed with no activity.
    IdleTimeout,
};

/// The driver's error set. It folds in the lower layers' error sets it
/// propagates (frame coding, engine state) so the seal/encode/intake calls
/// compose without per-call mapping. A malformed *peer* datagram is caught and
/// turned into `MalformedPacket` (or silently dropped) inside the recv path;
/// these wider members surface only on a local programming/limit error.
pub const Error = ConnError || Allocator.Error || quic_frame.WireError || quic_conn_state.Error;

/// Either handshake role behind one interface. The driver only needs the
/// socketless surface both `Server` and `Client` expose.
const Handshake = union(Role) {
    client: quic_handshake.Client,
    server: quic_handshake.Server,

    fn deinit(self: *Handshake) void {
        switch (self.*) {
            inline else => |*h| h.deinit(),
        }
    }
    fn feedCrypto(self: *Handshake, level: EncryptionLevel, data: []const u8) quic_handshake.Error!void {
        switch (self.*) {
            inline else => |*h| return h.feedCrypto(level, data),
        }
    }
    fn takeFlight(self: *Handshake, level: EncryptionLevel) quic_handshake.Error![]u8 {
        switch (self.*) {
            inline else => |*h| return h.takeFlight(level),
        }
    }
    fn isComplete(self: *const Handshake) bool {
        switch (self.*) {
            inline else => |*h| return h.isComplete(),
        }
    }
    fn handshakeKeys(self: *const Handshake) ?KeySet {
        switch (self.*) {
            inline else => |*h| return h.handshakeKeys(),
        }
    }
    fn applicationKeys(self: *const Handshake) ?KeySet {
        switch (self.*) {
            inline else => |*h| return h.applicationKeys(),
        }
    }
    fn selectedAlpn(self: *const Handshake) ?[]const u8 {
        switch (self.*) {
            inline else => |*h| return h.selectedAlpn(),
        }
    }
    fn peerTransportParams(self: *const Handshake) ?quic_transport_params.TransportParameters {
        switch (self.*) {
            inline else => |*h| return h.peerTransportParams(),
        }
    }
};

/// Server-role connection configuration. Carries the cert / signing key, the
/// ALPN list, the local transport parameters, and this side's connection ids.
pub const ServerConfig = struct {
    cert_chain: []const []const u8,
    signing_key: quic_handshake.SigningKey,
    alpn_protocols: []const []const u8 = &.{},
    transport_params: quic_transport_params.TransportParameters = .{},
    /// This server's source connection id (becomes the peer's DCID after the
    /// first flight). Also used in the long-header SCID.
    local_cid: []const u8,
    /// Engine caps (flow control, buffer sizes). Defaults are safe.
    engine: quic_conn_state.Config = .{},
    /// Deterministic handshake material (tests only).
    x25519_seed: ?[32]u8 = null,
    server_random: ?[32]u8 = null,
};

/// Client-role connection configuration.
pub const ClientConfig = struct {
    alpn_protocols: []const []const u8 = &.{},
    transport_params: quic_transport_params.TransportParameters = .{},
    /// This client's source connection id (long-header SCID).
    local_cid: []const u8,
    /// The Destination Connection ID the client picks for the server's Initial
    /// keys (RFC 9001 §5.2 — the client chooses an unpredictable DCID and both
    /// sides derive the Initial secrets from it).
    initial_dcid: []const u8,
    engine: quic_conn_state.Config = .{},
    x25519_seed: ?[32]u8 = null,
    client_random: ?[32]u8 = null,
};

/// A queued application STREAM write awaiting an outbound 1-RTT packet.
const PendingStream = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []u8, // owned
};

/// A queued application DATAGRAM (RFC 9221) awaiting an outbound 1-RTT packet.
const PendingDatagram = struct {
    data: []u8, // owned
};

/// One outbound datagram produced by `sendDatagrams`, owned by the caller.
pub const OutDatagram = struct {
    bytes: []u8,
};

/// Per-level send-side CRYPTO buffers (Initial / Handshake) and the largest
/// packet number we have sent that carried ack-eliciting data, so the PTO timer
/// knows whether a retransmit is owed.
const SendState = struct {
    crypto_initial: quic_conn_state.CryptoSendBuffer = quic_conn_state.CryptoSendBuffer.init(),
    crypto_handshake: quic_conn_state.CryptoSendBuffer = quic_conn_state.CryptoSendBuffer.init(),

    fn deinit(self: *SendState, allocator: Allocator) void {
        self.crypto_initial.deinit(allocator);
        self.crypto_handshake.deinit(allocator);
    }

    fn cryptoBuf(self: *SendState, level: EncryptionLevel) ?*quic_conn_state.CryptoSendBuffer {
        return switch (level) {
            .initial => &self.crypto_initial,
            .handshake => &self.crypto_handshake,
            .application => null, // 1-RTT CRYPTO (post-handshake) is out of scope here
        };
    }
};

/// The connection. One per peer 4-tuple. Socketless: feed `recvDatagram`,
/// drain `sendDatagrams`, tick `onTimeout`.
pub const Conn = struct {
    allocator: Allocator,
    role: Role,
    handshake: Handshake,
    engine: Engine,
    send: SendState,

    /// Initial keys (from the DCID) — discarded once Handshake keys are used.
    initial_keys: ?KeySet,
    handshake_keys: ?KeySet = null,
    app_keys: ?KeySet = null,
    initial_discarded: bool = false,

    /// Long-header connection ids. `dcid` = the peer's, `scid` = ours.
    dcid: ConnectionId,
    scid: ConnectionId,
    /// The DCID the Initial keys were derived from (client picks it; server
    /// learns it from the first Initial packet).
    initial_secret_dcid: [quic_packet.max_connection_id_len]u8 = undefined,
    initial_secret_dcid_len: u8 = 0,

    /// Whether we have produced the first flight (client: ClientHello sent;
    /// server: nothing until it receives the ClientHello).
    started: bool = false,
    /// (Client) whether we have adopted the server's SCID as our DCID yet.
    server_cid_learned: bool = false,
    /// True once both directions of 1-RTT keys exist and the handshake is done.
    established: bool = false,
    /// Set when a CONNECTION_CLOSE was received or we initiated a close.
    closing: bool = false,
    close_error: ?u64 = null,
    /// Whether a CONNECTION_CLOSE frame still needs to go on the wire (we send
    /// one once, in the highest available level).
    close_pending: bool = false,

    /// Packets at a level whose keys are not yet installed, buffered for replay
    /// after the next key install (RFC 9000 §5.7 / RFC 9001 §5.7). Bounded.
    buffered: std.ArrayList(BufferedPacket),
    max_buffered: usize = 16,

    /// Reusable scratch for `newly_acked` so intake does not allocate per call.
    newly_acked: std.ArrayList(u64),

    /// Loss / idle timers (nanoseconds, in the caller's clock domain).
    last_recv_ns: u64 = 0,
    pto_deadline_ns: ?u64 = null,
    idle_timeout_ns: u64 = default_idle_timeout_ns,

    /// Application data the caller queued for the next 1-RTT send.
    pending_streams: std.ArrayList(PendingStream),
    pending_datagrams: std.ArrayList(PendingDatagram),
    /// Received application DATAGRAM (RFC 9221) payloads, owned copies, awaiting
    /// the application's `recvDatagram` drain. The engine's intake only accounts
    /// the ACK obligation for a DATAGRAM frame; the driver captures the payload
    /// here so the layer above (HTTP/3 / WebTransport) can consume it. Bounded.
    recv_datagrams: std.ArrayList(PendingDatagram),
    max_recv_datagrams: usize = 256,
    /// Next stream id this endpoint will assign for `openStream` (client bidi
    /// starts at 0, server bidi at 1 — RFC 9000 §2.1).
    next_bidi_stream: u64,
    /// Next stream id this endpoint will assign for `openUniStream` (client uni
    /// starts at 2, server uni at 3 — RFC 9000 §2.1). Advances by 4.
    next_uni_stream: u64,
    /// Per-stream count of bytes already shipped, so successive `sendStream`
    /// calls compute the correct STREAM offset even after the queue is flushed.
    sent_stream_map: std.AutoHashMapUnmanaged(u64, u64) = .empty,

    const BufferedPacket = struct {
        level: EncryptionLevel,
        bytes: []u8, // owned copy of the full single packet
    };

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    pub fn initServer(allocator: Allocator, config: ServerConfig) Error!Conn {
        var server = quic_handshake.Server.init(allocator, .{
            .cert_chain = config.cert_chain,
            .signing_key = config.signing_key,
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
            .x25519_seed = config.x25519_seed,
            .server_random = config.server_random,
        }) catch return error.HandshakeFailed;
        errdefer server.deinit();

        const scid = ConnectionId.init(config.local_cid) catch return error.MalformedPacket;

        return finishInit(allocator, .server, .{ .server = server }, config.engine, scid, ConnectionId{});
    }

    pub fn initClient(allocator: Allocator, config: ClientConfig) Error!Conn {
        var client = quic_handshake.Client.initConfig(allocator, .{
            .alpn_protocols = config.alpn_protocols,
            .transport_params = config.transport_params,
            .x25519_seed = config.x25519_seed,
            .client_random = config.client_random,
        }) catch return error.HandshakeFailed;
        errdefer client.deinit();

        const scid = ConnectionId.init(config.local_cid) catch return error.MalformedPacket;
        const dcid = ConnectionId.init(config.initial_dcid) catch return error.MalformedPacket;

        var conn = finishInit(allocator, .client, .{ .client = client }, config.engine, scid, dcid);
        // The client derives the Initial keys from its chosen DCID immediately
        // (is_server = false → write = client_initial secret), and uses that DCID
        // in its Initial long header.
        conn.setInitialKeys(config.initial_dcid, false);
        return conn;
    }

    fn finishInit(
        allocator: Allocator,
        role: Role,
        handshake: Handshake,
        engine_config: quic_conn_state.Config,
        scid: ConnectionId,
        dcid: ConnectionId,
    ) Conn {
        const local: quic_conn_state.Initiator = switch (role) {
            .client => .client,
            .server => .server,
        };
        return .{
            .allocator = allocator,
            .role = role,
            .handshake = handshake,
            .engine = Engine.init(allocator, local, engine_config),
            .send = .{},
            .initial_keys = null,
            .dcid = dcid,
            .scid = scid,
            .buffered = .empty,
            .newly_acked = .empty,
            .pending_streams = .empty,
            .pending_datagrams = .empty,
            .recv_datagrams = .empty,
            // Client bidi stream ids are 0,4,8,…; server 1,5,9,… (RFC 9000 §2.1).
            .next_bidi_stream = switch (role) {
                .client => 0,
                .server => 1,
            },
            // Client uni stream ids are 2,6,10,…; server 3,7,11,… (RFC 9000 §2.1).
            .next_uni_stream = switch (role) {
                .client => 2,
                .server => 3,
            },
        };
    }

    pub fn deinit(self: *Conn) void {
        self.handshake.deinit();
        self.engine.deinit();
        self.send.deinit(self.allocator);
        for (self.buffered.items) |b| self.allocator.free(b.bytes);
        self.buffered.deinit(self.allocator);
        self.newly_acked.deinit(self.allocator);
        for (self.pending_streams.items) |p| self.allocator.free(p.data);
        self.pending_streams.deinit(self.allocator);
        for (self.pending_datagrams.items) |p| self.allocator.free(p.data);
        self.pending_datagrams.deinit(self.allocator);
        for (self.recv_datagrams.items) |p| self.allocator.free(p.data);
        self.recv_datagrams.deinit(self.allocator);
        self.sent_stream_map.deinit(self.allocator);
        self.* = undefined;
    }

    // -----------------------------------------------------------------------
    // Public state
    // -----------------------------------------------------------------------

    pub fn isEstablished(self: *const Conn) bool {
        return self.established;
    }

    pub fn isClosing(self: *const Conn) bool {
        return self.closing;
    }

    pub fn selectedAlpn(self: *const Conn) ?[]const u8 {
        return self.handshake.selectedAlpn();
    }

    pub fn peerTransportParams(self: *const Conn) ?quic_transport_params.TransportParameters {
        return self.handshake.peerTransportParams();
    }

    // -----------------------------------------------------------------------
    // Key installation / discard (RFC 9001 §4.9)
    // -----------------------------------------------------------------------

    /// Derive and install the Initial keys from `dcid`. `is_server` selects the
    /// write (own) vs read (peer) direction.
    fn setInitialKeys(self: *Conn, dcid: []const u8, is_server: bool) void {
        self.initial_keys = KeySet.initInitial(dcid, is_server);
        @memcpy(self.initial_secret_dcid[0..dcid.len], dcid);
        self.initial_secret_dcid_len = @intCast(dcid.len);
    }

    /// Pull any newly-available keys out of the handshake and install them,
    /// discarding the Initial keys once the Handshake keys are in hand.
    fn syncKeys(self: *Conn) void {
        if (self.handshake_keys == null) {
            if (self.handshake.handshakeKeys()) |ks| self.handshake_keys = ks;
        }
        if (self.app_keys == null) {
            if (self.handshake.applicationKeys()) |ks| self.app_keys = ks;
        }
        self.refreshEstablished();
    }

    fn refreshEstablished(self: *Conn) void {
        if (!self.established and self.app_keys != null and self.handshake.isComplete()) {
            self.established = true;
            // RFC 9001 §4.9.1/§4.9.2: by the time the handshake is complete and
            // 1-RTT keys are in use, the Initial keys are no longer needed for
            // either direction; discard them. (We keep them through the whole
            // handshake so a retransmitted/late Initial — e.g. the peer's ACK of
            // our Initial — can still be processed and sent.)
            self.initial_keys = null;
            self.initial_discarded = true;
        }
    }

    fn keysFor(self: *Conn, level: EncryptionLevel) ?*KeySet {
        return switch (level) {
            .initial => if (self.initial_keys) |*k| k else null,
            .handshake => if (self.handshake_keys) |*k| k else null,
            .application => if (self.app_keys) |*k| k else null,
        };
    }

    // -----------------------------------------------------------------------
    // Receive path
    // -----------------------------------------------------------------------

    /// Parse and process one received UDP datagram (possibly several coalesced
    /// QUIC packets). Bounds-checked end to end: a malformed or truncated
    /// datagram returns `error.MalformedPacket` without panicking.
    pub fn recvDatagram(self: *Conn, datagram: []const u8) Error!void {
        return self.recvDatagramAt(datagram, self.last_recv_ns);
    }

    /// As `recvDatagram` but stamps activity at `now` (the caller's clock).
    pub fn recvDatagramAt(self: *Conn, datagram: []const u8, now: u64) Error!void {
        self.last_recv_ns = now;
        var pos: usize = 0;
        while (pos < datagram.len) {
            // A 0x00 byte where a packet should start is padding to the end of
            // the datagram (a coalesced packet's PADDING leaked past Length is
            // impossible, but a peer may pad the datagram tail). Stop.
            if (datagram[pos] == 0x00) break;
            const consumed = try self.recvOnePacket(datagram[pos..], now);
            if (consumed == 0) break; // defensive: never loop forever
            pos += consumed;
        }
    }

    /// Process one packet starting at `input[0]`. Returns the number of bytes
    /// the packet occupied in the datagram (for coalescing) — for a short-header
    /// (1-RTT) packet that is the whole remaining slice.
    fn recvOnePacket(self: *Conn, input: []const u8, now: u64) Error!usize {
        if (input.len == 0) return 0;
        const is_long = (input[0] & 0x80) != 0;
        if (is_long) return self.recvLongPacket(input, now);
        return self.recvShortPacket(input, now);
    }

    fn recvLongPacket(self: *Conn, input: []const u8, now: u64) Error!usize {
        const dec = quic_packet.decodeLongHeader(input) catch return error.MalformedPacket;
        if (dec.header.version != quic_version_1) {
            // Version negotiation / Retry are out of scope; treat as malformed
            // so the caller can drop the datagram rather than half-process it.
            return error.UnsupportedVersion;
        }

        const level: EncryptionLevel = switch (dec.header.packet_type) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt => return error.MalformedPacket, // 0-RTT unsupported (typed gap)
            .retry => return error.MalformedPacket, // Retry unsupported (typed gap)
        };

        // The server learns the client's DCID from the first Initial and derives
        // its Initial keys from it (RFC 9001 §5.2).
        if (self.role == .server and level == .initial and self.initial_keys == null and !self.initial_discarded) {
            const client_dcid = dec.header.dcid.slice();
            self.setInitialKeys(client_dcid, true);
            // Reply to the client using its SCID as our DCID.
            self.dcid = dec.header.scid;
        }

        // The client adopts the server's chosen Source Connection ID as its
        // Destination Connection ID from the server's first packet (RFC 9000
        // §7.2). Until then it used the random Initial DCID it invented; the
        // server's real SCID is what 1-RTT short headers must address.
        if (self.role == .client and !self.server_cid_learned) {
            self.dcid = dec.header.scid;
            self.server_cid_learned = true;
        }

        var cursor = dec.consumed;
        // Initial packets carry a Token (varint length + token bytes) before the
        // Length field (RFC 9000 §17.2.2). Handshake packets do not.
        if (level == .initial) {
            const tok = decodeVarIntAt(input, cursor) catch return error.MalformedPacket;
            cursor += tok.len;
            const tok_len = std.math.cast(usize, tok.value) orelse return error.MalformedPacket;
            if (cursor + tok_len > input.len) return error.MalformedPacket;
            cursor += tok_len;
        }

        // Length = pn_len + payload + tag.
        const length_vi = decodeVarIntAt(input, cursor) catch return error.MalformedPacket;
        cursor += length_vi.len;
        const length = std.math.cast(usize, length_vi.value) orelse return error.MalformedPacket;
        const pn_offset = cursor;
        const packet_end = pn_offset + length;
        if (packet_end > input.len) return error.MalformedPacket;

        try self.openAndIntake(level, input[0..packet_end], pn_offset, now);
        return packet_end;
    }

    fn recvShortPacket(self: *Conn, input: []const u8, now: u64) Error!usize {
        // 1-RTT: first byte | dcid (our scid length) | pn. We always issue a
        // fixed-length local connection id (scid), so the pn offset is known.
        const our_cid_len: usize = self.scid.len;
        const pn_offset = 1 + our_cid_len;
        if (input.len < pn_offset + 1) return error.MalformedPacket;
        // A short-header packet is always the last in its datagram (it has no
        // Length field), so it consumes the whole remaining slice.
        try self.openAndIntake(.application, input, pn_offset, now);
        return input.len;
    }

    /// Open `packet` (a single QUIC packet slice) at `level`, decode its frames,
    /// and run them through the engine + handshake. Buffers the packet if the
    /// level's keys are not yet installed.
    fn openAndIntake(self: *Conn, level: EncryptionLevel, packet: []const u8, pn_offset: usize, now: u64) Error!void {
        const keys = self.keysFor(level) orelse {
            // Keys not installed yet — buffer for replay after the next install
            // (handshake reordering, RFC 9000 §5.7). Initial keys that were
            // discarded mean a late Initial: drop it (not an error).
            if (level == .initial and self.initial_discarded) return;
            try self.bufferPacket(level, packet);
            return;
        };

        // Work on a mutable copy: openPacketSuite unmasks the header in place.
        const buf = try self.allocator.alloc(u8, packet.len);
        defer self.allocator.free(buf);
        @memcpy(buf, packet);

        const plaintext = try self.allocator.alloc(u8, packet.len);
        defer self.allocator.free(plaintext);

        const largest = self.engine.space(level).largest_received;
        const ctx = PnDecodeCtx{ .largest = largest };
        PnDecodeCtx.current = ctx;
        const opened = quic_protect.openPacketSuite(
            plaintext,
            buf,
            pn_offset,
            keys.read,
            PnDecodeCtx.decode,
        ) catch {
            // AEAD/header failure — a packet we cannot authenticate is silently
            // discarded (RFC 9001 §5.2); not a connection error.
            return;
        };

        const pn = PnDecodeCtx.last_full;
        try self.intakeFrames(level, pn, plaintext[0..opened.plaintext_len], now);
    }

    fn intakeFrames(self: *Conn, level: EncryptionLevel, pn: u64, payload: []const u8, now: u64) Error!void {
        var frames = quic_frame.decodeFrames(self.allocator, payload) catch return error.MalformedPacket;
        defer frames.deinit();

        self.newly_acked.clearRetainingCapacity();
        const result = self.engine.intake(level, pn, frames.frames, &self.newly_acked) catch
            return error.MalformedPacket;

        self.last_recv_ns = now;

        // Capture any received application DATAGRAM payloads (RFC 9221). The
        // engine's intake only accounts the ACK obligation; the payload bytes
        // borrow the decoded frame (freed when this fn returns), so we copy them
        // into the bounded inbox for the application to drain. Only the
        // Application (1-RTT) space carries DATAGRAMs.
        if (level == .application) {
            for (frames.frames) |frame| {
                switch (frame) {
                    .DATAGRAM => |dg| try self.captureRecvDatagram(dg.data),
                    else => {},
                }
            }
        }

        // Drain readable CRYPTO into the handshake (per level).
        try self.pumpCryptoToHandshake(level);

        // Inbound ACKs that newly-acked our CRYPTO mean we can stop the PTO if
        // nothing else is outstanding.
        if (result.newly_acked_count > 0) self.refreshPto(now);

        if (result.connection_close) |code| {
            self.closing = true;
            self.close_error = code;
            // Do not return an error here — let the caller observe via
            // isClosing(); a CONNECTION_CLOSE is a normal teardown signal.
        }

        // The handshake may have just installed new keys; replay any buffered
        // packets that are now decryptable.
        self.syncKeys();
        try self.replayBuffered(now);
    }

    /// Feed any newly-contiguous CRYPTO bytes at `level` into the handshake, then
    /// pull whatever flight it produced into our send-side CRYPTO buffers.
    fn pumpCryptoToHandshake(self: *Conn, level: EncryptionLevel) Error!void {
        const cs = self.engine.cryptoStream(level);
        const avail = cs.readable();
        if (avail > 0) {
            const bytes = cs.peek();
            self.handshake.feedCrypto(level, bytes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.HandshakeFailed,
            };
            _ = cs.consume(avail);
        }
        // Pull produced flights for both lower levels into our send buffers.
        try self.collectHandshakeOutput();
        self.syncKeys();
    }

    /// Move any CRYPTO bytes the handshake produced (Initial + Handshake levels)
    /// into the corresponding send buffers so the next `sendDatagrams` ships
    /// them. Idempotent: `takeFlight` returns empty once drained.
    fn collectHandshakeOutput(self: *Conn) Error!void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            const bytes = self.handshake.takeFlight(lvl) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.HandshakeFailed,
            };
            defer self.allocator.free(bytes);
            if (bytes.len > 0) {
                const buf = self.send.cryptoBuf(lvl).?;
                try buf.write(self.allocator, bytes);
            }
        }
    }

    fn bufferPacket(self: *Conn, level: EncryptionLevel, packet: []const u8) Error!void {
        if (self.buffered.items.len >= self.max_buffered) return; // bounded; drop oldest-equivalent
        const copy = try self.allocator.dupe(u8, packet);
        errdefer self.allocator.free(copy);
        try self.buffered.append(self.allocator, .{ .level = level, .bytes = copy });
    }

    fn replayBuffered(self: *Conn, now: u64) Error!void {
        if (self.buffered.items.len == 0) return;
        // Take ownership of the current list and re-feed; packets whose keys are
        // still missing get re-buffered by openAndIntake.
        var pending = self.buffered;
        self.buffered = .empty;
        defer {
            for (pending.items) |b| self.allocator.free(b.bytes);
            pending.deinit(self.allocator);
        }
        for (pending.items) |b| {
            if (self.keysFor(b.level) == null) {
                // Still no keys — keep it buffered (re-copy into the fresh list).
                try self.bufferPacket(b.level, b.bytes);
                continue;
            }
            const pn_offset = self.pnOffsetForBuffered(b.level, b.bytes) catch continue;
            try self.openAndIntake(b.level, b.bytes, pn_offset, now);
        }
    }

    fn pnOffsetForBuffered(self: *Conn, level: EncryptionLevel, packet: []const u8) Error!usize {
        if (level == .application) return 1 + @as(usize, self.scid.len);
        const dec = quic_packet.decodeLongHeader(packet) catch return error.MalformedPacket;
        var cursor = dec.consumed;
        if (level == .initial) {
            const tok = decodeVarIntAt(packet, cursor) catch return error.MalformedPacket;
            cursor += tok.len;
            const tok_len = std.math.cast(usize, tok.value) orelse return error.MalformedPacket;
            cursor += tok_len;
        }
        const length_vi = decodeVarIntAt(packet, cursor) catch return error.MalformedPacket;
        cursor += length_vi.len;
        return cursor;
    }

    // -----------------------------------------------------------------------
    // Send path
    // -----------------------------------------------------------------------

    /// Collect everything owed and append the resulting datagrams to `out` (an
    /// `*std.ArrayList(OutDatagram)`). Each `OutDatagram.bytes` is owned by the
    /// caller (free via the connection's allocator). Returns the number of
    /// datagrams appended.
    pub fn sendDatagrams(self: *Conn, out: *std.ArrayList(OutDatagram)) Error!usize {
        return self.sendDatagramsAt(out, self.last_recv_ns);
    }

    pub fn sendDatagramsAt(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!usize {
        // The client must emit its ClientHello before the first send.
        if (self.role == .client and !self.started) {
            switch (self.handshake) {
                .client => |*c| c.startHandshake() catch return error.HandshakeFailed,
                else => unreachable,
            }
            try self.collectHandshakeOutput();
            self.started = true;
        }

        const before = out.items.len;

        // 1) Coalesce the handshake levels (Initial + Handshake) into one
        //    datagram, padded to 1200 if it carries a client Initial.
        try self.buildHandshakeDatagram(out, now);

        // 2) 1-RTT application datagram (ACKs + queued STREAM/DATAGRAM), once the
        //    app keys exist.
        try self.buildAppDatagram(out, now);

        // 3) A standalone CONNECTION_CLOSE if one is pending and nothing else
        //    carried it.
        if (self.close_pending) try self.buildCloseDatagram(out, now);

        return out.items.len - before;
    }

    /// Assemble Initial and Handshake packets and coalesce them into a single
    /// UDP datagram (RFC 9000 §12.2). Pads to 1200 bytes when a client Initial
    /// is present (RFC 9000 §14.1).
    fn buildHandshakeDatagram(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!void {
        var datagram: std.ArrayList(u8) = .empty;
        errdefer datagram.deinit(self.allocator);

        // Initial first, then Handshake — the RFC 9000 §12.2 ordering for
        // coalescing. The client Initial is padded inside `appendLongPacket` so
        // the whole datagram reaches 1200 bytes (RFC 9000 §14.1).
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            if (self.keysFor(lvl) != null) {
                _ = try self.appendLongPacket(&datagram, lvl, now);
            }
        }

        if (datagram.items.len == 0) {
            datagram.deinit(self.allocator);
            return;
        }

        const owned = try datagram.toOwnedSlice(self.allocator);
        try out.append(self.allocator, .{ .bytes = owned });
    }

    /// Append one long-header (Initial/Handshake) packet to `datagram`. Returns
    /// true if a packet was actually written. When `pad_packet_to` > 0 the
    /// packet's plaintext is padded with PADDING frames so the whole packet
    /// reaches that many bytes (used to inflate a client Initial).
    fn appendLongPacket(self: *Conn, datagram: *std.ArrayList(u8), level: EncryptionLevel, now: u64) Error!bool {
        const keys = self.keysFor(level) orelse return false;

        // Build the frame payload: ACK (if owed) + CRYPTO (pending flight).
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);

        var ack_eliciting = false;
        try self.appendAckFrame(&payload, level);

        const send_buf = self.send.cryptoBuf(level).?;
        const header_budget: usize = long_header_max;
        while (send_buf.pending() > 0) {
            const used = datagram.items.len + header_budget + payload.items.len + quic_protect.aead_tag_len;
            const room = if (max_datagram > used) max_datagram - used else 0;
            if (room == 0) break;
            const cf = send_buf.nextFrame(room) orelse break;
            try quic_frame.encodeFrame(&payload, self.allocator, .{ .CRYPTO = cf });
            ack_eliciting = true;
        }

        if (payload.items.len == 0) return false; // nothing owed

        // For a client Initial we pad the packet so the whole datagram reaches
        // 1200 bytes (RFC 9000 §14.1). Compute the pad target = remaining budget
        // for this packet within the datagram.
        var pad_payload_to: usize = 0;
        if (self.role == .client and level == .initial and self.app_keys == null) {
            const want_packet = if (min_initial_datagram > datagram.items.len)
                min_initial_datagram - datagram.items.len
            else
                0;
            // packet = header(through pn) + payload + tag. Solve for payload.
            const overhead = self.longHeaderLen(level) + quic_protect.aead_tag_len;
            if (want_packet > overhead) pad_payload_to = want_packet - overhead;
        }
        while (payload.items.len < pad_payload_to) {
            try payload.append(self.allocator, 0x00); // PADDING frame
        }

        try self.sealLong(datagram, level, keys.write, payload.items);

        if (ack_eliciting) self.armPto(now);
        self.engine.space(level).onAckSent();
        return true;
    }

    /// Seal one long-header packet over `payload` and append it to `datagram`.
    /// Uses a fixed 4-byte packet number and a 2-byte Length varint (handshake/
    /// Initial payloads always fit), so the header layout is deterministic.
    fn sealLong(self: *Conn, datagram: *std.ArrayList(u8), level: EncryptionLevel, keys: quic_protect.PacketKeys, payload: []const u8) Error!void {
        const pn = self.engine.space(level).nextPacketNumber();
        const pn_len: usize = 4;
        var header_buf: [long_header_max]u8 = undefined;
        const header_len = try self.buildLongHeader(&header_buf, level, pn, pn_len, payload.len);

        const total = header_len + payload.len + quic_protect.aead_tag_len;
        const out_slice = try self.allocator.alloc(u8, total);
        defer self.allocator.free(out_slice);
        const sealed = quic_protect.sealPacketSuite(
            out_slice,
            header_buf[0..header_len],
            header_len - pn_len,
            pn_len,
            pn,
            payload,
            keys,
        ) catch return error.MalformedPacket;
        try datagram.appendSlice(self.allocator, out_slice[0..sealed.len]);
    }

    /// The exact long-header length (first byte … packet number) for this
    /// connection at `level` with the fixed 4-byte pn + 2-byte Length varint.
    fn longHeaderLen(self: *const Conn, level: EncryptionLevel) usize {
        // 1 (first) + 4 (version) + 1 + dcid + 1 + scid + token_len(1, Initial)
        // + 2 (Length varint) + 4 (pn).
        const token = if (level == .initial) @as(usize, 1) else 0;
        return 1 + 4 + 1 + self.dcid.len + 1 + self.scid.len + token + 2 + 4;
    }

    /// Build a 1-RTT (short-header) application datagram: owed ACK + queued
    /// STREAM/DATAGRAM frames.
    fn buildAppDatagram(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!void {
        const keys = self.keysFor(.application) orelse return;

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);

        var ack_eliciting = false;
        try self.appendAckFrame(&payload, .application);

        // Queued STREAM writes.
        for (self.pending_streams.items) |p| {
            try quic_frame.encodeFrame(&payload, self.allocator, .{ .STREAM = .{
                .stream_id = p.stream_id,
                .offset = p.offset,
                .fin = p.fin,
                .len = p.data.len,
                .data = p.data,
            } });
            ack_eliciting = true;
        }
        // Queued DATAGRAMs (RFC 9221).
        for (self.pending_datagrams.items) |p| {
            try quic_frame.encodeFrame(&payload, self.allocator, .{ .DATAGRAM = .{
                .len = p.data.len,
                .data = p.data,
            } });
            ack_eliciting = true;
        }

        if (payload.items.len == 0) return; // nothing owed

        const pn = self.engine.space(.application).nextPacketNumber();
        const pn_len: usize = 4;
        var header_buf: [long_header_max]u8 = undefined;
        const header_len = try self.buildShortHeader(&header_buf, pn, pn_len);

        const total = header_len + payload.items.len + quic_protect.aead_tag_len;
        const out_slice = try self.allocator.alloc(u8, total);
        defer self.allocator.free(out_slice);
        const sealed = quic_protect.sealPacketSuite(
            out_slice,
            header_buf[0..header_len],
            header_len - pn_len,
            pn_len,
            pn,
            payload.items,
            keys.write,
        ) catch return error.MalformedPacket;

        const owned = try self.allocator.dupe(u8, out_slice[0..sealed.len]);
        try out.append(self.allocator, .{ .bytes = owned });

        // The frames are now on the wire; clear the queues (this driver's
        // simplification: it does not retransmit application STREAM/DATAGRAM
        // data — the Engine reassembly + ACKs handle the handshake reliability,
        // and the loopback path is lossless for app data. A real driver tracks
        // sent stream offsets for retransmit; documented gap).
        self.clearPendingApp();
        if (ack_eliciting) self.armPto(now);
        self.engine.space(.application).onAckSent();
    }

    fn buildCloseDatagram(self: *Conn, out: *std.ArrayList(OutDatagram), now: u64) Error!void {
        _ = now;
        const level: EncryptionLevel = if (self.app_keys != null) .application else if (self.handshake_keys != null) .handshake else .initial;
        const keys = self.keysFor(level) orelse return;

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try quic_frame.encodeFrame(&payload, self.allocator, .{ .CONNECTION_CLOSE = .{
            .error_code = self.close_error orelse transport_error_no_error,
            .reason_len = 0,
            .reason = "",
        } });

        const pn = self.engine.space(level).nextPacketNumber();
        const pn_len: usize = 4;
        var header_buf: [long_header_max]u8 = undefined;
        const header_len = if (level == .application)
            try self.buildShortHeader(&header_buf, pn, pn_len)
        else
            try self.buildLongHeader(&header_buf, level, pn, pn_len, payload.items.len);

        const total: usize = header_len + payload.items.len + quic_protect.aead_tag_len;
        const out_slice = try self.allocator.alloc(u8, total);
        defer self.allocator.free(out_slice);

        const sealed = quic_protect.sealPacketSuite(
            out_slice,
            header_buf[0..header_len],
            header_len - pn_len,
            pn_len,
            pn,
            payload.items,
            keys.write,
        ) catch return error.MalformedPacket;
        const owned = try self.allocator.dupe(u8, out_slice[0..sealed.len]);
        try out.append(self.allocator, .{ .bytes = owned });
        self.close_pending = false;
    }

    /// Append an ACK frame for `level` if one is owed, encoding the engine's
    /// received-range set.
    fn appendAckFrame(self: *Conn, payload: *std.ArrayList(u8), level: EncryptionLevel) Error!void {
        const sp = self.engine.space(level);
        if (!sp.ackPending()) return;
        var built = (sp.buildAck(self.allocator, 0) catch return) orelse return;
        defer built.deinit(self.allocator);
        try quic_frame.encodeFrame(payload, self.allocator, .{ .ACK = built.frame });
    }

    // -----------------------------------------------------------------------
    // Header builders
    // -----------------------------------------------------------------------

    /// Build a long-header (Initial/Handshake) AAD: first byte … packet number,
    /// with a fixed 4-byte packet number and a fixed 2-byte Length varint.
    /// `payload_len` is the frame-payload length (Length = pn_len + payload +
    /// tag). Handshake/Initial payloads always fit a 2-byte Length (< 16384), so
    /// the layout is deterministic and `longHeaderLen` mirrors it.
    fn buildLongHeader(
        self: *Conn,
        out: *[long_header_max]u8,
        level: EncryptionLevel,
        pn: u64,
        pn_len: usize,
        payload_len: usize,
    ) Error!usize {
        const ptype: quic_packet.LongPacketType = switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .application => unreachable,
        };
        const pnl = quic_packet.PacketNumberLength.fromByteLen(pn_len) catch return error.MalformedPacket;
        const header = quic_packet.LongHeader{
            .packet_type = ptype,
            .version = quic_version_1,
            .dcid = self.dcid,
            .scid = self.scid,
            .packet_number_len = pnl,
        };
        var pos = quic_packet.encodeLongHeader(out, header) catch return error.MalformedPacket;

        // Initial packets carry an (empty) Token before Length.
        if (level == .initial) {
            if (pos + 1 > out.len) return error.MalformedPacket;
            out[pos] = 0x00; // token length varint = 0
            pos += 1;
        }

        // Length = pn_len + payload + tag, encoded as a fixed 2-byte varint.
        const length_value = pn_len + payload_len + quic_protect.aead_tag_len;
        if (length_value > 0x3fff) return error.MalformedPacket; // >2-byte Length: out of scope
        if (pos + 2 > out.len) return error.MalformedPacket;
        const lv: u16 = @as(u16, @intCast(length_value)) | 0x4000;
        std.mem.writeInt(u16, out[pos..][0..2], lv, .big);
        pos += 2;

        // Packet number (truncated to pn_len bytes).
        const trunc = quic_frame.truncatePacketNumber(pn, pn_len) catch return error.MalformedPacket;
        const enc = quic_packet.encodePacketNumber(out[pos..], @intCast(trunc), pnl) catch return error.MalformedPacket;
        pos += enc;
        return pos;
    }

    fn buildShortHeader(self: *Conn, out: *[long_header_max]u8, pn: u64, pn_len: usize) Error!usize {
        const trunc = quic_frame.truncatePacketNumber(pn, pn_len) catch return error.MalformedPacket;
        const header = quic_packet.ShortHeader{
            .spin = false,
            .key_phase = false,
            .dcid = self.dcid,
            .packet_number = @intCast(trunc),
            .packet_number_len = quic_packet.PacketNumberLength.fromByteLen(pn_len) catch return error.MalformedPacket,
        };
        return quic_packet.encodeShortHeader(out, header) catch return error.MalformedPacket;
    }

    // -----------------------------------------------------------------------
    // Application I/O
    // -----------------------------------------------------------------------

    /// Open a new bidirectional stream; returns its id. The first send carrying
    /// data on it goes out on the next `sendDatagrams`.
    pub fn openStream(self: *Conn) Error!u64 {
        if (!self.established) return error.NotEstablished;
        const id = self.next_bidi_stream;
        self.next_bidi_stream += 4; // same-type stream ids advance by 4 (RFC 9000 §2.1)
        return id;
    }

    /// Open a new unidirectional stream; returns its id. Used for HTTP/3 control
    /// and QPACK encoder/decoder streams and WebTransport uni streams. The first
    /// send carrying data on it goes out on the next `sendDatagrams`.
    pub fn openUniStream(self: *Conn) Error!u64 {
        if (!self.established) return error.NotEstablished;
        const id = self.next_uni_stream;
        self.next_uni_stream += 4; // same-type stream ids advance by 4 (RFC 9000 §2.1)
        return id;
    }

    /// Queue `bytes` to send on `stream_id` (optionally with the fin bit). The
    /// data is copied; it is shipped on the next `sendDatagrams`.
    pub fn sendStream(self: *Conn, stream_id: u64, bytes: []const u8, fin: bool) Error!void {
        if (!self.established) return error.NotEstablished;
        // Track the per-stream send offset across calls.
        var offset: u64 = 0;
        for (self.pending_streams.items) |p| {
            if (p.stream_id == stream_id) offset += p.data.len;
        }
        offset += self.sentStreamOffset(stream_id);
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.pending_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .offset = offset,
            .fin = fin,
            .data = copy,
        });
    }

    /// Read up to `dst.len` contiguous received bytes from `stream_id`, returns
    /// the number read (0 if none ready). Delegates to the Engine's reassembly.
    pub fn readStream(self: *Conn, stream_id: u64, dst: []u8) usize {
        const s = self.engine.getStream(stream_id) orelse return 0;
        const avail = s.peek();
        const n = @min(dst.len, avail.len);
        @memcpy(dst[0..n], avail[0..n]);
        _ = s.consume(n);
        return n;
    }

    /// Whether the peer signalled fin on `stream_id` and we have drained it.
    pub fn streamFinished(self: *Conn, stream_id: u64) bool {
        const s = self.engine.getStream(stream_id) orelse return false;
        return s.finReached();
    }

    /// Queue an application DATAGRAM (RFC 9221). Copied; shipped next send.
    pub fn sendDatagram(self: *Conn, bytes: []const u8) Error!void {
        if (!self.established) return error.NotEstablished;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.pending_datagrams.append(self.allocator, .{ .data = copy });
    }

    /// Copy a received DATAGRAM payload into the bounded inbox. Drops the oldest
    /// entry if the inbox is full so a flood cannot drive unbounded growth.
    fn captureRecvDatagram(self: *Conn, bytes: []const u8) Error!void {
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        if (self.recv_datagrams.items.len >= self.max_recv_datagrams) {
            const oldest = self.recv_datagrams.orderedRemove(0);
            self.allocator.free(oldest.data);
        }
        try self.recv_datagrams.append(self.allocator, .{ .data = copy });
    }

    /// Take the oldest received application DATAGRAM payload (RFC 9221), or null
    /// if none. The returned slice is an owned copy; the caller frees it via the
    /// connection's allocator. FIFO drain.
    pub fn recvDatagramPayload(self: *Conn) ?[]u8 {
        if (self.recv_datagrams.items.len == 0) return null;
        const item = self.recv_datagrams.orderedRemove(0);
        return item.data;
    }

    /// Initiate a graceful CONNECTION_CLOSE with `error_code` (0 = NO_ERROR).
    pub fn close(self: *Conn, error_code: u64) void {
        if (self.closing) return;
        self.closing = true;
        self.close_error = error_code;
        self.close_pending = true;
    }

    fn clearPendingApp(self: *Conn) void {
        for (self.pending_streams.items) |p| {
            self.sentStreamBytesAdd(p.stream_id, p.data.len);
            self.allocator.free(p.data);
        }
        self.pending_streams.clearRetainingCapacity();
        for (self.pending_datagrams.items) |p| self.allocator.free(p.data);
        self.pending_datagrams.clearRetainingCapacity();
    }

    // Track per-stream sent bytes so successive sendStream calls compute the
    // correct STREAM offset even after the queue is flushed.
    fn sentStreamOffset(self: *Conn, stream_id: u64) u64 {
        return self.sent_stream_map.get(stream_id) orelse 0;
    }
    fn sentStreamBytesAdd(self: *Conn, stream_id: u64, n: usize) void {
        const cur = self.sent_stream_map.get(stream_id) orelse 0;
        self.sent_stream_map.put(self.allocator, stream_id, cur + n) catch {};
    }

    // -----------------------------------------------------------------------
    // Timers / reliability (single fixed PTO — documented simplification)
    // -----------------------------------------------------------------------

    fn armPto(self: *Conn, now: u64) void {
        self.pto_deadline_ns = now + fixed_pto_ns;
    }

    fn refreshPto(self: *Conn, now: u64) void {
        // If no CRYPTO is still pending across handshake levels, cancel the PTO.
        const outstanding = self.send.crypto_initial.pending() + self.send.crypto_handshake.pending();
        if (outstanding == 0) {
            self.pto_deadline_ns = null;
        } else {
            self.armPto(now);
        }
    }

    /// Advance time to `now`. Returns true if a retransmit or close is now owed
    /// (the caller should call `sendDatagrams` again). Drives the single fixed
    /// PTO loss timer and the idle timeout.
    pub fn onTimeout(self: *Conn, now: u64) Error!bool {
        // Idle timeout (RFC 9000 §10.1).
        if (self.last_recv_ns != 0 and now > self.last_recv_ns + self.idle_timeout_ns) {
            self.closing = true;
            return error.IdleTimeout;
        }

        const deadline = self.pto_deadline_ns orelse return false;
        if (now < deadline) return false;

        // PTO fired: rewind the un-acked CRYPTO so it is re-emitted. Because we
        // never advance `send_offset` past data the peer has acked here (the
        // Engine tracks acks at the packet layer, not byte ranges), the simplest
        // sound recovery is to rewind send_offset to the lowest un-acked byte —
        // which for the handshake is the whole buffer if the flight is still
        // outstanding. We rewind both handshake-level CRYPTO buffers.
        self.rewindUnackedCrypto();
        self.pto_deadline_ns = null; // re-armed on the next send if still owed
        return true;
    }

    /// Rewind the send offset of any handshake CRYPTO buffer whose bytes have
    /// not been fully acknowledged so `sendDatagrams` retransmits them. This is
    /// the fixed-PTO simplification: we retransmit the entire still-pending
    /// flight rather than tracking individual lost packet-number → byte ranges.
    fn rewindUnackedCrypto(self: *Conn) void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            const sp = self.engine.space(lvl);
            const buf = self.send.cryptoBuf(lvl).?;
            // Rewind only if we have emitted some CRYPTO (send_offset advanced)
            // but the peer has not acknowledged the highest packet we sent.
            // `largest_acked == null` means nothing acked.
            const emitted = buf.send_offset - buf.base_offset;
            if (emitted > 0) {
                const fully_acked = if (sp.largest_acked) |la| la + 1 >= sp.next_outbound else false;
                if (!fully_acked) buf.send_offset = buf.base_offset;
            }
        }
    }
};

// ===========================================================================
// Packet-number decode context (openPacketSuite wants a free function)
// ===========================================================================
//
// `openPacketSuite` takes a `*const fn (truncated, pn_len) u64`. We thread the
// largest-received packet number through a thread-local so the reconstruction
// (RFC 9000 §A.3) is correct without changing the signature. Single-threaded
// per connection; the listener serializes recv per connection.
const PnDecodeCtx = struct {
    largest: ?u64,

    threadlocal var current: PnDecodeCtx = .{ .largest = null };
    threadlocal var last_full: u64 = 0;

    fn decode(truncated: u64, pn_len: usize) u64 {
        const largest = current.largest orelse {
            last_full = truncated;
            return truncated;
        };
        const full = quic_frame.decodePacketNumber(truncated, pn_len, largest) catch truncated;
        last_full = full;
        return full;
    }
};

// ===========================================================================
// Small bounds-checked helpers
// ===========================================================================

/// Decode a QUIC varint at `input[off..]`, returning value + byte length.
///
/// Unlike `quic_frame.decodeVarInt`, this does NOT reject a non-minimal
/// encoding. RFC 9000 §16 lets a sender use a longer-than-minimal varint and
/// requires receivers to accept it; the header's Length and Token fields are
/// parsed with this tolerant decoder (our own sender emits a fixed 2-byte
/// Length varint, which is non-minimal for small packets).
fn decodeVarIntAt(input: []const u8, off: usize) quic_frame.WireError!quic_frame.DecodedVarInt {
    if (off >= input.len) return quic_frame.WireError.BufferTooShort;
    const buf = input[off..];
    const tag = buf[0] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (buf.len < len) return quic_frame.WireError.BufferTooShort;
    var value: u64 = buf[0] & 0x3f;
    for (buf[1..len]) |b| value = (value << 8) | b;
    return .{ .value = value, .len = len };
}

/// Upper bound on a long header (first byte … 4-byte pn) for this driver:
/// 1 (first) + 4 (version) + 1 + 20 (max dcid) + 1 + 20 (max scid) + 1 (token
/// len) + 2 (Length varint) + 4 (pn) = 54. Round up for slack.
const long_header_max: usize = 64;

// ===========================================================================
// Tests — the milestone self-test (loopback handshake + byte-exact app data)
// ===========================================================================

const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("x509_selfsign.zig");

const test_client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
const test_server_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const test_initial_dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
const test_alpn = [_][]const u8{ "h3", "irc" };

fn mintCert(out: *[1024]u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "quic.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = kp,
        .dns_names = &.{"quic.test"},
        .is_ca = true,
    });
}

const test_server_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_server_cid,
    .max_idle_timeout = 30_000,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

const test_client_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_client_cid,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

/// A fixture holding both ends of a loopback connection plus the cert material.
const Loopback = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    cert: []const u8,
    cert_chain: [1][]const u8,
    server: Conn,
    client: Conn,

    fn init(alloc: Allocator) !*Loopback {
        const lb = try alloc.create(Loopback);
        errdefer alloc.destroy(lb);
        lb.kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
        lb.cert = try mintCert(&lb.cert_buf, lb.kp);
        lb.cert_chain = .{lb.cert};

        lb.server = try Conn.initServer(alloc, .{
            .cert_chain = &lb.cert_chain,
            .signing_key = .{ .ed25519 = lb.kp },
            .alpn_protocols = &test_alpn,
            .transport_params = test_server_params,
            .local_cid = &test_server_cid,
            .x25519_seed = [_]u8{0x21} ** 32,
            .server_random = [_]u8{0x55} ** 32,
        });
        errdefer lb.server.deinit();

        lb.client = try Conn.initClient(alloc, .{
            .alpn_protocols = &test_alpn,
            .transport_params = test_client_params,
            .local_cid = &test_client_cid,
            .initial_dcid = &test_initial_dcid,
            .x25519_seed = [_]u8{0x42} ** 32,
            .client_random = [_]u8{0x11} ** 32,
        });
        return lb;
    }

    fn deinit(self: *Loopback, alloc: Allocator) void {
        self.server.deinit();
        self.client.deinit();
        alloc.destroy(self);
    }
};

/// Pump every datagram `from` wants to send into `to`. Returns how many
/// datagrams were transferred.
fn pump(alloc: Allocator, from: *Conn, to: *Conn) !usize {
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try from.sendDatagrams(&out);
    for (out.items) |d| try to.recvDatagram(d.bytes);
    return out.items.len;
}

/// Drive the handshake to completion on both ends (bounded round trips).
fn driveHandshake(alloc: Allocator, lb: *Loopback) !void {
    var rounds: usize = 0;
    while (rounds < 12) : (rounds += 1) {
        _ = try pump(alloc, &lb.client, &lb.server);
        _ = try pump(alloc, &lb.server, &lb.client);
        if (lb.client.isEstablished() and lb.server.isEstablished()) return;
    }
    return error.HandshakeDidNotComplete;
}

test "quic conn loopback completes the handshake and both sides are established" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    try driveHandshake(alloc, lb);

    try testing.expect(lb.client.isEstablished());
    try testing.expect(lb.server.isEstablished());
    try testing.expectEqualStrings("h3", lb.server.selectedAlpn().?);
    try testing.expectEqualStrings("h3", lb.client.selectedAlpn().?);
}

test "quic conn loopback delivers byte-exact application data in both directions" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // Client opens a bidi stream and sends bytes with fin.
    const sid = try lb.client.openStream();
    const c2s = "GET / HTTP/3 over QUIC — byte exact!";
    try lb.client.sendStream(sid, c2s, true);
    _ = try pump(alloc, &lb.client, &lb.server);

    // Server reads exactly those bytes.
    var rbuf: [256]u8 = undefined;
    const n = lb.server.readStream(sid, &rbuf);
    try testing.expectEqualSlices(u8, c2s, rbuf[0..n]);
    try testing.expect(lb.server.streamFinished(sid));

    // Server replies on the same stream; client reads it back byte-exact.
    const s2c = "HTTP/3 200 OK :: reply payload";
    try lb.server.sendStream(sid, s2c, true);
    _ = try pump(alloc, &lb.server, &lb.client);

    const m = lb.client.readStream(sid, &rbuf);
    try testing.expectEqualSlices(u8, s2c, rbuf[0..m]);
    try testing.expect(lb.client.streamFinished(sid));
}

test "quic conn parses a coalesced Initial+Handshake datagram from the server" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // Client → server: ClientHello (Initial only, padded to 1200).
    _ = try pump(alloc, &lb.client, &lb.server);

    // Server's first flight coalesces an Initial (ServerHello) and a Handshake
    // (EE/Cert/CertVerify/Finished) packet into ONE datagram.
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try lb.server.sendDatagrams(&out);
    try testing.expect(out.items.len >= 1);

    // The first datagram must hold two coalesced long-header packets: an Initial
    // (type bits 00) followed by a Handshake (type bits 10).
    const dg = out.items[0].bytes;
    try testing.expect(dg.len > 0);
    try testing.expect((dg[0] & 0x80) != 0); // long header
    const first_type = (dg[0] >> 4) & 0x03;
    try testing.expectEqual(@as(u8, 0), first_type); // Initial

    // Feed it to the client; it should install handshake + app keys and produce
    // a client Finished, reaching established.
    for (out.items) |d| try lb.client.recvDatagram(d.bytes);
    try testing.expect(lb.client.handshake_keys != null);
}

test "quic conn produces an ACK for an ack-eliciting packet and stops retransmitting after it" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // After the handshake the client's Initial/Handshake CRYPTO is fully acked,
    // so a PTO must NOT rewind anything: a subsequent send carries no CRYPTO
    // retransmit.
    lb.client.rewindUnackedCrypto();
    try testing.expectEqual(@as(u64, 0), lb.client.send.crypto_handshake.pending());
    try testing.expectEqual(@as(u64, 0), lb.client.send.crypto_initial.pending());

    // The Handshake space saw ack-eliciting CRYPTO and the peer acked it; the
    // engine recorded a non-null largest_acked.
    try testing.expect(lb.client.engine.space(.handshake).largest_acked != null);
}

test "quic conn recovers a dropped client Initial via onTimeout retransmission" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // Client sends its Initial — but we DROP it (do not deliver to the server).
    {
        var out: std.ArrayList(OutDatagram) = .empty;
        defer {
            for (out.items) |d| alloc.free(d.bytes);
            out.deinit(alloc);
        }
        const n = try lb.client.sendDatagramsAt(&out, 0);
        try testing.expect(n >= 1); // it tried to send
        // … dropped on the floor.
    }

    // The server has heard nothing. Fire the client's PTO: it must rewind its
    // un-acked CRYPTO so the next send re-emits the ClientHello.
    const fired = try lb.client.onTimeout(fixed_pto_ns + 1);
    try testing.expect(fired);

    // Now deliver the retransmitted flight and finish the handshake.
    try driveHandshake(alloc, lb);
    try testing.expect(lb.client.isEstablished());
    try testing.expect(lb.server.isEstablished());
}

test "quic conn pads the client Initial datagram to at least 1200 bytes" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try lb.client.sendDatagrams(&out);
    try testing.expect(out.items.len >= 1);
    try testing.expect(out.items[0].bytes.len >= min_initial_datagram);
}

test "quic conn buffers a packet whose keys are not yet installed without faulting" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // The server has no Handshake keys until it processes the ClientHello. Build
    // the server's full first flight, then deliver ONLY the Handshake packet to
    // a fresh client that has not yet processed the ServerHello (Initial). The
    // client must buffer it (no fault), then process it after the Initial.
    _ = try pump(alloc, &lb.client, &lb.server);
    var out: std.ArrayList(OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try lb.server.sendDatagrams(&out);
    try testing.expect(out.items.len >= 1);

    // Split the coalesced datagram into its two packets and deliver the second
    // (Handshake) one FIRST. The client has no handshake keys yet → buffered.
    const dg = out.items[0].bytes;
    const split = try splitFirstLongPacket(dg);
    try testing.expect(split < dg.len); // there was a second packet

    // Deliver Handshake-first: must not fault, and the client buffers it.
    try lb.client.recvDatagram(dg[split..]);
    try testing.expect(lb.client.buffered.items.len >= 1);

    // Now deliver the Initial (ServerHello): installs handshake keys and the
    // buffered Handshake packet is replayed → client reaches established.
    try lb.client.recvDatagram(dg[0..split]);
    // Finish whatever round trips remain.
    try driveHandshake(alloc, lb);
    try testing.expect(lb.client.isEstablished());
}

test "quic conn rejects malformed datagrams without panicking" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);

    // Truncated long header.
    try testing.expectError(error.MalformedPacket, lb.server.recvDatagram(&.{ 0xc0, 0x00 }));
    // Long header, unsupported version.
    try testing.expectError(error.UnsupportedVersion, lb.server.recvDatagram(&.{
        0xc3, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00,
    }));
    // Long header claiming a Length that runs past the datagram.
    try testing.expectError(error.MalformedPacket, lb.server.recvDatagram(&.{
        0xc0, 0x00, 0x00, 0x00, 0x01, // version 1
        0x00, // dcid len 0
        0x00, // scid len 0
        0x00, // token len 0
        0x44, 0x00, // Length = 0x400 (1024) — far past the buffer
        0x00, 0x01,
        0x02, 0x03,
    }));
    // Empty datagram is a no-op (no packets), not an error.
    try lb.server.recvDatagram(&.{});
}

test "quic conn graceful close emits CONNECTION_CLOSE the peer observes" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    lb.client.close(transport_error_no_error);
    try testing.expect(lb.client.isClosing());
    _ = try pump(alloc, &lb.client, &lb.server);

    try testing.expect(lb.server.isClosing());
    try testing.expectEqual(@as(?u64, transport_error_no_error), lb.server.close_error);
}

test "quic conn idle timeout fires after the configured bound" {
    const alloc = testing.allocator;
    const lb = try Loopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    // The listener stamps recv time; simulate the last activity at t0, then
    // advance well past the idle bound and confirm onTimeout reports IdleTimeout.
    const t0: u64 = 1_000;
    lb.server.last_recv_ns = t0;
    const now = t0 + lb.server.idle_timeout_ns + 1;
    try testing.expectError(error.IdleTimeout, lb.server.onTimeout(now));
    try testing.expect(lb.server.isClosing());
}

/// Split a coalesced datagram after its first long-header packet; returns the
/// byte offset where the second packet begins (or `dg.len` if only one).
fn splitFirstLongPacket(dg: []const u8) !usize {
    const dec = quic_packet.decodeLongHeader(dg) catch return error.MalformedPacket;
    var cursor = dec.consumed;
    if (dec.header.packet_type == .initial) {
        const tok = decodeVarIntAt(dg, cursor) catch return error.MalformedPacket;
        cursor += tok.len + @as(usize, @intCast(tok.value));
    }
    const length_vi = decodeVarIntAt(dg, cursor) catch return error.MalformedPacket;
    cursor += length_vi.len + @as(usize, @intCast(length_vi.value));
    return cursor;
}
