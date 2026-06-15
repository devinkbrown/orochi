//! Daemon-owned WebTransport listener (layer 7): the live UDP endpoint that
//! turns the from-scratch QUIC (`quic_conn`) + HTTP/3 + WebTransport
//! (`http3_conn`) stack into a real running server, and bridges each
//! WebTransport session to the daemon's ordinary IRC listener over a loopback
//! TCP proxy.
//!
//! Threading model (mirrors `native_media_transport.zig` exactly): a single
//! pump thread blocks on a UDP socket with a short recv timeout so it can
//! observe the stop flag, and is torn down + joined on `shutdown`/`deinit`.
//! No reactor / dispatch changes: the daemon already serves IRC over TCP, so
//! the WT user is handed to it as an ordinary local client via a loopback TCP
//! connection — there is no cross-thread injection into the reactor.
//!
//! Data flow for one WebTransport session
//! --------------------------------------
//!   browser ──QUIC/H3/WT bidi stream──▶ this pump ──TCP 127.0.0.1:irc──▶ daemon
//!   daemon  ──TCP──▶ this pump ──writeWtStream──▶ browser
//! IRC is a CRLF line protocol; we proxy raw bytes and let the daemon do all
//! the IRC framing. The WT bidi data stream is the first bidi stream the client
//! opens after the session is established.
//!
//! Connection demux (per inbound datagram)
//! ---------------------------------------
//! QUIC carries the connection identity in the packet's Destination Connection
//! ID. We demux:
//!   * long-header (Initial / Handshake) packets by the *client-chosen* DCID
//!     (stable for the whole handshake, RFC 9001 §5.2); a previously-unseen
//!     Initial DCID mints a new connection with a server-chosen SCID.
//!   * short-header (1-RTT) packets by our server SCID (the DCID the client
//!     addresses once it has learned our SCID, RFC 9000 §7.2).
//! Both keys point at the same connection slot, so a connection is reachable by
//! either id across its lifetime.
//!
//! DoS resistance / bounds (documented simplifications)
//! ----------------------------------------------------
//!   * `max_connections` caps the live connection table; a flood of fresh
//!     Initials past the cap is dropped (no per-flood allocation).
//!   * Each `Conn`/`Http3Conn`/proxy is fixed-shape; the QUIC engine already
//!     bounds per-connection buffers (flow control, bounded datagram inbox).
//!   * Anti-amplification (RFC 9000 §8.1): every new server connection is
//!     amplification-limited to 3× the bytes received until the peer's address
//!     is validated (a decrypted Handshake packet, or a returned Retry token).
//!     This gate lives in the `quic_conn` layer; the listener feeds it.
//!   * Version Negotiation (RFC 9000 §17.2.1): an Initial with an unsupported
//!     QUIC version is answered with a VN packet (listing v1) and no connection
//!     is created. The VN reply is always ≤ the triggering Initial, never an
//!     amplifier.
//!   * Retry (RFC 9000 §8.1.2): OFF by default (fast path). When
//!     `retry_policy = .always` (or `.under_load` past `retry_load_threshold`
//!     live connections), a fresh Initial WITHOUT a valid address-validation
//!     token is answered with a Retry packet instead of proceeding; the client
//!     re-sends its Initial carrying the token and is validated immediately. A
//!     replayed/expired/wrong-IP token is rejected (falls back to a new Retry).
//!   * Stateless reset (RFC 9000 §10.3): token derivation is wired (per-process
//!     key, HMAC of the CID); the unknown-short-header SEND path is a documented
//!     follow-up — see `quic_retry.zig`.
//!   * One server SCID per connection, no connection migration.
//!   * One WebTransport session per QUIC connection, one IRC bridge per
//!     session (the common deployment shape; `http3_conn` rejects a 2nd CONNECT).
//!   * Dual-stack UDP socket (`DualStackUdpSocket`, `AF_INET6` + `IPV6_V6ONLY=0`,
//!     bound `[::]`): ONE socket serves both native IPv6 peers and IPv4 peers
//!     (the latter arrive as IPv4-mapped `::ffff:a.b.c.d`, surfaced back as real
//!     ipv4 `TransportAddress` for PROXY-protocol + logging). The per-connection
//!     peer address + reply path are family-agnostic — they already use
//!     `TransportAddress`. The media plane keeps its own IPv4-only `MediaSocket`.
//!   * PROXY-protocol carry of the real client address is OPTIONAL and OFF by
//!     default: the daemon sees the bridge's loopback identity. When the daemon
//!     trusts loopback as a PROXY source, set `send_proxy_header = true` to
//!     prepend a PROXY v1 line carrying the QUIC peer's address.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const quic_conn = @import("../proto/quic_conn.zig");
const quic_packet = @import("../proto/quic_packet.zig");
const quic_retry = @import("../proto/quic_retry.zig");
const http3_conn = @import("../proto/http3_conn.zig");
const quic_transport_params = @import("../proto/quic_transport_params.zig");
const quic_handshake = @import("../proto/quic_handshake.zig");
const proxy_protocol = @import("../proto/proxy_protocol.zig");
const media_socket = @import("../substrate/media_socket.zig");
const dualstack_udp = @import("dualstack_udp.zig");

pub const MediaSocket = media_socket.MediaSocket;
pub const DualStackUdpSocket = dualstack_udp.DualStackUdpSocket;
pub const TransportAddress = media_socket.TransportAddress;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;

/// Default cap on concurrent QUIC connections (DoS bound). A flood of fresh
/// handshakes past this is dropped without allocation.
pub const default_max_connections: usize = 256;

/// Default live-connection count at/above which the `.under_load` Retry policy
/// starts forcing a stateless Retry round trip (half the connection cap).
pub const default_retry_load_threshold: usize = 128;

/// Retry address-validation policy (RFC 9000 §8.1.2). See the field docs on
/// `WebTransportListener.retry_policy`.
pub const RetryPolicy = enum {
    /// Never issue a Retry; mint connections directly (anti-amplification still
    /// applies). The default fast path.
    never,
    /// Issue a Retry for every tokenless new Initial.
    always,
    /// Issue a Retry only once the live connection count reaches the threshold.
    under_load,
};

/// Scratch read buffer size for a single UDP datagram (QUIC keeps datagrams
/// under ~1252 bytes; allow generous slack).
const recv_buf_len: usize = 2048;

/// Scratch buffer for one TCP↔WT pump pass.
const proxy_chunk_len: usize = 4096;

/// Periodic timer tick: how often (in pump iterations of `recv_timeout_ms`) we
/// run `onTimeout` on every live connection to drive idle/PTO timers.
const recv_timeout_ms: u32 = 100;

pub const Error = error{
    AlreadyStarted,
    BindFailed,
} || std.mem.Allocator.Error;

/// TLS material + transport identity the listener needs to stand up a QUIC
/// server connection. Mirrors what the daemon already loaded for its TLS
/// listener; `signing_key` is whichever key matches the leaf cert.
pub const TlsConfig = struct {
    cert_chain: []const []const u8,
    signing_key: quic_handshake.SigningKey,
};

/// One live QUIC connection and everything layered on it: the HTTP/3 +
/// WebTransport driver and (once a session is established) the loopback TCP
/// proxy carrying IRC bytes.
const Connection = struct {
    /// Server-chosen source connection id (the DCID short-header packets carry).
    scid: [quic_packet.max_connection_id_len]u8,
    scid_len: u8,
    /// Client-chosen Initial DCID (stable for the handshake); the other demux key.
    init_dcid: [quic_packet.max_connection_id_len]u8,
    init_dcid_len: u8,
    /// The peer's UDP return address (learned from the first datagram; this layer
    /// does not support migration, so it is fixed for the connection's life).
    peer: TransportAddress,
    conn: *quic_conn.Conn,
    h3: *http3_conn.Http3Conn,
    /// Loopback TCP fd to the daemon's IRC listener, once a session establishes.
    irc_fd: ?linux.fd_t = null,
    /// Whether we already opened a server→client WT bidi stream for IRC output.
    /// We instead reuse the client's first WT bidi data stream; this records it.
    wt_stream_id: ?u64 = null,
    /// Whether the client's WT data stream has been observed yet.
    have_wt_stream: bool = false,

    fn scidSlice(self: *const Connection) []const u8 {
        return self.scid[0..self.scid_len];
    }
    fn initDcidSlice(self: *const Connection) []const u8 {
        return self.init_dcid[0..self.init_dcid_len];
    }
};

pub const WebTransportListener = struct {
    allocator: std.mem.Allocator,
    tls: TlsConfig,
    /// Local TCP port of the daemon's IRC listener (loopback bridge target).
    irc_port: u16,
    /// Prepend a PROXY-protocol v1 header carrying the real QUIC peer address.
    /// Off by default (loopback identity); see module doc.
    send_proxy_header: bool = false,
    max_connections: usize = default_max_connections,

    /// Retry policy (RFC 9000 §8.1.2). `.never` is the default fast path — a new
    /// Initial mints a connection directly (still anti-amplification-limited).
    /// `.always` issues a Retry for every tokenless Initial. `.under_load` issues
    /// a Retry only once the live connection count reaches `retry_load_threshold`
    /// (a cheap DoS valve: under attack, force every client through a stateless
    /// round trip before any per-connection state is allocated).
    retry_policy: RetryPolicy = .never,
    /// Live-connection count at/above which `.under_load` starts issuing Retries.
    retry_load_threshold: usize = default_retry_load_threshold,
    /// Per-process address-validation / stateless-reset key bundle (RFC 9000
    /// §8.1.2 / §10.3). Minted on first use from the OS CSPRNG.
    retry_secret: ?quic_retry.Secret = null,
    /// Bounded single-use cache for accepted Retry tokens (replay defense).
    token_replay: quic_retry.ReplayCache = .{},

    socket: ?DualStackUdpSocket = null,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Bound local UDP port (0 until started).
    port: u16 = 0,

    /// Demux table: connection-id (owned dupe) → connection index in `conns`.
    by_cid: std.StringHashMapUnmanaged(usize) = .empty,
    /// Live connections. A slot is null once torn down (compacted lazily).
    conns: std.ArrayListUnmanaged(?*Connection) = .empty,

    /// Monotonic counter feeding the server-chosen SCID so each connection gets
    /// a unique id (no migration / no rotation — one SCID per connection).
    scid_counter: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, tls: TlsConfig, irc_port: u16) WebTransportListener {
        return .{ .allocator = allocator, .tls = tls, .irc_port = irc_port };
    }

    pub fn deinit(self: *WebTransportListener) void {
        self.shutdown();
        // Tear down any connections that survived (shutdown joins the pump first,
        // so nothing races us here).
        for (self.conns.items) |maybe| {
            if (maybe) |c| self.destroyConnection(c);
        }
        self.conns.deinit(self.allocator);
        var it = self.by_cid.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.by_cid.deinit(self.allocator);
        self.* = undefined;
    }

    /// Bind on `bind_be`:`port` (port 0 = ephemeral) and spawn the pump thread.
    ///
    /// `bind_be` is the legacy IPv4-in-network-byte-order bind selector kept for
    /// the existing `main.zig`/test call sites; it is mapped onto the dual-stack
    /// socket's `BindAddr` (so the socket itself is always `AF_INET6` with
    /// `IPV6_V6ONLY=0`, serving both families):
    ///   * `any_be` (0.0.0.0) → bind `[::]` (all interfaces, both families).
    ///   * `loopback_be` (127.0.0.1) → bind `::ffff:127.0.0.1` (v4-mapped loopback).
    ///   * any other configured v4 address → bind it v4-mapped.
    pub fn start(self: *WebTransportListener, bind_be: u32, port: u16) Error!void {
        if (self.socket != null) return error.AlreadyStarted;
        var sock = DualStackUdpSocket.bind(bindAddrFromBe(bind_be), port) catch return error.BindFailed;
        errdefer sock.deinit();
        self.port = sock.localPort() catch return error.BindFailed;
        sock.setRecvTimeoutMs(recv_timeout_ms);
        self.socket = sock;

        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch {
            self.socket.?.deinit();
            self.socket = null;
            return error.BindFailed;
        };
    }

    /// Signal the pump to stop, join it, and close the UDP socket. Idempotent.
    pub fn shutdown(self: *WebTransportListener) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (self.socket) |*s| {
            s.deinit();
            self.socket = null;
        }
    }

    // -----------------------------------------------------------------------
    // Pump thread
    // -----------------------------------------------------------------------

    fn pumpLoop(self: *WebTransportListener) void {
        var buf: [recv_buf_len]u8 = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const sock = if (self.socket) |*s| s else return;
            if (sock.recvFrom(&buf)) |got| {
                self.handleDatagram(got.data, got.from);
            }
            // On every wake (datagram or timeout) advance per-connection timers
            // and pump the IRC bridges. This is the periodic tick.
            self.serviceAll();
        }
    }

    /// Process one inbound UDP datagram: demux to (or create) a connection, feed
    /// the QUIC engine, service H3/WT, and flush owed datagrams to the peer.
    ///
    /// A previously-unseen connection id triggers the address-validation policy
    /// (RFC 9000 §8): Version Negotiation for an unsupported version, an optional
    /// Retry to force an address round trip, and — once a connection is minted —
    /// the per-connection 3× anti-amplification limit in `quic_conn`.
    fn handleDatagram(self: *WebTransportListener, data: []const u8, from: TransportAddress) void {
        if (data.len == 0) return;
        const cid = peekDestCid(data) orelse return;

        if (self.lookup(cid)) |conn| {
            self.feedConnection(conn, data);
            return;
        }

        // Unknown connection id. Only a long-header (Initial) packet may create a
        // new connection; a short header for an unknown cid is dropped (a
        // stateless reset on it is a documented follow-up — see quic_retry.zig).
        if ((data[0] & 0x80) == 0) return;

        const conn = self.admitNewInitial(data, from) orelse return;
        self.feedConnection(conn, data);
    }

    /// Apply the RFC 9000 §8 admission policy to a long-header Initial from an
    /// unknown connection id and, if it passes, mint the connection. Returns null
    /// (after possibly emitting a VN or Retry packet) when no connection should
    /// be created for this datagram.
    fn admitNewInitial(self: *WebTransportListener, data: []const u8, from: TransportAddress) ?*Connection {
        const hdr = parseInitialHeader(data) orelse {
            // A long header we cannot parse as an Initial (e.g. a 0-RTT/Retry/
            // Handshake for an unknown cid): drop without state.
            return null;
        };

        // Version Negotiation (RFC 9000 §17.2.1): unsupported version → reply with
        // a VN packet listing v1 and create NO connection. The VN is ≤ the
        // triggering datagram, so it never amplifies.
        if (!quic_retry.supportsVersion(hdr.version)) {
            self.sendVersionNegotiation(hdr, from, data.len);
            return null;
        }

        // Retry / address-validation token policy (RFC 9000 §8.1.2).
        if (self.retryActive()) {
            if (hdr.token.len > 0) {
                // The client returned a token. Accept it only if it authenticates
                // for THIS source IP, is unexpired, and is not a replay; then the
                // new connection is address-validated immediately (no 3× limit).
                if (self.acceptToken(hdr.token, from, hdr.dcid)) {
                    const conn = self.createConnection(hdr.dcid, from) orelse return null;
                    conn.conn.markAddressValidated();
                    return conn;
                }
                // A bad/expired/replayed token: fall through and issue a fresh
                // Retry rather than trusting it.
            }
            // No token (or a rejected one): issue a Retry and create no state.
            self.sendRetry(hdr, from);
            return null;
        }

        // Fast path: mint the connection directly. It is still subject to the
        // per-connection 3× anti-amplification limit until a Handshake packet
        // validates the address.
        return self.createConnection(hdr.dcid, from);
    }

    /// Whether the Retry policy is currently active for a new Initial.
    fn retryActive(self: *const WebTransportListener) bool {
        return switch (self.retry_policy) {
            .never => false,
            .always => true,
            .under_load => self.liveCount() >= self.retry_load_threshold,
        };
    }

    /// Lazily mint (once) and return the per-process address-validation secret.
    fn secret(self: *WebTransportListener) *const quic_retry.Secret {
        if (self.retry_secret == null) self.retry_secret = quic_retry.Secret.generate();
        return &self.retry_secret.?;
    }

    /// Verify a returned Retry token: authenticates under our key, was minted for
    /// `from`'s IP and the client-chosen `original_dcid`, is unexpired, and is
    /// not a replay. Records it on success (single-use). Returns true if valid.
    fn acceptToken(self: *WebTransportListener, token: []const u8, from: TransportAddress, original_dcid: []const u8) bool {
        const sec = self.secret();
        var addr = from;
        _ = quic_retry.Token.verify(
            token,
            sec,
            addr.bytes(),
            original_dcid,
            nowNs(),
            quic_retry.default_token_lifetime_ns,
        ) catch return false;
        // Authenticated + fresh; enforce single-use (replay defense).
        self.token_replay.checkAndRecord(token) catch return false;
        return true;
    }

    /// Emit a Retry packet (RFC 9000 §17.2.5): a fresh server SCID + an
    /// address-validation token binding the client IP and original DCID. Creates
    /// no per-connection state — the client must re-send its Initial with the
    /// token. Failure to build/send is silently dropped (the client will retry).
    fn sendRetry(self: *WebTransportListener, hdr: InitialHeader, from: TransportAddress) void {
        const sec = self.secret();
        // Mint the token (bind IP + the client's original DCID + issue time).
        var addr = from;
        var token_buf: [quic_retry.max_token_len]u8 = undefined;
        const token = quic_retry.Token.seal(&token_buf, sec, addr.bytes(), hdr.dcid, nowNs()) catch return;

        // A fresh server SCID (the connection-id the client will address next).
        var scid: [8]u8 = undefined;
        std.mem.writeInt(u64, scid[0..8], self.scid_counter, .big);
        self.scid_counter +%= 1;

        // Retry's DCID = the client's SCID (so the client recognises the reply).
        var out: [quic_retry.retry_packet_max]u8 = undefined;
        const n = quic_retry.encodeRetry(&out, hdr.scid, &scid, token_buf[0..token], hdr.dcid) catch return;
        const sock = if (self.socket) |*s| s else return;
        sock.sendTo(from, out[0..n]);
    }

    /// Emit a Version Negotiation packet (RFC 9000 §17.2.1) in response to an
    /// unsupported-version Initial. The VN swaps the connection ids and lists the
    /// versions we support (v1). It is sent only when it cannot exceed the
    /// triggering datagram's size (`trigger_len`), so it can never amplify.
    fn sendVersionNegotiation(self: *WebTransportListener, hdr: InitialHeader, from: TransportAddress, trigger_len: usize) void {
        var out: [256]u8 = undefined;
        // Our DCID = the client's SCID; our SCID = the client's DCID (§17.2.1).
        const n = quic_retry.encodeVersionNegotiation(&out, hdr.scid, hdr.dcid) catch return;
        if (n > trigger_len) return; // never amplify (defensive; always holds here)
        const sock = if (self.socket) |*s| s else return;
        sock.sendTo(from, out[0..n]);
    }

    /// Drive QUIC recv → H3 service → flush for one connection, then handle any
    /// session lifecycle events and pump its IRC bridge.
    fn feedConnection(self: *WebTransportListener, conn: *Connection, data: []const u8) void {
        const now = nowNs();
        conn.conn.recvDatagram(data) catch {
            // A malformed/undecryptable datagram is dropped by the lower layer;
            // a hard error means the connection is unusable → tear it down.
            self.teardownConnection(conn);
            return;
        };
        self.serviceConnection(conn, now);
    }

    /// Run H3 service + event handling + bridge pump + flush for one connection.
    /// Any step that destroys the connection short-circuits the rest (the `conn`
    /// pointer is freed by `teardownConnection`, so nothing may touch it after).
    fn serviceConnection(self: *WebTransportListener, conn: *Connection, now: u64) void {
        conn.h3.service() catch {
            self.teardownConnection(conn);
            return;
        };
        self.drainEvents(conn); // never tears down (only opens/closes the bridge)
        if (!self.pumpBridge(conn)) return; // may tear down on a TCP/WT fault
        self.flush(conn);

        // Drive idle / PTO timers.
        if (conn.conn.onTimeout(now)) |owed| {
            if (owed) self.flush(conn);
        } else |_| {
            // Idle timeout (or fatal) → close the connection.
            self.teardownConnection(conn);
            return;
        }
        if (conn.conn.isClosing()) self.teardownConnection(conn);
    }

    /// Periodic per-iteration work: advance timers + pump bridges for every live
    /// connection (called on every pump wake so an idle connection still ticks).
    fn serviceAll(self: *WebTransportListener) void {
        const now = nowNs();
        var i: usize = 0;
        while (i < self.conns.items.len) : (i += 1) {
            const conn = self.conns.items[i] orelse continue;
            self.serviceConnection(conn, now);
        }
    }

    // -----------------------------------------------------------------------
    // WebTransport session events → IRC loopback bridge
    // -----------------------------------------------------------------------

    fn drainEvents(self: *WebTransportListener, conn: *Connection) void {
        while (conn.h3.nextEvent()) |ev| {
            switch (ev) {
                .session_established => {
                    self.openBridge(conn);
                },
                .session_closed => {
                    self.closeBridge(conn);
                },
                .connect_rejected => {},
            }
        }
        // Discover the client's WT bidi data stream once established.
        if (conn.irc_fd != null and !conn.have_wt_stream) {
            if (firstClientWtBidiStream(conn.h3)) |sid| {
                conn.wt_stream_id = sid;
                conn.have_wt_stream = true;
            }
        }
    }

    /// On session establishment, open the loopback TCP connection to the IRC
    /// listener (the daemon will treat this as an ordinary local client).
    fn openBridge(self: *WebTransportListener, conn: *Connection) void {
        if (conn.irc_fd != null) return; // already bridged (one session per conn)
        const fd = connectLoopbackTcp(self.irc_port) orelse return;
        // Non-blocking so the single pump thread never stalls on a slow read.
        setNonBlocking(fd);
        conn.irc_fd = fd;
        if (self.send_proxy_header) self.writeProxyHeader(conn, fd);
    }

    fn closeBridge(self: *WebTransportListener, conn: *Connection) void {
        _ = self;
        if (conn.irc_fd) |fd| {
            _ = linux.close(fd);
            conn.irc_fd = null;
        }
        conn.have_wt_stream = false;
        conn.wt_stream_id = null;
    }

    /// Move bytes both directions between the WT data stream and the TCP socket.
    /// WT bidi stream → TCP, and TCP → `writeWtStream`. Non-blocking. Returns
    /// `false` if the connection was torn down (a TCP/WT fault); the caller must
    /// then NOT touch `conn` again (the pointer is freed). Returns `true` if the
    /// connection is still alive (including the no-bridge-yet and IRC-closed
    /// cases — the latter closes only the session, not the QUIC connection).
    fn pumpBridge(self: *WebTransportListener, conn: *Connection) bool {
        const fd = conn.irc_fd orelse return true;
        const sid = conn.wt_stream_id orelse return true;

        var buf: [proxy_chunk_len]u8 = undefined;

        // WT stream → TCP (browser → IRC daemon).
        while (true) {
            const n = conn.h3.readWtStream(sid, &buf);
            if (n == 0) break;
            if (!writeAllFd(fd, buf[0..n])) {
                self.teardownConnection(conn);
                return false;
            }
        }

        // TCP → WT stream (IRC daemon → browser).
        while (true) {
            const rc = linux.read(fd, &buf, buf.len);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) {
                        // Daemon closed the IRC connection → close the WT session
                        // (but keep the QUIC connection alive to deliver the FIN).
                        conn.h3.closeSession() catch {};
                        self.closeBridge(conn);
                        return true;
                    }
                    conn.h3.writeWtStream(sid, buf[0..n], false) catch {
                        self.teardownConnection(conn);
                        return false;
                    };
                },
                .AGAIN => break, // no more TCP data right now
                .INTR => continue,
                else => {
                    self.teardownConnection(conn);
                    return false;
                },
            }
        }
        return true;
    }

    /// Prepend a PROXY v1 line carrying the real QUIC peer address. Works for
    /// both families: an IPv4 peer (incl. an IPv4-mapped one, surfaced as a
    /// 4-byte address) → TCP4 with a 127.0.0.1 destination; a native IPv6 peer →
    /// TCP6 with a ::1 destination. The peer address is already a
    /// `TransportAddress`, so the family is just its `ip_len`.
    fn writeProxyHeader(self: *WebTransportListener, conn: *Connection, fd: linux.fd_t) void {
        _ = self;
        var out: [proxy_protocol.v1_max_line_len]u8 = undefined;
        const peer = conn.peer;
        var dst_ip: [16]u8 = @splat(0);
        const family: proxy_protocol.Family = switch (peer.ip_len) {
            4 => blk: {
                dst_ip[0..4].* = [_]u8{ 127, 0, 0, 1 };
                break :blk .tcp4;
            },
            16 => blk: {
                dst_ip[15] = 1; // ::1
                break :blk .tcp6;
            },
            else => return, // malformed peer address: skip the header
        };
        const hdr = proxy_protocol.Header{
            .family = family,
            .src_ip = peer.ip,
            .dst_ip = dst_ip,
            .src_port = peer.port,
            .dst_port = 0,
        };
        const line = proxy_protocol.buildV1(&out, hdr) catch return;
        _ = writeAllFd(fd, line);
    }

    /// Flush all datagrams the QUIC engine owes to the peer's UDP address.
    fn flush(self: *WebTransportListener, conn: *Connection) void {
        var out: std.ArrayList(quic_conn.OutDatagram) = .empty;
        defer {
            for (out.items) |d| self.allocator.free(d.bytes);
            out.deinit(self.allocator);
        }
        _ = conn.conn.sendDatagrams(&out) catch return;
        const sock = if (self.socket) |*s| s else return;
        for (out.items) |d| sock.sendTo(conn.peer, d.bytes);
    }

    // -----------------------------------------------------------------------
    // Connection table
    // -----------------------------------------------------------------------

    fn lookup(self: *WebTransportListener, cid: []const u8) ?*Connection {
        const idx = self.by_cid.get(cid) orelse return null;
        return self.conns.items[idx];
    }

    fn createConnection(self: *WebTransportListener, init_dcid: []const u8, from: TransportAddress) ?*Connection {
        if (self.liveCount() >= self.max_connections) return null;

        // Mint a unique server SCID (8 bytes: counter || marker).
        var scid: [8]u8 = undefined;
        std.mem.writeInt(u64, scid[0..8], self.scid_counter, .big);
        self.scid_counter +%= 1;

        const conn = self.allocator.create(Connection) catch return null;
        errdefer self.allocator.destroy(conn);

        const qconn = self.allocator.create(quic_conn.Conn) catch {
            self.allocator.destroy(conn);
            return null;
        };
        qconn.* = quic_conn.Conn.initServer(self.allocator, .{
            .cert_chain = self.tls.cert_chain,
            .signing_key = self.tls.signing_key,
            .alpn_protocols = &[_][]const u8{"h3"},
            .transport_params = serverTransportParams(&scid),
            .local_cid = &scid,
        }) catch {
            self.allocator.destroy(qconn);
            self.allocator.destroy(conn);
            return null;
        };

        const h3 = self.allocator.create(http3_conn.Http3Conn) catch {
            qconn.deinit();
            self.allocator.destroy(qconn);
            self.allocator.destroy(conn);
            return null;
        };
        h3.* = http3_conn.Http3Conn.init(self.allocator, qconn);

        conn.* = .{
            .scid = undefined,
            .scid_len = @intCast(scid.len),
            .init_dcid = undefined,
            .init_dcid_len = @intCast(init_dcid.len),
            .peer = from,
            .conn = qconn,
            .h3 = h3,
        };
        @memcpy(conn.scid[0..scid.len], &scid);
        @memcpy(conn.init_dcid[0..init_dcid.len], init_dcid);

        // Register the connection slot.
        const idx = self.appendSlot(conn) catch {
            self.destroyConnection(conn);
            return null;
        };

        // Index by both demux keys; failure to index → drop the connection.
        self.indexCid(conn.initDcidSlice(), idx) catch {
            self.removeSlot(idx);
            self.destroyConnection(conn);
            return null;
        };
        self.indexCid(conn.scidSlice(), idx) catch {
            _ = self.by_cid.remove(conn.initDcidSlice());
            self.removeSlot(idx);
            self.destroyConnection(conn);
            return null;
        };
        return conn;
    }

    fn indexCid(self: *WebTransportListener, cid: []const u8, idx: usize) !void {
        // Avoid a duplicate-key dupe leak if init_dcid == scid (never, but safe).
        if (self.by_cid.contains(cid)) {
            try self.by_cid.put(self.allocator, cid, idx);
            return;
        }
        const key = try self.allocator.dupe(u8, cid);
        errdefer self.allocator.free(key);
        try self.by_cid.put(self.allocator, key, idx);
    }

    fn appendSlot(self: *WebTransportListener, conn: *Connection) !usize {
        // Reuse a freed slot if one exists.
        for (self.conns.items, 0..) |slot, i| {
            if (slot == null) {
                self.conns.items[i] = conn;
                return i;
            }
        }
        try self.conns.append(self.allocator, conn);
        return self.conns.items.len - 1;
    }

    fn removeSlot(self: *WebTransportListener, idx: usize) void {
        if (idx < self.conns.items.len) self.conns.items[idx] = null;
    }

    /// Remove a connection from the table (freeing its cid keys) and destroy it.
    fn teardownConnection(self: *WebTransportListener, conn: *Connection) void {
        // Find + clear its slot.
        for (self.conns.items, 0..) |slot, i| {
            if (slot == conn) {
                self.conns.items[i] = null;
                break;
            }
        }
        // Remove both demux keys (free the owned key strings).
        self.unindexCid(conn.initDcidSlice());
        self.unindexCid(conn.scidSlice());
        self.destroyConnection(conn);
    }

    fn unindexCid(self: *WebTransportListener, cid: []const u8) void {
        if (self.by_cid.fetchRemove(cid)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    fn destroyConnection(self: *WebTransportListener, conn: *Connection) void {
        if (conn.irc_fd) |fd| _ = linux.close(fd);
        conn.h3.deinit();
        self.allocator.destroy(conn.h3);
        conn.conn.deinit();
        self.allocator.destroy(conn.conn);
        self.allocator.destroy(conn);
    }

    fn liveCount(self: *const WebTransportListener) usize {
        var n: usize = 0;
        for (self.conns.items) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }
};

// ===========================================================================
// Helpers
// ===========================================================================

/// Local transport parameters for a server connection. Generous stream/data
/// windows so a full IRC session streams without artificial flow-control stalls.
fn serverTransportParams(scid: []const u8) quic_transport_params.TransportParameters {
    return .{
        .initial_source_connection_id = scid,
        .max_idle_timeout = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_streams_bidi = 100,
    };
}

/// Peek the Destination Connection ID out of a QUIC packet header without
/// decrypting. Long header: parse the dcid-len-prefixed field. Short header:
/// the dcid is a fixed 8 bytes (our server SCID length) — we issue 8-byte SCIDs.
fn peekDestCid(data: []const u8) ?[]const u8 {
    if (data.len < 1) return null;
    const is_long = (data[0] & 0x80) != 0;
    if (is_long) {
        // first(1) + version(4) + dcid_len(1) + dcid...
        if (data.len < 6) return null;
        const dcid_len = data[5];
        if (dcid_len > quic_packet.max_connection_id_len) return null;
        if (data.len < 6 + dcid_len) return null;
        return data[6 .. 6 + dcid_len];
    }
    // Short header: first(1) + dcid(8). We always issue 8-byte SCIDs.
    const dcid_len: usize = 8;
    if (data.len < 1 + dcid_len) return null;
    return data[1 .. 1 + dcid_len];
}

/// The fields of a long-header Initial the admission policy needs, parsed
/// without decrypting. Slices borrow from the input datagram.
const InitialHeader = struct {
    version: u32,
    /// The client-chosen Destination Connection ID (stable for the handshake;
    /// also the "original DCID" the Retry token binds, RFC 9000 §17.2.5.2).
    dcid: []const u8,
    /// The client's Source Connection ID (becomes the Retry/VN reply's DCID).
    scid: []const u8,
    /// The address-validation token the client echoed (empty on a first Initial).
    token: []const u8,
};

/// Parse a long-header Initial's version, connection ids, and token, bounds-
/// checked. Returns null for a non-Initial long header or any truncation, so a
/// malformed datagram is dropped without allocation (and never amplifies).
///
/// Layout (RFC 9000 §17.2.2): first(1) ‖ version(4) ‖ DCIDL(1) ‖ DCID ‖
/// SCIDL(1) ‖ SCID ‖ TokenLen(varint) ‖ Token ‖ Length(varint) ‖ ...
fn parseInitialHeader(data: []const u8) ?InitialHeader {
    if (data.len < 6) return null;
    if ((data[0] & 0x80) == 0) return null; // not a long header

    // Long packet type lives in bits 4–5 of the first byte. Only Initial (0b00)
    // may create a connection via this path; the type bits are NOT
    // header-protected on a long header, so we can read them in the clear.
    const ptype = (data[0] >> 4) & 0x03;
    if (ptype != @intFromEnum(quic_packet.LongPacketType.initial)) return null;

    const version = std.mem.readInt(u32, data[1..5], .big);

    var pos: usize = 5;
    if (pos >= data.len) return null;
    const dcid_len = data[pos];
    pos += 1;
    if (dcid_len > quic_packet.max_connection_id_len) return null;
    if (pos + dcid_len + 1 > data.len) return null;
    const dcid = data[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = data[pos];
    pos += 1;
    if (scid_len > quic_packet.max_connection_id_len) return null;
    if (pos + scid_len > data.len) return null;
    const scid = data[pos .. pos + scid_len];
    pos += scid_len;

    // Token length varint, then the token bytes.
    const tok_vi = decodeVarintAt(data, pos) orelse return null;
    pos += tok_vi.len;
    const tok_len = std.math.cast(usize, tok_vi.value) orelse return null;
    if (pos + tok_len > data.len) return null;
    const token = data[pos .. pos + tok_len];

    return .{ .version = version, .dcid = dcid, .scid = scid, .token = token };
}

/// A QUIC varint decoded from `data[off..]` (RFC 9000 §16). Returns null on
/// truncation. Tolerant of non-minimal encodings (the spec permits them).
const DecodedVarint = struct { value: u64, len: usize };
fn decodeVarintAt(data: []const u8, off: usize) ?DecodedVarint {
    if (off >= data.len) return null;
    const tag = data[off] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (off + len > data.len) return null;
    var value: u64 = data[off] & 0x3f;
    var i: usize = 1;
    while (i < len) : (i += 1) value = (value << 8) | data[off + i];
    return .{ .value = value, .len = len };
}

/// The QUIC stream id of the first *client-opened* WebTransport bidirectional
/// stream registered on the session, distinct from the CONNECT stream. This is
/// the WT data channel carrying the IRC byte stream.
fn firstClientWtBidiStream(h3: *http3_conn.Http3Conn) ?u64 {
    const s = if (h3.session) |*ss| ss else return null;
    for (s.streams.items) |wt| {
        if (wt.is_bidirectional and wt.stream_id != s.session_id.stream_id) {
            return wt.stream_id;
        }
    }
    return null;
}

/// Map the legacy IPv4-in-network-byte-order bind selector to the dual-stack
/// socket's `BindAddr`. `any_be` (0) → bind `[::]` (all interfaces, both
/// families). A configured v4 address → bind it v4-mapped (`::ffff:a.b.c.d`), so
/// a v4-only operator config still works over the single dual-stack socket.
fn bindAddrFromBe(bind_be: u32) DualStackUdpSocket.BindAddr {
    if (bind_be == any_be) return .any;
    // `bind_be` is already in network byte order; its bytes are the v4 octets.
    return .{ .v4_mapped = @bitCast(bind_be) };
}

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn sleepMs(ms: u32) void {
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

fn connectLoopbackTcp(port: u16) ?linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return null;
    const fd: linux.fd_t = @intCast(rc);
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    if (posix.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

fn setNonBlocking(fd: linux.fd_t) void {
    const flags = linux.fcntl(fd, posix.F.GETFL, 0);
    _ = linux.fcntl(fd, posix.F.SETFL, flags | @as(usize, 0o4000)); // O_NONBLOCK
}

fn writeAllFd(fd: linux.fd_t, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return false;
                sent += n;
            },
            .INTR, .AGAIN => continue,
            else => return false,
        }
    }
    return true;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const webtransport = @import("../proto/webtransport.zig");
const qpack = @import("../proto/http3_qpack.zig");

// ---- pure unit tests: demux header parsing --------------------------------

test "peekDestCid extracts the long-header DCID" {
    // first | version(4) | dcid_len=4 | dcid(4) | scid_len=0 | ...
    const pkt = [_]u8{
        0xc0, // long header, Initial
        0x00, 0x00, 0x00, 0x01, // version 1
        0x04, 0xde, 0xad, 0xbe, 0xef, // dcid_len + dcid
        0x00, // scid_len
    };
    const cid = peekDestCid(&pkt) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, cid);
}

test "peekDestCid extracts the short-header 8-byte DCID" {
    const pkt = [_]u8{ 0x40, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb };
    const cid = peekDestCid(&pkt) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, cid);
}

test "peekDestCid rejects a truncated header" {
    try testing.expect(peekDestCid(&[_]u8{0xc0}) == null);
    try testing.expect(peekDestCid(&[_]u8{ 0x40, 1, 2 }) == null);
}

// ---- listener lifecycle: bind / port / clean shutdown ---------------------

const TestServerKeys = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    cert: []const u8,
    cert_chain: [1][]const u8,

    fn init(self: *TestServerKeys) !void {
        self.kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
        self.cert = try x509_selfsign.buildSelfSigned(&self.cert_buf, .{
            .common_name = "wt.test",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{ 0x51, 0x99 },
            .key_pair = self.kp,
            .dns_names = &.{"wt.test"},
            .is_ca = true,
        });
        self.cert_chain = .{self.cert};
    }
};

test "WebTransportListener: bind, port, and clean re-startable shutdown" {
    var keys: TestServerKeys = undefined;
    try keys.init();
    var lst = WebTransportListener.init(testing.allocator, .{
        .cert_chain = &keys.cert_chain,
        .signing_key = .{ .ed25519 = keys.kp },
    }, 0);
    defer lst.deinit();

    try lst.start(loopback_be, 0);
    try testing.expect(lst.port != 0);
    lst.shutdown();
    // Re-start cleanly on a fresh ephemeral port.
    try lst.start(loopback_be, 0);
    try testing.expect(lst.port != 0);
}

// ---- REAL-UDP-SOCKET end-to-end: live QUIC/H3/WT handshake + bridge --------

/// A loopback "IRC server": a blocking TCP listener thread that accepts one
/// connection, reads the bytes the bridge forwards, echoes a fixed reply, and
/// records what it saw. Stands in for the daemon's IRC listener so the test can
/// assert the WT→TCP→WT loopback proxy round-trips real bytes.
const FakeIrcServer = struct {
    listen_fd: linux.fd_t,
    port: u16,
    thread: ?std.Thread = null,
    got: [256]u8 = undefined,
    got_len: usize = 0,
    reply: []const u8,

    fn start(reply: []const u8) !*FakeIrcServer {
        const self = try testing.allocator.create(FakeIrcServer);
        errdefer testing.allocator.destroy(self);
        const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
        self.listen_fd = @intCast(rc);
        var addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
        if (posix.errno(linux.bind(self.listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
            return error.BindFailed;
        if (posix.errno(linux.listen(self.listen_fd, 4)) != .SUCCESS) return error.ListenFailed;
        var sa: linux.sockaddr.in = undefined;
        var slen: posix.socklen_t = @sizeOf(linux.sockaddr.in);
        _ = linux.getsockname(self.listen_fd, @ptrCast(&sa), &slen);
        self.port = std.mem.bigToNative(u16, sa.port);
        self.got_len = 0;
        self.reply = reply;
        self.thread = try std.Thread.spawn(.{}, accept, .{self});
        return self;
    }

    fn accept(self: *FakeIrcServer) void {
        const cfd_rc = linux.accept(self.listen_fd, null, null);
        if (posix.errno(cfd_rc) != .SUCCESS) return;
        const cfd: linux.fd_t = @intCast(cfd_rc);
        defer _ = linux.close(cfd);
        // Read one chunk of forwarded IRC bytes.
        const rc = linux.read(cfd, &self.got, self.got.len);
        if (posix.errno(rc) == .SUCCESS) self.got_len = @intCast(rc);
        // Echo a reply back so the bridge proxies it WT-bound.
        _ = linux.write(cfd, self.reply.ptr, self.reply.len);
        // Hold the connection open briefly so the reply is flushed.
        sleepMs(50);
    }

    fn join(self: *FakeIrcServer) void {
        if (self.thread) |t| t.join();
        _ = linux.close(self.listen_fd);
        testing.allocator.destroy(self);
    }
};

test "WebTransportListener: live UDP QUIC/H3/WT session bridges IRC bytes both ways" {
    // End-to-end over the DUAL-STACK socket: `lst.start` now binds an AF_INET6
    // socket with IPV6_V6ONLY=0, and the client below is a plain IPv4 loopback
    // `MediaSocket`. So this also proves the full QUIC/H3/WT handshake + IRC
    // bridge still completes after the socket swap, with the v4 client reaching
    // the dual-stack server as an IPv4-mapped source surfaced back as ipv4.
    const alloc = testing.allocator;
    var keys: TestServerKeys = undefined;
    try keys.init();

    // Fake IRC server the bridge will dial on loopback.
    var irc = try FakeIrcServer.start(":server NOTICE * :hi from irc\r\n");
    defer irc.join();

    var lst = WebTransportListener.init(alloc, .{
        .cert_chain = &keys.cert_chain,
        .signing_key = .{ .ed25519 = keys.kp },
    }, irc.port);
    defer lst.deinit();
    try lst.start(loopback_be, 0);
    const server_port = lst.port;

    // A real IPv4 UDP socket acting as the QUIC/WT client. It addresses the
    // dual-stack server at 127.0.0.1:server_port; the server sees it as a
    // v4-mapped source and replies via the same dual-stack socket.
    var cli_sock = try MediaSocket.bind(loopback_be, 0);
    defer cli_sock.deinit();
    cli_sock.setRecvTimeoutMs(400);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, server_port);

    // Build the client QUIC connection. Its Initial DCID is what the server's
    // listener will demux + mint a connection for.
    const client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const initial_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    var client = try quic_conn.Conn.initClient(alloc, .{
        .alpn_protocols = &[_][]const u8{"h3"},
        .transport_params = .{
            .initial_source_connection_id = &client_cid,
            .initial_max_data = 1 << 20,
            .initial_max_stream_data_bidi_local = 256 * 1024,
            .initial_max_stream_data_bidi_remote = 256 * 1024,
            .initial_max_streams_bidi = 100,
        },
        .local_cid = &client_cid,
        .initial_dcid = &initial_dcid,
        .x25519_seed = [_]u8{0x42} ** 32,
        .client_random = [_]u8{0x11} ** 32,
    });
    defer client.deinit();

    // Drive the QUIC handshake over the REAL UDP socket pair.
    var established = false;
    var round: usize = 0;
    while (round < 40 and !established) : (round += 1) {
        try sendQuic(alloc, &client, &cli_sock, server_addr);
        // Receive whatever the server flushed back.
        try recvQuicAll(&client, &cli_sock);
        if (client.isEstablished()) established = true;
    }
    try testing.expect(established);

    // Now run the WT control + Extended CONNECT, then open a WT bidi data stream
    // and write an IRC line. We reuse the codecs directly (no WtClient struct).
    try sendControlAndConnect(alloc, &client, "irc.example", "/wt");
    // Drive until the CONNECT is answered 200.
    var ok = false;
    round = 0;
    var connect_stream: u64 = undefined;
    connect_stream = lastOpenedBidi(&client);
    while (round < 40 and !ok) : (round += 1) {
        try sendQuic(alloc, &client, &cli_sock, server_addr);
        try recvQuicAll(&client, &cli_sock);
        ok = connectAnswered200(alloc, &client, connect_stream) catch false;
    }
    try testing.expect(ok);

    // Open a WT bidi data stream and write an IRC registration line.
    const session_id = try webtransport.SessionId.initClientBidirectional(connect_stream);
    const data_stream = try client.openStream();
    const prefix = try webtransport.encodeStreamSignal(alloc, webtransport.StreamType.webtransport_bidirectional, session_id);
    defer alloc.free(prefix);
    try client.sendStream(data_stream, prefix, false);
    const irc_line = "NICK wtuser\r\n";
    try client.sendStream(data_stream, irc_line, false);

    // Pump until the fake IRC server has seen the forwarded bytes AND the client
    // has received the server's echoed reply over the WT data stream.
    var reply_buf: [256]u8 = undefined;
    var reply_total: usize = 0;
    round = 0;
    while (round < 60) : (round += 1) {
        try sendQuic(alloc, &client, &cli_sock, server_addr);
        try recvQuicAll(&client, &cli_sock);
        // Read any WT-stream bytes the server proxied from the IRC reply.
        reply_total += readWtBidi(&client, data_stream, reply_buf[reply_total..], session_id);
        if (irc.got_len > 0 and reply_total >= irc.reply.len) break;
        sleepMs(5);
    }

    // The fake IRC server received the IRC line forwarded by the bridge.
    try testing.expect(irc.got_len > 0);
    try testing.expectEqualStrings(irc_line, irc.got[0..irc.got_len]);
    // The client received the IRC server's reply, proxied back over the WT stream.
    try testing.expectEqualStrings(irc.reply, reply_buf[0..reply_total]);
}

// -- test-only QUIC/WT client glue over a real UDP socket -------------------

fn sendQuic(alloc: std.mem.Allocator, conn: *quic_conn.Conn, sock: *MediaSocket, dst: TransportAddress) !void {
    var out: std.ArrayList(quic_conn.OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try conn.sendDatagrams(&out);
    for (out.items) |d| sock.sendTo(dst, d.bytes);
}

fn recvQuicAll(conn: *quic_conn.Conn, sock: *MediaSocket) !void {
    var buf: [recv_buf_len]u8 = undefined;
    var tries: usize = 0;
    while (tries < 8) : (tries += 1) {
        const got = sock.recvFrom(&buf) orelse return;
        conn.recvDatagram(got.data) catch {};
    }
}

fn sendControlAndConnect(alloc: std.mem.Allocator, conn: *quic_conn.Conn, authority: []const u8, path: []const u8) !void {
    const ctl = try conn.openUniStream();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    var vbuf: [8]u8 = undefined;
    try out.appendSlice(alloc, try webtransport.encodeVarint(http3_conn.UniStreamType.control, &vbuf));
    const body = try http3_conn.encodeSettingsBody(alloc, http3_conn.Settings.serverDefault());
    defer alloc.free(body);
    try http3_conn.encodeFrame(alloc, &out, http3_conn.FrameType.settings, body);
    try conn.sendStream(ctl, out.items, false);

    const cs = try conn.openStream();
    const block = try http3_conn.encodeConnectHeaders(alloc, authority, path);
    defer alloc.free(block);
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(alloc);
    try http3_conn.encodeFrame(alloc, &req, http3_conn.FrameType.headers, block);
    try conn.sendStream(cs, req.items, false);
}

/// The last bidi stream id this client opened (the CONNECT stream).
fn lastOpenedBidi(conn: *quic_conn.Conn) u64 {
    // Client bidi ids are 0,4,8,…; next_bidi_stream points past the last issued.
    return conn.next_bidi_stream - 4;
}

fn connectAnswered200(alloc: std.mem.Allocator, conn: *quic_conn.Conn, cs: u64) !bool {
    var scratch: [2048]u8 = undefined;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    while (true) {
        const n = conn.readStream(cs, &scratch);
        if (n == 0) break;
        try buf.appendSlice(alloc, scratch[0..n]);
    }
    var pos: usize = 0;
    const frame = (try http3_conn.findFrame(buf.items, &pos, http3_conn.FrameType.headers)) orelse return false;
    const headers = try qpack.decodeFieldSection(alloc, frame.payload);
    defer alloc.free(headers);
    for (headers) |h| {
        if (std.mem.eql(u8, h.name, ":status") and std.mem.eql(u8, h.value, "200")) return true;
    }
    return false;
}

/// Read WT-bidi payload from a client-opened stream: the server never sends a
/// signal prefix back on this stream (it reuses the same stream id), so the
/// bytes are the raw proxied IRC reply.
fn readWtBidi(conn: *quic_conn.Conn, sid: u64, dst: []u8, session_id: webtransport.SessionId) usize {
    _ = session_id;
    if (dst.len == 0) return 0;
    return conn.readStream(sid, dst);
}

// ===========================================================================
// Address-validation policy tests (RFC 9000 §8 / §17.2.1 / §17.2.5)
// ===========================================================================

/// Build a synthetic long-header Initial header with the given fields and an
/// optional token, into `out`. Returns the slice. This is only the header (no
/// frames/padding) — enough to drive the listener's admission/parse path.
fn buildInitialHeader(out: []u8, version: u32, dcid: []const u8, scid: []const u8, token: []const u8) []const u8 {
    var pos: usize = 0;
    out[pos] = 0xc0; // long header, fixed bit, Initial type (0b00)
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], version, .big);
    pos += 4;
    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos..][0..scid.len], scid);
    pos += scid.len;
    // Token length varint (1-byte form for < 64).
    out[pos] = @intCast(token.len);
    pos += 1;
    @memcpy(out[pos..][0..token.len], token);
    pos += token.len;
    // A minimal Length varint + a byte so the packet looks structurally sane.
    out[pos] = 0x00;
    pos += 1;
    return out[0..pos];
}

test "parseInitialHeader extracts version, cids, and token; rejects truncation" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const scid = [_]u8{ 0x11, 0x22 };
    const token = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const pkt = buildInitialHeader(&buf, 0x0000_0001, &dcid, &scid, &token);

    const hdr = parseInitialHeader(pkt) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 0x0000_0001), hdr.version);
    try testing.expectEqualSlices(u8, &dcid, hdr.dcid);
    try testing.expectEqualSlices(u8, &scid, hdr.scid);
    try testing.expectEqualSlices(u8, &token, hdr.token);

    // A short-header (no long bit) is not an Initial.
    try testing.expect(parseInitialHeader(&[_]u8{ 0x40, 1, 2, 3, 4, 5, 6, 7, 8 }) == null);
    // Truncated mid-header → null (no panic).
    try testing.expect(parseInitialHeader(pkt[0..7]) == null);
}

/// A listener bound to a real UDP socket but NOT started (no pump thread), so we
/// can call `handleDatagram` directly and read what it sends from a peer socket.
const PolicyFixture = struct {
    keys: TestServerKeys,
    lst: WebTransportListener,
    peer: MediaSocket,
    server_addr: TransportAddress,
    peer_addr: TransportAddress,

    fn init(self: *PolicyFixture, policy: RetryPolicy) !void {
        try self.keys.init();
        self.lst = WebTransportListener.init(testing.allocator, .{
            .cert_chain = &self.keys.cert_chain,
            .signing_key = .{ .ed25519 = self.keys.kp },
        }, 0);
        self.lst.retry_policy = policy;
        // Bind the listener's DUAL-STACK UDP socket WITHOUT spawning the pump
        // thread (so we can call `handleDatagram` directly). It binds [::] but
        // serves the v4 peer below as an IPv4-mapped source.
        var sock = try DualStackUdpSocket.bind(.any, 0);
        self.lst.port = try sock.localPort();
        sock.setRecvTimeoutMs(200);
        self.lst.socket = sock;

        // A peer socket to send Initials from and read VN/Retry replies on.
        self.peer = try MediaSocket.bind(loopback_be, 0);
        self.peer.setRecvTimeoutMs(300);
        self.server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, self.lst.port);
        self.peer_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try self.peer.localPort());
    }

    fn deinit(self: *PolicyFixture) void {
        // The listener never started its pump, so deinit just frees state +
        // closes the socket we handed it.
        self.lst.deinit();
        self.peer.deinit();
    }

    /// Feed `data` to the listener as if it arrived from the peer, then read one
    /// reply datagram the listener sent back (or null on timeout).
    fn exchange(self: *PolicyFixture, data: []const u8, reply: []u8) ?usize {
        self.lst.handleDatagram(data, self.peer_addr);
        const got = self.peer.recvFrom(reply) orelse return null;
        return got.data.len;
    }
};

test "version negotiation — an Initial with version 0xff000099 yields a VN listing v1 and no connection" {
    var fx: PolicyFixture = undefined;
    try fx.init(.never);
    defer fx.deinit();

    // A real client Initial is padded to ≥1200 bytes (RFC 9000 §14.1), so the VN
    // reply (a few dozen bytes) never amplifies. We mimic that here: the parsed
    // header is the same, but the on-wire datagram is padded so the VN passes the
    // never-amplify guard.
    var buf: [1300]u8 = [_]u8{0} ** 1300;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const hdr = buildInitialHeader(&buf, 0xff00_0099, &dcid, &scid, &.{});
    const pkt = buf[0..1200]; // header + trailing zero PADDING to 1200 bytes
    _ = hdr;

    var reply: [256]u8 = undefined;
    const n = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;

    // A VN packet: high bit set, version field == 0, lists v1 in the trailer.
    try testing.expect((reply[0] & 0x80) != 0);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, reply[1..5], .big));
    try testing.expectEqual(quic_retry.quic_version_1, std.mem.readInt(u32, reply[n - 4 ..][0..4], .big));
    // No connection was created for an unsupported version.
    try testing.expectEqual(@as(usize, 0), fx.lst.liveCount());
    // VN never amplifies relative to the trigger.
    try testing.expect(n <= pkt.len);
}

test "retry — a tokenless Initial under .always policy is answered with a Retry and no connection" {
    var fx: PolicyFixture = undefined;
    try fx.init(.always);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, &.{});

    var reply: [256]u8 = undefined;
    const n = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;

    // The reply is a Retry packet: long header, Retry type bits 0b11.
    try testing.expect((reply[0] & 0x80) != 0);
    try testing.expectEqual(@as(u8, @intFromEnum(quic_packet.LongPacketType.retry)), (reply[0] >> 4) & 0x03);
    // Retry's DCID = the client's SCID (so the client recognises the reply).
    try testing.expectEqual(@as(u8, scid.len), reply[5]);
    try testing.expectEqualSlices(u8, &scid, reply[6 .. 6 + scid.len]);
    // No connection state was allocated.
    try testing.expectEqual(@as(usize, 0), fx.lst.liveCount());
    // The Retry's integrity tag (last 16 bytes) verifies against the §5.8
    // construction over the pseudo-packet (binding the client's original DCID).
    const expected_tag = try quic_retry.retryIntegrityTag(&dcid, reply[0 .. n - quic_retry.tag_len]);
    try testing.expectEqualSlices(u8, &expected_tag, reply[n - quic_retry.tag_len .. n]);
}

test "retry — a client returning a valid token is address-validated immediately (no 3x cap)" {
    var fx: PolicyFixture = undefined;
    try fx.init(.always);
    defer fx.deinit();

    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };

    // Step 1: tokenless Initial → the listener issues a Retry carrying a token.
    var buf: [128]u8 = undefined;
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, &.{});
    var reply: [256]u8 = undefined;
    const rn = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;

    // Extract the token from the Retry: after first(1)+ver(4)+DCIDL(1)+DCID+
    // SCIDL(1)+SCID, the token runs to the 16-byte integrity tag.
    var pos: usize = 5;
    const r_dcidl = reply[pos];
    pos += 1 + r_dcidl;
    const r_scidl = reply[pos];
    pos += 1 + r_scidl;
    const token = reply[pos .. rn - quic_retry.tag_len];
    try testing.expect(token.len > 0);

    // Step 2: the client re-sends its Initial WITH the token. It must now be
    // accepted, the connection created, and the address validated (no 3× cap).
    // We call `admitNewInitial` directly (the admission decision under test);
    // feeding the synthetic header through the full recv path would tear the
    // connection down on the (intentionally undecryptable) body.
    var buf2: [256]u8 = undefined;
    const pkt2 = buildInitialHeader(&buf2, quic_retry.quic_version_1, &dcid, &scid, token);
    const conn = fx.lst.admitNewInitial(pkt2, fx.peer_addr) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), fx.lst.liveCount());
    try testing.expect(conn.conn.isAddressValidated());

    // Step 3: a REPLAY of the same token (new DCID, same IP) is rejected — the
    // listener issues a fresh Retry instead of a second validated connection.
    const dcid2 = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    var buf3: [256]u8 = undefined;
    const pkt3 = buildInitialHeader(&buf3, quic_retry.quic_version_1, &dcid2, &scid, token);
    try testing.expect(fx.lst.admitNewInitial(pkt3, fx.peer_addr) == null);
    // No new validated connection for the replayed token.
    try testing.expect(fx.lst.lookup(&dcid2) == null);
}

test "retry — a token from a different client IP is rejected" {
    var fx: PolicyFixture = undefined;
    try fx.init(.always);
    defer fx.deinit();

    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };

    // Seal a token bound to a DIFFERENT IP than the peer's loopback address.
    const sec = fx.lst.secret();
    var token_buf: [quic_retry.max_token_len]u8 = undefined;
    const tn = try quic_retry.Token.seal(&token_buf, sec, &[_]u8{ 203, 0, 113, 5 }, &dcid, nowNs());

    var buf: [256]u8 = undefined;
    const scid = [_]u8{ 0xb1, 0xb2 };
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, token_buf[0..tn]);
    // The Initial arrives from the peer's loopback IP, which the token does NOT
    // match → rejected → a fresh Retry, no connection.
    var reply: [256]u8 = undefined;
    _ = fx.exchange(pkt, &reply) orelse return error.TestUnexpectedResult;
    try testing.expect(fx.lst.lookup(&dcid) == null);
    try testing.expectEqual(@as(u8, @intFromEnum(quic_packet.LongPacketType.retry)), (reply[0] >> 4) & 0x03);
}

test "retry policy .never mints a connection directly (default fast path unaffected)" {
    var fx: PolicyFixture = undefined;
    try fx.init(.never);
    defer fx.deinit();

    var buf: [64]u8 = undefined;
    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const pkt = buildInitialHeader(&buf, quic_retry.quic_version_1, &dcid, &scid, &.{});

    // No Retry/VN under .never: the connection is created directly (still
    // anti-amplification-limited until a Handshake validates the address). We
    // exercise the admission decision in isolation (admitNewInitial) since the
    // synthetic header has no valid encrypted body to feed through recv.
    const conn = fx.lst.admitNewInitial(pkt, fx.peer_addr) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), fx.lst.liveCount());
    try testing.expect(!conn.conn.isAddressValidated());
}
