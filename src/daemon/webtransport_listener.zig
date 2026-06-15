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
//!   * One server SCID per connection, no connection migration, no Retry,
//!     no stateless reset (inherited from the `quic_conn` layer's typed gaps).
//!   * One WebTransport session per QUIC connection, one IRC bridge per
//!     session (the common deployment shape; `http3_conn` rejects a 2nd CONNECT).
//!   * IPv4 socket (reuses the proven `MediaSocket`); the daemon's dual-stack
//!     story is unchanged for the TCP legs. v6 UDP is a typed follow-up.
//!   * PROXY-protocol carry of the real client address is OPTIONAL and OFF by
//!     default: the daemon sees the bridge's loopback identity. When the daemon
//!     trusts loopback as a PROXY source, set `send_proxy_header = true` to
//!     prepend a PROXY v1 line carrying the QUIC peer's address.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const quic_conn = @import("../proto/quic_conn.zig");
const quic_packet = @import("../proto/quic_packet.zig");
const http3_conn = @import("../proto/http3_conn.zig");
const quic_transport_params = @import("../proto/quic_transport_params.zig");
const quic_handshake = @import("../proto/quic_handshake.zig");
const proxy_protocol = @import("../proto/proxy_protocol.zig");
const media_socket = @import("../substrate/media_socket.zig");

pub const MediaSocket = media_socket.MediaSocket;
pub const TransportAddress = media_socket.TransportAddress;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;

/// Default cap on concurrent QUIC connections (DoS bound). A flood of fresh
/// handshakes past this is dropped without allocation.
pub const default_max_connections: usize = 256;

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

    socket: ?MediaSocket = null,
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
    pub fn start(self: *WebTransportListener, bind_be: u32, port: u16) Error!void {
        if (self.socket != null) return error.AlreadyStarted;
        var sock = MediaSocket.bind(bind_be, port) catch return error.BindFailed;
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
    fn handleDatagram(self: *WebTransportListener, data: []const u8, from: TransportAddress) void {
        if (data.len == 0) return;
        const cid = peekDestCid(data) orelse return;

        const conn = self.lookup(cid) orelse blk: {
            // Only a long-header (Initial) packet may create a new connection.
            if ((data[0] & 0x80) == 0) return; // short header for unknown cid → drop
            break :blk self.createConnection(cid, from) orelse return;
        };

        self.feedConnection(conn, data);
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

    fn writeProxyHeader(self: *WebTransportListener, conn: *Connection, fd: linux.fd_t) void {
        _ = self;
        var out: [proxy_protocol.v1_max_line_len]u8 = undefined;
        const peer = conn.peer;
        if (peer.ip_len != 4) return; // only the IPv4 leg is wired (typed gap)
        var dst_ip: [16]u8 = @splat(0);
        dst_ip[0..4].* = [_]u8{ 127, 0, 0, 1 };
        const hdr = proxy_protocol.Header{
            .family = .tcp4,
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

    // A real UDP socket acting as the QUIC/WT client, over the live socket pair.
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
