// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-owned media transport plane: ties the SFU endpoint registry
//! (MediaTransport) to a live UDP MediaSocket and a background pump thread.
//!
//! The pump thread blocks on the media socket (with a short recv timeout so it
//! can observe the stop flag), demultiplexes each datagram, and answers STUN
//! connectivity checks under a mutex. The daemon's main thread allocates and
//! removes endpoints (on MEDIA OFFER / LEAVE) through the same mutex, so the two
//! threads share the registry safely. Media STUN traffic is low-rate (a call
//! handshake), so a single coarse mutex is more than adequate.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const media_transport = @import("../substrate/media_transport.zig");
const media_socket = @import("../substrate/media_socket.zig");
const rtp_profile = @import("../proto/rtp_profile.zig");
const rtp_nack = @import("../substrate/rtp_nack.zig");
const media_bridge = @import("media_bridge.zig");
const dtls_server = @import("../proto/dtls12_server.zig");
const dtls13_server = @import("../proto/dtls13_server.zig");
const platform = @import("../substrate/platform.zig");

pub const MediaTransport = media_transport.MediaTransport;
pub const MediaSocket = media_socket.MediaSocket;
pub const TransportAddress = media_transport.TransportAddress;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;
pub const max_datagram = media_socket.max_datagram;

/// Blocking acquire on the tryLock-only `std.atomic.Mutex`. Contention is
/// near-zero (rare allocate/remove vs. low-rate STUN handshakes), so yielding.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

/// Whether byte 1 of a version-2 packet marks it as RTCP rather than RTP.
/// RFC 5761 reserves RTP payload types 64–95 so RTCP packet types (200–204,
/// i.e. byte 1 in 192–223) are unambiguous on a muxed RTP/RTCP socket.
fn isRtcp(b1: u8) bool {
    return b1 >= 192 and b1 <= 223;
}

/// Fill `buf` with OS entropy (getrandom).
fn osEntropy(buf: []u8) !void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.EntropyUnavailable,
        }
        if (rc == 0) return error.EntropyUnavailable;
        filled += @intCast(rc);
    }
}

/// ICE credentials handed back to the signaling layer to advertise to a client.
pub const Creds = struct {
    ufrag: [media_transport.ufrag_len]u8,
    pwd: [media_transport.pwd_len]u8,

    pub fn ufragSlice(self: *const Creds) []const u8 {
        return self.ufrag[0..];
    }
    pub fn pwdSlice(self: *const Creds) []const u8 {
        return self.pwd[0..];
    }
};

pub const MediaPlane = struct {
    allocator: std.mem.Allocator,
    transport: MediaTransport,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// The bound local UDP port (0 until started); advertised to clients.
    port: u16 = 0,
    /// Optional STUN server to query at boot for the reflexive candidate. Set
    /// before `start`.
    stun_server: ?TransportAddress = null,
    /// The discovered server-reflexive address (null if discovery is off/failed).
    discovered: ?TransportAddress = null,
    /// Runtime cap for accepted RTP/RTCP datagrams.
    max_frame_bytes: usize = media_socket.max_datagram,
    /// Runtime cap reserved for upload-bearing media operations.
    max_upload_bytes: u64 = 16 * 1024 * 1024,
    /// CSPRNG for ICE credential generation, seeded from the OS at init.
    /// Accessed only under `mutex` (in allocate).
    csprng: std.Random.DefaultCsprng,
    /// Optional cross-leg sink: after relaying an RTP frame to WebRTC peers, the
    /// pump hands it here to also reach the channel's native members (rewrapped to
    /// kagura). Null = no native members / no bridging.
    cross: ?media_bridge.RtpCrossSink = null,
    /// Opt-in DTLS-SRTP termination (RFC 5764). Set before `start`; when false
    /// the pump has no DTLS demux branch and is byte-identical to today.
    dtls_enabled: bool = false,
    /// Per-peer DTLS server terminator, allocated in `start` when `dtls_enabled`
    /// and freed in `shutdown`. Pump-thread-owned (not internally synchronised).
    dtls: ?*dtls_server.Terminator = null,
    /// Backing session table for `dtls` (owned; freed alongside it).
    dtls_sessions: []dtls_server.Session = &.{},
    /// Inline snapshot of the DTLS `a=fingerprint` line, taken once at `start`
    /// from the immutable cert. Read by the signaling layer from any thread
    /// WITHOUT dereferencing the mutable terminator pointer (never a UAF, and
    /// the buffer is inline so it is never freed). `len` 0 = DTLS off/down.
    dtls_fingerprint_buf: [128]u8 = undefined,
    dtls_fingerprint_len: usize = 0,
    /// Independent opt-in for the DTLS 1.3 engine (default OFF). Set before
    /// `start`. When false, enabling `dtls_enabled` gives exactly Increment 1's
    /// DTLS 1.2-only behavior — the 1.3 engine is never stood up and 1.3-offering
    /// peers fall through to the 1.2 path. Kept separate because the RFC 9147
    /// transcript interop points are not yet browser-validated (see
    /// `dtls13_server.zig`).
    dtls13_enabled: bool = false,
    /// Opt-in DTLS 1.3 engine (RFC 9147), sharing the 1.2 terminator's cert +
    /// `a=fingerprint`. A peer offering DTLS 1.3 (supported_versions) routes here;
    /// 1.2 stays on `dtls`. Pump-thread-owned; null when 1.3 is off/unavailable.
    dtls13: ?*dtls13_server.Terminator = null,
    /// Backing session table for `dtls13` (owned; freed alongside it).
    dtls13_sessions: []dtls13_server.Session = &.{},

    pub fn init(allocator: std.mem.Allocator) MediaPlane {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        osEntropy(&seed) catch @panic("media CSPRNG entropy unavailable");
        return .{
            .allocator = allocator,
            .transport = MediaTransport.init(allocator),
            .csprng = std.Random.DefaultCsprng.init(seed),
        };
    }

    pub fn deinit(self: *MediaPlane) void {
        self.shutdown();
        self.transport.deinit();
        self.* = undefined;
    }

    /// Install the cross-leg sink (call before `start`, or while stopped).
    pub fn setCrossLegSink(self: *MediaPlane, sink: media_bridge.RtpCrossSink) void {
        self.cross = sink;
    }

    /// Bind the media socket on `bind_be`:`port` (port 0 = ephemeral) and spawn
    /// the pump thread. No-op if already started.
    pub fn start(self: *MediaPlane, bind_be: u32, port: u16) !void {
        if (self.socket != null) return;
        var sock = try MediaSocket.bind(bind_be, port);
        errdefer sock.deinit();
        self.port = try sock.localPort();
        self.socket = sock;

        // Discover the server-reflexive candidate before the pump owns the socket.
        if (self.stun_server) |srv| {
            self.socket.?.setRecvTimeoutMs(1500); // allow for STUN RTT
            var txid: [12]u8 = undefined;
            self.csprng.random().bytes(&txid);
            self.discovered = self.socket.?.queryReflexive(srv, txid, self.allocator);
        }
        self.socket.?.setRecvTimeoutMs(250); // pump: wake to observe the stop flag

        // Stand up the DTLS-SRTP terminator before the pump owns it (the pump is
        // the sole thread that drives handshakes). A failure disables DTLS but
        // keeps the media plane serving.
        if (self.dtls_enabled) self.startDtls() catch |e| {
            self.dtls_enabled = false;
            std.log.warn("orochi: DTLS-SRTP terminator disabled ({s})", .{@errorName(e)});
        };

        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch |e| {
            self.stopDtls();
            self.socket.?.deinit();
            self.socket = null;
            return e;
        };
    }

    /// Allocate + initialise the DTLS terminator and its session table.
    fn startDtls(self: *MediaPlane) !void {
        var seed: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed); // don't leave the seed on the stack
        try platform.fillOsEntropy(&seed);
        const sessions = try self.allocator.alloc(dtls_server.Session, dtls_server.default_max_sessions);
        errdefer self.allocator.free(sessions);
        const now_s = @divTrunc(platform.realtimeMillis(), 1000);
        const term = try self.allocator.create(dtls_server.Terminator);
        errdefer self.allocator.destroy(term);
        term.* = try dtls_server.Terminator.init(seed, sessions, now_s - 86_400, now_s + 10 * 365 * 86_400);
        // Snapshot the immutable fingerprint for lock-free cross-thread reads.
        if (term.fingerprintLine(&self.dtls_fingerprint_buf)) |fp| {
            self.dtls_fingerprint_len = fp.len;
        } else |_| {
            self.dtls_fingerprint_len = 0;
        }
        self.dtls_sessions = sessions;
        self.dtls = term;

        // Stand up the DTLS 1.3 engine (opt-in, sharing the same certificate +
        // fingerprint). Best-effort: a 1.3 failure leaves the 1.2 path serving.
        if (self.dtls13_enabled) self.startDtls13(term) catch |e| {
            self.stopDtls13();
            std.log.warn("orochi: DTLS 1.3 engine disabled ({s})", .{@errorName(e)});
        };
    }

    /// Allocate + initialise the DTLS 1.3 terminator, sharing the 1.2
    /// terminator's certificate + key so both version engines present ONE
    /// `a=fingerprint`. The DER is copied into the 1.3 terminator (no borrow).
    fn startDtls13(self: *MediaPlane, term12: *const dtls_server.Terminator) !void {
        var seed: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try platform.fillOsEntropy(&seed);
        const sessions = try self.allocator.alloc(dtls13_server.Session, dtls13_server.default_max_sessions);
        errdefer self.allocator.free(sessions);
        const term = try self.allocator.create(dtls13_server.Terminator);
        errdefer self.allocator.destroy(term);
        term.* = try dtls13_server.Terminator.init(seed, sessions, term12.certDer(), term12.certKeyPair());
        self.dtls13_sessions = sessions;
        self.dtls13 = term;
    }

    /// Tear down the DTLS 1.3 terminator (secure-zeroing key material) and free it.
    fn stopDtls13(self: *MediaPlane) void {
        if (self.dtls13) |term| {
            term.deinit();
            self.allocator.destroy(term);
            self.dtls13 = null;
        }
        if (self.dtls13_sessions.len != 0) {
            self.allocator.free(self.dtls13_sessions);
            self.dtls13_sessions = &.{};
        }
    }

    /// Tear down the DTLS terminators (secure-zeroing key material) and free them.
    fn stopDtls(self: *MediaPlane) void {
        self.dtls_fingerprint_len = 0;
        self.stopDtls13(); // LIFO: 1.3 was stood up after 1.2
        if (self.dtls) |term| {
            term.deinit();
            self.allocator.destroy(term);
            self.dtls = null;
        }
        if (self.dtls_sessions.len != 0) {
            self.allocator.free(self.dtls_sessions);
            self.dtls_sessions = &.{};
        }
    }

    /// Signal the pump thread to stop, join it, and close the socket.
    pub fn shutdown(self: *MediaPlane) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        // Only safe to free after the pump (sole DTLS driver) has joined.
        self.stopDtls();
        if (self.socket) |*s| {
            s.deinit();
            self.socket = null;
        }
    }

    fn pumpLoop(self: *MediaPlane) void {
        var buf: [media_socket.max_datagram]u8 = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const sock = &(self.socket orelse return);
            const got = sock.recvFrom(&buf) orelse continue; // timeout/idle
            if (got.data.len == 0) continue;
            if (got.data.len > self.max_frame_bytes) continue;
            // RFC 7983 demultiplexing: DTLS records carry a content-type byte in
            // 20..=63. Only taken when DTLS-SRTP is enabled, so the STUN/RTP
            // paths below are byte-identical when off.
            if (self.dtls_enabled and got.data[0] >= 20 and got.data[0] <= 63) {
                self.handleDtls(sock, got.from, got.data);
                continue;
            }
            if (MediaSocket.isStun(got.data[0])) {
                lockSpin(&self.mutex);
                const resp = self.transport.handleStunBinding(self.allocator, got.data, got.from) catch null;
                self.mutex.unlock();
                if (resp) |r| {
                    defer self.allocator.free(r);
                    sock.sendTo(got.from, r);
                }
            } else {
                // Media: require RTP/RTCP framing (version 2 in the top two bits,
                // min header) so the port is not an open UDP reflector.
                if (got.data.len < rtp_profile.header_len or (got.data[0] & 0xC0) != 0x80) continue;
                const b1 = got.data[1];
                if (isRtcp(b1)) {
                    // Terminate Generic NACK (RTPFB PT=205, FMT=1) locally from the
                    // retransmit cache; other RTCP is relayed like media.
                    if (b1 == 205 and (got.data[0] & 0x1f) == 1 and got.data.len >= 12) {
                        const media_ssrc = std.mem.readInt(u32, got.data[8..12], .big);
                        self.handleNack(sock, got.from, media_ssrc, got.data[12..]);
                        continue;
                    }
                    self.relay(sock, got.from, got.data, 0, null, false);
                } else {
                    var ssrc: u32 = 0;
                    var seq: ?u16 = null;
                    if (rtp_profile.decodeHeader(got.data)) |dh| {
                        ssrc = dh.header.ssrc;
                        seq = dh.header.sequence;
                    } else |_| {}
                    self.relay(&sock.*, got.from, got.data, ssrc, seq, true);
                }
            }
        }
    }

    /// Drive one DTLS record datagram through the per-peer terminator and send
    /// any response flight back to `from`. Terminator state is touched only by
    /// this (pump) thread. The response is a small handshake flight (< 2 KiB).
    fn handleDtls(self: *MediaPlane, sock: *MediaSocket, from: TransportAddress, data: []const u8) void {
        var out: [2048]u8 = undefined;
        const now = platform.monotonicMillis();
        // Version dispatch: a peer the 1.3 engine already owns, or a fresh
        // ClientHello offering DTLS 1.3 (supported_versions), routes to the 1.3
        // engine; everything else stays on Increment 1's DTLS 1.2 path.
        if (self.dtls13) |t13| {
            if (t13.owns(from) or dtls13_server.offersDtls13(data)) {
                if (t13.handleDatagram(from, data, now, &out)) |resp| sock.sendTo(from, resp);
                return;
            }
        }
        const term = self.dtls orelse return;
        if (term.handleDatagram(from, data, now, &out)) |resp| {
            sock.sendTo(from, resp);
        }
    }

    /// The daemon's DTLS `a=fingerprint` line (SHA-256), copied into `out`, for
    /// the signaling layer to advertise (Increment 3). Null when DTLS-SRTP is
    /// disabled/down. Reads the inline snapshot taken at `start` — never
    /// dereferences the mutable terminator pointer, so it is UAF-safe from any
    /// thread even racing teardown (worst case: a stale-but-valid line or null).
    pub fn dtlsFingerprint(self: *const MediaPlane, out: []u8) ?[]const u8 {
        const n = self.dtls_fingerprint_len;
        if (n == 0 or out.len < n) return null;
        @memcpy(out[0..n], self.dtls_fingerprint_buf[0..n]);
        return out[0..n];
    }

    /// Selectively forward `packet` (from `source`) to the other call
    /// participants; meter + (for RTP, `seq` non-null) cache it for NACK.
    fn relay(self: *MediaPlane, sock: *MediaSocket, source: TransportAddress, packet: []const u8, ssrc: u32, seq: ?u16, bridge_media: bool) void {
        var targets: [media_transport.max_forward]TransportAddress = undefined;
        var chanbuf: [256]u8 = undefined;
        var chanlen: usize = 0;
        lockSpin(&self.mutex);
        const n = self.transport.forwardFromSource(source, packet, ssrc, seq, &targets);
        if (bridge_media) {
            // Copy the source's channel out under the lock so the cross-leg sink
            // can use it after we unlock (the composite key may be freed).
            if (self.transport.channelForSource(source)) |chan| {
                if (chan.len <= chanbuf.len) {
                    @memcpy(chanbuf[0..chan.len], chan);
                    chanlen = chan.len;
                }
            }
        }
        self.mutex.unlock();
        for (targets[0..n]) |dst| sock.sendTo(dst, packet);

        // Bridge the same RTP frame to any native members of this channel.
        if (bridge_media and chanlen != 0) {
            if (self.cross) |sink| sink.onRtpFrame(chanbuf[0..chanlen], packet, false);
        }
    }

    /// Answer a Generic NACK from `requester` for `media_ssrc`: resend each
    /// requested-and-still-cached packet from the publisher's retransmit buffer.
    fn handleNack(self: *MediaPlane, sock: *MediaSocket, requester: TransportAddress, media_ssrc: u32, fci: []const u8) void {
        const missing = rtp_nack.parseNackFci(self.allocator, fci) catch return;
        defer self.allocator.free(missing);
        var scratch: [media_socket.max_datagram]u8 = undefined;
        for (missing) |seq| {
            lockSpin(&self.mutex);
            const got = self.transport.copyRetransmit(media_ssrc, seq, &scratch);
            self.mutex.unlock();
            if (got) |len| sock.sendTo(requester, scratch[0..len]);
        }
    }

    /// Allocate (or rotate) the ICE credentials for a call participant and return
    /// them for the signaling layer to advertise. Null on allocation failure.
    pub fn allocate(self: *MediaPlane, channel: []const u8, participant: []const u8) ?Creds {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.allocate(channel, participant, self.csprng.random()) catch return null;
        return .{ .ufrag = ep.ufrag, .pwd = ep.pwd };
    }

    /// Format the discovered server-reflexive IPv4 into `buf` for advertising as
    /// the media candidate, or null when discovery is off/failed (caller uses
    /// its configured fallback host).
    pub fn candidateIp(self: *const MediaPlane, buf: []u8) ?[]const u8 {
        const a = self.discovered orelse return null;
        if (a.ip_len != 4) return null;
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a.ip[0], a.ip[1], a.ip[2], a.ip[3] }) catch null;
    }

    /// The per-call SRTP group key (SDES) for `channel`, generated on first use.
    pub fn groupKey(self: *MediaPlane, channel: []const u8) [media_transport.group_key_len]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.transport.ensureGroupKey(channel, self.csprng.random());
    }

    /// Drop a participant's endpoint (MEDIA LEAVE / disconnect).
    pub fn remove(self: *MediaPlane, channel: []const u8, participant: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.transport.remove(channel, participant);
    }

    /// Snapshot per-participant transport stats for `channel` into `out`.
    pub fn statsForChannel(self: *MediaPlane, channel: []const u8, out: []MediaTransport.ParticipantStat) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.transport.statsForChannel(channel, out);
    }

    /// Send `bytes` to `dest` on the media socket. Used by the native pump's
    /// cross-leg sink to deliver RTP-rewrapped frames to WebRTC peers. UDP
    /// sendto on a shared fd is safe to call from another thread.
    pub fn sendTo(self: *MediaPlane, dest: TransportAddress, bytes: []const u8) void {
        if (self.socket) |*s| s.sendTo(dest, bytes);
    }

    /// The bound remote address of a WebRTC participant (learned via STUN), or
    /// null if unknown/unbound. Lets the cross-leg sink resolve a live target
    /// address rather than a stale one.
    pub fn remoteFor(self: *MediaPlane, channel: []const u8, participant: []const u8) ?TransportAddress {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.get(channel, participant) orelse return null;
        if (!ep.connected()) return null;
        return ep.remote;
    }

    /// Whether a participant's ICE check has bound a peer address (test/introspection).
    pub fn isConnected(self: *MediaPlane, channel: []const u8, participant: []const u8) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.get(channel, participant) orelse return false;
        return ep.connected();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const stun = @import("../proto/stun.zig");
const dtls_messages = @import("../proto/dtls12_messages.zig");
const dtls_record = @import("../proto/dtls12_record.zig");
const dtls_handshake = @import("../proto/dtls_handshake.zig");
const dtls_srtp = @import("../proto/dtls_srtp.zig");
const dtls13_messages = @import("../proto/dtls13_messages.zig");
const dtls_kx = @import("../proto/dtls_keyexchange.zig");

test "MediaPlane: threaded pump answers a STUN check and binds the peer" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);

    const creds = plane.allocate("#c", "alice") orelse return error.TestUnexpectedResult;

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    var user_buf: [media_transport.ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{creds.ufragSlice()}) catch unreachable;
    const tx: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = creds.pwdSlice(),
        .fingerprint = true,
    });
    defer testing.allocator.free(req);

    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, req);

    // The pump thread answers; receiving the response proves it was processed.
    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    var decoded = try stun.decode(testing.allocator, got.data);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    try testing.expect(plane.isConnected("#c", "alice"));
}

test "MediaPlane: start/shutdown is clean and re-startable port is reported" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    try testing.expect(plane.port != 0);
    plane.shutdown();
    // After shutdown the socket is closed; re-start binds a fresh ephemeral port.
    try plane.start(loopback_be, 0);
    try testing.expect(plane.port != 0);
}

test "MediaPlane: DTLS off leaves the pump with no terminator and no fingerprint" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    try testing.expect(plane.dtls == null);
    var fp_buf: [128]u8 = undefined;
    try testing.expect(plane.dtlsFingerprint(&fp_buf) == null);
}

test "MediaPlane: DTLS-enabled pump demultiplexes a ClientHello into a HelloVerifyRequest" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    try plane.start(loopback_be, 0);
    // Terminator stood up and exposes a well-formed SHA-256 fingerprint.
    try testing.expect(plane.dtls != null);
    var fp_buf: [128]u8 = undefined;
    const fp = plane.dtlsFingerprint(&fp_buf) orelse return error.TestUnexpectedResult;
    try testing.expect(std.mem.startsWith(u8, fp, "sha-256 "));

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    // Send a bare ClientHello (RFC 7983 DTLS range → content-type byte 22).
    var rnd: [32]u8 = undefined;
    for (&rnd, 0..) |*b, i| b.* = @intCast(i +% 1);
    var ch_body: [512]u8 = undefined;
    const chb = try dtls_messages.buildClientHello(&ch_body, .{
        .random = rnd,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var dgram: [700]u8 = undefined;
    const dlen = try dtls_server.framePlaintextHandshake(&dgram, .client_hello, 0, 0, 0, chb);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, dgram[0..dlen]);

    // The pump demuxes to DTLS and replies with a HelloVerifyRequest.
    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    const rdec = try dtls_record.RecordHeader.decode(got.data);
    try testing.expectEqual(dtls_record.ContentType.handshake, rdec.hdr.content_type);
    const hh = try dtls_handshake.Header.decode(rdec.fragment);
    try testing.expectEqual(dtls_handshake.HandshakeType.hello_verify_request, hh.hdr.msg_type);
}

test "MediaPlane: DTLS-SRTP on but dtls13 off leaves the 1.3 engine down (1.2-only)" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true; // dtls13_enabled defaults false
    try plane.start(loopback_be, 0);
    try testing.expect(plane.dtls != null); // 1.2 up
    try testing.expect(plane.dtls13 == null); // 1.3 stays down by default
}

test "MediaPlane: version seam routes a DTLS 1.3 ClientHello to the 1.3 engine (HRR)" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    plane.dtls_enabled = true;
    plane.dtls13_enabled = true;
    try plane.start(loopback_be, 0);
    // Both engines stood up sharing one certificate → one fingerprint.
    try testing.expect(plane.dtls != null);
    try testing.expect(plane.dtls13 != null);

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    // A DTLS 1.3 ClientHello (supported_versions offers 0xfefc) → the pump routes
    // to the 1.3 engine, which replies with a HelloRetryRequest.
    var ch_body: [512]u8 = undefined;
    const chb = try dtls13_messages.buildClientHello13(&ch_body, .{
        .random = @splat(0x33),
        .key_share_point = dtls_kx.generateKeyPair(@splat(0x5c)).public,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    var dgram: [700]u8 = undefined;
    const dlen = try dtls13_server.framePlaintext13(&dgram, .client_hello, 0, 0, chb);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, dgram[0..dlen]);

    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    const rdec = try dtls_record.RecordHeader.decode(got.data);
    try testing.expectEqual(dtls_record.ContentType.handshake, rdec.hdr.content_type);
    const hh = try dtls_handshake.Header.decode(rdec.fragment);
    const shv = try dtls13_messages.parseServerHello13(rdec.fragment[dtls_handshake.handshake_header_len..][0..hh.hdr.length]);
    try testing.expect(shv.isHelloRetryRequest());
    try testing.expectEqual(@as(usize, dtls13_server.cookie_len), shv.cookie.len);
}
