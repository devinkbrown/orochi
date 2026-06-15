//! Per-connection TLS 1.3 adapter that drives `crypto/tls_server.Server` from the
//! daemon's socket loop. The loop never touches the handshake state machine
//! directly: it hands raw socket bytes to `onInbound()`, writes back the returned
//! ciphertext, and once `handshakeDone()` is true reads decrypted application
//! data from the same `Outcome`. Outbound application data goes through `write()`.
//!
//! This wrapper owns the record-layer framing: a TLS record is a 5-byte header
//! (content type, 2-byte legacy version, 2-byte length) followed by `length`
//! body bytes. `onInbound()` buffers the inbound stream, processes only complete
//! records, and retains any trailing partial record for the next call. The inner
//! `Server` already buffers internally too, but we frame before feeding so we can
//! cleanly switch from "feed the handshake" to "decrypt application_data" the
//! instant the handshake completes (a connected `Server.feed` rejects records).
//!
//! Scope mirrors `tls_server`: TLS 1.3, X25519, an Ed25519 leaf. This module does
//! no syscalls — it is a pure byte transform over the `Server` it wraps.

const std = @import("std");
const Allocator = std.mem.Allocator;

const tls_server = @import("../crypto/tls_server.zig");
const tls12_server = @import("../crypto/tls12_server.zig");
const tls_record = @import("../crypto/tls_record.zig");
const tls_resumption = @import("../crypto/tls_resumption.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_conn requires a 64-bit target");
}

/// Errors surfaced by the adapter: the inner 1.3 + 1.2 handshake/record errors
/// plus the allocator errors from growing the internal buffers.
pub const Error = tls_server.Error || tls12_server.Error || Allocator.Error;

/// What a single `onInbound()` produced. Both slices point into internal buffers
/// and stay valid only until the next `onInbound()` / `write()` call; the caller
/// must consume or copy them before driving the connection again.
///
///   * `handshake_bytes` — ciphertext to write straight back to the socket. This
///     is the server flight during the handshake and is empty afterwards.
///   * `plaintext` — decrypted application data accumulated from any
///     application_data records in this batch. Empty until the handshake is done
///     and whenever a batch carried no complete application records.
pub const Outcome = struct {
    handshake_bytes: []const u8 = &.{},
    plaintext: []const u8 = &.{},
};

/// Inner engine selected from the first ClientHello. `undecided` holds until a
/// version is detected; afterwards exactly one engine drives the connection.
const Engine = union(enum) {
    undecided,
    tls13: tls_server.Server,
    tls12: tls12_server.Server,
};

pub const Version = enum { tls12, tls13 };

pub const TlsConn = struct {
    allocator: Allocator,
    engine: Engine,
    /// TLS 1.3 server config (always present; the default/preferred protocol).
    cfg13: tls_server.Config,
    /// Optional hardened TLS 1.2 config. When null the listener is 1.3-only and
    /// a non-1.3 ClientHello is rejected with `error.ProtocolVersion`.
    cfg12: ?tls12_server.Config,

    /// Inbound socket bytes not yet split into a complete record.
    recv_buf: std.ArrayList(u8) = .empty,
    /// Ciphertext to send back, rebuilt per `onInbound()` call.
    send_buf: std.ArrayList(u8) = .empty,
    /// Decrypted application data, rebuilt per `onInbound()` call.
    plain_buf: std.ArrayList(u8) = .empty,
    /// Scratch for outbound ciphertext, rebuilt per `write()` call.
    write_buf: std.ArrayList(u8) = .empty,

    /// TLS 1.3-only adapter (back-compatible): the engine is fixed to the TLS 1.3
    /// server and a 1.2 ClientHello is rejected.
    pub fn init(allocator: Allocator, config: tls_server.Config) Error!TlsConn {
        return .{
            .allocator = allocator,
            .engine = .{ .tls13 = try tls_server.Server.init(allocator, config) },
            .cfg13 = config,
            .cfg12 = null,
        };
    }

    /// Version-dispatching adapter: the first ClientHello is routed to the TLS
    /// 1.3 server when it offers supported_versions=0x0304, otherwise to the
    /// hardened TLS 1.2 server. Both configs are borrowed.
    pub fn initDual(allocator: Allocator, cfg13: tls_server.Config, cfg12: tls12_server.Config) TlsConn {
        return .{ .allocator = allocator, .engine = .undecided, .cfg13 = cfg13, .cfg12 = cfg12 };
    }

    pub fn deinit(self: *TlsConn) void {
        switch (self.engine) {
            .undecided => {},
            .tls13 => |*s| s.deinit(),
            .tls12 => |*s| s.deinit(),
        }
        self.recv_buf.deinit(self.allocator);
        self.send_buf.deinit(self.allocator);
        self.plain_buf.deinit(self.allocator);
        self.write_buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// True once the chosen engine's handshake has completed.
    pub fn handshakeDone(self: *const TlsConn) bool {
        return switch (self.engine) {
            .undecided => false,
            .tls13 => |*s| s.handshakeDone(),
            .tls12 => |*s| s.handshakeDone(),
        };
    }

    /// The negotiated protocol version, or null before the engine is chosen.
    pub fn negotiatedVersion(self: *const TlsConn) ?Version {
        return switch (self.engine) {
            .undecided => null,
            .tls13 => .tls13,
            .tls12 => .tls12,
        };
    }

    pub fn selectedAlpn(self: *const TlsConn) ?[]const u8 {
        return switch (self.engine) {
            .undecided => null,
            .tls13 => |*s| s.selectedAlpn(),
            .tls12 => |*s| s.selectedAlpn(),
        };
    }

    /// IANA name of the negotiated cipher suite (e.g. "TLS_AES_128_GCM_SHA256"),
    /// or null until the chosen engine has selected one. The returned string is
    /// static — safe to hold for the connection's lifetime (WHOIS 671).
    pub fn cipherName(self: *const TlsConn) ?[]const u8 {
        return switch (self.engine) {
            .undecided => null,
            .tls13 => |*s| s.cipherName(),
            .tls12 => |*s| s.cipherName(),
        };
    }

    /// The verified client leaf DER (mTLS), or null. mTLS client auth is a
    /// TLS 1.3-only path here; the hardened 1.2 engine never requests a cert.
    pub fn clientCertDer(self: *const TlsConn) ?[]const u8 {
        return switch (self.engine) {
            .tls13 => |*s| s.clientCertDer(),
            else => null,
        };
    }

    /// RFC 9266 tls-exporter channel-binding value for TLS 1.3 connections.
    /// TLS 1.2 does not implement this clean-room exporter path, so callers
    /// treat error.BadState as "not available" and keep PLUS mechanisms gated.
    pub fn channelBindingTlsExporter(self: *const TlsConn, out: *[32]u8) Error!void {
        return switch (self.engine) {
            .tls13 => |*s| s.channelBindingTlsExporter(out),
            else => error.BadState,
        };
    }

    /// Drive the connection with a chunk of bytes read from the socket. On the
    /// first call it selects the protocol version from the buffered ClientHello,
    /// then drives the chosen engine.
    pub fn onInbound(self: *TlsConn, socket_bytes: []const u8) Error!Outcome {
        self.send_buf.clearRetainingCapacity();
        self.plain_buf.clearRetainingCapacity();
        try self.recv_buf.appendSlice(self.allocator, socket_bytes);

        if (std.meta.activeTag(self.engine) == .undecided) {
            switch (try self.detectVersion()) {
                .need_more => return .{ .handshake_bytes = &.{}, .plaintext = &.{} },
                .tls13 => self.engine = .{ .tls13 = try tls_server.Server.init(self.allocator, self.cfg13) },
                .tls12 => {
                    const c12 = self.cfg12 orelse return error.ProtocolVersion;
                    self.engine = .{ .tls12 = try tls12_server.Server.init(self.allocator, c12) };
                },
            }
        }

        // Process complete records front-to-back, consuming each from recv_buf.
        while (completeRecordLen(self.recv_buf.items)) |wire_len| {
            if (self.handshakeDone()) {
                try self.decryptRecord(self.recv_buf.items[0..wire_len]);
            } else {
                try self.feedRecord(self.recv_buf.items[0..wire_len]);
            }
            consumePrefix(&self.recv_buf, wire_len);
        }

        // A post-handshake KeyUpdate (TLS 1.3 only) makes the inner server queue
        // a reply; send it back alongside any handshake flight.
        switch (self.engine) {
            .tls13 => |*s| {
                if (try s.takePendingSend()) |reply| {
                    defer self.allocator.free(reply);
                    try self.send_buf.appendSlice(self.allocator, reply);
                }
            },
            else => {},
        }

        return .{ .handshake_bytes = self.send_buf.items, .plaintext = self.plain_buf.items };
    }

    /// Adapter-level resume state for a Helix live upgrade: the chosen engine's
    /// connected-state snapshot plus any buffered partial inbound record. The
    /// `pending_recv` slice borrows this TlsConn's internal buffer — serialize it
    /// before driving the connection again.
    pub const ResumeState = struct {
        engine: EngineState,
        /// Bytes of a partially received TLS record buffered at export time.
        pending_recv: []const u8 = &.{},

        pub const EngineState = union(Version) {
            tls12: tls12_server.Server.ResumeState,
            tls13: tls_server.Server.ResumeState,
        };
    };

    /// Capture this connection's live TLS state for a Helix upgrade handoff.
    /// Only valid once the handshake completed (`error.BadState` otherwise —
    /// mid-handshake connections are not resumable and must reconnect).
    pub fn exportResume(self: *const TlsConn) Error!ResumeState {
        if (!self.handshakeDone()) return error.BadState;
        return switch (self.engine) {
            .tls13 => |*s| .{ .engine = .{ .tls13 = try s.exportResume() }, .pending_recv = self.recv_buf.items },
            .tls12 => |*s| .{ .engine = .{ .tls12 = try s.exportResume() }, .pending_recv = self.recv_buf.items },
            .undecided => error.BadState,
        };
    }

    /// Successor side of a Helix upgrade: rebuild a CONNECTED adapter from an
    /// exported `ResumeState`. The matching engine config must be supplied (a
    /// 1.2-engine state with no `cfg12` fails with `error.ProtocolVersion`).
    /// Any carried partial inbound record is re-buffered so the byte stream
    /// continues exactly where the predecessor stopped.
    pub fn resumeFrom(allocator: Allocator, cfg13: tls_server.Config, cfg12: ?tls12_server.Config, st: ResumeState) Error!TlsConn {
        var self = TlsConn{
            .allocator = allocator,
            .engine = .undecided,
            .cfg13 = cfg13,
            .cfg12 = cfg12,
        };
        errdefer self.deinit();
        switch (st.engine) {
            .tls13 => |s13| self.engine = .{ .tls13 = try tls_server.Server.resumeConnected(allocator, cfg13, s13) },
            .tls12 => |s12| {
                const c12 = cfg12 orelse return error.ProtocolVersion;
                self.engine = .{ .tls12 = try tls12_server.Server.resumeConnected(allocator, c12, s12) };
            },
        }
        try self.recv_buf.appendSlice(allocator, st.pending_recv);
        return self;
    }

    /// Encrypt `plaintext` into one or more application_data records.
    pub fn write(self: *TlsConn, plaintext: []const u8) Error![]const u8 {
        if (!self.handshakeDone()) return error.BadState;
        self.write_buf.clearRetainingCapacity();

        var offset: usize = 0;
        while (true) {
            const end = @min(offset + tls_record.max_plaintext_len, plaintext.len);
            const chunk = plaintext[offset..end];
            const record = try self.encryptOne(chunk);
            defer self.allocator.free(record);
            try self.write_buf.appendSlice(self.allocator, record);
            offset = end;
            if (offset >= plaintext.len) break;
        }
        return self.write_buf.items;
    }

    fn encryptOne(self: *TlsConn, chunk: []const u8) Error![]u8 {
        return switch (self.engine) {
            .tls13 => |*s| try s.encrypt(chunk),
            .tls12 => |*s| try s.encrypt(chunk),
            .undecided => error.BadState,
        };
    }

    /// Feed one complete handshake-phase record to the chosen engine.
    fn feedRecord(self: *TlsConn, record: []const u8) Error!void {
        switch (self.engine) {
            .tls13 => |*s| {
                switch (try s.feed(record)) {
                    .need_more => {},
                    .bytes_to_send => |flight| {
                        defer self.allocator.free(flight);
                        try self.send_buf.appendSlice(self.allocator, flight);
                    },
                }
                if (s.handshakeDone()) {
                    if (try s.takeEarlyData()) |early| {
                        defer self.allocator.free(early);
                        try self.plain_buf.appendSlice(self.allocator, early);
                    }
                }
            },
            .tls12 => |*s| switch (try s.feed(record)) {
                .need_more => {},
                .bytes_to_send => |flight| {
                    defer self.allocator.free(flight);
                    try self.send_buf.appendSlice(self.allocator, flight);
                },
            },
            .undecided => return error.BadState,
        }
    }

    /// Decrypt one complete application_data record into `plain_buf`.
    fn decryptRecord(self: *TlsConn, record: []const u8) Error!void {
        const opened = switch (self.engine) {
            .tls13 => |*s| try s.decrypt(record),
            .tls12 => |*s| try s.decrypt(record),
            .undecided => return error.BadState,
        };
        defer self.allocator.free(opened);
        try self.plain_buf.appendSlice(self.allocator, opened);
    }

    const Detected = enum { need_more, tls12, tls13 };

    /// Inspect the buffered first ClientHello and decide the protocol version: a
    /// supported_versions extension listing 0x0304 selects TLS 1.3, otherwise
    /// TLS 1.2. Reassembles the ClientHello across handshake records if needed.
    fn detectVersion(self: *const TlsConn) Error!Detected {
        var hs: [tls_record.max_plaintext_len]u8 = undefined;
        var hs_len: usize = 0;
        var pos: usize = 0;
        const buf = self.recv_buf.items;
        while (true) {
            const wire = completeRecordLen(buf[pos..]) orelse return .need_more;
            const rec = buf[pos .. pos + wire];
            if (rec[0] != @intFromEnum(tls_record.ContentType.handshake)) return error.BadRecord;
            const frag = rec[tls_record.record_header_len..];
            if (hs_len + frag.len > hs.len) return error.BadHandshake;
            @memcpy(hs[hs_len..][0..frag.len], frag);
            hs_len += frag.len;
            pos += wire;
            if (hs_len >= 4) {
                const msg_len = (@as(usize, hs[1]) << 16) | (@as(usize, hs[2]) << 8) | hs[3];
                if (hs_len >= 4 + msg_len) {
                    if (hs[0] != 1) return error.BadHandshake; // must be client_hello
                    return classifyClientHello(hs[4 .. 4 + msg_len]);
                }
            }
        }
    }
};

/// Classify a ClientHello body: returns `.tls13` when a supported_versions
/// extension lists 0x0304, else `.tls12`. Strict bounds checks throughout.
fn classifyClientHello(body: []const u8) TlsConn.Detected {
    var i: usize = 0;
    // client_version(2) + random(32)
    i += 2 + 32;
    if (i > body.len) return .tls12;
    // session_id
    if (i >= body.len) return .tls12;
    i += 1 + body[i];
    if (i + 2 > body.len) return .tls12;
    // cipher_suites
    const cs_len = (@as(usize, body[i]) << 8) | body[i + 1];
    i += 2 + cs_len;
    if (i >= body.len) return .tls12;
    // compression_methods
    i += 1 + body[i];
    // extensions are optional; a TLS 1.2 ClientHello may omit them entirely.
    if (i + 2 > body.len) return .tls12;
    const ext_total = (@as(usize, body[i]) << 8) | body[i + 1];
    i += 2;
    const ext_end = @min(i + ext_total, body.len);
    while (i + 4 <= ext_end) {
        const etype = (@as(usize, body[i]) << 8) | body[i + 1];
        const elen = (@as(usize, body[i + 2]) << 8) | body[i + 3];
        i += 4;
        if (i + elen > ext_end) break;
        if (etype == 43) { // supported_versions
            const list = body[i .. i + elen];
            if (list.len >= 1) {
                const ll = list[0];
                var j: usize = 1;
                while (j + 1 < list.len and j + 1 <= ll) : (j += 2) {
                    if (((@as(usize, list[j]) << 8) | list[j + 1]) == 0x0304) return .tls13;
                }
            }
        }
        i += elen;
    }
    return .tls12;
}

/// Length on the wire of the first complete TLS record in `buf`, or null when
/// fewer than a full record's worth of bytes are present yet. Validates only the
/// 5-byte framing header; the inner server validates content type and body.
fn completeRecordLen(buf: []const u8) ?usize {
    if (buf.len < tls_record.record_header_len) return null;
    const body_len = std.mem.readInt(u16, buf[3..5], .big);
    const wire_len = tls_record.record_header_len + @as(usize, body_len);
    if (buf.len < wire_len) return null;
    return wire_len;
}

/// Drop the first `n` bytes of `list`, shifting the remainder down in place.
fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const remain = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..remain], list.items[n..]);
    list.shrinkRetainingCapacity(remain);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Ed25519 = std.crypto.sign.Ed25519;
const tls_client = @import("../crypto/tls_client.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");

/// Build the self-signed Ed25519 leaf the loopback tests share: a CA-flagged
/// cert carrying the `irc.test` dNSName, matching the tls_server loopback test.
fn makeLeaf(out: []u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x34 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
}

test "onInbound drives a full handshake against tls_client and streams app data both ways" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    // ClientHello -> TlsConn returns the server flight, no plaintext yet.
    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    try std.testing.expect(sh_out.handshake_bytes.len != 0);
    try std.testing.expectEqual(@as(usize, 0), sh_out.plaintext.len);
    try std.testing.expect(!conn.handshakeDone());

    // Client consumes the flight and produces its Finished.
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());

    // Finished -> TlsConn completes the handshake with nothing to send back.
    const fin_out = try conn.onInbound(cfin);
    try std.testing.expectEqual(@as(usize, 0), fin_out.handshake_bytes.len);
    try std.testing.expectEqual(@as(usize, 0), fin_out.plaintext.len);
    try std.testing.expect(conn.handshakeDone());

    // Client -> server application data surfaces as Outcome.plaintext.
    const c2s = try client.encrypt("hello server");
    defer alloc.free(c2s);
    const app_out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("hello server", app_out.plaintext);
    try std.testing.expectEqual(@as(usize, 0), app_out.handshake_bytes.len);

    // Server -> client application data round-trips through write().
    const cipher = try conn.write("hello client");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("hello client", got);
}

test "shared ticket key and replay guard resume across TlsConn instances" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x68} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const ticket_key = [_]u8{0x24} ** @sizeOf(tls_resumption.TicketKey);
    var guard = tls_resumption.ReplayGuard{};

    var conn1 = try TlsConn.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .ticket_key = ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_000,
        .max_early_data_size = 4096,
    });
    defer conn1.deinit();
    var client1 = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client1.deinit();

    const ch1 = try client1.start();
    defer alloc.free(ch1);
    const sh1 = try conn1.onInbound(ch1);
    const cfin1 = switch (try client1.feed(sh1.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin1);
    const fin1 = try conn1.onInbound(cfin1);
    try std.testing.expect(conn1.handshakeDone());
    try std.testing.expect(fin1.handshake_bytes.len != 0);
    try std.testing.expectEqual(tls_client.AppRead.control, try client1.decryptApp(fin1.handshake_bytes));
    const stored = client1.takeSessionTicket() orelse return error.TestUnexpectedResult;
    defer alloc.free(stored);

    var conn2 = try TlsConn.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .ticket_key = ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_001,
        .max_early_data_size = 4096,
    });
    defer conn2.deinit();
    var client2 = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client2.deinit();
    try client2.setSessionTicket(stored, 1000);
    try client2.setEarlyData("EARLY hello");

    const rch = try client2.start();
    defer alloc.free(rch);
    const sh2 = try conn2.onInbound(rch);
    try std.testing.expect(switch (conn2.engine) {
        .tls13 => |*s| s.acceptedSessionTicket(),
        else => false,
    });
    try std.testing.expect(switch (conn2.engine) {
        .tls13 => |*s| s.earlyDataAccepted(),
        else => false,
    });
    const cfin2 = switch (try client2.feed(sh2.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin2);
    try std.testing.expectEqual(@as(?bool, true), client2.earlyDataAccepted());
    const fin2 = try conn2.onInbound(cfin2);
    try std.testing.expect(conn2.handshakeDone());
    try std.testing.expectEqualStrings("EARLY hello", fin2.plaintext);

    var conn3 = try TlsConn.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
        .replay_guard = &guard,
        .now_unix_seconds = 1_700_000_001,
        .max_early_data_size = 4096,
    });
    defer conn3.deinit();
    const replay = try conn3.onInbound(rch);
    try std.testing.expect(replay.handshake_bytes.len != 0);
    try std.testing.expect(switch (conn3.engine) {
        .tls13 => |*s| s.acceptedSessionTicket(),
        else => false,
    });
    try std.testing.expect(!switch (conn3.engine) {
        .tls13 => |*s| s.earlyDataAccepted(),
        else => true,
    });
}

test "exportResume/resumeFrom carries a live TLS 1.3 conn, including a buffered partial record" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x71} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const cfg13 = tls_server.Config{ .cert_chain = &.{der}, .signing_key = kp };

    var conn = try TlsConn.init(alloc, cfg13);
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    // Export before the handshake completes is rejected (fail-safe: such a
    // connection is dropped from the upgrade carry set, never mis-carried).
    try std.testing.expectError(error.BadState, conn.exportResume());

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // Advance both directions, then leave HALF of a client record buffered so
    // the export carries a non-empty pending_recv.
    const pre = try client.encrypt("before upgrade");
    defer alloc.free(pre);
    const pre_out = try conn.onInbound(pre);
    try std.testing.expectEqualStrings("before upgrade", pre_out.plaintext);
    const ack = try conn.write("ack");
    const ack_plain = try client.decrypt(ack);
    defer alloc.free(ack_plain);
    try std.testing.expectEqualStrings("ack", ack_plain);

    const split_rec = try client.encrypt("split across upgrade");
    defer alloc.free(split_rec);
    const half = split_rec.len / 2;
    const part = try conn.onInbound(split_rec[0..half]);
    try std.testing.expectEqual(@as(usize, 0), part.plaintext.len);

    const st = try conn.exportResume();
    try std.testing.expectEqual(Version.tls13, std.meta.activeTag(st.engine));
    try std.testing.expect(st.pending_recv.len != 0);

    // Successor adapter: the second half of the record completes and decrypts.
    var conn2 = try TlsConn.resumeFrom(alloc, cfg13, null, st);
    defer conn2.deinit();
    try std.testing.expect(conn2.handshakeDone());
    const rest = try conn2.onInbound(split_rec[half..]);
    try std.testing.expectEqualStrings("split across upgrade", rest.plaintext);

    // Both directions keep flowing on the resumed adapter.
    const cipher = try conn2.write("hello from successor");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("hello from successor", got);
    const more = try client.encrypt("more after upgrade");
    defer alloc.free(more);
    const more_out = try conn2.onInbound(more);
    try std.testing.expectEqualStrings("more after upgrade", more_out.plaintext);
}

test "resumeFrom rejects a TLS 1.2 engine state when no 1.2 config is supplied" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x72} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);
    const st = TlsConn.ResumeState{ .engine = .{ .tls12 = .{
        .suite = 0xc02b,
        .keys = .{},
        .app_read_seq = 0,
        .app_write_seq = 0,
    } } };
    try std.testing.expectError(
        error.ProtocolVersion,
        TlsConn.resumeFrom(alloc, .{ .cert_chain = &.{der}, .signing_key = kp }, null, st),
    );
}

test "onInbound reassembles a handshake record split across two calls" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);

    // Feed the ClientHello in two chunks: the first half is an incomplete record,
    // so the partial bytes must be retained and no flight produced yet.
    const split = ch.len / 2;
    const part1 = try conn.onInbound(ch[0..split]);
    try std.testing.expectEqual(@as(usize, 0), part1.handshake_bytes.len);
    try std.testing.expect(!conn.handshakeDone());

    // The second chunk completes the record and yields the full server flight.
    const part2 = try conn.onInbound(ch[split..]);
    try std.testing.expect(part2.handshake_bytes.len != 0);

    // The flight still drives the standards client to a finished handshake.
    const cfin = switch (try client.feed(part2.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());

    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // End-to-end app data confirms the reassembled handshake derived live keys.
    const c2s = try client.encrypt("after split");
    defer alloc.free(c2s);
    const out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("after split", out.plaintext);
}

test "write splits plaintext larger than the record limit into multiple records" {
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh_out = try conn.onInbound(ch);
    const cfin = switch (try client.feed(sh_out.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    // A payload just over one record's worth must produce two records: the client
    // decrypts each independently, and concatenated they reproduce the payload.
    const big = try alloc.alloc(u8, tls_record.max_plaintext_len + 100);
    defer alloc.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);

    const cipher = try conn.write(big);
    // Two records: 2 * 5-byte headers of overhead beyond the plaintext + tags.
    try std.testing.expect(cipher.len > big.len + 2 * tls_record.record_header_len);

    var reassembled: std.ArrayList(u8) = .empty;
    defer reassembled.deinit(alloc);
    var pos: usize = 0;
    while (completeRecordLen(cipher[pos..])) |wire_len| {
        const rec = cipher[pos .. pos + wire_len];
        const pt = try client.decrypt(rec);
        defer alloc.free(pt);
        try reassembled.appendSlice(alloc, pt);
        pos += wire_len;
    }
    try std.testing.expectEqual(cipher.len, pos);
    try std.testing.expectEqualSlices(u8, big, reassembled.items);
}

test "write before handshakeDone is rejected" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    var conn = try TlsConn.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer conn.deinit();
    try std.testing.expectError(error.BadState, conn.write("too early"));
}

const tls12_client = @import("../crypto/tls12_client.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");

test "version-dispatch: a TLS 1.3 client completes through a dual TlsConn" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp);

    // ECDSA cert/key for the (unused here) 1.2 leg.
    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ec_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x34 },
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var conn = TlsConn.initDual(
        alloc,
        .{ .cert_chain = &.{der}, .signing_key = kp },
        .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key },
    );
    defer conn.deinit();

    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sh = try conn.onInbound(ch);
    try std.testing.expectEqual(Version.tls13, conn.negotiatedVersion().?);
    const cfin = switch (try client.feed(sh.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    _ = try conn.onInbound(cfin);
    try std.testing.expect(conn.handshakeDone());

    const c2s = try client.encrypt("hello 1.3");
    defer alloc.free(c2s);
    const out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("hello 1.3", out.plaintext);
    const cipher = try conn.write("reply 1.3");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("reply 1.3", got);
}

test "version-dispatch: a TLS 1.2 client completes through a dual TlsConn" {
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x55} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try makeLeaf(&cert_buf, kp); // 1.3 leg (unused here)

    const ec_key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var ec_buf: [2048]u8 = undefined;
    const ec_der = try x509_selfsign.buildSelfSignedEcdsaP256(&ec_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 1, 2, 3, 4 },
        .key_pair = ec_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var conn = TlsConn.initDual(
        alloc,
        .{ .cert_chain = &.{der}, .signing_key = kp },
        .{ .cert_chain = &.{ec_der}, .ecdsa_p256_signing_key = ec_key },
    );
    defer conn.deinit();

    var client = try tls12_client.Client.init(alloc, .{
        .server_name = "irc.test",
        .trust_anchors = &.{ec_der},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sf = try conn.onInbound(ch);
    try std.testing.expectEqual(Version.tls12, conn.negotiatedVersion().?);
    const cf = switch (try client.feed(sf.handshake_bytes)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cf);
    const sfin = try conn.onInbound(cf);
    _ = try client.feed(sfin.handshake_bytes);
    try std.testing.expect(conn.handshakeDone());
    try std.testing.expect(client.handshakeDone());

    const c2s = try client.encrypt("hello 1.2");
    defer alloc.free(c2s);
    const out = try conn.onInbound(c2s);
    try std.testing.expectEqualStrings("hello 1.2", out.plaintext);
    const cipher = try conn.write("reply 1.2");
    const got = try client.decrypt(cipher);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("reply 1.2", got);
}

test {
    std.testing.refAllDecls(@This());
}
