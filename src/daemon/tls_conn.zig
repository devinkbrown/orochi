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
const tls_record = @import("../crypto/tls_record.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_conn requires a 64-bit target");
}

/// Errors surfaced by the adapter: the inner handshake/record errors plus the
/// allocator errors from growing the internal buffers.
pub const Error = tls_server.Error || Allocator.Error;

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

pub const TlsConn = struct {
    allocator: Allocator,
    server: tls_server.Server,

    /// Inbound socket bytes not yet split into a complete record. Drained as
    /// whole records become available; a trailing partial record is retained.
    recv_buf: std.ArrayList(u8) = .empty,
    /// Ciphertext to send back, rebuilt per `onInbound()` call (the handshake
    /// flight). Returned via `Outcome.handshake_bytes`.
    send_buf: std.ArrayList(u8) = .empty,
    /// Decrypted application data, rebuilt per `onInbound()` call. Returned via
    /// `Outcome.plaintext`.
    plain_buf: std.ArrayList(u8) = .empty,
    /// Scratch for outbound ciphertext, rebuilt per `write()` call.
    write_buf: std.ArrayList(u8) = .empty,

    /// Wrap a freshly-initialized `Server` built from `config`. The config (cert
    /// chain, signing key, ALPN list) is borrowed by the inner `Server` exactly
    /// as `tls_server.Server.init` documents.
    pub fn init(allocator: Allocator, config: tls_server.Config) Error!TlsConn {
        return .{
            .allocator = allocator,
            .server = try tls_server.Server.init(allocator, config),
        };
    }

    pub fn deinit(self: *TlsConn) void {
        self.server.deinit();
        self.recv_buf.deinit(self.allocator);
        self.send_buf.deinit(self.allocator);
        self.plain_buf.deinit(self.allocator);
        self.write_buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// True once the inner handshake has completed and `write()` / application
    /// data in `Outcome.plaintext` are live.
    pub fn handshakeDone(self: *const TlsConn) bool {
        return self.server.handshakeDone();
    }

    /// The ALPN protocol the inner server selected, if any (null before the
    /// handshake completes or when ALPN was not negotiated).
    pub fn selectedAlpn(self: *const TlsConn) ?[]const u8 {
        return self.server.selectedAlpn();
    }

    /// The verified client leaf DER (mTLS), or null. SHA-256 of this is the
    /// SASL EXTERNAL CertFP.
    pub fn clientCertDer(self: *const TlsConn) ?[]const u8 {
        return self.server.clientCertDer();
    }

    /// Drive the connection with a chunk of bytes read from the socket.
    ///
    /// Appends `socket_bytes` to the receive buffer, then drains every complete
    /// TLS record: while handshaking, each record is fed to `Server.feed` and any
    /// returned flight is accumulated into `handshake_bytes`; once the handshake
    /// is done, each application_data record is decrypted into `plaintext`. A
    /// trailing partial record is retained for the next call.
    ///
    /// Returns slices into internal buffers, valid only until the next call.
    pub fn onInbound(self: *TlsConn, socket_bytes: []const u8) Error!Outcome {
        self.send_buf.clearRetainingCapacity();
        self.plain_buf.clearRetainingCapacity();
        try self.recv_buf.appendSlice(self.allocator, socket_bytes);

        // Process complete records front-to-back, consuming each from recv_buf.
        while (completeRecordLen(self.recv_buf.items)) |wire_len| {
            if (self.server.handshakeDone()) {
                try self.decryptRecord(self.recv_buf.items[0..wire_len]);
            } else {
                try self.feedRecord(self.recv_buf.items[0..wire_len]);
            }
            consumePrefix(&self.recv_buf, wire_len);
        }

        return .{
            .handshake_bytes = self.send_buf.items,
            .plaintext = self.plain_buf.items,
        };
    }

    /// Encrypt `plaintext` into one or more TLS application_data records and
    /// return the ciphertext to send. Plaintext longer than the record limit is
    /// split across records so no single record exceeds `max_plaintext_len`.
    ///
    /// Returns a slice into an internal buffer, valid until the next `write()`.
    pub fn write(self: *TlsConn, plaintext: []const u8) Error![]const u8 {
        if (!self.server.handshakeDone()) return error.BadState;
        self.write_buf.clearRetainingCapacity();

        var offset: usize = 0;
        // A single empty write still emits one (empty) application_data record so
        // the caller's intent to flush is preserved.
        while (true) {
            const end = @min(offset + tls_record.max_plaintext_len, plaintext.len);
            const chunk = plaintext[offset..end];
            const record = try self.server.encrypt(chunk);
            defer self.allocator.free(record);
            try self.write_buf.appendSlice(self.allocator, record);
            offset = end;
            if (offset >= plaintext.len) break;
        }
        return self.write_buf.items;
    }

    /// Feed one complete handshake-phase record to the inner server, copying any
    /// returned flight into `send_buf` and freeing the server-owned slice.
    fn feedRecord(self: *TlsConn, record: []const u8) Error!void {
        switch (try self.server.feed(record)) {
            .need_more => {},
            .bytes_to_send => |flight| {
                defer self.allocator.free(flight);
                try self.send_buf.appendSlice(self.allocator, flight);
            },
        }
    }

    /// Decrypt one complete application_data record into `plain_buf`, freeing the
    /// server-owned plaintext slice after copying.
    fn decryptRecord(self: *TlsConn, record: []const u8) Error!void {
        const opened = try self.server.decrypt(record);
        defer self.allocator.free(opened);
        try self.plain_buf.appendSlice(self.allocator, opened);
    }
};

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

test {
    std.testing.refAllDecls(@This());
}
