//! Socketless TLS 1.2 server handshake state machine.
//!
//! The server is intentionally fail-closed: TLS 1.2 only, null compression,
//! secp256r1 ECDHE, ECDSA-P256 ServerKeyExchange signing, and the AEAD suites
//! listed in `tls12.zig`. The caller feeds raw record bytes and writes returned
//! flights; application records use `encrypt()` / `decrypt()` after
//! `handshakeDone()`.

const std = @import("std");
const builtin = @import("builtin");

const tls12 = @import("tls12.zig");
const tls12_client = @import("tls12_client.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");

const Allocator = std.mem.Allocator;

const named_group_secp256r1: u16 = 0x0017;
const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;

pub const Error = tls12.Error || ecdh_p256.EcdhError || ecdsa_p256.DerError ||
    Allocator.Error || error{
    BadHandshake,
    BadState,
    FinishedMismatch,
    NoCertificate,
    NoSigningKey,
    ProtocolVersion,
    TlsAlert,
    UnsupportedCipherSuite,
    UnsupportedGroup,
    EntropyUnavailable,
};

pub const Config = struct {
    /// DER certificates, leaf first.
    cert_chain: []const []const u8,
    /// ECDSA-P256 leaf key. TLS 1.2 ServerKeyExchange is signed with
    /// ecdsa_secp256r1_sha256. RSA leaf signing is intentionally not exposed
    /// here because this codebase has RSA verification but no RSA signer.
    ecdsa_p256_signing_key: ?ecdsa_p256.KeyPair = null,
    /// ALPN protocols in server preference order.
    alpn_protocols: []const []const u8 = &.{},
};

pub const FeedResult = union(enum) {
    need_more,
    bytes_to_send: []u8,
};

const State = enum {
    wait_client_hello,
    wait_client_key_exchange,
    wait_client_ccs,
    wait_client_finished,
    connected,
};

const HandshakeMsg = struct {
    typ: tls12.HandshakeType,
    body: []const u8,
    raw: []const u8,
};

pub const Server = struct {
    allocator: Allocator,
    config: Config,
    state: State = .wait_client_hello,

    recv_buf: std.ArrayList(u8) = .empty,
    transcript: std.ArrayList(u8) = .empty,

    key_pair: ecdh_p256.KeyPair,
    client_random: [32]u8 = [_]u8{0} ** 32,
    server_random: [32]u8,
    session_id: [32]u8 = [_]u8{0} ** 32,
    session_id_len: usize = 0,
    selected_suite: ?tls12.CipherSuite = null,
    selected_alpn: ?[]u8 = null,

    master_secret: [tls12.master_secret_len]u8 = [_]u8{0} ** tls12.master_secret_len,
    keys: tls12.KeyMaterial = .{},
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,
    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,

    pub fn init(allocator: Allocator, config: Config) Error!Server {
        if (config.cert_chain.len == 0) return error.NoCertificate;
        if (config.ecdsa_p256_signing_key == null) return error.NoSigningKey;
        var random: [32]u8 = undefined;
        try osEntropy(&random);
        return .{
            .allocator = allocator,
            .config = config,
            .key_pair = try ecdh_p256.generate(),
            .server_random = random,
        };
    }

    pub fn deinit(self: *Server) void {
        self.recv_buf.deinit(self.allocator);
        self.transcript.deinit(self.allocator);
        if (self.selected_alpn) |p| self.allocator.free(p);
        std.crypto.secureZero(u8, &self.key_pair.secret);
        std.crypto.secureZero(u8, &self.master_secret);
        self.keys.wipe();
    }

    pub fn handshakeDone(self: *const Server) bool {
        return self.state == .connected;
    }

    pub fn selectedAlpn(self: *const Server) ?[]const u8 {
        return if (self.selected_alpn) |p| p else null;
    }

    pub fn feed(self: *Server, received: []const u8) Error!FeedResult {
        if (self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);
        while (true) {
            const rec = (try tls12.completeRecord(self.recv_buf.items)) orelse return .need_more;
            switch (self.state) {
                .wait_client_hello => {
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(rec.fragment, &off);
                    if (off != rec.fragment.len or msg.typ != .client_hello) return error.BadHandshake;
                    try self.parseClientHello(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    const reply = try self.buildServerFlight();
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_client_key_exchange;
                    return .{ .bytes_to_send = reply };
                },
                .wait_client_key_exchange => {
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(rec.fragment, &off);
                    if (off != rec.fragment.len or msg.typ != .client_key_exchange) return error.BadHandshake;
                    try self.parseClientKeyExchange(msg.body);
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_client_ccs;
                },
                .wait_client_ccs => {
                    if (rec.content_type != .change_cipher_spec or rec.fragment.len != 1 or rec.fragment[0] != 1) return error.BadHandshake;
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    self.state = .wait_client_finished;
                },
                .wait_client_finished => {
                    const suite = self.selected_suite orelse return error.BadState;
                    if (rec.content_type != .handshake) return error.BadHandshake;
                    const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.client_write, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
                    self.hs_read_seq += 1;
                    defer self.allocator.free(opened.plaintext);
                    if (opened.content_type != .handshake) return error.BadHandshake;
                    var off: usize = 0;
                    const msg = try parseHandshake(opened.plaintext, &off);
                    if (off != opened.plaintext.len or msg.typ != .finished) return error.BadHandshake;
                    const expected = try tls12.finishedVerifyData(suite, &self.master_secret, "client finished", self.transcript.items);
                    if (!tls12.constantTimeEq(&expected, msg.body)) return error.FinishedMismatch;
                    try self.transcript.appendSlice(self.allocator, msg.raw);
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    const reply = try self.buildServerFinishedFlight();
                    self.state = .connected;
                    return .{ .bytes_to_send = reply };
                },
                .connected => return error.BadState,
            }
        }
    }

    pub fn encrypt(self: *Server, appdata: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const out = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.server_write, self.app_write_seq, .application_data, appdata);
        self.app_write_seq += 1;
        return out;
    }

    pub fn decrypt(self: *Server, record: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try tls12.openRecordAlloc(self.allocator, suite, &self.keys.client_write, self.app_read_seq, record);
        self.app_read_seq += 1;
        errdefer self.allocator.free(opened.plaintext);
        if (opened.content_type == .alert) return error.TlsAlert;
        if (opened.content_type != .application_data) return error.BadHandshake;
        return opened.plaintext;
    }

    fn parseClientHello(self: *Server, body: []const u8) Error!void {
        var c = Cursor.init(body);
        if (try c.readU16() != tls12.tls_version) return error.ProtocolVersion;
        @memcpy(&self.client_random, try c.take(32));
        self.session_id_len = try c.readU8();
        if (self.session_id_len > self.session_id.len) return error.BadHandshake;
        @memcpy(self.session_id[0..self.session_id_len], try c.take(self.session_id_len));
        const suites_bytes = try c.take(try c.readU16());
        const comp = try c.take(try c.readU8());
        if (comp.len != 1 or comp[0] != 0) return error.BadHandshake;

        var selected: ?tls12.CipherSuite = null;
        var s = Cursor.init(suites_bytes);
        while (s.remaining() != 0) {
            const suite = tls12.CipherSuite.fromWire(try s.readU16()) catch continue;
            if (!suite.isEcdsa()) continue;
            if (selected == null) selected = suite;
        }
        self.selected_suite = selected orelse return error.UnsupportedCipherSuite;

        if (c.remaining() != 0) {
            const ext_len = try c.readU16();
            const exts = try c.take(ext_len);
            try self.parseClientExtensions(exts);
        }
        try c.expectEmpty();
    }

    fn parseClientExtensions(self: *Server, bytes: []const u8) Error!void {
        var saw_p256 = false;
        var c = Cursor.init(bytes);
        while (c.remaining() != 0) {
            const typ = try c.readU16();
            const body = try c.take(try c.readU16());
            switch (typ) {
                0x000a => {
                    var g = Cursor.init(body);
                    const list = try g.take(try g.readU16());
                    var groups = Cursor.init(list);
                    while (groups.remaining() != 0) {
                        if (try groups.readU16() == named_group_secp256r1) saw_p256 = true;
                    }
                    try g.expectEmpty();
                },
                0x0010 => try self.selectAlpn(body),
                0x002b => return error.ProtocolVersion,
                else => {},
            }
        }
        if (!saw_p256) return error.UnsupportedGroup;
    }

    fn selectAlpn(self: *Server, body: []const u8) Error!void {
        if (self.config.alpn_protocols.len == 0) return;
        var c = Cursor.init(body);
        const list = try c.take(try c.readU16());
        try c.expectEmpty();
        for (self.config.alpn_protocols) |server_proto| {
            var p = Cursor.init(list);
            while (p.remaining() != 0) {
                const client_proto = try p.take(try p.readU8());
                if (std.mem.eql(u8, server_proto, client_proto)) {
                    const copy = try self.allocator.dupe(u8, server_proto);
                    errdefer self.allocator.free(copy);
                    if (self.selected_alpn) |old| self.allocator.free(old);
                    self.selected_alpn = copy;
                    return;
                }
            }
        }
    }

    fn buildServerFlight(self: *Server) Error![]u8 {
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);

        var sh_body: std.ArrayList(u8) = .empty;
        defer sh_body.deinit(self.allocator);
        try appendU16(self.allocator, &sh_body, tls12.tls_version);
        try sh_body.appendSlice(self.allocator, &self.server_random);
        try sh_body.append(self.allocator, @intCast(self.session_id_len));
        try sh_body.appendSlice(self.allocator, self.session_id[0..self.session_id_len]);
        try appendU16(self.allocator, &sh_body, @intFromEnum(self.selected_suite orelse return error.BadState));
        try sh_body.append(self.allocator, 0);
        var exts: std.ArrayList(u8) = .empty;
        defer exts.deinit(self.allocator);
        if (self.selected_alpn) |proto| {
            var alpn_body: [3 + 255]u8 = undefined;
            std.mem.writeInt(u16, alpn_body[0..2], @intCast(1 + proto.len), .big);
            alpn_body[2] = @intCast(proto.len);
            @memcpy(alpn_body[3 .. 3 + proto.len], proto);
            try writeExtension(self.allocator, &exts, 0x0010, alpn_body[0 .. 3 + proto.len]);
        }
        try appendU16(self.allocator, &sh_body, @intCast(exts.items.len));
        try sh_body.appendSlice(self.allocator, exts.items);
        try writeHandshake(self.allocator, &hs, .server_hello, sh_body.items);

        var cert_body: std.ArrayList(u8) = .empty;
        defer cert_body.deinit(self.allocator);
        var cert_list: std.ArrayList(u8) = .empty;
        defer cert_list.deinit(self.allocator);
        for (self.config.cert_chain) |der| {
            try appendU24(self.allocator, &cert_list, @intCast(der.len));
            try cert_list.appendSlice(self.allocator, der);
        }
        try appendU24(self.allocator, &cert_body, @intCast(cert_list.items.len));
        try cert_body.appendSlice(self.allocator, cert_list.items);
        try writeHandshake(self.allocator, &hs, .certificate, cert_body.items);

        const ske_body = try self.buildServerKeyExchange();
        defer self.allocator.free(ske_body);
        try writeHandshake(self.allocator, &hs, .server_key_exchange, ske_body);
        try writeHandshake(self.allocator, &hs, .server_hello_done, "");

        try self.transcript.appendSlice(self.allocator, hs.items);
        return tls12.writePlainRecord(self.allocator, .handshake, hs.items);
    }

    fn buildServerKeyExchange(self: *Server) Error![]u8 {
        var params: [1 + 2 + 1 + ecdh_p256.public_length]u8 = undefined;
        params[0] = 3;
        std.mem.writeInt(u16, params[1..3], named_group_secp256r1, .big);
        params[3] = ecdh_p256.public_length;
        @memcpy(params[4..], &self.key_pair.public_sec1);

        var signed: std.ArrayList(u8) = .empty;
        defer signed.deinit(self.allocator);
        try signed.appendSlice(self.allocator, &self.client_random);
        try signed.appendSlice(self.allocator, &self.server_random);
        try signed.appendSlice(self.allocator, &params);
        const sig = ecdsa_p256.sign(signed.items, self.config.ecdsa_p256_signing_key.?) catch return error.BadState;
        var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
        const der = try ecdsa_p256.signatureToDer(sig, &der_buf);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, &params);
        try appendU16(self.allocator, &out, sig_ecdsa_secp256r1_sha256);
        try appendU16(self.allocator, &out, @intCast(der.len));
        try out.appendSlice(self.allocator, der);
        return out.toOwnedSlice(self.allocator);
    }

    fn parseClientKeyExchange(self: *Server, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const point = try c.take(try c.readU8());
        try c.expectEmpty();
        if (point.len != ecdh_p256.public_length) return error.UnsupportedGroup;
        var client_pub: [ecdh_p256.public_length]u8 = undefined;
        @memcpy(&client_pub, point);
        const shared = try ecdh_p256.sharedSecret(self.key_pair.secret, client_pub);
        const suite = self.selected_suite orelse return error.BadState;
        self.master_secret = try tls12.deriveMasterSecret(suite, &shared, &self.client_random, &self.server_random);
        self.keys = try tls12.deriveKeyMaterial(suite, &self.master_secret, &self.client_random, &self.server_random);
    }

    fn buildServerFinishedFlight(self: *Server) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;
        const verify = try tls12.finishedVerifyData(suite, &self.master_secret, "server finished", self.transcript.items);
        var fin: std.ArrayList(u8) = .empty;
        defer fin.deinit(self.allocator);
        try writeHandshake(self.allocator, &fin, .finished, &verify);
        try self.transcript.appendSlice(self.allocator, fin.items);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        const ccs = try tls12.writePlainRecord(self.allocator, .change_cipher_spec, &.{1});
        defer self.allocator.free(ccs);
        try out.appendSlice(self.allocator, ccs);
        const fin_rec = try tls12.sealRecordAlloc(self.allocator, suite, &self.keys.server_write, self.hs_write_seq, .handshake, fin.items);
        self.hs_write_seq += 1;
        defer self.allocator.free(fin_rec);
        try out.appendSlice(self.allocator, fin_rec);
        return out.toOwnedSlice(self.allocator);
    }
};

fn writeExtension(allocator: Allocator, out: *std.ArrayList(u8), typ: u16, body: []const u8) Error!void {
    try appendU16(allocator, out, typ);
    try appendU16(allocator, out, @intCast(body.len));
    try out.appendSlice(allocator, body);
}

fn writeHandshake(allocator: Allocator, out: *std.ArrayList(u8), typ: tls12.HandshakeType, body: []const u8) Error!void {
    try out.append(allocator, @intFromEnum(typ));
    try appendU24(allocator, out, @intCast(body.len));
    try out.appendSlice(allocator, body);
}

fn parseHandshake(bytes: []const u8, off: *usize) Error!HandshakeMsg {
    if (bytes.len - off.* < 4) return error.BadHandshake;
    const start = off.*;
    const len = (@as(usize, bytes[start + 1]) << 16) | (@as(usize, bytes[start + 2]) << 8) | bytes[start + 3];
    if (bytes.len - start < 4 + len) return error.BadHandshake;
    off.* = start + 4 + len;
    return .{
        .typ = @enumFromInt(bytes[start]),
        .body = bytes[start + 4 .. start + 4 + len],
        .raw = bytes[start .. start + 4 + len],
    };
}

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn init(bytes: []const u8) Cursor {
        return .{ .bytes = bytes };
    }

    fn remaining(self: Cursor) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (n > self.remaining()) return error.BadHandshake;
        const out = self.bytes[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    fn readU8(self: *Cursor) Error!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Cursor) Error!u16 {
        const b = try self.take(2);
        return (@as(u16, b[0]) << 8) | b[1];
    }

    fn expectEmpty(self: Cursor) Error!void {
        if (self.remaining() != 0) return error.BadHandshake;
    }
};

fn appendU16(allocator: Allocator, out: *std.ArrayList(u8), v: u16) Allocator.Error!void {
    try out.append(allocator, @intCast(v >> 8));
    try out.append(allocator, @intCast(v & 0xff));
}

fn appendU24(allocator: Allocator, out: *std.ArrayList(u8), v: u32) Allocator.Error!void {
    try out.append(allocator, @intCast((v >> 16) & 0xff));
    try out.append(allocator, @intCast((v >> 8) & 0xff));
    try out.append(allocator, @intCast(v & 0xff));
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    std.mem.copyForwards(u8, list.items[0 .. list.items.len - n], list.items[n..]);
    list.shrinkRetainingCapacity(list.items.len - n);
}

fn osEntropy(buf: []u8) Error!void {
    switch (builtin.os.tag) {
        .linux => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
                const signed: isize = @bitCast(rc);
                if (signed < 0 or rc == 0) return error.EntropyUnavailable;
                filled += rc;
            }
        },
        else => return error.EntropyUnavailable,
    }
}

const Fixture = struct {
    storage: []u8,
    cert: []const u8,
    key: ecdsa_p256.KeyPair,

    fn deinit(self: Fixture, allocator: Allocator) void {
        allocator.free(self.storage);
    }
};

fn makeFixture(allocator: Allocator) !Fixture {
    const key = ecdsa_p256.KeyPair.generate(std.testing.io);
    var buf = try allocator.alloc(u8, 2048);
    errdefer allocator.free(buf);
    const cert = try x509_selfsign.buildSelfSignedEcdsaP256(buf, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 1, 2, 3, 4 },
        .key_pair = key,
        .dns_names = &.{"localhost"},
        .is_ca = true,
    });
    return .{ .storage = buf, .cert = buf[0..cert.len], .key = key };
}

fn runLoopback(comptime chacha: bool) !void {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .ecdsa_p256_signing_key = fixture.key,
        .alpn_protocols = &.{"irc"},
    });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .alpn_protocols = &.{"irc"},
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();
    if (chacha) client.offerOnlyChaChaForTest() else client.offerOnlyAes128ForTest();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    const cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    const sfin = switch (try server.feed(cf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sfin);
    _ = try client.feed(sfin);

    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
    try std.testing.expectEqualSlices(u8, "irc", client.selectedAlpn().?);
    try std.testing.expectEqualSlices(u8, "irc", server.selectedAlpn().?);

    const c_app = try client.encrypt("client to server");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "client to server", s_plain);

    const s_app = try server.encrypt("server to client");
    defer allocator.free(s_app);
    const c_plain = try client.decrypt(s_app);
    defer allocator.free(c_plain);
    try std.testing.expectEqualSlices(u8, "server to client", c_plain);
}

test "TLS 1.2 loopback ECDHE ECDSA AES-128-GCM" {
    try runLoopback(false);
}

test "TLS 1.2 loopback ECDHE ECDSA ChaCha20-Poly1305" {
    try runLoopback(true);
}

test "TLS 1.2 tampered encrypted Finished is rejected" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};
    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{ .server_name = "localhost", .trust_anchors = &anchors });
    defer client.deinit();

    const ch = try client.start();
    defer allocator.free(ch);
    const sf = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(sf);
    var cf = switch (try client.feed(sf)) {
        .bytes_to_send => |b| b,
        .need_more => return error.BadHandshake,
    };
    defer allocator.free(cf);
    cf[cf.len - 1] ^= 0x01;
    try std.testing.expectError(error.AeadAuthFailed, server.feed(cf));
}
