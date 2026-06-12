//! Socketless TLS 1.2 server handshake state machine.
//!
//! The server is intentionally fail-closed: TLS 1.2 only, null compression,
//! secp256r1 ECDHE, ECDSA-P256 or RSA ServerKeyExchange signing, and the AEAD
//! suites listed in `tls12.zig`. The caller feeds raw record bytes and writes
//! returned flights; application records use `encrypt()` / `decrypt()` after
//! `handshakeDone()`.

const std = @import("std");
const builtin = @import("builtin");

const tls12 = @import("tls12.zig");
const tls12_client = @import("tls12_client.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_sign = @import("rsa_sign.zig");
const rsa_verify = @import("rsa_verify.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");

const Allocator = std.mem.Allocator;

const named_group_secp256r1: u16 = 0x0017;
const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;
const sig_rsa_pkcs1_sha256: u16 = 0x0401;

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
    /// ecdsa_secp256r1_sha256.
    ecdsa_p256_signing_key: ?ecdsa_p256.KeyPair = null,
    /// RSA leaf key. TLS 1.2 ServerKeyExchange is signed with
    /// rsa_pkcs1_sha256, and an ECDHE_RSA AEAD suite is selected.
    rsa_signing_key: ?rsa_sign.PrivateKey = null,
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

const CertificateAuth = enum {
    ecdsa_p256,
    rsa,
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
        if (activeCertificateAuth(config) == null) return error.NoSigningKey;
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

    /// Everything a successor process needs to keep driving an ESTABLISHED
    /// hardened TLS 1.2 connection: the negotiated suite, the derived directional
    /// AEAD key material, and the live record sequence numbers. There is no
    /// post-handshake re-keying in this profile, so the master secret and
    /// handshake transcript are deliberately NOT carried.
    pub const ResumeState = struct {
        suite: u16,
        keys: tls12.KeyMaterial,
        app_read_seq: u64,
        app_write_seq: u64,
    };

    /// Capture the connected-state snapshot for a Helix live upgrade. Only valid
    /// once the handshake completed; the key material in the returned struct is
    /// sensitive and must be handled accordingly by the caller.
    pub fn exportResume(self: *const Server) Error!ResumeState {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        return .{
            .suite = @intFromEnum(suite),
            .keys = self.keys,
            .app_read_seq = self.app_read_seq,
            .app_write_seq = self.app_write_seq,
        };
    }

    /// Successor side of a Helix live upgrade: rebuild a CONNECTED server from an
    /// exported `ResumeState`. The handshake machinery is never re-entered.
    pub fn resumeConnected(allocator: Allocator, config: Config, st: ResumeState) Error!Server {
        var self = try Server.init(allocator, config);
        errdefer self.deinit();
        self.selected_suite = tls12.CipherSuite.fromWire(st.suite) catch return error.UnsupportedCipherSuite;
        self.keys = st.keys;
        self.app_read_seq = st.app_read_seq;
        self.app_write_seq = st.app_write_seq;
        self.state = .connected;
        return self;
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

        const auth = activeCertificateAuth(self.config) orelse return error.NoSigningKey;
        var selected: ?tls12.CipherSuite = null;
        var s = Cursor.init(suites_bytes);
        while (s.remaining() != 0) {
            const suite = tls12.CipherSuite.fromWire(try s.readU16()) catch continue;
            if (!suiteMatchesAuth(suite, auth)) continue;
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
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, &params);
        switch (activeCertificateAuth(self.config) orelse return error.NoSigningKey) {
            .ecdsa_p256 => {
                const sig = ecdsa_p256.sign(signed.items, self.config.ecdsa_p256_signing_key.?) catch return error.BadState;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = try ecdsa_p256.signatureToDer(sig, &der_buf);
                try appendU16(self.allocator, &out, sig_ecdsa_secp256r1_sha256);
                try appendU16(self.allocator, &out, @intCast(der.len));
                try out.appendSlice(self.allocator, der);
            },
            .rsa => {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(signed.items, &digest, .{});
                var sig_buf: [512]u8 = undefined;
                const key = self.config.rsa_signing_key.?;
                const sig = rsa_sign.signPkcs1v15(key, .sha256, &digest, &sig_buf) catch return error.BadState;
                try appendU16(self.allocator, &out, sig_rsa_pkcs1_sha256);
                try appendU16(self.allocator, &out, @intCast(sig.len));
                try out.appendSlice(self.allocator, sig);
            },
        }
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

fn activeCertificateAuth(config: Config) ?CertificateAuth {
    if (config.rsa_signing_key != null) return .rsa;
    if (config.ecdsa_p256_signing_key != null) return .ecdsa_p256;
    return null;
}

fn suiteMatchesAuth(suite: tls12.CipherSuite, auth: CertificateAuth) bool {
    return switch (auth) {
        .ecdsa_p256 => suite.isEcdsa(),
        .rsa => !suite.isEcdsa(),
    };
}

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

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const rsa_test_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
const rsa_test_e = hexToBytes("010001");
const rsa_test_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
const rsa_test_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
const rsa_test_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
const rsa_test_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
const rsa_test_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
const rsa_test_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");

fn rsaTestPrivateKey() rsa_sign.PrivateKey {
    return .{
        .n = &rsa_test_n,
        .e = &rsa_test_e,
        .d = &rsa_test_d,
        .p = &rsa_test_p,
        .q = &rsa_test_q,
        .dp = &rsa_test_dp,
        .dq = &rsa_test_dq,
        .qinv = &rsa_test_qinv,
    };
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

test "TLS 1.2 exportResume/resumeConnected carries a live session across Server instances" {
    const allocator = std.testing.allocator;
    const fixture = try makeFixture(allocator);
    defer fixture.deinit(allocator);
    const chain = [_][]const u8{fixture.cert};
    const anchors = [_][]const u8{fixture.cert};

    var server = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer server.deinit();
    var client = try tls12_client.Client.init(allocator, .{
        .server_name = "localhost",
        .trust_anchors = &anchors,
        .now_unix_seconds = 1_735_689_600,
    });
    defer client.deinit();

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
    try std.testing.expect(server.handshakeDone());

    // Advance both directions so the carried seqs are non-zero.
    const pre_c = try client.encrypt("pre c2s");
    defer allocator.free(pre_c);
    const pre_cp = try server.decrypt(pre_c);
    defer allocator.free(pre_cp);
    const pre_s = try server.encrypt("pre s2c");
    defer allocator.free(pre_s);
    const pre_sp = try client.decrypt(pre_s);
    defer allocator.free(pre_sp);

    // Export is rejected mid-handshake and works once connected.
    var fresh = try Server.init(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key });
    defer fresh.deinit();
    try std.testing.expectError(error.BadState, fresh.exportResume());
    const st = try server.exportResume();
    try std.testing.expectEqual(@as(u64, 1), st.app_read_seq);
    try std.testing.expectEqual(@as(u64, 1), st.app_write_seq);

    var successor = try Server.resumeConnected(allocator, .{ .cert_chain = &chain, .ecdsa_p256_signing_key = fixture.key }, st);
    defer successor.deinit();
    try std.testing.expect(successor.handshakeDone());

    const c2s = try client.encrypt("post c2s");
    defer allocator.free(c2s);
    const got_s = try successor.decrypt(c2s);
    defer allocator.free(got_s);
    try std.testing.expectEqualSlices(u8, "post c2s", got_s);

    const s2c = try successor.encrypt("post s2c");
    defer allocator.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer allocator.free(got_c);
    try std.testing.expectEqualSlices(u8, "post s2c", got_c);
}

test "TLS 1.2 loopback ECDHE ECDSA ChaCha20-Poly1305" {
    try runLoopback(true);
}

test "TLS 1.2 loopback ECDHE RSA AES-128-GCM" {
    const allocator = std.testing.allocator;
    const rsa_key = rsaTestPrivateKey();
    const cert_buf = try allocator.alloc(u8, 2048);
    defer allocator.free(cert_buf);
    const cert = try x509_selfsign.buildSelfSignedRsa(cert_buf, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200,
        .not_after = 1_893_456_000,
        .serial = &.{ 5, 2, 0, 1 },
        .public_modulus = rsa_key.n,
        .public_exponent = rsa_key.e,
        .private_key = rsa_key,
        .dns_names = &.{"localhost"},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    const anchors = [_][]const u8{cert};

    var server = try Server.init(allocator, .{
        .cert_chain = &chain,
        .rsa_signing_key = rsa_key,
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

    // Clean end-to-end flow: the in-repo client verifies the RSA ServerKeyExchange
    // directly (the leaf RSA key no longer dangles after the Certificate message).
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

    const c_app = try client.encrypt("rsa client to server");
    defer allocator.free(c_app);
    const s_plain = try server.decrypt(c_app);
    defer allocator.free(s_plain);
    try std.testing.expectEqualSlices(u8, "rsa client to server", s_plain);

    const s_app = try server.encrypt("rsa server to client");
    defer allocator.free(s_app);
    const c_plain = try client.decrypt(s_app);
    defer allocator.free(c_plain);
    try std.testing.expectEqualSlices(u8, "rsa server to client", c_plain);
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
