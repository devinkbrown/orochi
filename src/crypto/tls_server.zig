//! Socketless TLS 1.3 server handshake state machine for the inbound IRC-over-TLS
//! listener. The daemon feeds raw bytes from the socket via `feed()` and writes
//! back the returned flight; once `handshakeDone()` is true it streams
//! application data through `encrypt()` / `decrypt()`.
//!
//! Scope (slice B of the TLS arc): TLS 1.3 only, X25519 key exchange, an
//! Ed25519 leaf certificate (CertificateVerify signed with `ed25519`), and the
//! AES-128-GCM / ChaCha20-Poly1305 suites. Interop is pinned by a loopback test
//! against the in-repo standards client `tls_client.Client`. P-256 key exchange,
//! RSA/ECDSA certs, HelloRetryRequest, and 0-RTT are intentionally out of scope
//! here and rejected with a typed error.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const kx = @import("kx.zig");
const hkdf = @import("hkdf_tls13.zig");
const Sha256 = hkdf.Sha256;
const tls_record = @import("tls_record.zig");
const tls_keyshare = @import("../proto/tls_keyshare.zig");
const tls_extension = @import("../proto/tls_extension.zig");
const tls_supported_versions = @import("../proto/tls_supported_versions.zig");
const tls_signature_scheme = @import("../proto/tls_signature_scheme.zig");
const tls_finished = @import("../proto/tls_finished.zig");
const tls_alpn = @import("../proto/tls_alpn.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Error = error{
    BadState,
    BadRecord,
    BadHandshake,
    UnsupportedGroup,
    UnsupportedCipherSuite,
    ProtocolVersion,
    MissingExtension,
    FinishedMismatch,
    NoCertificate,
} || Allocator.Error || tls_record.Error || hkdf.Error ||
    tls_extension.Error || tls_alpn.Error || tls_keyshare.Error || tls_supported_versions.Error;

pub const Config = struct {
    /// DER certificates, leaf first. The leaf SPKI must be the Ed25519 public
    /// key matching `signing_key`.
    cert_chain: []const []const u8,
    /// Ed25519 key pair whose public key is the leaf certificate's SPKI; signs
    /// the CertificateVerify.
    signing_key: Ed25519.KeyPair,
    /// ALPN protocols the server is willing to select, in preference order.
    /// Empty disables ALPN negotiation.
    alpn_protocols: []const []const u8 = &.{},
};

pub const FeedResult = union(enum) {
    need_more,
    bytes_to_send: []u8,
};

const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_chacha20_poly1305_sha256 = 0x1303,

    fn keyLen(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => Aes128Gcm.key_length,
            .tls_chacha20_poly1305_sha256 => ChaCha20Poly1305.key_length,
        };
    }

    fn tagLen(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => Aes128Gcm.tag_length,
            .tls_chacha20_poly1305_sha256 => ChaCha20Poly1305.tag_length,
        };
    }
};

const State = enum { idle, wait_client_hello, wait_client_finished, connected };

const TrafficKeys = struct {
    key: [ChaCha20Poly1305.key_length]u8 = [_]u8{0} ** ChaCha20Poly1305.key_length,
    iv: tls_record.Nonce96 = [_]u8{0} ** 12,

    fn wipe(self: *TrafficKeys) void {
        secureZero(&self.key);
        secureZero(&self.iv);
    }
};

pub const Server = struct {
    allocator: Allocator,
    config: Config,
    state: State = .idle,

    x25519_pair: kx.X25519Kx.KeyPair,
    selected_suite: ?CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    legacy_session_id: [32]u8 = [_]u8{0} ** 32,
    session_id_len: usize = 0,

    transcript: std.ArrayList(u8) = .empty,
    recv_buf: std.ArrayList(u8) = .empty,

    early_secret: [Sha256.hash_len]u8 = [_]u8{0} ** Sha256.hash_len,
    handshake_secret: [Sha256.hash_len]u8 = [_]u8{0} ** Sha256.hash_len,
    master_secret: [Sha256.hash_len]u8 = [_]u8{0} ** Sha256.hash_len,
    client_hs_secret: [Sha256.hash_len]u8 = [_]u8{0} ** Sha256.hash_len,
    server_hs_secret: [Sha256.hash_len]u8 = [_]u8{0} ** Sha256.hash_len,
    client_app_secret: [Sha256.hash_len]u8 = [_]u8{0} ** Sha256.hash_len,
    server_app_secret: [Sha256.hash_len]u8 = [_]u8{0} ** Sha256.hash_len,
    client_hs_keys: TrafficKeys = .{},
    server_hs_keys: TrafficKeys = .{},
    client_app_keys: TrafficKeys = .{},
    server_app_keys: TrafficKeys = .{},

    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,

    pub fn init(allocator: Allocator, config: Config) Error!Server {
        if (config.cert_chain.len == 0) return error.NoCertificate;
        var seed: [kx.X25519Kx.seed_len]u8 = undefined;
        try osEntropy(&seed);
        defer secureZero(&seed);
        return .{
            .allocator = allocator,
            .config = config,
            .state = .wait_client_hello,
            .x25519_pair = kx.X25519Kx.generateDeterministic(seed) catch return error.BadState,
        };
    }

    pub fn deinit(self: *Server) void {
        self.x25519_pair.wipe();
        secureZero(&self.early_secret);
        secureZero(&self.handshake_secret);
        secureZero(&self.master_secret);
        secureZero(&self.client_hs_secret);
        secureZero(&self.server_hs_secret);
        secureZero(&self.client_app_secret);
        secureZero(&self.server_app_secret);
        self.client_hs_keys.wipe();
        self.server_hs_keys.wipe();
        self.client_app_keys.wipe();
        self.server_app_keys.wipe();
        self.transcript.deinit(self.allocator);
        self.recv_buf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn handshakeDone(self: *const Server) bool {
        return self.state == .connected;
    }

    pub fn selectedAlpn(self: *const Server) ?[]const u8 {
        return self.selected_alpn;
    }

    pub fn feed(self: *Server, received: []const u8) Error!FeedResult {
        if (self.state == .idle or self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);

        if (self.state == .wait_client_hello) {
            const rec = completePlainRecord(self.recv_buf.items) orelse return .need_more;
            if (rec.content_type == .change_cipher_spec) {
                consumePrefix(&self.recv_buf, rec.wire_len);
                return self.feed(&.{});
            }
            if (rec.content_type != .handshake) return error.BadRecord;
            var off: usize = 0;
            const msg = try parseHandshake(rec.fragment, &off);
            if (off != rec.fragment.len or msg.typ != .client_hello) return error.BadHandshake;
            try self.appendTranscript(msg.raw);
            const reply = try self.buildServerFlight(msg.body);
            consumePrefix(&self.recv_buf, rec.wire_len);
            self.state = .wait_client_finished;
            return .{ .bytes_to_send = reply };
        }

        // wait_client_finished: an encrypted handshake record carrying Finished.
        const rec = completePlainRecord(self.recv_buf.items) orelse return .need_more;
        if (rec.content_type == .change_cipher_spec) {
            consumePrefix(&self.recv_buf, rec.wire_len);
            return self.feed(&.{});
        }
        if (rec.content_type != .application_data) return error.BadRecord;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try openRecordAlloc(self.allocator, suite, &self.client_hs_keys, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
        self.hs_read_seq += 1;
        defer self.allocator.free(opened.content);
        consumePrefix(&self.recv_buf, rec.wire_len);
        if (opened.content_type != .handshake) return error.BadRecord;
        var off: usize = 0;
        const fin = try parseHandshake(opened.content, &off);
        if (fin.typ != .finished) return error.BadHandshake;
        const th = Sha256.transcriptHash(self.transcript.items);
        if (!tls_finished.verify(self.client_hs_secret, th, fin.body)) return error.FinishedMismatch;
        self.state = .connected;
        return .need_more;
    }

    pub fn encrypt(self: *Server, appdata: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const out = try sealRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_write_seq, .application_data, appdata);
        self.app_write_seq += 1;
        return out;
    }

    pub fn decrypt(self: *Server, record: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try openRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_read_seq, record);
        self.app_read_seq += 1;
        errdefer self.allocator.free(opened.content);
        if (opened.content_type != .application_data) return error.BadRecord;
        return opened.content;
    }

    fn buildServerFlight(self: *Server, client_hello_body: []const u8) Error![]u8 {
        const shared = try self.processClientHello(client_hello_body);

        // ServerHello (plaintext handshake record).
        var sh_hs: std.ArrayList(u8) = .empty;
        defer sh_hs.deinit(self.allocator);
        try self.writeServerHello(&sh_hs);
        try self.appendTranscript(sh_hs.items);

        // Handshake keys are derived over CH + SH.
        try self.deriveHandshakeKeys(shared);

        // Encrypted flight: EncryptedExtensions, Certificate, CertificateVerify,
        // Finished — concatenated into one handshake payload, sealed once.
        var flight: std.ArrayList(u8) = .empty;
        defer flight.deinit(self.allocator);
        try self.writeEncryptedExtensions(&flight);
        try self.writeCertificate(&flight);
        try self.writeCertificateVerify(&flight);
        try self.writeServerFinished(&flight);

        // Application keys are derived over CH..server Finished (matches client).
        try self.deriveApplicationKeys();

        const suite = self.selected_suite.?;
        const sh_record = try writePlainRecord(self.allocator, .handshake, sh_hs.items);
        defer self.allocator.free(sh_record);
        const ccs = [_]u8{ @intFromEnum(tls_record.ContentType.change_cipher_spec), 0x03, 0x03, 0x00, 0x01, 0x01 };
        const enc_record = try sealRecordAlloc(self.allocator, suite, &self.server_hs_keys, self.hs_write_seq, .handshake, flight.items);
        defer self.allocator.free(enc_record);
        self.hs_write_seq += 1;

        var out = try self.allocator.alloc(u8, sh_record.len + ccs.len + enc_record.len);
        @memcpy(out[0..sh_record.len], sh_record);
        @memcpy(out[sh_record.len..][0..ccs.len], &ccs);
        @memcpy(out[sh_record.len + ccs.len ..], enc_record);
        return out;
    }

    fn processClientHello(self: *Server, body: []const u8) Error![32]u8 {
        var c = Cursor.init(body);
        if (try c.readU16() != tls_record.legacy_record_version) return error.ProtocolVersion;
        _ = try c.take(32); // client random (unused by the server key schedule)
        const sid = try c.take(try c.readU8());
        if (sid.len > self.legacy_session_id.len) return error.BadHandshake;
        @memcpy(self.legacy_session_id[0..sid.len], sid);
        self.session_id_len = sid.len;

        const suites_block = try c.take(try c.readU16());
        self.selected_suite = pickSuite(suites_block) orelse return error.UnsupportedCipherSuite;

        const comp = try c.take(try c.readU8());
        var null_comp = false;
        for (comp) |m| if (m == 0) {
            null_comp = true;
        };
        if (!null_comp) return error.BadHandshake;

        const ext_block = try c.take(try c.readU16());

        var offered_tls13 = false;
        var client_share: ?[]const u8 = null;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            switch (ext.typed()) {
                .supported_versions => {
                    if (tls_supported_versions.clientOffers(ext.data, tls_supported_versions.tls13)) offered_tls13 = true;
                },
                .key_share => {
                    var shares = tls_keyshare.parseClientShares(ext.data) catch continue;
                    while (shares.next() catch null) |entry| {
                        if (entry.group == .x25519 and entry.key_exchange.len == kx.X25519Kx.public_len) {
                            client_share = entry.key_exchange;
                            break;
                        }
                    }
                },
                .alpn => self.maybeSelectAlpn(ext.data),
                else => {},
            }
        }

        if (!offered_tls13) return error.ProtocolVersion;
        const peer = client_share orelse return error.UnsupportedGroup;
        var peer_pub: kx.PublicKey = undefined;
        @memcpy(&peer_pub, peer);
        var secret = kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer_pub) catch return error.BadHandshake;
        defer secret.wipe();
        return secret.declassify();
    }

    fn maybeSelectAlpn(self: *Server, data: []const u8) void {
        if (self.config.alpn_protocols.len == 0) return;
        var names = tls_alpn.Iterator.fromBlock(data) catch return;
        while (names.next() catch null) |offered| {
            for (self.config.alpn_protocols) |pref| {
                if (std.mem.eql(u8, pref, offered)) {
                    self.selected_alpn = pref;
                    return;
                }
            }
        }
    }

    fn writeServerHello(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);

        try appendU16(self.allocator, &body, tls_record.legacy_record_version);
        var random: [32]u8 = undefined;
        try osEntropy(&random);
        try body.appendSlice(self.allocator, &random);
        secureZero(&random);

        try body.append(self.allocator, @intCast(self.session_id_len));
        try body.appendSlice(self.allocator, self.legacy_session_id[0..self.session_id_len]);

        try appendU16(self.allocator, &body, @intFromEnum(self.selected_suite.?));
        try body.append(self.allocator, 0); // null compression

        var ext_storage: [256]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        var ver_buf: [2]u8 = undefined;
        try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildServer(&ver_buf, tls_supported_versions.tls13));
        var ks_buf: [64]u8 = undefined;
        const ks = try tls_keyshare.buildServerShare(&ks_buf, .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key });
        try ext_builder.addTyped(.key_share, ks);
        try body.appendSlice(self.allocator, try ext_builder.finish());

        try writeHandshake(self.allocator, out, .server_hello, body.items);
    }

    fn writeEncryptedExtensions(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var ext_storage: [256]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        if (self.selected_alpn) |proto| {
            var alpn_buf: [260]u8 = undefined;
            var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
            try alpn_builder.add(proto);
            try ext_builder.addTyped(.alpn, try alpn_builder.finish());
        }
        try self.emit(out, .encrypted_extensions, try ext_builder.finish());
    }

    /// Append a handshake message to the encrypted flight AND to the running
    /// transcript (every message after ServerHello must be folded in before the
    /// CertificateVerify signature and Finished MAC are computed).
    fn emit(self: *Server, out: *std.ArrayList(u8), typ: HandshakeType, body: []const u8) Error!void {
        const start = out.items.len;
        try writeHandshake(self.allocator, out, typ, body);
        try self.appendTranscript(out.items[start..]);
    }

    fn writeCertificate(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.append(self.allocator, 0); // certificate_request_context = empty

        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.allocator);
        for (self.config.cert_chain) |der| {
            try appendU24(self.allocator, &list, der.len);
            try list.appendSlice(self.allocator, der);
            try appendU16(self.allocator, &list, 0); // per-cert extensions = empty
        }
        try appendU24(self.allocator, &body, list.items.len);
        try body.appendSlice(self.allocator, list.items);
        try self.emit(out, .certificate, body.items);
    }

    fn writeCertificateVerify(self: *Server, out: *std.ArrayList(u8)) Error!void {
        const th = Sha256.transcriptHash(self.transcript.items);
        const input = certificateVerifyInput(th);
        const sig = (self.config.signing_key.sign(&input, null) catch return error.BadHandshake).toBytes();

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ed25519));
        try appendU16(self.allocator, &body, @intCast(sig.len));
        try body.appendSlice(self.allocator, &sig);
        try self.emit(out, .certificate_verify, body.items);
    }

    fn writeServerFinished(self: *Server, out: *std.ArrayList(u8)) Error!void {
        const th = Sha256.transcriptHash(self.transcript.items);
        const verify_data = tls_finished.verifyData(self.server_hs_secret, th);
        try self.emit(out, .finished, &verify_data);
    }

    fn deriveHandshakeKeys(self: *Server, shared_secret: [32]u8) Error!void {
        var early = Sha256.earlySecret("");
        defer early.wipe();
        self.early_secret = early.declassify();

        var handshake = try Sha256.handshakeSecret(&early, &shared_secret);
        defer handshake.wipe();
        self.handshake_secret = handshake.declassify();

        const th = Sha256.transcriptHash(self.transcript.items);
        var traffic = try Sha256.handshakeTrafficSecrets(&handshake, &th);
        defer traffic.wipe();
        self.client_hs_secret = traffic.client.declassify();
        self.server_hs_secret = traffic.server.declassify();

        var master = try Sha256.masterSecret(&handshake);
        defer master.wipe();
        self.master_secret = master.declassify();

        const suite = self.selected_suite.?;
        try deriveTrafficKeys(suite, self.client_hs_secret, &self.client_hs_keys);
        try deriveTrafficKeys(suite, self.server_hs_secret, &self.server_hs_keys);
        self.hs_read_seq = 0;
        self.hs_write_seq = 0;
    }

    fn deriveApplicationKeys(self: *Server) Error!void {
        var master = Sha256.SecretBytes.init(self.master_secret);
        defer master.wipe();
        const th = Sha256.transcriptHash(self.transcript.items);
        var traffic = try Sha256.applicationTrafficSecrets(&master, &th);
        defer traffic.wipe();
        self.client_app_secret = traffic.client.declassify();
        self.server_app_secret = traffic.server.declassify();
        const suite = self.selected_suite.?;
        try deriveTrafficKeys(suite, self.client_app_secret, &self.client_app_keys);
        try deriveTrafficKeys(suite, self.server_app_secret, &self.server_app_keys);
        self.app_read_seq = 0;
        self.app_write_seq = 0;
    }

    fn appendTranscript(self: *Server, bytes: []const u8) Error!void {
        try self.transcript.appendSlice(self.allocator, bytes);
    }
};

// --- record + handshake helpers (mirror tls_client.zig; kept local so the
//     proven client stays untouched) -------------------------------------

const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
    _,
};

const HandshakeMsg = struct { typ: HandshakeType, body: []const u8, raw: []const u8 };

const PlainRecord = struct { content_type: tls_record.ContentType, fragment: []const u8, wire_len: usize };
const OpenedRecord = struct { content_type: tls_record.ContentType, content: []u8 };

const certificate_verify_context = "TLS 1.3, server CertificateVerify";

fn certificateVerifyInput(transcript_hash: [Sha256.hash_len]u8) [64 + certificate_verify_context.len + 1 + Sha256.hash_len]u8 {
    var out: [64 + certificate_verify_context.len + 1 + Sha256.hash_len]u8 = undefined;
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..certificate_verify_context.len], certificate_verify_context);
    out[64 + certificate_verify_context.len] = 0;
    @memcpy(out[64 + certificate_verify_context.len + 1 ..], &transcript_hash);
    return out;
}

fn pickSuite(block: []const u8) ?CipherSuite {
    if (block.len % 2 != 0) return null;
    // Prefer AES-128-GCM, then ChaCha20-Poly1305.
    var has_chacha = false;
    var i: usize = 0;
    while (i + 1 < block.len) : (i += 2) {
        const v = std.mem.readInt(u16, block[i..][0..2], .big);
        if (v == @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256)) return .tls_aes_128_gcm_sha256;
        if (v == @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256)) has_chacha = true;
    }
    return if (has_chacha) .tls_chacha20_poly1305_sha256 else null;
}

fn osEntropy(buf: []u8) Error!void {
    switch (builtin.os.tag) {
        .linux => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
                const signed: isize = @bitCast(rc);
                if (signed < 0 or rc == 0) return error.BadState;
                filled += rc;
            }
        },
        else => return error.BadState,
    }
}

fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

fn writePlainRecord(allocator: Allocator, typ: tls_record.ContentType, fragment: []const u8) Error![]u8 {
    if (fragment.len > tls_record.max_plaintext_len) return error.BadRecord;
    var out = try allocator.alloc(u8, tls_record.record_header_len + fragment.len);
    errdefer allocator.free(out);
    out[0] = @intFromEnum(typ);
    std.mem.writeInt(u16, out[1..3], 0x0303, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(fragment.len), .big);
    @memcpy(out[5..], fragment);
    return out;
}

fn completePlainRecord(buf: []const u8) ?PlainRecord {
    if (buf.len < tls_record.record_header_len) return null;
    const len = std.mem.readInt(u16, buf[3..5], .big);
    const total = tls_record.record_header_len + @as(usize, len);
    if (buf.len < total) return null;
    const typ = tls_record.ContentType.fromWire(buf[0]) orelse return null;
    return .{ .content_type = typ, .fragment = buf[5..total], .wire_len = total };
}

fn sealRecordAlloc(allocator: Allocator, suite: CipherSuite, keys: *const TrafficKeys, seq: u64, typ: tls_record.ContentType, plaintext: []const u8) Error![]u8 {
    const inner = try allocator.alloc(u8, plaintext.len + 1);
    defer allocator.free(inner);
    const encoded = try tls_record.encodeInnerPlaintext(typ, plaintext, 0, inner);
    const encrypted_len = encoded.len + suite.tagLen();
    var out = try allocator.alloc(u8, tls_record.record_header_len + encrypted_len);
    errdefer allocator.free(out);
    const aad = tls_record.makeAdditionalData(@intCast(encrypted_len));
    @memcpy(out[0..tls_record.record_header_len], &aad);
    const nonce = tls_record.deriveNonce(keys.iv, seq);
    switch (suite) {
        .tls_aes_128_gcm_sha256 => {
            const key = keys.key[0..Aes128Gcm.key_length].*;
            var tag: [Aes128Gcm.tag_length]u8 = undefined;
            Aes128Gcm.encrypt(out[5..][0..encoded.len], &tag, encoded, &aad, nonce, key);
            @memcpy(out[5 + encoded.len ..][0..tag.len], &tag);
        },
        .tls_chacha20_poly1305_sha256 => {
            const key = keys.key[0..ChaCha20Poly1305.key_length].*;
            var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
            ChaCha20Poly1305.encrypt(out[5..][0..encoded.len], &tag, encoded, &aad, nonce, key);
            @memcpy(out[5 + encoded.len ..][0..tag.len], &tag);
        },
    }
    return out;
}

fn openRecordAlloc(allocator: Allocator, suite: CipherSuite, keys: *const TrafficKeys, seq: u64, record: []const u8) Error!OpenedRecord {
    const parsed = try tls_record.parseCiphertext(record);
    if (parsed.encrypted_record.len < suite.tagLen()) return error.BadRecord;
    const clen = parsed.encrypted_record.len - suite.tagLen();
    const inner = try allocator.alloc(u8, clen);
    errdefer allocator.free(inner);
    const aad = parsed.headerBytes();
    const nonce = tls_record.deriveNonce(keys.iv, seq);
    switch (suite) {
        .tls_aes_128_gcm_sha256 => {
            const key = keys.key[0..Aes128Gcm.key_length].*;
            const tag = parsed.encrypted_record[clen..][0..Aes128Gcm.tag_length].*;
            Aes128Gcm.decrypt(inner, parsed.encrypted_record[0..clen], tag, &aad, nonce, key) catch return error.BadRecord;
        },
        .tls_chacha20_poly1305_sha256 => {
            const key = keys.key[0..ChaCha20Poly1305.key_length].*;
            const tag = parsed.encrypted_record[clen..][0..ChaCha20Poly1305.tag_length].*;
            ChaCha20Poly1305.decrypt(inner, parsed.encrypted_record[0..clen], tag, &aad, nonce, key) catch return error.BadRecord;
        },
    }
    const opened = try tls_record.decodeInnerPlaintext(inner);
    const content = try allocator.dupe(u8, opened.content);
    allocator.free(inner);
    return .{ .content_type = opened.content_type, .content = content };
}

fn deriveTrafficKeys(suite: CipherSuite, secret_bytes: [Sha256.hash_len]u8, out: *TrafficKeys) Error!void {
    var secret = Sha256.SecretBytes.init(secret_bytes);
    defer secret.wipe();
    out.wipe();
    try Sha256.hkdfExpandLabel(&secret, "key", "", out.key[0..suite.keyLen()]);
    try Sha256.hkdfExpandLabel(&secret, "iv", "", &out.iv);
}

fn writeHandshake(allocator: Allocator, out: *std.ArrayList(u8), typ: HandshakeType, body: []const u8) Error!void {
    if (body.len > 0x00ff_ffff) return error.BadHandshake;
    try out.append(allocator, @intFromEnum(typ));
    try appendU24(allocator, out, body.len);
    try out.appendSlice(allocator, body);
}

fn parseHandshake(input: []const u8, offset: *usize) Error!HandshakeMsg {
    if (input.len - offset.* < 4) return error.BadHandshake;
    const start = offset.*;
    const typ: HandshakeType = @enumFromInt(input[start]);
    const len = (@as(usize, input[start + 1]) << 16) | (@as(usize, input[start + 2]) << 8) | input[start + 3];
    const body_start = start + 4;
    const body_end = body_start + len;
    if (body_end > input.len) return error.BadHandshake;
    offset.* = body_end;
    return .{ .typ = typ, .body = input[body_start..body_end], .raw = input[start..body_end] };
}

fn appendU16(allocator: Allocator, out: *std.ArrayList(u8), value: u16) Allocator.Error!void {
    try out.append(allocator, @intCast(value >> 8));
    try out.append(allocator, @intCast(value & 0xff));
}

fn appendU24(allocator: Allocator, out: *std.ArrayList(u8), value: usize) Error!void {
    if (value > 0x00ff_ffff) return error.BadHandshake;
    try out.append(allocator, @intCast((value >> 16) & 0xff));
    try out.append(allocator, @intCast((value >> 8) & 0xff));
    try out.append(allocator, @intCast(value & 0xff));
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const remain = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..remain], list.items[n..]);
    list.shrinkRetainingCapacity(remain);
}

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(buf: []const u8) Cursor {
        return .{ .buf = buf };
    }

    fn remaining(self: Cursor) usize {
        return self.buf.len - self.pos;
    }

    fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.BadHandshake;
        const out = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    fn readU8(self: *Cursor) Error!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Cursor) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }
};

test "loopback: tls_client completes a handshake against tls_server + app data both ways" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x37} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x34 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);

    const cfin = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());

    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    // Server -> client application data.
    const s2c = try server.encrypt("hello client");
    defer alloc.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("hello client", got_c);

    // Client -> server application data.
    const c2s = try client.encrypt("hello server");
    defer alloc.free(c2s);
    const got_s = try server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("hello server", got_s);
}

test {
    std.testing.refAllDecls(@This());
}
