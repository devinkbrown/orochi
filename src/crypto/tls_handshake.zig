//! TLS 1.3 handshake FSM for Orochi (RFC 8446, one-RTT, X25519, no PSK).
//!
//! This module is pure caller-buffered orchestration. It consumes the local
//! TLS policy/state vocabulary, HKDF TLS 1.3 schedule, record-layer framing,
//! X25519 key exchange, and X.509 structural verification helpers.
const std = @import("std");
const hkdf_tls13 = @import("hkdf_tls13.zig");
const tls_record = @import("tls_record.zig");
const kx = @import("kx.zig");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const Secret = @import("secret.zig").Secret;

const Allocator = std.mem.Allocator;
const Sha256 = hkdf_tls13.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Error = error{
    BadHandshake,
    BadMessageType,
    BadRecord,
    BadSignature,
    BadState,
    CertificateInvalid,
    FinishedMismatch,
    MissingSigningKey,
    MissingVerifyKey,
    OutputTooSmall,
    TranscriptOverflow,
    UnsupportedSuite,
} || Allocator.Error || kx.KeyExchangeError || hkdf_tls13.Error ||
    tls_record.Error || x509.Error || x509_verify.Error || Ed25519.Signature.VerifyError ||
    error{ IdentityElement, NonCanonical, KeyMismatch, WeakPublicKey };

pub const Role = enum { client, server };
pub const State = enum {
    start,
    client_hello,
    server_hello,
    encrypted_extensions,
    certificate,
    certificate_verify,
    finished,
    connected,
};

pub const suite: u16 = 0x1303;
pub const tls12_wire_version: u16 = 0x0303;
pub const group_x25519: u16 = 0x001d;
pub const sig_ed25519: u16 = 0x0807;
pub const transcript_cap = 16 * 1024;

const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,

    fn fromByte(b: u8) Error!HandshakeType {
        return switch (b) {
            1 => .client_hello,
            2 => .server_hello,
            8 => .encrypted_extensions,
            11 => .certificate,
            15 => .certificate_verify,
            20 => .finished,
            else => error.BadMessageType,
        };
    }
};

pub const Config = struct {
    cert_chain: []const []const u8 = &.{},
    server_signing_key: ?Ed25519.KeyPair = null,
    expected_server_public_key: ?Ed25519.PublicKey = null,
};

pub const TrafficSecrets = struct {
    client: Secret([Sha256.hash_len]u8),
    server: Secret([Sha256.hash_len]u8),

    pub fn clientBytes(self: *const TrafficSecrets) [Sha256.hash_len]u8 {
        return self.client.declassify();
    }

    pub fn serverBytes(self: *const TrafficSecrets) [Sha256.hash_len]u8 {
        return self.server.declassify();
    }
};

const TrafficKeys = struct {
    key: Secret([Aead.key_length]u8),
    iv: tls_record.Nonce96,

    fn wipe(self: *TrafficKeys) void {
        self.key.wipe();
        secureZero(&self.iv);
    }
};

const HandshakeMsg = struct {
    typ: HandshakeType,
    body: []const u8,
    raw: []const u8,
};

const HandshakeEvent = enum {
    send_client_hello,
    recv_client_hello,
    send_server_hello,
    recv_server_hello,
    send_encrypted_extensions,
    recv_encrypted_extensions,
    send_certificate,
    recv_certificate,
    send_certificate_verify,
    recv_certificate_verify,
    send_finished,
    recv_finished,
};

const RuntimeHandshake = struct {
    role: Role,
    state: State = .start,

    fn step(self: *RuntimeHandshake, event: HandshakeEvent) Error!void {
        self.state = nextState(self.role, self.state, event) orelse return error.BadState;
    }
};

fn nextState(role: Role, state: State, event: HandshakeEvent) ?State {
    return switch (role) {
        .client => switch (state) {
            .start => if (event == .send_client_hello) .client_hello else null,
            .client_hello => if (event == .recv_server_hello) .server_hello else null,
            .server_hello => if (event == .recv_encrypted_extensions) .encrypted_extensions else null,
            .encrypted_extensions => if (event == .recv_certificate) .certificate else null,
            .certificate => if (event == .recv_certificate_verify) .certificate_verify else null,
            .certificate_verify => if (event == .recv_finished) .finished else null,
            .finished => if (event == .send_finished) .connected else null,
            .connected => null,
        },
        .server => switch (state) {
            .start => if (event == .recv_client_hello) .client_hello else null,
            .client_hello => if (event == .send_server_hello) .server_hello else null,
            .server_hello => if (event == .send_encrypted_extensions) .encrypted_extensions else null,
            .encrypted_extensions => if (event == .send_certificate) .certificate else null,
            .certificate => if (event == .send_certificate_verify) .certificate_verify else null,
            .certificate_verify => if (event == .send_finished) .finished else null,
            .finished => if (event == .recv_finished) .connected else null,
            .connected => null,
        },
    };
}

pub const Fsm = struct {
    role: Role,
    runtime: RuntimeHandshake,
    config: Config,
    kx_pair: kx.X25519Kx.KeyPair,
    transcript: [transcript_cap]u8 = undefined,
    transcript_len: usize = 0,

    early: Secret([Sha256.hash_len]u8) = Secret([Sha256.hash_len]u8).init([_]u8{0} ** Sha256.hash_len),
    handshake_secret: Secret([Sha256.hash_len]u8) = Secret([Sha256.hash_len]u8).init([_]u8{0} ** Sha256.hash_len),
    master: Secret([Sha256.hash_len]u8) = Secret([Sha256.hash_len]u8).init([_]u8{0} ** Sha256.hash_len),
    handshake_traffic: ?TrafficSecrets = null,
    application_traffic: ?TrafficSecrets = null,
    client_hs_keys: ?TrafficKeys = null,
    server_hs_keys: ?TrafficKeys = null,
    // NOTE (TLS1.3 RFC8446 5.3): seq MUST reset to 0 on each key-epoch change.
    // Only handshake records are sealed/opened today; reset these when wiring
    // application-data records on the application_traffic keys.
    read_seq: u64 = 0,
    write_seq: u64 = 0,

    pub fn initDeterministic(role: Role, seed: [kx.X25519Kx.seed_len]u8, config: Config) Error!Fsm {
        return .{
            .role = role,
            .runtime = .{ .role = role },
            .config = config,
            .kx_pair = try kx.X25519Kx.generateDeterministic(seed),
        };
    }

    pub fn deinit(self: *Fsm) void {
        self.kx_pair.wipe();
        secureZero(self.transcript[0..self.transcript_len]);
        self.early.wipe();
        self.handshake_secret.wipe();
        self.master.wipe();
        if (self.handshake_traffic) |*s| {
            s.client.wipe();
            s.server.wipe();
        }
        if (self.application_traffic) |*s| {
            s.client.wipe();
            s.server.wipe();
        }
        if (self.client_hs_keys) |*k2| k2.wipe();
        if (self.server_hs_keys) |*k2| k2.wipe();
    }

    pub fn state(self: *const Fsm) State {
        return self.runtime.state;
    }

    pub fn start(self: *Fsm, allocator: Allocator) Error![]u8 {
        if (self.role != .client or self.runtime.state != .start) return error.BadState;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try writeClientHello(allocator, &out, self.kx_pair.public_key);
        try self.runtime.step(.send_client_hello);
        try self.appendTranscript(out.items);
        return out.toOwnedSlice(allocator);
    }

    pub fn feed(self: *Fsm, allocator: Allocator, flight: []const u8) Error![]u8 {
        return switch (self.role) {
            .server => self.feedServer(allocator, flight),
            .client => self.feedClient(allocator, flight),
        };
    }

    pub fn derivedApplicationSecrets(self: *const Fsm) ?TrafficSecrets {
        return self.application_traffic;
    }

    fn feedServer(self: *Fsm, allocator: Allocator, flight: []const u8) Error![]u8 {
        if (self.runtime.state == .start) return self.recvClientHello(allocator, flight);
        if (self.runtime.state == .finished) return self.recvClientFinished(allocator, flight);
        return error.BadState;
    }

    fn recvClientHello(self: *Fsm, allocator: Allocator, flight: []const u8) Error![]u8 {
        var off: usize = 0;
        const ch = try parseHandshake(flight, &off);
        if (off != flight.len or ch.typ != .client_hello) return error.BadHandshake;
        const peer_pub = try parseClientHello(ch.body);
        try self.runtime.step(.recv_client_hello);
        try self.appendTranscript(ch.raw);

        var shared = try kx.X25519Kx.sharedSecret(&self.kx_pair.secret_key, peer_pub);
        defer shared.wipe();

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try writeServerHello(allocator, &out, self.kx_pair.public_key);
        try self.runtime.step(.send_server_hello);
        try self.appendTranscript(out.items);

        try self.deriveHandshakeKeys(&shared.declassify());

        var encrypted: std.ArrayList(u8) = .empty;
        defer encrypted.deinit(allocator);
        try self.writeServerEncryptedFlight(allocator, &encrypted);
        const record = try self.sealHandshake(allocator, encrypted.items, .server);
        defer allocator.free(record);
        try out.appendSlice(allocator, record);
        return out.toOwnedSlice(allocator);
    }

    fn feedClient(self: *Fsm, allocator: Allocator, flight: []const u8) Error![]u8 {
        if (self.runtime.state != .client_hello) return error.BadState;
        var off: usize = 0;
        const sh = try parseHandshake(flight, &off);
        if (sh.typ != .server_hello) return error.BadHandshake;
        const peer_pub = try parseServerHello(sh.body);
        try self.runtime.step(.recv_server_hello);
        try self.appendTranscript(sh.raw);

        var shared = try kx.X25519Kx.sharedSecret(&self.kx_pair.secret_key, peer_pub);
        defer shared.wipe();
        try self.deriveHandshakeKeys(&shared.declassify());

        const plain = try self.openHandshake(allocator, flight[off..], .server);
        defer allocator.free(plain);
        try self.consumeServerEncrypted(plain);
        try self.deriveApplicationSecrets();

        var fin: std.ArrayList(u8) = .empty;
        errdefer fin.deinit(allocator);
        try self.writeFinished(allocator, &fin, .client);
        try self.runtime.step(.send_finished);
        const record = try self.sealHandshake(allocator, fin.items, .client);
        fin.deinit(allocator);
        return record;
    }

    fn recvClientFinished(self: *Fsm, allocator: Allocator, flight: []const u8) Error![]u8 {
        const plain = try self.openHandshake(allocator, flight, .client);
        defer allocator.free(plain);
        var off: usize = 0;
        const fin = try parseHandshake(plain, &off);
        if (off != plain.len or fin.typ != .finished) return error.BadHandshake;
        try self.verifyFinished(fin.body, .client);
        try self.runtime.step(.recv_finished);
        try self.appendTranscript(fin.raw);
        return allocator.alloc(u8, 0);
    }

    fn writeServerEncryptedFlight(self: *Fsm, allocator: Allocator, out: *std.ArrayList(u8)) Error!void {
        try writeHandshake(allocator, out, .encrypted_extensions, "");
        try self.runtime.step(.send_encrypted_extensions);
        try self.appendTranscript(out.items[out.items.len - 4 ..]);

        const before_cert = out.items.len;
        try writeCertificate(allocator, out, self.config.cert_chain);
        try self.runtime.step(.send_certificate);
        try self.appendTranscript(out.items[before_cert..]);

        const before_cv = out.items.len;
        try self.writeCertificateVerify(allocator, out);
        try self.runtime.step(.send_certificate_verify);
        try self.appendTranscript(out.items[before_cv..]);

        const before_fin = out.items.len;
        try self.writeFinished(allocator, out, .server);
        try self.runtime.step(.send_finished);
        try self.appendTranscript(out.items[before_fin..]);
        try self.deriveApplicationSecrets();
    }

    fn consumeServerEncrypted(self: *Fsm, plain: []const u8) Error!void {
        var off: usize = 0;
        const ee = try parseHandshake(plain, &off);
        if (ee.typ != .encrypted_extensions or ee.body.len != 0) return error.BadHandshake;
        try self.runtime.step(.recv_encrypted_extensions);
        try self.appendTranscript(ee.raw);

        const cert = try parseHandshake(plain, &off);
        if (cert.typ != .certificate) return error.BadHandshake;
        try verifyCertificateMessage(cert.body);
        try self.runtime.step(.recv_certificate);
        try self.appendTranscript(cert.raw);

        const cv = try parseHandshake(plain, &off);
        if (cv.typ != .certificate_verify) return error.BadHandshake;
        try self.verifyCertificateVerify(cv.body);
        try self.runtime.step(.recv_certificate_verify);
        try self.appendTranscript(cv.raw);

        const fin = try parseHandshake(plain, &off);
        if (off != plain.len or fin.typ != .finished) return error.BadHandshake;
        try self.verifyFinished(fin.body, .server);
        try self.runtime.step(.recv_finished);
        try self.appendTranscript(fin.raw);
    }

    fn deriveHandshakeKeys(self: *Fsm, shared_secret: []const u8) Error!void {
        self.early = Sha256.earlySecret("");
        self.handshake_secret = try Sha256.handshakeSecret(&self.early, shared_secret);
        const th = Sha256.transcriptHash(self.transcript[0..self.transcript_len]);
        const hs_traffic = try Sha256.handshakeTrafficSecrets(&self.handshake_secret, &th);
        self.handshake_traffic = .{ .client = hs_traffic.client, .server = hs_traffic.server };
        self.master = try Sha256.masterSecret(&self.handshake_secret);
        self.client_hs_keys = try trafficKeys(&self.handshake_traffic.?.client);
        self.server_hs_keys = try trafficKeys(&self.handshake_traffic.?.server);
    }

    fn deriveApplicationSecrets(self: *Fsm) Error!void {
        const th = Sha256.transcriptHash(self.transcript[0..self.transcript_len]);
        const app_traffic = try Sha256.applicationTrafficSecrets(&self.master, &th);
        self.application_traffic = .{ .client = app_traffic.client, .server = app_traffic.server };
    }

    fn writeCertificateVerify(self: *Fsm, allocator: Allocator, out: *std.ArrayList(u8)) Error!void {
        const key = self.config.server_signing_key orelse return error.MissingSigningKey;
        const th = Sha256.transcriptHash(self.transcript[0..self.transcript_len]);
        const msg = certificateVerifyInput("TLS 1.3, server CertificateVerify", &th);
        const sig = try Ed25519.KeyPair.sign(key, &msg, null);
        var body: [2 + 2 + Ed25519.Signature.encoded_length]u8 = undefined;
        std.mem.writeInt(u16, body[0..2], sig_ed25519, .big);
        std.mem.writeInt(u16, body[2..4], Ed25519.Signature.encoded_length, .big);
        const bytes = sig.toBytes();
        @memcpy(body[4..], &bytes);
        try writeHandshake(allocator, out, .certificate_verify, &body);
    }

    fn verifyCertificateVerify(self: *Fsm, body: []const u8) Error!void {
        if (body.len != 4 + Ed25519.Signature.encoded_length) return error.BadHandshake;
        if (std.mem.readInt(u16, body[0..2], .big) != sig_ed25519) return error.BadSignature;
        if (std.mem.readInt(u16, body[2..4], .big) != Ed25519.Signature.encoded_length) return error.BadSignature;
        const pk = self.config.expected_server_public_key orelse return error.MissingVerifyKey;
        const sig = Ed25519.Signature.fromBytes(body[4..][0..Ed25519.Signature.encoded_length].*);
        const th = Sha256.transcriptHash(self.transcript[0..self.transcript_len]);
        const msg = certificateVerifyInput("TLS 1.3, server CertificateVerify", &th);
        Ed25519.Signature.verify(sig, &msg, pk) catch return error.BadSignature;
    }

    fn writeFinished(self: *Fsm, allocator: Allocator, out: *std.ArrayList(u8), who: Role) Error!void {
        const traffic = self.handshake_traffic orelse return error.BadState;
        const base = if (who == .client) &traffic.client else &traffic.server;
        var fk = try Sha256.finishedKey(base);
        defer fk.wipe();
        const th = Sha256.transcriptHash(self.transcript[0..self.transcript_len]);
        var vd = try Sha256.finishedVerifyData(&fk, &th);
        defer secureZero(&vd);
        try writeHandshake(allocator, out, .finished, &vd);
    }

    fn verifyFinished(self: *Fsm, body: []const u8, who: Role) Error!void {
        if (body.len != Sha256.hash_len) return error.BadHandshake;
        const traffic = self.handshake_traffic orelse return error.BadState;
        const base = if (who == .client) &traffic.client else &traffic.server;
        var fk = try Sha256.finishedKey(base);
        defer fk.wipe();
        const th = Sha256.transcriptHash(self.transcript[0..self.transcript_len]);
        var expected = try Sha256.finishedVerifyData(&fk, &th);
        defer secureZero(&expected);
        // Constant-time MAC compare via std (project invariant); body.len checked above.
        if (!std.crypto.timing_safe.eql([Sha256.hash_len]u8, expected, body[0..Sha256.hash_len].*)) return error.FinishedMismatch;
    }

    fn sealHandshake(self: *Fsm, allocator: Allocator, plaintext: []const u8, from: Role) Error![]u8 {
        const keys = if (from == .client) self.client_hs_keys.? else self.server_hs_keys.?;
        var key = keys.key.declassify();
        defer secureZero(&key);
        const inner_len = plaintext.len + 1;
        const encrypted_len = inner_len + Aead.tag_length;
        var record = try allocator.alloc(u8, tls_record.record_header_len + encrypted_len);
        errdefer allocator.free(record);
        const aad = tls_record.makeAdditionalData(@intCast(encrypted_len));
        @memcpy(record[0..tls_record.record_header_len], &aad);
        @memcpy(record[tls_record.record_header_len..][0..plaintext.len], plaintext);
        record[tls_record.record_header_len + plaintext.len] = @intFromEnum(tls_record.ContentType.handshake);
        const nonce = tls_record.deriveNonce(keys.iv, self.write_seq);
        self.write_seq += 1;
        var tag: [Aead.tag_length]u8 = undefined;
        Aead.encrypt(record[tls_record.record_header_len..][0..inner_len], &tag, record[tls_record.record_header_len..][0..inner_len], &aad, nonce, key);
        @memcpy(record[tls_record.record_header_len + inner_len ..], &tag);
        return record;
    }

    fn openHandshake(self: *Fsm, allocator: Allocator, record: []const u8, from: Role) Error![]u8 {
        const keys = if (from == .client) self.client_hs_keys.? else self.server_hs_keys.?;
        var key = keys.key.declassify();
        defer secureZero(&key);
        const parsed = try tls_record.parseCiphertext(record);
        if (parsed.encrypted_record.len < Aead.tag_length) return error.BadRecord;
        const clen = parsed.encrypted_record.len - Aead.tag_length;
        const inner = try allocator.alloc(u8, clen);
        errdefer allocator.free(inner);
        const aad = parsed.headerBytes();
        const nonce = tls_record.deriveNonce(keys.iv, self.read_seq);
        self.read_seq += 1;
        const tag = parsed.encrypted_record[clen..][0..Aead.tag_length].*;
        Aead.decrypt(inner, parsed.encrypted_record[0..clen], tag, &aad, nonce, key) catch return error.BadRecord;
        const opened = try tls_record.decodeInnerPlaintext(inner);
        if (opened.content_type != .handshake) return error.BadRecord;
        const plain = try allocator.dupe(u8, opened.content);
        allocator.free(inner);
        return plain;
    }

    fn appendTranscript(self: *Fsm, bytes: []const u8) Error!void {
        if (bytes.len > transcript_cap - self.transcript_len) return error.TranscriptOverflow;
        @memcpy(self.transcript[self.transcript_len..][0..bytes.len], bytes);
        self.transcript_len += bytes.len;
    }
};

fn trafficKeys(secret: *const Secret([Sha256.hash_len]u8)) Error!TrafficKeys {
    var key: [Aead.key_length]u8 = undefined;
    var iv: tls_record.Nonce96 = undefined;
    try Sha256.hkdfExpandLabel(secret, "key", "", &key);
    try Sha256.hkdfExpandLabel(secret, "iv", "", &iv);
    return .{ .key = Secret([Aead.key_length]u8).init(key), .iv = iv };
}

fn writeClientHello(allocator: Allocator, out: *std.ArrayList(u8), public_key: kx.PublicKey) Error!void {
    var body: [2 + 32 + 2 + 2 + 32]u8 = undefined;
    std.mem.writeInt(u16, body[0..2], tls12_wire_version, .big);
    @memset(body[2..34], 0x43);
    std.mem.writeInt(u16, body[34..36], suite, .big);
    std.mem.writeInt(u16, body[36..38], group_x25519, .big);
    @memcpy(body[38..70], &public_key);
    try writeHandshake(allocator, out, .client_hello, &body);
}

fn parseClientHello(body: []const u8) Error!kx.PublicKey {
    if (body.len != 70) return error.BadHandshake;
    if (std.mem.readInt(u16, body[0..2], .big) != tls12_wire_version) return error.BadHandshake;
    if (std.mem.readInt(u16, body[34..36], .big) != suite) return error.UnsupportedSuite;
    if (std.mem.readInt(u16, body[36..38], .big) != group_x25519) return error.BadHandshake;
    return body[38..70].*;
}

fn writeServerHello(allocator: Allocator, out: *std.ArrayList(u8), public_key: kx.PublicKey) Error!void {
    var body: [2 + 2 + 32 + 2 + 32]u8 = undefined;
    std.mem.writeInt(u16, body[0..2], tls12_wire_version, .big);
    std.mem.writeInt(u16, body[2..4], suite, .big);
    @memset(body[4..36], 0x53);
    std.mem.writeInt(u16, body[36..38], group_x25519, .big);
    @memcpy(body[38..70], &public_key);
    try writeHandshake(allocator, out, .server_hello, &body);
}

fn parseServerHello(body: []const u8) Error!kx.PublicKey {
    if (body.len != 70) return error.BadHandshake;
    if (std.mem.readInt(u16, body[0..2], .big) != tls12_wire_version) return error.BadHandshake;
    if (std.mem.readInt(u16, body[2..4], .big) != suite) return error.UnsupportedSuite;
    if (std.mem.readInt(u16, body[36..38], .big) != group_x25519) return error.BadHandshake;
    return body[38..70].*;
}

fn writeCertificate(allocator: Allocator, out: *std.ArrayList(u8), chain: []const []const u8) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.append(allocator, 0);
    const list_len_pos = body.items.len;
    try body.appendNTimes(allocator, 0, 3);
    const list_start = body.items.len;
    for (chain) |der| {
        if (der.len > 0x00ff_ffff) return error.BadHandshake;
        try appendU24(allocator, &body, der.len);
        try body.appendSlice(allocator, der);
        try body.appendNTimes(allocator, 0, 2);
    }
    writeU24(body.items[list_len_pos..][0..3], body.items.len - list_start);
    try writeHandshake(allocator, out, .certificate, body.items);
}

fn verifyCertificateMessage(body: []const u8) Error!void {
    if (body.len < 4 or body[0] != 0) return error.BadHandshake;
    const list_len = readU24(body[1..4]);
    if (list_len != body.len - 4) return error.BadHandshake;
    var off: usize = 4;
    var chain_buf: [8][]const u8 = undefined;
    var count: usize = 0;
    while (off < body.len) {
        if (count == chain_buf.len or body.len - off < 5) return error.BadHandshake;
        const der_len = readU24(body[off..][0..3]);
        off += 3;
        if (der_len > body.len - off) return error.BadHandshake;
        chain_buf[count] = body[off..][0..der_len];
        count += 1;
        off += der_len;
        if (body.len - off < 2) return error.BadHandshake;
        const ext_len = std.mem.readInt(u16, body[off..][0..2], .big);
        off += 2;
        if (ext_len > body.len - off) return error.BadHandshake;
        off += ext_len;
    }
    if (count != 0) x509_verify.verifySimpleChain(chain_buf[0..count]) catch return error.CertificateInvalid;
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
    const typ = try HandshakeType.fromByte(input[start]);
    const len = readU24(input[start + 1 ..][0..3]);
    if (len > input.len - start - 4) return error.BadHandshake;
    offset.* = start + 4 + len;
    return .{ .typ = typ, .body = input[start + 4 .. offset.*], .raw = input[start..offset.*] };
}

fn certificateVerifyInput(comptime label: []const u8, th: *const [Sha256.hash_len]u8) [64 + label.len + 1 + Sha256.hash_len]u8 {
    var out: [64 + label.len + 1 + Sha256.hash_len]u8 = undefined;
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..label.len], label);
    out[64 + label.len] = 0;
    @memcpy(out[64 + label.len + 1 ..], th);
    return out;
}

fn appendU24(allocator: Allocator, out: *std.ArrayList(u8), n: usize) Error!void {
    var tmp: [3]u8 = undefined;
    writeU24(&tmp, n);
    try out.appendSlice(allocator, &tmp);
}

fn writeU24(out: []u8, n: usize) void {
    std.debug.assert(out.len == 3);
    out[0] = @intCast((n >> 16) & 0xff);
    out[1] = @intCast((n >> 8) & 0xff);
    out[2] = @intCast(n & 0xff);
}

fn readU24(bytes: []const u8) usize {
    return (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const TestPem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT
    \\BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz
    \\MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj
    \\GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp
    \\LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O
    \\BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf
    \\lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN
    \\Lw0=
    \\-----END CERTIFICATE-----
;

fn testDer(allocator: Allocator) ![]u8 {
    const storage = try allocator.alloc(u8, 512);
    defer allocator.free(storage);
    const der = try x509.pemToDer(TestPem, storage);
    return allocator.dupe(u8, der);
}

test "loopback client server handshake completes and derives matching application secrets" {
    const allocator = std.testing.allocator;
    const der = try testDer(allocator);
    defer allocator.free(der);
    const chain = [_][]const u8{der};
    const sign_key = try Ed25519.KeyPair.generateDeterministic([_]u8{0x7a} ** 32);

    var client = try Fsm.initDeterministic(.client, hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177f3aa1c5b7987"), .{
        .expected_server_public_key = sign_key.public_key,
    });
    defer client.deinit();
    var server = try Fsm.initDeterministic(.server, hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"), .{
        .cert_chain = &chain,
        .server_signing_key = sign_key,
    });
    defer server.deinit();

    const ch = try client.start(allocator);
    defer allocator.free(ch);
    try std.testing.expectEqual(State.client_hello, client.state());

    const sf = try server.feed(allocator, ch);
    defer allocator.free(sf);
    try std.testing.expectEqual(State.finished, server.state());

    const cf = try client.feed(allocator, sf);
    defer allocator.free(cf);
    try std.testing.expectEqual(State.connected, client.state());

    const done = try server.feed(allocator, cf);
    defer allocator.free(done);
    try std.testing.expectEqual(State.connected, server.state());

    const ca = client.derivedApplicationSecrets().?;
    const sa = server.derivedApplicationSecrets().?;
    try std.testing.expectEqualSlices(u8, &ca.clientBytes(), &sa.clientBytes());
    try std.testing.expectEqualSlices(u8, &ca.serverBytes(), &sa.serverBytes());
}

test "tamper detection rejects modified server flight" {
    const allocator = std.testing.allocator;
    const sign_key = try Ed25519.KeyPair.generateDeterministic([_]u8{0x55} ** 32);
    var client = try Fsm.initDeterministic(.client, [_]u8{1} ** 32, .{
        .expected_server_public_key = sign_key.public_key,
    });
    defer client.deinit();
    var server = try Fsm.initDeterministic(.server, [_]u8{2} ** 32, .{ .server_signing_key = sign_key });
    defer server.deinit();

    const ch = try client.start(allocator);
    defer allocator.free(ch);
    const sf = try server.feed(allocator, ch);
    defer allocator.free(sf);
    sf[sf.len - 1] ^= 0x40;
    try std.testing.expectError(error.BadRecord, client.feed(allocator, sf));
}

test "state transitions reject illegal order and finished tampering" {
    const allocator = std.testing.allocator;
    const sign_key = try Ed25519.KeyPair.generateDeterministic([_]u8{0x33} ** 32);
    var client = try Fsm.initDeterministic(.client, [_]u8{3} ** 32, .{
        .expected_server_public_key = sign_key.public_key,
    });
    defer client.deinit();
    var server = try Fsm.initDeterministic(.server, [_]u8{4} ** 32, .{ .server_signing_key = sign_key });
    defer server.deinit();

    try std.testing.expectError(error.BadState, client.feed(allocator, ""));
    const ch = try client.start(allocator);
    defer allocator.free(ch);
    const sf = try server.feed(allocator, ch);
    defer allocator.free(sf);
    const cf = try client.feed(allocator, sf);
    defer allocator.free(cf);
    cf[cf.len - 3] ^= 1;
    try std.testing.expectError(error.BadRecord, server.feed(allocator, cf));
}

test {
    std.testing.refAllDecls(@This());
}
