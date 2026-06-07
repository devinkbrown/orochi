//! Socketless TLS 1.3 client handshake state machine for outbound HTTPS.
//!
//! The caller owns transport I/O: call `start()` to get the ClientHello record,
//! pass received bytes to `feed()`, send any returned bytes, then use
//! `encrypt()` / `decrypt()` once `handshakeDone()` is true.

const std = @import("std");
const builtin = @import("builtin");

const hkdf_tls13 = @import("hkdf_tls13.zig");
const tls_record = @import("tls_record.zig");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_verify = @import("rsa_verify.zig");
const sign = @import("sign.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const kx = @import("kx.zig");

const tls_supported_versions = @import("../proto/tls_supported_versions.zig");
const tls_keyshare = @import("../proto/tls_keyshare.zig");
const tls_signature_scheme = @import("../proto/tls_signature_scheme.zig");
const tls_extension = @import("../proto/tls_extension.zig");
const supported_groups = @import("../proto/supported_groups.zig");
const sni = @import("../proto/sni.zig");
const tls_alert = @import("../proto/tls_alert.zig");
const tls_finished = @import("../proto/tls_finished.zig");
const tls_alpn = @import("../proto/tls_alpn.zig");

const Allocator = std.mem.Allocator;
const Sha256 = hkdf_tls13.Sha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_client requires a 64-bit target");
}

pub const Error = error{
    BadCertificate,
    BadHandshake,
    BadRecord,
    BadSignature,
    BadState,
    CertificateNameMismatch,
    DecodeError,
    EmptyCertificateChain,
    FinishedMismatch,
    HelloRetryRequestUnsupported,
    MissingExtension,
    NeedMore,
    OutputTooSmall,
    ProtocolVersion,
    TlsAlert,
    TranscriptOverflow,
    UnknownCa,
    UnsupportedCipherSuite,
    UnsupportedGroup,
    UnsupportedSignatureScheme,
    UnsupportedPublicKey,
} || Allocator.Error || hkdf_tls13.Error || tls_record.Error || x509.Error ||
    x509_verify.Error || ecdh_p256.EcdhError || kx.KeyExchangeError ||
    ecdsa_p256.DerError || ecdsa_p256.Sec1Error || tls_extension.Error ||
    tls_keyshare.Error || tls_supported_versions.Error ||
    tls_signature_scheme.Error || supported_groups.Error || tls_alpn.Error ||
    tls_alert.ParseError || rsa_verify.Error || sign.VerifyError;

pub const Options = struct {
    server_name: []const u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8 = &.{},
};

pub const FeedResult = union(enum) {
    need_more,
    bytes_to_send: []u8,
};

/// Result of `decryptApp`: decrypted application bytes (caller owns) or a
/// benign post-handshake control record that was consumed and ignored.
pub const AppRead = union(enum) {
    application_data: []u8,
    control,
};

const State = enum {
    idle,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_certificate,
    wait_certificate_verify,
    wait_finished,
    connected,
};

const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
    _,
};

const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_chacha20_poly1305_sha256 = 0x1303,

    fn fromWire(v: u16) Error!CipherSuite {
        return switch (v) {
            0x1301 => .tls_aes_128_gcm_sha256,
            0x1303 => .tls_chacha20_poly1305_sha256,
            else => error.UnsupportedCipherSuite,
        };
    }

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

const TrafficKeys = struct {
    key: [ChaCha20Poly1305.key_length]u8 = [_]u8{0} ** ChaCha20Poly1305.key_length,
    iv: tls_record.Nonce96 = [_]u8{0} ** 12,

    fn wipe(self: *TrafficKeys) void {
        secureZero(&self.key);
        secureZero(&self.iv);
    }
};

const HandshakeMsg = struct {
    typ: HandshakeType,
    body: []const u8,
    raw: []const u8,
};

const LeafPublicKey = union(enum) {
    rsa: rsa_verify.PublicKey,
    ecdsa_p256: ecdsa_p256.PublicKey,
    ed25519: sign.PublicKey,
};

const CertParts = struct {
    tbs_der: []const u8,
    signature_algorithm_oid: []const u8,
    signature: []const u8,
    issuer_der: []const u8,
    subject_der: []const u8,
    spki_der: []const u8,
};

pub const Client = struct {
    allocator: Allocator,
    server_name: []u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8,

    state: State = .idle,
    x25519_pair: kx.X25519Kx.KeyPair,
    p256_pair: ecdh_p256.KeyPair,
    legacy_session_id: [32]u8,
    selected_suite: ?CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    leaf_key: ?LeafPublicKey = null,
    last_alert: ?tls_alert.Alert = null,

    transcript: std.ArrayList(u8) = .empty,
    recv_buf: std.ArrayList(u8) = .empty,
    hs_plain: std.ArrayList(u8) = .empty,

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

    pub fn init(allocator: Allocator, options: Options) Error!Client {
        if (options.server_name.len == 0) return error.BadHandshake;
        var seed: [kx.X25519Kx.seed_len]u8 = undefined;
        try osEntropy(&seed);
        var session_id: [32]u8 = undefined;
        try osEntropy(&session_id);

        const name = try allocator.dupe(u8, options.server_name);
        errdefer allocator.free(name);
        const anchors = try allocator.dupe([]const u8, options.trust_anchors);
        errdefer allocator.free(anchors);
        const alpn = try allocator.dupe([]const u8, options.alpn_protocols);
        errdefer allocator.free(alpn);

        return .{
            .allocator = allocator,
            .server_name = name,
            .trust_anchors = anchors,
            .alpn_protocols = alpn,
            .x25519_pair = try kx.X25519Kx.generateDeterministic(seed),
            .p256_pair = try ecdh_p256.generate(),
            .legacy_session_id = session_id,
        };
    }

    pub fn deinit(self: *Client) void {
        self.x25519_pair.wipe();
        secureZero(&self.p256_pair.secret);
        secureZero(&self.legacy_session_id);
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
        self.hs_plain.deinit(self.allocator);
        self.allocator.free(self.server_name);
        self.allocator.free(self.trust_anchors);
        self.allocator.free(self.alpn_protocols);
        self.* = undefined;
    }

    pub fn start(self: *Client) Error![]u8 {
        if (self.state != .idle) return error.BadState;
        var handshake: std.ArrayList(u8) = .empty;
        defer handshake.deinit(self.allocator);
        try self.writeClientHello(&handshake);
        try self.appendTranscript(handshake.items);
        self.state = .wait_server_hello;
        return writePlainRecord(self.allocator, .handshake, handshake.items);
    }

    pub fn feed(self: *Client, received: []const u8) Error!FeedResult {
        if (self.state == .idle or self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);

        if (self.state == .wait_server_hello) {
            const progressed = try self.tryConsumeServerHello();
            if (!progressed) return .need_more;
        }

        if (try self.tryConsumeServerFlight()) |reply| {
            return .{ .bytes_to_send = reply };
        }
        return .need_more;
    }

    pub fn handshakeDone(self: *const Client) bool {
        return self.state == .connected;
    }

    /// Raw (still-encrypted) record bytes received but not consumed by the
    /// handshake driver. After `handshakeDone()`, a one-shot caller should frame
    /// and `decryptApp` these *before* reading further from the socket, since a
    /// server may flush post-handshake records in the same segment as Finished.
    pub fn pendingBytes(self: *const Client) []const u8 {
        return self.recv_buf.items;
    }

    pub fn encrypt(self: *Client, appdata: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const out = try sealRecordAlloc(
            self.allocator,
            suite,
            &self.client_app_keys,
            self.app_write_seq,
            .application_data,
            appdata,
        );
        self.app_write_seq += 1;
        return out;
    }

    pub fn decrypt(self: *Client, record: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try openRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_read_seq, record);
        self.app_read_seq += 1;
        errdefer self.allocator.free(opened.content);
        if (opened.content_type == .alert) {
            self.last_alert = try tls_alert.parse(opened.content);
            return error.TlsAlert;
        }
        if (opened.content_type != .application_data) return error.BadRecord;
        return opened.content;
    }

    /// Post-handshake-aware read of one decrypted record. Returns the decrypted
    /// application bytes, or `.control` for benign post-handshake handshake
    /// records the one-shot client ignores (e.g. NewSessionTicket). Alerts raise
    /// `error.TlsAlert`. Note: a post-handshake KeyUpdate is *not* honored here
    /// (treated as control); a one-shot request never triggers a server rekey.
    pub fn decryptApp(self: *Client, record: []const u8) Error!AppRead {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try openRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_read_seq, record);
        self.app_read_seq += 1;
        switch (opened.content_type) {
            .application_data => return .{ .application_data = opened.content },
            .alert => {
                defer self.allocator.free(opened.content);
                self.last_alert = try tls_alert.parse(opened.content);
                return error.TlsAlert;
            },
            .handshake => {
                self.allocator.free(opened.content);
                return .control;
            },
            else => {
                self.allocator.free(opened.content);
                return error.BadRecord;
            },
        }
    }

    fn writeClientHello(self: *Client, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);

        try appendU16(self.allocator, &body, tls_record.legacy_record_version);
        var random: [32]u8 = undefined;
        try osEntropy(&random);
        try body.appendSlice(self.allocator, &random);
        secureZero(&random);

        try body.append(self.allocator, @intCast(self.legacy_session_id.len));
        try body.appendSlice(self.allocator, &self.legacy_session_id);

        try appendU16(self.allocator, &body, 4);
        try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256));
        try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));

        try body.append(self.allocator, 1);
        try body.append(self.allocator, 0);

        var ext_storage: [2048]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);

        var sni_buf: [512]u8 = undefined;
        const sni_body = try buildSniBody(&sni_buf, self.server_name);
        try ext_builder.addTyped(.server_name, sni_body);

        var versions_buf: [8]u8 = undefined;
        const versions = try tls_supported_versions.buildClient(&versions_buf, &[_]u16{tls_supported_versions.tls13});
        try ext_builder.addTyped(.supported_versions, versions);

        var groups_buf: [16]u8 = undefined;
        const groups = try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{ .x25519, .secp256r1 });
        try ext_builder.addTyped(.supported_groups, groups);

        var sigs_buf: [16]u8 = undefined;
        const sigs = try tls_signature_scheme.build(&sigs_buf, &[_]tls_signature_scheme.SignatureScheme{
            .rsa_pss_rsae_sha256,
            .ecdsa_secp256r1_sha256,
            .ed25519,
            .rsa_pkcs1_sha256,
        });
        try ext_builder.addTyped(.signature_algorithms, sigs);

        var keyshare_buf: [128]u8 = undefined;
        const keyshares = try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
            .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key },
            .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 },
        });
        try ext_builder.addTyped(.key_share, keyshares);

        if (self.alpn_protocols.len != 0) {
            var alpn_buf: [512]u8 = undefined;
            var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
            for (self.alpn_protocols) |proto| try alpn_builder.add(proto);
            const alpn_body = try alpn_builder.finish();
            try ext_builder.addTyped(.alpn, alpn_body);
        }

        const extensions = try ext_builder.finish();
        try body.appendSlice(self.allocator, extensions);
        try writeHandshake(self.allocator, out, .client_hello, body.items);
    }

    fn tryConsumeServerHello(self: *Client) Error!bool {
        while (true) {
            const rec = completePlainRecord(self.recv_buf.items) orelse return false;
            if (rec.content_type == .change_cipher_spec) {
                consumePrefix(&self.recv_buf, rec.wire_len);
                continue;
            }
            if (rec.content_type == .alert) {
                self.last_alert = try tls_alert.parse(rec.fragment);
                return error.TlsAlert;
            }
            if (rec.content_type != .handshake) return error.BadRecord;

            var off: usize = 0;
            const msg = try parseHandshake(rec.fragment, &off);
            if (off != rec.fragment.len or msg.typ != .server_hello) return error.BadHandshake;
            var selected = try self.parseServerHello(msg.body);
            try self.appendTranscript(msg.raw);
            try self.deriveHandshakeKeys(selected.shared_secret);
            secureZero(&selected.shared_secret);
            consumePrefix(&self.recv_buf, rec.wire_len);
            self.state = .wait_encrypted_extensions;
            return true;
        }
    }

    fn tryConsumeServerFlight(self: *Client) Error!?[]u8 {
        while (self.state != .connected) {
            while (try self.tryProcessPlainHandshake()) {}
            if (self.state == .connected) return try self.writeClientFinishedRecord();

            const rec = completePlainRecord(self.recv_buf.items) orelse return null;
            if (rec.content_type == .change_cipher_spec) {
                consumePrefix(&self.recv_buf, rec.wire_len);
                continue;
            }
            if (rec.content_type != .application_data) return error.BadRecord;
            const suite = self.selected_suite orelse return error.BadState;
            const opened = try openRecordAlloc(self.allocator, suite, &self.server_hs_keys, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
            self.hs_read_seq += 1;
            defer self.allocator.free(opened.content);
            consumePrefix(&self.recv_buf, rec.wire_len);

            if (opened.content_type == .alert) {
                self.last_alert = try tls_alert.parse(opened.content);
                return error.TlsAlert;
            }
            if (opened.content_type != .handshake) return error.BadRecord;
            try self.hs_plain.appendSlice(self.allocator, opened.content);
        }
        return null;
    }

    fn tryProcessPlainHandshake(self: *Client) Error!bool {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(self.hs_plain.items, &off) orelse return false;
        switch (self.state) {
            .wait_encrypted_extensions => {
                if (msg.typ != .encrypted_extensions) return error.BadHandshake;
                try self.parseEncryptedExtensions(msg.body);
                try self.appendTranscript(msg.raw);
                self.state = .wait_certificate;
            },
            .wait_certificate => {
                if (msg.typ != .certificate) return error.BadHandshake;
                try self.parseAndVerifyCertificate(msg.body);
                try self.appendTranscript(msg.raw);
                self.state = .wait_certificate_verify;
            },
            .wait_certificate_verify => {
                if (msg.typ != .certificate_verify) return error.BadHandshake;
                try self.verifyCertificateVerify(msg.body);
                try self.appendTranscript(msg.raw);
                self.state = .wait_finished;
            },
            .wait_finished => {
                if (msg.typ != .finished) return error.BadHandshake;
                try self.verifyFinished(msg.body);
                try self.appendTranscript(msg.raw);
                try self.deriveApplicationKeys();
                self.state = .connected;
            },
            else => return error.BadState,
        }
        consumePrefix(&self.hs_plain, off);
        return true;
    }

    fn parseServerHello(self: *Client, body: []const u8) Error!struct { shared_secret: [32]u8 } {
        var c = Cursor.init(body);
        if (try c.readU16() != tls_record.legacy_record_version) return error.ProtocolVersion;
        const random = try c.take(32);
        if (std.mem.eql(u8, random, &hello_retry_request_random)) return error.HelloRetryRequestUnsupported;
        const sid = try c.take(try c.readU8());
        if (!std.mem.eql(u8, sid, &self.legacy_session_id)) return error.BadHandshake;
        const suite = try CipherSuite.fromWire(try c.readU16());
        if (try c.readU8() != 0) return error.BadHandshake;
        const extensions_block = try c.take(try c.readU16());
        try c.expectEmpty();

        var selected_version = false;
        var selected_share: ?tls_keyshare.Entry = null;
        var it = tls_extension.Iterator.init(extensions_block);
        while (try it.next()) |ext| {
            switch (ext.typed()) {
                .supported_versions => {
                    if (try tls_supported_versions.parseServer(ext.data) != tls_supported_versions.tls13) {
                        return error.ProtocolVersion;
                    }
                    selected_version = true;
                },
                .key_share => selected_share = try tls_keyshare.parseServerShare(ext.data),
                else => {},
            }
        }
        if (!selected_version or selected_share == null) return error.MissingExtension;
        self.selected_suite = suite;
        const share = selected_share.?;
        const shared = switch (share.group) {
            .x25519 => blk: {
                if (share.key_exchange.len != kx.X25519Kx.public_len) return error.BadHandshake;
                var peer: kx.PublicKey = undefined;
                @memcpy(&peer, share.key_exchange);
                var secret = try kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer);
                defer secret.wipe();
                break :blk secret.declassify();
            },
            .secp256r1 => blk: {
                if (share.key_exchange.len != ecdh_p256.public_length) return error.BadHandshake;
                break :blk try ecdh_p256.sharedSecret(self.p256_pair.secret, share.key_exchange[0..ecdh_p256.public_length].*);
            },
            else => return error.UnsupportedGroup,
        };
        return .{ .shared_secret = shared };
    }

    fn parseEncryptedExtensions(self: *Client, body: []const u8) Error!void {
        const extensions = try tls_extension.unwrap(body);
        var it = tls_extension.Iterator.init(extensions);
        while (try it.next()) |ext| {
            switch (ext.typed()) {
                .alpn => {
                    var names = try tls_alpn.Iterator.fromBlock(ext.data);
                    const selected = (try names.next()) orelse return error.BadHandshake;
                    if ((try names.next()) != null) return error.BadHandshake;
                    var ok = false;
                    for (self.alpn_protocols) |offered| {
                        if (std.mem.eql(u8, offered, selected)) ok = true;
                    }
                    if (!ok) return error.BadHandshake;
                    self.selected_alpn = selected;
                },
                .supported_versions, .key_share, .signature_algorithms, .supported_groups, .server_name => {
                    return error.BadHandshake;
                },
                else => {},
            }
        }
    }

    fn parseAndVerifyCertificate(self: *Client, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const request_context = try c.take(try c.readU8());
        if (request_context.len != 0) return error.BadHandshake;
        const list = try c.take(try c.readU24());
        try c.expectEmpty();

        var chain_buf: [16][]const u8 = undefined;
        var count: usize = 0;
        var certs = Cursor.init(list);
        while (certs.remaining() != 0) {
            if (count == chain_buf.len) return error.BadCertificate;
            const der = try certs.take(try certs.readU24());
            const ext = try certs.take(try certs.readU16());
            if (ext.len != 0) {
                var eit = tls_extension.Iterator.init(ext);
                while (try eit.next()) |_| {}
            }
            chain_buf[count] = der;
            count += 1;
        }
        if (count == 0) return error.EmptyCertificateChain;
        const chain = chain_buf[0..count];
        try verifyChainToTrustAnchors(chain, self.trust_anchors, self.server_name);
        self.leaf_key = try parsePublicKeyFromSpki((try extractCertParts(chain[0])).spki_der);
    }

    fn verifyCertificateVerify(self: *Client, body: []const u8) Error!void {
        if (body.len < 4) return error.BadHandshake;
        const scheme = tls_signature_scheme.SignatureScheme.fromInt(std.mem.readInt(u16, body[0..2], .big));
        const sig_len = std.mem.readInt(u16, body[2..4], .big);
        if (body.len != 4 + @as(usize, sig_len)) return error.BadHandshake;
        const sig_bytes = body[4..];
        const th = Sha256.transcriptHash(self.transcript.items);
        const input = certificateVerifyInput(&th);
        const leaf = self.leaf_key orelse return error.BadCertificate;
        try verifySignatureScheme(leaf, scheme, &input, sig_bytes);
    }

    fn verifyFinished(self: *Client, body: []const u8) Error!void {
        const th = Sha256.transcriptHash(self.transcript.items);
        if (!tls_finished.verify(self.server_hs_secret, th, body)) return error.FinishedMismatch;
    }

    fn writeClientFinishedRecord(self: *Client) Error![]u8 {
        const th = Sha256.transcriptHash(self.transcript.items);
        const verify_data = tls_finished.verifyData(self.client_hs_secret, th);
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .finished, &verify_data);
        try self.appendTranscript(hs.items);
        const suite = self.selected_suite orelse return error.BadState;
        const record = try sealRecordAlloc(self.allocator, suite, &self.client_hs_keys, self.hs_write_seq, .handshake, hs.items);
        self.hs_write_seq += 1;
        return record;
    }

    fn deriveHandshakeKeys(self: *Client, shared_secret: [32]u8) Error!void {
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

        const suite = self.selected_suite orelse return error.BadState;
        try deriveTrafficKeys(suite, self.client_hs_secret, &self.client_hs_keys);
        try deriveTrafficKeys(suite, self.server_hs_secret, &self.server_hs_keys);
        self.hs_read_seq = 0;
        self.hs_write_seq = 0;
    }

    fn deriveApplicationKeys(self: *Client) Error!void {
        var master = Sha256.SecretBytes.init(self.master_secret);
        defer master.wipe();
        const th = Sha256.transcriptHash(self.transcript.items);
        var traffic = try Sha256.applicationTrafficSecrets(&master, &th);
        defer traffic.wipe();
        self.client_app_secret = traffic.client.declassify();
        self.server_app_secret = traffic.server.declassify();
        const suite = self.selected_suite orelse return error.BadState;
        try deriveTrafficKeys(suite, self.client_app_secret, &self.client_app_keys);
        try deriveTrafficKeys(suite, self.server_app_secret, &self.server_app_keys);
        self.app_read_seq = 0;
        self.app_write_seq = 0;
    }

    fn appendTranscript(self: *Client, bytes: []const u8) Error!void {
        if (self.transcript.items.len > std.math.maxInt(usize) - bytes.len) return error.TranscriptOverflow;
        try self.transcript.appendSlice(self.allocator, bytes);
    }
};

const PlainRecord = struct {
    content_type: tls_record.ContentType,
    fragment: []const u8,
    wire_len: usize,
};

const OpenedRecord = struct {
    content_type: tls_record.ContentType,
    content: []u8,
};

const ServerNameTypeHost: u8 = 0;
const hello_retry_request_random = [_]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

fn osEntropy(buf: []u8) Error!void {
    switch (builtin.os.tag) {
        .linux => {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
                const signed: isize = @bitCast(rc);
                if (signed < 0 or rc == 0) return error.BadHandshake;
                filled += rc;
            }
        },
        else => return error.BadHandshake,
    }
}

fn writePlainRecord(allocator: Allocator, typ: tls_record.ContentType, fragment: []const u8) Error![]u8 {
    if (fragment.len > tls_record.max_plaintext_len) return error.BadRecord;
    var out = try allocator.alloc(u8, tls_record.record_header_len + fragment.len);
    errdefer allocator.free(out);
    out[0] = @intFromEnum(typ);
    std.mem.writeInt(u16, out[1..3], 0x0301, .big);
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

fn sealRecordAlloc(
    allocator: Allocator,
    suite: CipherSuite,
    keys: *const TrafficKeys,
    seq: u64,
    typ: tls_record.ContentType,
    plaintext: []const u8,
) Error![]u8 {
    const inner_len = plaintext.len + 1;
    const inner = try allocator.alloc(u8, inner_len);
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

fn openRecordAlloc(
    allocator: Allocator,
    suite: CipherSuite,
    keys: *const TrafficKeys,
    seq: u64,
    record: []const u8,
) Error!OpenedRecord {
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

fn buildSniBody(out: []u8, name: []const u8) Error![]const u8 {
    if (name.len > std.math.maxInt(u16)) return error.BadHandshake;
    const entry_len = 1 + 2 + name.len;
    const total = 2 + entry_len;
    if (out.len < total) return error.OutputTooSmall;
    std.mem.writeInt(u16, out[0..2], @intCast(entry_len), .big);
    out[2] = ServerNameTypeHost;
    std.mem.writeInt(u16, out[3..5], @intCast(name.len), .big);
    @memcpy(out[5..][0..name.len], name);
    return out[0..total];
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
    const len = readU24Bytes(input[start + 1 ..][0..3]);
    const body_start = start + 4;
    const body_end = body_start + len;
    if (body_end > input.len) return error.BadHandshake;
    offset.* = body_end;
    return .{ .typ = typ, .body = input[body_start..body_end], .raw = input[start..body_end] };
}

fn parseHandshakeMaybe(input: []const u8, offset: *usize) ?HandshakeMsg {
    if (input.len < 4) return null;
    const len = readU24Bytes(input[1..4]);
    if (input.len < 4 + len) return null;
    return parseHandshake(input, offset) catch null;
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

fn readU24Bytes(bytes: []const u8) usize {
    return (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
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
        if (self.remaining() < n) return error.DecodeError;
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

    fn readU24(self: *Cursor) Error!usize {
        return readU24Bytes((try self.take(3))[0..3]);
    }

    fn expectEmpty(self: Cursor) Error!void {
        if (self.remaining() != 0) return error.DecodeError;
    }
};

fn certificateVerifyInput(transcript_hash: *const [Sha256.hash_len]u8) [64 + certificate_verify_context.len + 1 + Sha256.hash_len]u8 {
    var out: [64 + certificate_verify_context.len + 1 + Sha256.hash_len]u8 = undefined;
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..certificate_verify_context.len], certificate_verify_context);
    out[64 + certificate_verify_context.len] = 0;
    @memcpy(out[64 + certificate_verify_context.len + 1 ..], transcript_hash);
    return out;
}

const certificate_verify_context = "TLS 1.3, server CertificateVerify";

fn verifySignatureScheme(key: LeafPublicKey, scheme: tls_signature_scheme.SignatureScheme, msg: []const u8, sig: []const u8) Error!void {
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            const pk = switch (key) {
                .ecdsa_p256 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            const decoded = try ecdsa_p256.signatureFromDer(sig);
            if (!ecdsa_p256.verify(decoded, msg, pk)) return error.BadSignature;
        },
        .rsa_pss_rsae_sha256 => {
            const pk = switch (key) {
                .rsa => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            if (!rsa_verify.verifyPss(pk, .sha256, &digest, sig, 32)) return error.BadSignature;
        },
        .rsa_pkcs1_sha256 => {
            const pk = switch (key) {
                .rsa => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, sig)) return error.BadSignature;
        },
        .ed25519 => {
            const pk = switch (key) {
                .ed25519 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            if (sig.len != sign.signature_len) return error.BadSignature;
            var fixed: sign.Signature = undefined;
            @memcpy(&fixed, sig);
            if (!try sign.verify(msg, fixed, pk)) return error.BadSignature;
        },
        else => return error.UnsupportedSignatureScheme,
    }
}

fn verifyChainToTrustAnchors(chain: []const []const u8, anchors: []const []const u8, server_name: []const u8) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    if (anchors.len == 0) return error.UnknownCa;
    const leaf = try x509.parse(chain[0]);
    if (!dnsNameMatchesCert(server_name, leaf)) return error.CertificateNameMismatch;

    var i: usize = 0;
    while (i + 1 < chain.len) : (i += 1) {
        try verifyIssuedBy(chain[i], chain[i + 1]);
        const issuer = try x509.parse(chain[i + 1]);
        if (!issuer.basic_constraints_ca) return error.BadCertificate;
    }

    const last = chain[chain.len - 1];
    const last_parts = try extractCertParts(last);
    for (anchors) |anchor_der| {
        const anchor_parts = extractCertParts(anchor_der) catch continue;
        if (!std.mem.eql(u8, last_parts.issuer_der, anchor_parts.subject_der) and
            !std.mem.eql(u8, last_parts.subject_der, anchor_parts.subject_der))
        {
            continue;
        }
        verifyCertSignature(last_parts, anchor_der) catch continue;
        return;
    }
    return error.UnknownCa;
}

fn verifyIssuedBy(child_der: []const u8, issuer_der: []const u8) Error!void {
    const child = try extractCertParts(child_der);
    const issuer = try extractCertParts(issuer_der);
    if (!std.mem.eql(u8, child.issuer_der, issuer.subject_der)) return error.BadCertificate;
    try verifyCertSignature(child, issuer_der);
}

fn verifyCertSignature(cert: CertParts, issuer_der: []const u8) Error!void {
    const issuer = try extractCertParts(issuer_der);
    const key = try parsePublicKeyFromSpki(issuer.spki_der);
    if (oidEq(cert.signature_algorithm_oid, &oid_ecdsa_sha256)) {
        try verifySignatureScheme(key, .ecdsa_secp256r1_sha256, cert.tbs_der, cert.signature);
    } else if (oidEq(cert.signature_algorithm_oid, &oid_sha256_rsa)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(cert.tbs_der, &digest, .{});
        if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, cert.signature)) return error.BadSignature;
    } else if (oidEq(cert.signature_algorithm_oid, &oid_rsassa_pss)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(cert.tbs_der, &digest, .{});
        if (!rsa_verify.verifyPss(pk, .sha256, &digest, cert.signature, 32)) return error.BadSignature;
    } else if (oidEq(cert.signature_algorithm_oid, &oid_ed25519)) {
        try verifySignatureScheme(key, .ed25519, cert.tbs_der, cert.signature);
    } else {
        return error.UnsupportedSignatureScheme;
    }
}

fn dnsNameMatchesCert(server_name: []const u8, cert: x509.Certificate) bool {
    var i: usize = 0;
    while (i < cert.san_dns_count) : (i += 1) {
        if (dnsPatternMatches(cert.san_dns[i], server_name)) return true;
    }
    return false;
}

fn dnsPatternMatches(pattern: []const u8, name: []const u8) bool {
    if (asciiEqlIgnoreCase(pattern, name)) return true;
    if (pattern.len < 3 or pattern[0] != '*' or pattern[1] != '.') return false;
    const suffix = pattern[1..];
    if (!asciiEndsWithIgnoreCase(name, suffix)) return false;
    const prefix = name[0 .. name.len - suffix.len];
    return prefix.len != 0 and std.mem.indexOfScalar(u8, prefix, '.') == null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn asciiEndsWithIgnoreCase(name: []const u8, suffix: []const u8) bool {
    if (name.len < suffix.len) return false;
    return asciiEqlIgnoreCase(name[name.len - suffix.len ..], suffix);
}

fn extractCertParts(der: []const u8) Error!CertParts {
    _ = try x509_verify.linkInfo(der);
    var top = x509.DerReader.init(der);
    const cert_seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(x509.Tag.sequence);
    const sig_alg = try body.readExpected(x509.Tag.sequence);
    const signature = try body.readExpected(x509.Tag.bit_string);
    try body.expectEmpty();

    var tbs_reader = try body.child(tbs);
    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == x509.Tag.context_0_constructed) {
        _ = try tbs_reader.readTlv();
    }
    _ = try tbs_reader.readExpected(x509.Tag.integer);
    _ = try tbs_reader.readExpected(x509.Tag.sequence);
    const issuer = try tbs_reader.readExpected(x509.Tag.sequence);
    _ = try tbs_reader.readExpected(x509.Tag.sequence);
    const subject = try tbs_reader.readExpected(x509.Tag.sequence);
    const spki = try tbs_reader.readExpected(x509.Tag.sequence);

    return .{
        .tbs_der = tbs.raw,
        .signature_algorithm_oid = try algorithmOid(body, sig_alg),
        .signature = try bitStringBytes(signature),
        .issuer_der = issuer.raw,
        .subject_der = subject.raw,
        .spki_der = spki.raw,
    };
}

fn parsePublicKeyFromSpki(spki_der: []const u8) Error!LeafPublicKey {
    var top = x509.DerReader.init(spki_der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(x509.Tag.sequence);
    const key_bits = try spki.readExpected(x509.Tag.bit_string);
    try spki.expectEmpty();
    const alg = try parseSpkiAlgorithm(spki, alg_seq);
    const key_bytes = try bitStringBytes(key_bits);
    if (oidEq(alg.oid, &oid_rsa_encryption)) {
        var r = x509.DerReader.init(key_bytes);
        const rsa_seq = try r.readExpected(x509.Tag.sequence);
        try r.expectEmpty();
        var body = try r.child(rsa_seq);
        const n = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        const e = try positiveIntegerBytes(try body.readExpected(x509.Tag.integer));
        try body.expectEmpty();
        return .{ .rsa = .{ .n = n, .e = e } };
    }
    if (oidEq(alg.oid, &oid_ec_public_key)) {
        if (alg.params == null or !oidEq(alg.params.?, &oid_prime256v1)) return error.UnsupportedPublicKey;
        return .{ .ecdsa_p256 = try ecdsa_p256.parsePublicKeySec1(key_bytes) };
    }
    if (oidEq(alg.oid, &oid_ed25519)) {
        if (key_bytes.len != sign.public_key_len) return error.UnsupportedPublicKey;
        var pk: sign.PublicKey = undefined;
        @memcpy(&pk, key_bytes);
        return .{ .ed25519 = pk };
    }
    return error.UnsupportedPublicKey;
}

const SpkiAlgorithm = struct {
    oid: []const u8,
    params: ?[]const u8,
};

fn parseSpkiAlgorithm(parent: x509.DerReader, seq_tlv: x509.Tlv) Error!SpkiAlgorithm {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) {
        const p = try r.readTlv();
        if (p.tag == x509.Tag.oid) params = p.value;
    }
    try r.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

fn algorithmOid(parent: x509.DerReader, seq_tlv: x509.Tlv) Error![]const u8 {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    while (r.hasRemaining()) _ = try r.readTlv();
    return oid.value;
}

fn bitStringBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.BadCertificate;
    if (tlv.value[0] != 0) return error.BadCertificate;
    return tlv.value[1..];
}

fn positiveIntegerBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.tag != x509.Tag.integer or tlv.value.len == 0) return error.BadCertificate;
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..];
    if (v.len == 0 or v[0] & 0x80 != 0) return error.BadCertificate;
    return v;
}

fn oidEq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const oid_rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
const oid_sha256_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
const oid_rsassa_pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const p: *volatile u8 = @ptrCast(b);
        p.* = 0;
    }
}

test "ClientHello record carries SNI, TLS 1.3, suites, and key shares" {
    // Arrange
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();

    // Act
    const record = try client.start();
    defer allocator.free(record);

    // Assert
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls_record.ContentType.handshake)), record[0]);
    try std.testing.expectEqual(.found, std.meta.activeTag(sni.extract(record)));
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    try std.testing.expectEqual(HandshakeType.client_hello, ch.typ);
    const ext_block = clientHelloExtensions(ch.body).?;
    var ext_it = tls_extension.Iterator.init(ext_block);
    var offers_tls13 = false;
    while (try ext_it.next()) |ext| {
        if (ext.typed() == .supported_versions) {
            offers_tls13 = tls_supported_versions.clientOffers(ext.data, tls_supported_versions.tls13);
        }
    }
    try std.testing.expect(offers_tls13);
}

test "DNS wildcard matching is single-label only" {
    // Arrange
    const pattern = "*.example.com";

    // Act / Assert
    try std.testing.expect(dnsPatternMatches(pattern, "www.example.com"));
    try std.testing.expect(!dnsPatternMatches(pattern, "example.com"));
    try std.testing.expect(!dnsPatternMatches(pattern, "a.b.example.com"));
}

test "Finished verify detects tampering" {
    // Arrange
    const base = [_]u8{0x11} ** tls_finished.mac_len;
    const transcript = [_]u8{0x22} ** tls_finished.mac_len;
    var mac = tls_finished.verifyData(base, transcript);

    // Act
    const ok = tls_finished.verify(base, transcript, &mac);
    mac[0] ^= 1;
    const tampered = tls_finished.verify(base, transcript, &mac);

    // Assert
    try std.testing.expect(ok);
    try std.testing.expect(!tampered);
}

test "application record seals and opens with AES-128-GCM" {
    // Arrange
    const allocator = std.testing.allocator;
    var keys = TrafficKeys{};
    keys.key[0..Aes128Gcm.key_length].* = [_]u8{0x42} ** Aes128Gcm.key_length;
    keys.iv = [_]u8{0x24} ** 12;
    const msg = "GET / HTTP/1.1\r\n\r\n";

    // Act
    const record = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &keys, 0, .application_data, msg);
    defer allocator.free(record);
    const opened = try openRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &keys, 0, record);
    defer allocator.free(opened.content);

    // Assert
    try std.testing.expectEqual(tls_record.ContentType.application_data, opened.content_type);
    try std.testing.expectEqualSlices(u8, msg, opened.content);
}

test "decryptApp skips post-handshake handshake records (NewSessionTicket)" {
    // Arrange: a connected client with known server app keys.
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();
    client.state = .connected;
    client.selected_suite = .tls_aes_128_gcm_sha256;
    client.server_app_keys.key[0..Aes128Gcm.key_length].* = [_]u8{0x5A} ** Aes128Gcm.key_length;
    client.server_app_keys.iv = [_]u8{0xA5} ** 12;

    // A NewSessionTicket arrives first (seq 0), then real application data (seq 1).
    const ticket = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 0, .handshake, "\x04\x00\x00\x00");
    defer allocator.free(ticket);
    const app = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 1, .application_data, "HTTP/1.1 200 OK");
    defer allocator.free(app);

    // Act / Assert
    try std.testing.expectEqual(AppRead.control, try client.decryptApp(ticket));
    const got = try client.decryptApp(app);
    defer allocator.free(got.application_data);
    try std.testing.expectEqualSlices(u8, "HTTP/1.1 200 OK", got.application_data);
}

fn clientHelloExtensions(body: []const u8) ?[]const u8 {
    var c = Cursor.init(body);
    _ = c.take(2) catch return null;
    _ = c.take(32) catch return null;
    _ = c.take(c.readU8() catch return null) catch return null;
    _ = c.take(c.readU16() catch return null) catch return null;
    _ = c.take(c.readU8() catch return null) catch return null;
    return c.take(c.readU16() catch return null) catch return null;
}

test {
    std.testing.refAllDecls(@This());
}
