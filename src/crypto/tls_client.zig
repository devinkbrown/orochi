// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socketless TLS 1.3 client handshake state machine for outbound HTTPS.
//!
//! The caller owns transport I/O: call `start()` to get the ClientHello record,
//! pass received bytes to `feed()`, send any returned bytes, then use
//! `encrypt()` / `decrypt()` once `handshakeDone()` is true.

const std = @import("std");
const builtin = @import("builtin");

const hkdf_tls13 = @import("hkdf_tls13.zig");
const tls_resumption = @import("tls_resumption.zig");
const tls_record = @import("tls_record.zig");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const ocsp = @import("ocsp.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_verify = @import("rsa_verify.zig");
const rsa_sign = @import("rsa_sign.zig");
const sign = @import("sign.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const kx = @import("kx.zig");

const tls_supported_versions = @import("../proto/tls_supported_versions.zig");
const tls_keyshare = @import("../proto/tls_keyshare.zig");
const tls_signature_scheme = @import("../proto/tls_signature_scheme.zig");
const tls_extension = @import("../proto/tls_extension.zig");
const supported_groups = @import("../proto/supported_groups.zig");
const cert_compression = @import("../proto/cert_compression.zig");
const sni = @import("../proto/sni.zig");
const tls_alert = @import("../proto/tls_alert.zig");
const tls_finished = @import("../proto/tls_finished.zig");
const tls_psk = @import("../proto/tls_psk.zig");
const tls_session_ticket = @import("../proto/tls_session_ticket.zig");
const tls_alpn = @import("../proto/tls_alpn.zig");
const toml = @import("../proto/toml.zig");

const Allocator = std.mem.Allocator;
const Sha256 = hkdf_tls13.Sha256;
const Sha384 = hkdf_tls13.Sha384;
/// Largest TLS 1.3 transcript-hash / traffic-secret length we handle (SHA-384).
const max_hash_len = Sha384.hash_len;

/// Opt-in handshake tracing (set by out-of-band tools like acme_runner).
pub var debug_log: bool = false;

/// Overlay `[tls].debug_log` onto the module-level tracing flag. Absent key
/// leaves the current value unchanged (behavior preserved).
pub fn applyToml(doc: *const toml.Document) void {
    if (doc.getBool("tls.debug_log")) |v| debug_log = v;
}
fn dbg(comptime fmt: []const u8, args: anytype) void {
    if (debug_log) std.debug.print("tls: " ++ fmt ++ "\n", args);
}
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const HashAlg = enum { sha256, sha384 };

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
    CertificateRevoked,
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
    tls_alert.ParseError || rsa_verify.Error || sign.VerifyError ||
    tls_psk.Error || tls_session_ticket.ParseError || tls_session_ticket.EncodeError ||
    tls_resumption.Error || ocsp.Error || cert_compression.Error;

pub const Options = struct {
    server_name: []const u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8 = &.{},
    /// Current wall-clock time (Unix seconds) used to reject expired and
    /// not-yet-valid certificates in the chain. When null the validity window is
    /// not checked — callers that can supply a trustworthy clock (the live HTTPS
    /// and ACME paths) should always set it; loopback tests with fixed fixtures
    /// leave it null.
    now_unix_seconds: ?i64 = null,
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
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    compressed_certificate = 25, // RFC 8879
    _,
};

const KeyUpdateRequest = enum(u8) {
    not_requested = 0,
    requested = 1,
};

const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,

    fn fromWire(v: u16) Error!CipherSuite {
        return switch (v) {
            0x1301 => .tls_aes_128_gcm_sha256,
            0x1302 => .tls_aes_256_gcm_sha384,
            0x1303 => .tls_chacha20_poly1305_sha256,
            else => error.UnsupportedCipherSuite,
        };
    }

    fn keyLen(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => Aes128Gcm.key_length,
            .tls_aes_256_gcm_sha384 => Aes256Gcm.key_length,
            .tls_chacha20_poly1305_sha256 => ChaCha20Poly1305.key_length,
        };
    }

    fn tagLen(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => Aes128Gcm.tag_length,
            .tls_aes_256_gcm_sha384 => Aes256Gcm.tag_length,
            .tls_chacha20_poly1305_sha256 => ChaCha20Poly1305.tag_length,
        };
    }

    fn hashAlg(self: CipherSuite) HashAlg {
        return switch (self) {
            .tls_aes_256_gcm_sha384 => .sha384,
            else => .sha256,
        };
    }

    fn hashLen(self: CipherSuite) usize {
        return switch (self.hashAlg()) {
            .sha256 => Sha256.hash_len,
            .sha384 => Sha384.hash_len,
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

/// Test-only client-certificate signing key (mutual TLS loopback tests).
const ClientCertKey = union(enum) {
    ed25519: sign.KeyPair,
    ecdsa_p256: ecdsa_p256.KeyPair,
    rsa: rsa_sign.PrivateKey,
};

const LeafPublicKey = union(enum) {
    rsa: rsa_verify.PublicKey,
    ecdsa_p256: ecdsa_p256.PublicKey,
    ecdsa_p384: EcdsaP384.PublicKey,
    ed25519: sign.PublicKey,
};

const CertParts = struct {
    tbs_der: []const u8,
    signature_algorithm_oid: []const u8,
    /// Raw `parameters` TLV of the outer signatureAlgorithm, or `null` if absent.
    /// Needed for RSASSA-PSS, whose hash/MGF/salt live here, not in the OID.
    signature_algorithm_params: ?[]const u8,
    signature: []const u8,
    issuer_der: []const u8,
    subject_der: []const u8,
    spki_der: []const u8,
};

const ResumeOffer = struct {
    ticket: []u8,
    ticket_age_add: u32,
    ticket_lifetime: u32,
    ticket_age_ms: u64,
    suite: CipherSuite,
    psk: [max_hash_len]u8,
    psk_len: usize,
    max_early_data_size: u32,

    fn wipe(self: *ResumeOffer, allocator: Allocator) void {
        allocator.free(self.ticket);
        secureZero(&self.psk);
        self.* = undefined;
    }
};

pub const Client = struct {
    allocator: Allocator,
    server_name: []u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8,

    state: State = .idle,
    /// Wall-clock time (Unix seconds) for certificate validity checks, or null to
    /// skip the validity window (see `Options.now_unix_seconds`).
    verify_time: ?i64 = null,
    x25519_pair: kx.X25519Kx.KeyPair,
    p256_pair: ecdh_p256.KeyPair,
    /// Ephemeral X25519MLKEM768 keypair (its own x25519 half + an ML-KEM-768
    /// keypair) backing the post-quantum hybrid key_share we offer. Distinct from
    /// `x25519_pair` (the classical x25519 share) so the two shares never share
    /// an ephemeral.
    hybrid_pair: kx.HybridKx.KeyPair,
    legacy_session_id: [32]u8,
    /// ClientHello random, generated once. RFC 8446 §4.1.2 requires the second
    /// ClientHello (after a HelloRetryRequest) to carry the same random.
    client_random: [32]u8,
    selected_suite: ?CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    /// Owned storage for `selected_alpn`: the negotiated protocol is read from the
    /// EncryptedExtensions body in `hs_plain`, which is consumed after the message,
    /// so the borrowed slice would dangle for any post-handshake reader. Copy it.
    selected_alpn_buf: [256]u8 = undefined,
    leaf_key: ?LeafPublicKey = null,
    /// Owned storage for the leaf RSA key's modulus/exponent. The parsed key
    /// borrows the certificate SPKI bytes, which live in `hs_plain` and are
    /// consumed (shifted) after the Certificate message — so an RSA key would
    /// dangle by the time the server CertificateVerify is verified. We copy
    /// n/e here and re-point the key. (EC/Ed25519 keys are value types.)
    leaf_rsa_n: [rsa_verify.max_bytes]u8 = undefined,
    leaf_rsa_e: [16]u8 = undefined,
    last_alert: ?tls_alert.Alert = null,

    /// HelloRetryRequest state. `hrr_seen` guards against a second HRR (fatal per
    /// RFC 8446). `cookie` (when present) is echoed in the second ClientHello;
    /// it borrows `cookie_buf` (copied out of the consumed record). `retry_hello`
    /// holds the second ClientHello bytes to send, owned until `feed` returns them.
    hrr_seen: bool = false,
    cookie: ?[]const u8 = null,
    cookie_buf: [512]u8 = undefined,
    retry_hello: ?[]u8 = null,
    /// Group a HelloRetryRequest asked us to retry with. When set, the second
    /// ClientHello offers exactly one key_share — for this group (RFC 8446
    /// §4.1.2). Null on the first ClientHello.
    retry_key_share_group: ?supported_groups.NamedGroup = null,

    /// Post-handshake records the client must send back (a KeyUpdate response
    /// when the peer requested one). Drained by the caller via `takePendingSend`.
    post_handshake_send: std.ArrayList(u8) = .empty,

    // --- Test-only client-certificate support (mutual TLS) ---
    // Existing behavior is fully preserved when no client cert is configured:
    // an incoming CertificateRequest is otherwise ignored and no client
    // Certificate/CertificateVerify is ever sent. These are exercised only by
    // the tls_server mTLS loopback tests, never by the production HTTPS path.
    /// Set true once the server's CertificateRequest is seen.
    cert_requested: bool = false,
    /// RFC 8879 diagnostic: set true when the server's certificate arrived as a
    /// CompressedCertificate that we inflated (rather than a plain Certificate).
    received_compressed_cert: bool = false,
    /// Borrowed client leaf DER to present, or null to present an empty
    /// Certificate (decline). Only meaningful when the server requested a cert.
    client_cert_der: ?[]const u8 = null,
    /// Key pair matching `client_cert_der`'s SPKI, used to sign the client
    /// CertificateVerify (Ed25519 or ECDSA P-256).
    client_key_pair: ?ClientCertKey = null,
    /// RFC 8879: when true, advertise `compress_certificate` (zlib) and decode a
    /// server's CompressedCertificate. Default false ⇒ the ClientHello is
    /// byte-identical and no compressed-cert decode path is reachable, keeping
    /// the outbound (ACME) TLS surface unchanged until explicitly opted in —
    /// symmetric with the server's `enable_cert_compression`.
    offer_cert_compression: bool = false,
    /// When true, the server certificate's chain-to-trust-anchor and DNS-name
    /// checks are skipped (the leaf key is still parsed so the server
    /// CertificateVerify signature is verified). Used only by the tls_server
    /// mTLS loopback tests, whose x509_selfsign leaves carry a CN but no SAN.
    skip_cert_verify_for_test: bool = false,
    /// Test-only: offer secp256r1 as the sole key-exchange group, so the server's
    /// P-256 fallback path can be exercised over the loopback.
    force_p256_only_for_test: bool = false,
    /// Test-only: offer X25519MLKEM768 as the sole key-exchange group, so the
    /// post-quantum hybrid encaps/decaps path is exercised over the loopback (the
    /// server otherwise prefers classical x25519).
    force_hybrid_only_for_test: bool = false,
    /// Test-only: advertise the full supported_groups but send an EMPTY key_share
    /// list, forcing the server to answer with a HelloRetryRequest. The client
    /// then retries with exactly the requested group's share.
    force_no_shares_for_test: bool = false,
    /// Test-only: offer TLS_AES_256_GCM_SHA384 as the sole cipher suite, so the
    /// SHA-384 key schedule is exercised end-to-end over the loopback.
    force_aes256_only_for_test: bool = false,

    /// Optional PSK resumption offer loaded from a serialized session ticket.
    resume_offer: ?ResumeOffer = null,
    /// True when the server echoes `pre_shared_key(selected_identity = 0)` in
    /// ServerHello and the certificate-auth flight is therefore omitted.
    psk_accepted: bool = false,
    /// Caller-owned 0-RTT payload copied by `setEarlyData`, or null when this
    /// resumption attempt is a normal 1-RTT PSK-DHE handshake.
    early_data: ?[]u8 = null,
    /// Null until EncryptedExtensions is processed, then the server's decision
    /// for this ClientHello's `early_data` offer.
    early_data_accepted: ?bool = null,
    /// Latest captured serialized session ticket. Ownership transfers through
    /// `takeSessionTicket`.
    captured_session_ticket: ?[]u8 = null,

    transcript: std.ArrayList(u8) = .empty,
    recv_buf: std.ArrayList(u8) = .empty,
    hs_plain: std.ArrayList(u8) = .empty,

    // Traffic secrets are stored at the maximum hash length (SHA-384); only the
    // first `selected_suite.hashLen()` bytes are live for a given connection.
    early_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    handshake_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    master_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    exporter_master_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    exporter_master_secret_ready: bool = false,
    resumption_master_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    client_hs_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    server_hs_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    client_app_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    server_app_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    client_hs_keys: TrafficKeys = .{},
    server_hs_keys: TrafficKeys = .{},
    client_early_keys: TrafficKeys = .{},
    client_app_keys: TrafficKeys = .{},
    server_app_keys: TrafficKeys = .{},
    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,
    early_write_seq: u64 = 0,
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,
    /// RFC 8449 record_size_limit advertised by the server (max TLSInnerPlaintext
    /// it accepts). Default 2^14+1 = unrestricted; outbound records are fragmented
    /// to honor a smaller value.
    peer_record_size_limit: usize = tls_record.max_plaintext_len + 1,

    pub fn init(allocator: Allocator, options: Options) Error!Client {
        if (options.server_name.len == 0) return error.BadHandshake;
        var seed: [kx.X25519Kx.seed_len]u8 = undefined;
        try osEntropy(&seed);
        var hy_seed: [kx.HybridKx.seed_len]u8 = undefined;
        try osEntropy(&hy_seed);
        defer secureZero(&hy_seed);
        var session_id: [32]u8 = undefined;
        try osEntropy(&session_id);
        var random: [32]u8 = undefined;
        try osEntropy(&random);

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
            .verify_time = options.now_unix_seconds,
            .x25519_pair = try kx.X25519Kx.generateDeterministic(seed),
            .p256_pair = try ecdh_p256.generate(),
            .hybrid_pair = try kx.HybridKx.generateDeterministic(hy_seed),
            .legacy_session_id = session_id,
            .client_random = random,
        };
    }

    pub fn deinit(self: *Client) void {
        self.x25519_pair.wipe();
        self.hybrid_pair.wipe();
        secureZero(&self.p256_pair.secret);
        secureZero(&self.legacy_session_id);
        secureZero(&self.early_secret);
        secureZero(&self.handshake_secret);
        secureZero(&self.master_secret);
        secureZero(&self.exporter_master_secret);
        secureZero(&self.resumption_master_secret);
        secureZero(&self.client_hs_secret);
        secureZero(&self.server_hs_secret);
        secureZero(&self.client_app_secret);
        secureZero(&self.server_app_secret);
        self.client_hs_keys.wipe();
        self.server_hs_keys.wipe();
        self.client_early_keys.wipe();
        self.client_app_keys.wipe();
        self.server_app_keys.wipe();
        self.transcript.deinit(self.allocator);
        self.recv_buf.deinit(self.allocator);
        self.hs_plain.deinit(self.allocator);
        self.post_handshake_send.deinit(self.allocator);
        if (self.early_data) |data| self.allocator.free(data);
        if (self.retry_hello) |r| self.allocator.free(r);
        if (self.resume_offer) |*offer| offer.wipe(self.allocator);
        if (self.captured_session_ticket) |ticket| self.allocator.free(ticket);
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
        const ch_record = try writePlainRecord(self.allocator, .handshake, handshake.items);
        if (self.early_data == null) return ch_record;
        defer self.allocator.free(ch_record);

        try self.deriveClientEarlyTrafficKeys();
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, ch_record);

        const early = self.early_data.?;
        const early_record = try sealRecordAlloc(
            self.allocator,
            self.resume_offer.?.suite,
            &self.client_early_keys,
            self.early_write_seq,
            .application_data,
            early,
        );
        defer self.allocator.free(early_record);
        self.early_write_seq += 1;
        try out.appendSlice(self.allocator, early_record);

        var eoed: std.ArrayList(u8) = .empty;
        defer eoed.deinit(self.allocator);
        try writeHandshake(self.allocator, &eoed, .end_of_early_data, "");
        const eoed_record = try sealRecordAlloc(
            self.allocator,
            self.resume_offer.?.suite,
            &self.client_early_keys,
            self.early_write_seq,
            .handshake,
            eoed.items,
        );
        defer self.allocator.free(eoed_record);
        self.early_write_seq += 1;
        try out.appendSlice(self.allocator, eoed_record);
        return out.toOwnedSlice(self.allocator);
    }

    pub fn feed(self: *Client, received: []const u8) Error!FeedResult {
        if (self.state == .idle or self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);

        if (self.state == .wait_server_hello) {
            switch (try self.tryConsumeServerHello()) {
                .need_more => return .need_more,
                .retry => {
                    // Send ClientHello2; keep waiting for the real ServerHello.
                    const reply = self.retry_hello.?;
                    self.retry_hello = null;
                    return .{ .bytes_to_send = reply };
                },
                .proceed => {},
            }
        }

        if (try self.tryConsumeServerFlight()) |reply| {
            return .{ .bytes_to_send = reply };
        }
        return .need_more;
    }

    pub fn handshakeDone(self: *const Client) bool {
        return self.state == .connected;
    }

    /// RFC 8446 section 7.5 TLS exporter. Valid only after the handshake
    /// reaches connected state.
    pub fn exportKeyingMaterial(self: *const Client, label: []const u8, context: []const u8, out: []u8) Error!void {
        if (self.state != .connected) return error.BadState;
        if (!self.exporter_master_secret_ready) return error.BadState;
        switch (self.hashAlg()) {
            .sha256 => try self.exportKeyingMaterialT(Sha256, label, context, out),
            .sha384 => try self.exportKeyingMaterialT(Sha384, label, context, out),
        }
    }

    /// RFC 9266 tls-exporter channel binding for SCRAM-SHA-*-PLUS.
    pub fn channelBindingTlsExporter(self: *const Client, out: *[32]u8) Error!void {
        try self.exportKeyingMaterial("EXPORTER-Channel-Binding", "", out[0..]);
    }

    /// Load a serialized TLS 1.3 session ticket previously returned by
    /// `takeSessionTicket`. `ticket_age_ms` is the caller's elapsed wall-clock
    /// age for the ticket and is folded into `obfuscated_ticket_age`.
    pub fn setSessionTicket(self: *Client, serialized: []const u8, ticket_age_ms: u64) Error!void {
        const decoded = try tls_resumption.decodeStoredSession(serialized);
        const suite = try CipherSuite.fromWire(decoded.suite);
        if (decoded.psk.len != suite.hashLen()) return error.BadSession;
        if (self.resume_offer) |*old| {
            old.wipe(self.allocator);
            self.resume_offer = null;
        }
        const ticket = try self.allocator.dupe(u8, decoded.ticket);
        errdefer self.allocator.free(ticket);
        var psk: [max_hash_len]u8 = [_]u8{0} ** max_hash_len;
        @memcpy(psk[0..decoded.psk.len], decoded.psk);
        self.resume_offer = .{
            .ticket = ticket,
            .ticket_age_add = decoded.ticket_age_add,
            .ticket_lifetime = decoded.ticket_lifetime,
            .ticket_age_ms = ticket_age_ms,
            .suite = suite,
            .psk = psk,
            .psk_len = decoded.psk.len,
            .max_early_data_size = decoded.max_early_data_size,
        };
    }

    /// Queue TLS 1.3 0-RTT early application data for the next `start()`.
    ///
    /// This is deliberately opt-in: it is valid only before the handshake
    /// starts, only when a resumption session with a non-zero
    /// `max_early_data_size` is loaded, and only when `bytes` fits that limit.
    /// Anti-replay policy is not enforced in this socketless TLS module; callers
    /// must layer single-use tickets or a replay cache above it before sending
    /// non-idempotent data.
    pub fn setEarlyData(self: *Client, bytes: []const u8) Error!void {
        if (self.state != .idle) return error.BadState;
        const offer = self.resume_offer orelse return error.BadState;
        if (offer.max_early_data_size == 0 or bytes.len > offer.max_early_data_size) return error.BadHandshake;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        if (self.early_data) |old| self.allocator.free(old);
        self.early_data = copy;
        self.early_data_accepted = null;
    }

    /// Return the server's 0-RTT decision after EncryptedExtensions is parsed.
    /// Null means this handshake has not reached EncryptedExtensions yet.
    pub fn earlyDataAccepted(self: *const Client) ?bool {
        return self.early_data_accepted;
    }

    /// Take ownership of the newest captured resumable session ticket, if a
    /// post-handshake NewSessionTicket has been received and parsed.
    pub fn takeSessionTicket(self: *Client) ?[]u8 {
        const ticket = self.captured_session_ticket orelse return null;
        self.captured_session_ticket = null;
        return ticket;
    }

    /// Test-only: configure a client certificate to present in response to a
    /// server CertificateRequest. `der` and `key_pair` are borrowed. Without
    /// this call (or `declineClientCertForTest`) the client never sends a
    /// client Certificate, preserving the production server-only-auth path.
    pub fn setClientCertForTest(self: *Client, der: []const u8, key_pair: sign.KeyPair) void {
        self.client_cert_der = der;
        self.client_key_pair = .{ .ed25519 = key_pair };
    }

    /// Test-only: like `setClientCertForTest` but for an ECDSA P-256 client
    /// certificate; CertificateVerify is signed with ecdsa_secp256r1_sha256.
    pub fn setClientCertEcdsaP256ForTest(self: *Client, der: []const u8, key_pair: ecdsa_p256.KeyPair) void {
        self.client_cert_der = der;
        self.client_key_pair = .{ .ecdsa_p256 = key_pair };
    }

    /// Test-only: like `setClientCertForTest` but for an RSA client certificate;
    /// CertificateVerify is signed with rsa_pss_rsae_sha256 (TLS 1.3's only
    /// RSA scheme). `der` and `key` are borrowed.
    pub fn setClientCertRsaForTest(self: *Client, der: []const u8, key: rsa_sign.PrivateKey) void {
        self.client_cert_der = der;
        self.client_key_pair = .{ .rsa = key };
    }

    /// Test-only: respond to a server CertificateRequest with an empty
    /// Certificate (decline client auth). The client still completes the
    /// handshake; no CertificateVerify is sent. This is the default behavior
    /// when no client cert is configured; the explicit call documents intent.
    pub fn declineClientCertForTest(self: *Client) void {
        self.client_cert_der = null;
        self.client_key_pair = null;
    }

    /// Test-only: skip the server-certificate chain and DNS-name checks. The
    /// leaf public key is still parsed and the server CertificateVerify is
    /// still verified. Lets the mTLS loopback use CN-only self-signed leaves.
    pub fn skipServerCertVerifyForTest(self: *Client) void {
        self.skip_cert_verify_for_test = true;
    }

    /// Test-only: offer secp256r1 as the sole supported group + key share.
    pub fn offerOnlyP256ForTest(self: *Client) void {
        self.force_p256_only_for_test = true;
    }

    /// Test-only: offer X25519MLKEM768 as the sole supported group + key share.
    pub fn offerOnlyHybridForTest(self: *Client) void {
        self.force_hybrid_only_for_test = true;
    }

    /// Test-only: offer TLS_AES_256_GCM_SHA384 as the sole cipher suite.
    pub fn offerOnlyAes256ForTest(self: *Client) void {
        self.force_aes256_only_for_test = true;
    }

    /// Test-only: advertise the full group set but send no key_shares, forcing the
    /// server to respond with a HelloRetryRequest.
    pub fn offerNoSharesForTest(self: *Client) void {
        self.force_no_shares_for_test = true;
    }

    /// Opt into RFC 8879 certificate compression: advertise `compress_certificate`
    /// (zlib) and decode a server's CompressedCertificate under the bomb guard.
    pub fn offerCertCompression(self: *Client) void {
        self.offer_cert_compression = true;
    }

    /// Test-only: emit a post-handshake KeyUpdate — a TLS 1.3 *control* record
    /// (inner content_type = handshake). Drain it via `takePendingSend`. Used to
    /// exercise how a kTLS-RX peer surfaces a non-application-data record.
    pub fn sendKeyUpdateForTest(self: *Client) Error!void {
        try self.sendKeyUpdate(.not_requested);
    }

    /// Groups this client can complete a key exchange for. Kept in sync with the
    /// supported_groups advertisement and the key_share builder in writeClientHello.
    fn supportsGroup(self: *const Client, g: supported_groups.NamedGroup) bool {
        _ = self;
        return switch (g) {
            .x25519, .secp256r1, .x25519mlkem768 => true,
            else => false,
        };
    }

    /// Whether ClientHello1 already carried a key_share for `g` — an HRR asking us
    /// to retry with a group we already shared changes nothing and is illegal.
    fn offeredShareFor(self: *const Client, g: supported_groups.NamedGroup) bool {
        if (self.force_no_shares_for_test) return false;
        if (self.force_p256_only_for_test) return g == .secp256r1;
        if (self.force_hybrid_only_for_test) return g == .x25519mlkem768;
        return switch (g) {
            .x25519, .secp256r1, .x25519mlkem768 => true,
            else => false,
        };
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
        const limit = tls_record.recordContentLimit(self.peer_record_size_limit);
        if (appdata.len <= limit) {
            const out = try sealRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_write_seq, .application_data, appdata);
            self.app_write_seq += 1;
            return out;
        }
        // RFC 8449: fragment application data to the server's smaller record limit,
        // one record per fragment, concatenated (seq bumped per record).
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        var off: usize = 0;
        while (off < appdata.len) {
            const n = @min(limit, appdata.len - off);
            const rec = try sealRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_write_seq, .application_data, appdata[off .. off + n]);
            defer self.allocator.free(rec);
            try buf.appendSlice(self.allocator, rec);
            self.app_write_seq += 1;
            off += n;
        }
        return buf.toOwnedSlice(self.allocator);
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
        if (opened.content_type == .handshake) {
            // On error the function-scoped errdefer frees opened.content; on
            // success free it here (no application bytes to return).
            try self.handlePostHandshake(opened.content);
            self.allocator.free(opened.content);
            return self.allocator.alloc(u8, 0);
        }
        if (opened.content_type != .application_data) return error.BadRecord;
        return opened.content;
    }

    /// Post-handshake-aware read of one decrypted record. Returns the decrypted
    /// application bytes, or `.control` for post-handshake handshake records
    /// (NewSessionTicket is ignored; a KeyUpdate rotates the server→client keys
    /// and, when the peer set update_requested, queues our own KeyUpdate reply in
    /// `post_handshake_send` — flush it with `takePendingSend`). Alerts raise
    /// `error.TlsAlert`.
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
                defer self.allocator.free(opened.content);
                try self.handlePostHandshake(opened.content);
                return .control;
            },
            else => {
                self.allocator.free(opened.content);
                return error.BadRecord;
            },
        }
    }

    /// Take ownership of any queued post-handshake bytes the caller must write to
    /// the socket (currently a KeyUpdate reply). Returns null when nothing is
    /// queued; otherwise the caller owns and must free the returned slice.
    pub fn takePendingSend(self: *Client) Error!?[]u8 {
        if (self.post_handshake_send.items.len == 0) return null;
        return try self.post_handshake_send.toOwnedSlice(self.allocator);
    }

    /// Process a decrypted post-handshake handshake fragment. NewSessionTicket
    /// and other informational messages are ignored; a KeyUpdate rotates the
    /// server→client application keys and, when the peer requested an update,
    /// queues our own KeyUpdate(update_not_requested) reply and rotates the
    /// client→server keys (RFC 8446 §4.6.3). The fragment may carry more than one
    /// handshake message.
    fn handlePostHandshake(self: *Client, fragment: []const u8) Error!void {
        var off: usize = 0;
        while (parseHandshakeMaybe(fragment, &off)) |msg| {
            if (msg.typ == .key_update) {
                if (msg.body.len != 1) return error.BadHandshake;
                const request = msg.body[0];
                if (request != @intFromEnum(KeyUpdateRequest.not_requested) and
                    request != @intFromEnum(KeyUpdateRequest.requested))
                {
                    return error.BadHandshake;
                }
                // Rotate the receive (server) application traffic secret + keys.
                try self.applyKeyUpdate(&self.server_app_secret, &self.server_app_keys);
                self.app_read_seq = 0;
                if (request == @intFromEnum(KeyUpdateRequest.requested)) {
                    try self.sendKeyUpdate(.not_requested);
                }
            } else if (msg.typ == .new_session_ticket) {
                try self.captureNewSessionTicket(msg.body);
            }
            // Other post-handshake messages are ignored.
        }
    }

    fn captureNewSessionTicket(self: *Client, body: []const u8) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        const ticket = try tls_session_ticket.parse(body);
        if (ticket.ticket.len == 0 or ticket.ticket_lifetime == 0) return;
        const max_early_data_size = try parseTicketEarlyDataLimit(ticket.extensions);

        var psk: [max_hash_len]u8 = undefined;
        const psk_len = switch (self.hashAlg()) {
            .sha256 => try self.deriveTicketPskT(Sha256, ticket.ticket_nonce, &psk),
            .sha384 => try self.deriveTicketPskT(Sha384, ticket.ticket_nonce, &psk),
        };
        const serialized = try tls_resumption.encodeStoredSession(self.allocator, .{
            .suite = @intFromEnum(suite),
            .ticket_lifetime = ticket.ticket_lifetime,
            .ticket_age_add = ticket.ticket_age_add,
            .ticket = ticket.ticket,
            .psk = psk[0..psk_len],
            .max_early_data_size = max_early_data_size,
        });
        secureZero(psk[0..psk_len]);
        if (self.captured_session_ticket) |old| self.allocator.free(old);
        self.captured_session_ticket = serialized;
    }

    fn deriveTicketPskT(self: *Client, comptime KS: type, ticket_nonce: []const u8, out: *[max_hash_len]u8) Error!usize {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.resumption_master_secret[0..KS.hash_len]);
        var rms = KS.SecretBytes.init(sk);
        defer rms.wipe();
        try KS.hkdfExpandLabel(&rms, "resumption", ticket_nonce, out[0..KS.hash_len]);
        return KS.hash_len;
    }

    /// Emit a KeyUpdate of our own (encrypted under the *current* send keys),
    /// queue it for the caller, then rotate the client→server application keys so
    /// the next application record uses the new keys (RFC 8446 §4.6.3).
    fn sendKeyUpdate(self: *Client, request: KeyUpdateRequest) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .key_update, &[_]u8{@intFromEnum(request)});
        const record = try sealRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_write_seq, .handshake, hs.items);
        defer self.allocator.free(record);
        self.app_write_seq += 1;
        try self.post_handshake_send.appendSlice(self.allocator, record);
        try self.applyKeyUpdate(&self.client_app_secret, &self.client_app_keys);
        self.app_write_seq = 0;
    }

    /// In-place KeyUpdate of one traffic secret: secret' =
    /// HKDF-Expand-Label(secret, "traffic upd", "", Hash.length); re-derive keys.
    fn applyKeyUpdate(self: *Client, secret: *[max_hash_len]u8, keys: *TrafficKeys) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        switch (self.hashAlg()) {
            .sha256 => try applyKeyUpdateT(Sha256, suite, secret, keys),
            .sha384 => try applyKeyUpdateT(Sha384, suite, secret, keys),
        }
    }

    fn writeClientHello(self: *Client, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);

        try appendU16(self.allocator, &body, tls_record.legacy_record_version);
        // RFC 8446 §4.1.2: a retried ClientHello reuses the same random.
        try body.appendSlice(self.allocator, &self.client_random);

        try body.append(self.allocator, @intCast(self.legacy_session_id.len));
        try body.appendSlice(self.allocator, &self.legacy_session_id);

        if (self.force_aes256_only_for_test) {
            try appendU16(self.allocator, &body, 2);
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384));
        } else {
            try appendU16(self.allocator, &body, 6);
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384));
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256));
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
        }

        try body.append(self.allocator, 1);
        try body.append(self.allocator, 0);

        var ext_storage: [4096]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);

        var sni_buf: [512]u8 = undefined;
        const sni_body = try buildSniBody(&sni_buf, self.server_name);
        try ext_builder.addTyped(.server_name, sni_body);

        var versions_buf: [8]u8 = undefined;
        const versions = try tls_supported_versions.buildClient(&versions_buf, &[_]u16{tls_supported_versions.tls13});
        try ext_builder.addTyped(.supported_versions, versions);

        var groups_buf: [16]u8 = undefined;
        const groups = if (self.force_p256_only_for_test)
            try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{.secp256r1})
        else if (self.force_hybrid_only_for_test)
            try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{.x25519mlkem768})
        else
            // Prefer the post-quantum hybrid, then classical x25519 / P-256.
            try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{ .x25519mlkem768, .x25519, .secp256r1 });
        try ext_builder.addTyped(.supported_groups, groups);

        var sigs_buf: [16]u8 = undefined;
        const sigs = try tls_signature_scheme.build(&sigs_buf, &[_]tls_signature_scheme.SignatureScheme{
            .rsa_pss_rsae_sha256,
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            .ed25519,
            .rsa_pkcs1_sha256,
        });
        try ext_builder.addTyped(.signature_algorithms, sigs);

        // RFC 8449 record_size_limit: advertise the largest TLSInnerPlaintext we
        // accept (the protocol max — our recv path handles full-size records).
        var rsl_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &rsl_buf, tls_record.record_size_limit_max, .big);
        try ext_builder.addTyped(.record_size_limit, &rsl_buf);

        // X25519MLKEM768 client key_share = ml-kem_ek(1184) || x25519_pub(32).
        var hybrid_share: [kx.HybridKx.mlkem_public_len + kx.X25519Kx.public_len]u8 = undefined;
        const hy_pub = self.hybrid_pair.publicShare();
        @memcpy(hybrid_share[0..kx.HybridKx.mlkem_public_len], &hy_pub.mlkem_public_key);
        @memcpy(hybrid_share[kx.HybridKx.mlkem_public_len..], &hy_pub.x25519_public_key);

        // Sized for the hybrid share (1216B) + x25519 (32B) + P-256 (65B) + headers.
        var keyshare_buf: [1400]u8 = undefined;
        const keyshares = if (self.retry_key_share_group) |g|
            // ClientHello2 after a HelloRetryRequest: exactly one share, for the
            // group the server requested (RFC 8446 §4.1.2).
            switch (g) {
                .x25519 => try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                    .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key },
                }),
                .secp256r1 => try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                    .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 },
                }),
                .x25519mlkem768 => try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                    .{ .group = .x25519mlkem768, .key_exchange = &hybrid_share },
                }),
                else => return error.UnsupportedGroup,
            }
        else if (self.force_no_shares_for_test)
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{})
        else if (self.force_p256_only_for_test)
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 },
            })
        else if (self.force_hybrid_only_for_test)
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                .{ .group = .x25519mlkem768, .key_exchange = &hybrid_share },
            })
        else
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                .{ .group = .x25519mlkem768, .key_exchange = &hybrid_share },
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

        // RFC 6066 / RFC 8446 OCSP stapling request:
        // status_type=ocsp(1), empty responder_id_list, empty request_extensions.
        try ext_builder.add(ext_status_request, &[_]u8{ 1, 0, 0, 0, 0 });

        // RFC 8879 certificate compression: advertise the one algorithm we can
        // decode (zlib). algorithms_length=2, then the u16 zlib(1) code point. A
        // server MAY then send a CompressedCertificate; our wait_certificate path
        // inflates it under the mandatory decompression-bomb guard. Opt-in so the
        // outbound TLS surface stays unchanged by default.
        if (self.offer_cert_compression) {
            try ext_builder.addTyped(.compress_certificate, &[_]u8{ 2, 0x00, 0x01 });
        }

        // Echo a HelloRetryRequest cookie in the retried ClientHello. The cookie
        // extension body is opaque cookie<1..2^16-1>: a u16 length then the bytes.
        if (self.cookie) |cookie| {
            var cookie_ext: [514]u8 = undefined;
            std.mem.writeInt(u16, cookie_ext[0..2], @intCast(cookie.len), .big);
            @memcpy(cookie_ext[2..][0..cookie.len], cookie);
            try ext_builder.addTyped(.cookie, cookie_ext[0 .. 2 + cookie.len]);
        }

        var binder_offset: ?usize = null;
        var binder_len: usize = 0;
        var binder_truncated_len: usize = 0;
        if (self.resume_offer) |offer| {
            if (self.early_data != null) {
                var early_body: [0]u8 = .{};
                try ext_builder.addTyped(.early_data, &early_body);
            }
            // RFC 8446 §4.2.9: PSK resumption here always keeps a fresh ECDHE
            // key_share, so advertise only psk_dhe_ke.
            try ext_builder.addTyped(.psk_key_exchange_modes, &[_]u8{ 1, 1 });

            const identity = tls_psk.PskIdentity{
                .identity = offer.ticket,
                .obfuscated_ticket_age = tls_session_ticket.obfuscatedAge(offer.ticket_age_ms, offer.ticket_age_add),
            };
            var zero_binder: [max_hash_len]u8 = [_]u8{0} ** max_hash_len;
            const binders = [_][]const u8{zero_binder[0..offer.psk_len]};
            const psk_ext_data_offset = ext_builder.len + tls_extension.header_len;
            const psk_tmp_len = 2 + (try identity.wireLen()) + 2 + 1 + offer.psk_len;
            const psk_tmp = try self.allocator.alloc(u8, psk_tmp_len);
            defer self.allocator.free(psk_tmp);
            const psk_body = try tls_psk.buildClientPsk(psk_tmp, &[_]tls_psk.PskIdentity{identity}, &binders);
            const binder_list_offset = try tls_psk.binderListOffset(psk_body);
            try ext_builder.addTyped(.pre_shared_key, psk_body);

            const extensions_offset_in_body = body.items.len;
            binder_truncated_len = 4 + extensions_offset_in_body + psk_ext_data_offset + binder_list_offset;
            binder_offset = binder_truncated_len + 2 + 1;
            binder_len = offer.psk_len;
        }

        const extensions = try ext_builder.finish();
        try body.appendSlice(self.allocator, extensions);
        const hs_start = out.items.len;
        try writeHandshake(self.allocator, out, .client_hello, body.items);
        if (binder_offset) |rel| {
            const hs = out.items[hs_start..];
            if (rel + binder_len > hs.len or binder_truncated_len > hs.len) return error.BadHandshake;
            var binder: [max_hash_len]u8 = undefined;
            try self.computePskBinder(hs[0..binder_truncated_len], binder[0..binder_len]);
            @memcpy(hs[rel..][0..binder_len], binder[0..binder_len]);
            secureZero(binder[0..binder_len]);
        }
    }

    fn computePskBinder(self: *Client, truncated_client_hello: []const u8, out: []u8) Error!void {
        const offer = self.resume_offer orelse return error.BadState;
        switch (offer.suite.hashAlg()) {
            .sha256 => try self.computePskBinderT(Sha256, offer, truncated_client_hello, out),
            .sha384 => try self.computePskBinderT(Sha384, offer, truncated_client_hello, out),
        }
    }

    fn computePskBinderT(
        self: *Client,
        comptime KS: type,
        offer: ResumeOffer,
        truncated_client_hello: []const u8,
        out: []u8,
    ) Error!void {
        if (offer.psk_len != KS.hash_len or out.len != KS.hash_len) return error.BadHandshake;
        var early = KS.earlySecret(offer.psk[0..offer.psk_len]);
        defer early.wipe();
        var binder_key = try KS.deriveSecret(&early, "res binder", &KS.emptyTranscriptHash());
        defer binder_key.wipe();

        var transcript = std.ArrayList(u8).empty;
        defer transcript.deinit(self.allocator);
        try transcript.appendSlice(self.allocator, self.transcript.items);
        try transcript.appendSlice(self.allocator, truncated_client_hello);
        const th = KS.transcriptHash(transcript.items);
        const verify = tls_finished.For(KS).verifyData(binder_key.declassify(), th);
        @memcpy(out, &verify);
    }

    const ServerHelloStep = enum { need_more, proceed, retry };

    fn tryConsumeServerHello(self: *Client) Error!ServerHelloStep {
        while (true) {
            const rec = completePlainRecord(self.recv_buf.items) orelse return .need_more;
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

            if (isHelloRetryRequest(msg.body)) {
                // A second HelloRetryRequest in one connection is fatal.
                if (self.hrr_seen) return error.BadHandshake;
                const ch2 = try self.handleHelloRetryRequest(msg.body, msg.raw);
                consumePrefix(&self.recv_buf, rec.wire_len);
                self.retry_hello = ch2;
                return .retry;
            }

            var selected = try self.parseServerHello(msg.body);
            try self.appendTranscript(msg.raw);
            try self.deriveHandshakeKeys(selected.buf[0..selected.len]);
            secureZero(&selected.buf);
            consumePrefix(&self.recv_buf, rec.wire_len);
            self.state = .wait_encrypted_extensions;
            return .proceed;
        }
    }

    /// Process a HelloRetryRequest (RFC 8446 §4.1.4): apply the cookie, rewrite
    /// the transcript with the synthetic message_hash, and produce the second
    /// ClientHello to send. Returns the plaintext handshake record (caller owns).
    fn handleHelloRetryRequest(self: *Client, body: []const u8, raw: []const u8) Error![]u8 {
        var c = Cursor.init(body);
        if (try c.readU16() != tls_record.legacy_record_version) return error.ProtocolVersion;
        _ = try c.take(32); // the HelloRetryRequest magic random
        const sid = try c.take(try c.readU8());
        if (!std.mem.eql(u8, sid, &self.legacy_session_id)) return error.BadHandshake;
        const suite = try CipherSuite.fromWire(try c.readU16());
        if (try c.readU8() != 0) return error.BadHandshake;
        const ext_block = try c.take(try c.readU16());
        try c.expectEmpty();

        var selected_version = false;
        var hrr_group: ?u16 = null;
        var cookie_bytes: ?[]const u8 = null;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            switch (ext.typed()) {
                .supported_versions => {
                    if (try tls_supported_versions.parseServer(ext.data) != tls_supported_versions.tls13) {
                        return error.ProtocolVersion;
                    }
                    selected_version = true;
                },
                .key_share => {
                    // In a HelloRetryRequest the key_share carries only the group.
                    if (ext.data.len != 2) return error.BadHandshake;
                    hrr_group = std.mem.readInt(u16, ext.data[0..2], .big);
                },
                .cookie => {
                    if (ext.data.len < 2) return error.BadHandshake;
                    const clen = std.mem.readInt(u16, ext.data[0..2], .big);
                    if (ext.data.len != 2 + @as(usize, clen)) return error.BadHandshake;
                    cookie_bytes = ext.data[2..];
                },
                else => {},
            }
        }
        if (!selected_version) return error.MissingExtension;
        self.selected_suite = suite; // selects the transcript hash below

        // RFC 8446 §4.1.4: the requested group must be one we support AND did not
        // already offer a key_share for (a change-nothing HRR is illegal). By
        // default we share every group we support, so any group-change request is
        // non-compliant — but a test that withheld shares legitimately retries.
        if (hrr_group) |g| {
            const ng = supported_groups.NamedGroup.fromInt(g);
            if (!self.supportsGroup(ng)) return error.UnsupportedGroup;
            if (self.offeredShareFor(ng)) return error.BadHandshake; // no change — illegal
            self.retry_key_share_group = ng;
        }

        if (cookie_bytes) |cb| {
            if (cb.len == 0 or cb.len > self.cookie_buf.len) return error.BadHandshake;
            @memcpy(self.cookie_buf[0..cb.len], cb);
            self.cookie = self.cookie_buf[0..cb.len];
        }

        // Replace ClientHello1 in the transcript with the synthetic message_hash
        // (handshake type 254): 0xFE || uint24(Hash.length) || Hash(ClientHello1).
        var ch1_hash: [max_hash_len]u8 = undefined;
        const hlen = self.transcriptHash(&ch1_hash);
        self.transcript.clearRetainingCapacity();
        try self.transcript.append(self.allocator, 0xFE);
        try appendU24(self.allocator, &self.transcript, hlen);
        try self.transcript.appendSlice(self.allocator, ch1_hash[0..hlen]);
        try self.appendTranscript(raw); // fold in the HelloRetryRequest itself
        self.hrr_seen = true;

        // Build ClientHello2 (same random/session-id; key_share now the single
        // requested group when the HRR changed groups, plus any cookie) and fold
        // it into the transcript before sending.
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try self.writeClientHello(&hs);
        try self.appendTranscript(hs.items);
        return writePlainRecord(self.allocator, .handshake, hs.items);
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

            dbg("decrypted flight record ct={d} len={d}", .{ @intFromEnum(opened.content_type), opened.content.len });
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
        dbg("plain handshake state={s} msg typ={d} len={d}", .{ @tagName(self.state), @intFromEnum(msg.typ), msg.body.len });
        switch (self.state) {
            .wait_encrypted_extensions => {
                if (msg.typ != .encrypted_extensions) return error.BadHandshake;
                try self.parseEncryptedExtensions(msg.body);
                try self.appendTranscript(msg.raw);
                self.state = if (self.psk_accepted) .wait_finished else .wait_certificate;
            },
            .wait_certificate => {
                // An optional CertificateRequest precedes the server
                // Certificate (RFC 8446 §4.3.2). Record it and keep waiting for
                // the server Certificate; the request itself stays in the
                // transcript. Only the test-only mTLS path acts on it later.
                if (msg.typ == .certificate_request) {
                    try validateCertificateRequest(msg.body);
                    self.cert_requested = true;
                    try self.appendTranscript(msg.raw);
                } else if (msg.typ == .compressed_certificate) {
                    // RFC 8879 §4: a CompressedCertificate we never solicited is a
                    // protocol violation — reject it rather than decode it.
                    if (!self.offer_cert_compression) return error.BadHandshake;
                    // Inflate into a plain Certificate body, verify it, then fold
                    // the type-25 wire bytes (not a reconstructed type-11) into the
                    // transcript — exactly what the peer hashed.
                    const plain = try self.decompressCertificate(msg.body);
                    defer self.allocator.free(plain);
                    try self.parseAndVerifyCertificate(plain);
                    try self.appendTranscript(msg.raw);
                    self.received_compressed_cert = true;
                    self.state = .wait_certificate_verify;
                } else {
                    if (msg.typ != .certificate) return error.BadHandshake;
                    try self.parseAndVerifyCertificate(msg.body);
                    try self.appendTranscript(msg.raw);
                    self.state = .wait_certificate_verify;
                }
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

    /// The negotiated (EC)DHE secret: 32 bytes for a classical group, 64 for the
    /// X25519MLKEM768 hybrid (ml-kem_ss || x25519_ss). Fed to the key schedule.
    const ServerKexSecret = struct { buf: [64]u8 = undefined, len: usize = 0 };

    fn parseServerHello(self: *Client, body: []const u8) Error!ServerKexSecret {
        var c = Cursor.init(body);
        if (try c.readU16() != tls_record.legacy_record_version) return error.ProtocolVersion;
        const random = try c.take(32);
        // HelloRetryRequest is intercepted in tryConsumeServerHello; a magic
        // random reaching here would be a logic error or a second HRR.
        if (std.mem.eql(u8, random, &hello_retry_request_random)) return error.BadHandshake;
        const sid = try c.take(try c.readU8());
        if (!std.mem.eql(u8, sid, &self.legacy_session_id)) return error.BadHandshake;
        const suite = try CipherSuite.fromWire(try c.readU16());
        if (try c.readU8() != 0) return error.BadHandshake;
        const extensions_block = try c.take(try c.readU16());
        try c.expectEmpty();

        var selected_version = false;
        var selected_share: ?tls_keyshare.Entry = null;
        var selected_psk: ?u16 = null;
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
                .pre_shared_key => selected_psk = try tls_psk.parseServerPsk(ext.data),
                else => {},
            }
        }
        if (!selected_version or selected_share == null) return error.MissingExtension;
        self.selected_suite = suite;
        self.psk_accepted = false;
        if (selected_psk) |idx| {
            if (idx != 0) return error.BadHandshake;
            const offer = self.resume_offer orelse return error.BadHandshake;
            if (offer.suite != suite or offer.psk_len != suite.hashLen()) return error.BadHandshake;
            self.psk_accepted = true;
        }
        const share = selected_share.?;
        var out = ServerKexSecret{};
        switch (share.group) {
            .x25519 => {
                if (share.key_exchange.len != kx.X25519Kx.public_len) return error.BadHandshake;
                var peer: kx.PublicKey = undefined;
                @memcpy(&peer, share.key_exchange);
                var secret = try kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer);
                defer secret.wipe();
                const ss = secret.declassify();
                @memcpy(out.buf[0..32], &ss);
                out.len = 32;
            },
            .secp256r1 => {
                if (share.key_exchange.len != ecdh_p256.public_length) return error.BadHandshake;
                const ss = try ecdh_p256.sharedSecret(self.p256_pair.secret, share.key_exchange[0..ecdh_p256.public_length].*);
                @memcpy(out.buf[0..32], &ss);
                out.len = 32;
            },
            .x25519mlkem768 => {
                // Server share = ml-kem_ct(1088) || x25519_pub(32). The combined
                // (EC)DHE secret is the RAW concatenation ml-kem_ss(32) || x25519_ss(32)
                // fed to the TLS key schedule — matching tls_server. (NOT
                // kx.HybridKx.decapsulate, which is the TSUMUGI mesh HKDF combiner.)
                const ct_len = kx.HybridKx.mlkem_ciphertext_len;
                if (share.key_exchange.len != ct_len + kx.X25519Kx.public_len) return error.BadHandshake;
                var ct: [ct_len]u8 = undefined;
                @memcpy(&ct, share.key_exchange[0..ct_len]);
                var mlkem_ss = try self.hybrid_pair.mlkem.secret_key.decaps(&ct);
                defer secureZero(&mlkem_ss);
                var x_peer: kx.PublicKey = undefined;
                @memcpy(&x_peer, share.key_exchange[ct_len..]);
                var x_secret = try kx.X25519Kx.sharedSecret(&self.hybrid_pair.x25519.secret_key, x_peer);
                defer x_secret.wipe();
                const x_ss = x_secret.declassify();
                @memcpy(out.buf[0..32], &mlkem_ss);
                @memcpy(out.buf[32..64], &x_ss);
                out.len = 64;
            },
            else => return error.UnsupportedGroup,
        }
        return out;
    }

    fn parseEncryptedExtensions(self: *Client, body: []const u8) Error!void {
        const extensions = try tls_extension.unwrap(body);
        var it = tls_extension.Iterator.init(extensions);
        var server_accepted_early = false;
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
                    // Copy into owned storage; `selected` borrows hs_plain.
                    if (selected.len > self.selected_alpn_buf.len) return error.BadHandshake;
                    @memcpy(self.selected_alpn_buf[0..selected.len], selected);
                    self.selected_alpn = self.selected_alpn_buf[0..selected.len];
                },
                .early_data => {
                    if (ext.data.len != 0 or self.early_data == null or !self.psk_accepted) return error.BadHandshake;
                    server_accepted_early = true;
                },
                .record_size_limit => {
                    // RFC 8449: a 2-byte value in [64, 2^14+1]; anything else is
                    // illegal_parameter. Store it so our outbound records honor it.
                    if (ext.data.len != 2) return error.BadHandshake;
                    const limit = std.mem.readInt(u16, ext.data[0..2], .big);
                    if (limit < tls_record.record_size_limit_min or limit > tls_record.record_size_limit_max) return error.BadHandshake;
                    self.peer_record_size_limit = limit;
                },
                // key_share / supported_versions / signature_algorithms belong to
                // ServerHello/CertificateRequest and are illegal here. server_name
                // (empty SNI ack) and supported_groups ARE permitted in EE
                // (RFC 8446 §4.3.1), so only reject the genuinely-illegal ones.
                .supported_versions, .key_share, .signature_algorithms => {
                    return error.BadHandshake;
                },
                else => {},
            }
        }
        if (self.early_data != null) self.early_data_accepted = server_accepted_early;
    }

    /// Inflate a CompressedCertificate (RFC 8879 §5) body into the plain
    /// Certificate message bytes. Layout: u16 algorithm, u24 uncompressed_length,
    /// then `compressed_certificate_message<1..2^24-1>` (a u24-prefixed vector).
    /// We only advertised zlib, so any other algorithm is a protocol violation.
    /// Caller owns the returned slice. The bomb guard lives in `inflateZlib`.
    fn decompressCertificate(self: *Client, body: []const u8) Error![]u8 {
        var c = Cursor.init(body);
        const algorithm = try c.readU16();
        if (algorithm != cert_compression.Algorithm.zlib.toInt()) return error.BadHandshake;
        const uncompressed_length = try c.readU24();
        const compressed_length = try c.readU24();
        const compressed = try c.take(compressed_length);
        try c.expectEmpty();
        return cert_compression.inflateZlib(self.allocator, compressed, uncompressed_length);
    }

    fn parseAndVerifyCertificate(self: *Client, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const request_context = try c.take(try c.readU8());
        if (request_context.len != 0) return error.BadHandshake;
        const list = try c.take(try c.readU24());
        try c.expectEmpty();

        var chain_buf: [16][]const u8 = undefined;
        var count: usize = 0;
        var leaf_ocsp_staple: ?[]const u8 = null;
        var certs = Cursor.init(list);
        while (certs.remaining() != 0) {
            if (count == chain_buf.len) return error.BadCertificate;
            const der = try certs.take(try certs.readU24());
            const ext = try certs.take(try certs.readU16());
            if (ext.len != 0) {
                var eit = tls_extension.Iterator.init(ext);
                while (try eit.next()) |entry_ext| {
                    if (count == 0 and entry_ext.ext_type == ext_status_request) {
                        leaf_ocsp_staple = try parseCertificateStatusOcsp(entry_ext.data);
                    }
                }
            }
            chain_buf[count] = der;
            count += 1;
        }
        if (count == 0) return error.EmptyCertificateChain;
        const chain = chain_buf[0..count];
        if (!self.skip_cert_verify_for_test) {
            try verifyChainToTrustAnchors(chain, self.trust_anchors, self.server_name, self.verify_time);
        }
        if (leaf_ocsp_staple) |staple| {
            const leaf = try x509.parse(chain[0]);
            const issuer_der = if (chain.len > 1) chain[1] else chain[0];
            const issuer_parts = try extractCertParts(issuer_der);
            try verifyOcspStapleForLeaf(staple, issuer_parts.spki_der, leaf.serial_der, self.verify_time);
        }
        self.leaf_key = try parsePublicKeyFromSpki((try extractCertParts(chain[0])).spki_der);
        // The RSA variant borrows the SPKI bytes (in hs_plain); copy n/e into
        // owned storage so the key survives the post-message consume of hs_plain.
        if (self.leaf_key) |lk| {
            if (lk == .rsa) {
                const n = lk.rsa.n;
                const e = lk.rsa.e;
                if (n.len > self.leaf_rsa_n.len or e.len > self.leaf_rsa_e.len) return error.BadCertificate;
                @memcpy(self.leaf_rsa_n[0..n.len], n);
                @memcpy(self.leaf_rsa_e[0..e.len], e);
                self.leaf_key = .{ .rsa = .{ .n = self.leaf_rsa_n[0..n.len], .e = self.leaf_rsa_e[0..e.len] } };
            }
        }
    }

    fn verifyCertificateVerify(self: *Client, body: []const u8) Error!void {
        if (body.len < 4) return error.BadHandshake;
        const scheme = tls_signature_scheme.SignatureScheme.fromInt(std.mem.readInt(u16, body[0..2], .big));
        const sig_len = std.mem.readInt(u16, body[2..4], .big);
        if (body.len != 4 + @as(usize, sig_len)) return error.BadHandshake;
        const sig_bytes = body[4..];
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, certificate_verify_context, th[0..th_len]);
        const leaf = self.leaf_key orelse return error.BadCertificate;
        try verifySignatureScheme(leaf, scheme, input, sig_bytes);
    }

    fn verifyFinished(self: *Client, body: []const u8) Error!void {
        if (!self.finishedVerify(&self.server_hs_secret, body)) return error.FinishedMismatch;
    }

    fn writeClientFinishedRecord(self: *Client) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);

        // mTLS (test-only): if the server requested a client certificate, send
        // a client Certificate first (empty when declining), then a
        // CertificateVerify when a key pair is configured. Each goes out as its
        // own encrypted handshake record and is folded into the transcript
        // before the client Finished MAC is computed.
        if (self.cert_requested) {
            try self.appendClientCertificate(&out, suite);
            if (self.client_cert_der != null and self.client_key_pair != null) {
                try self.appendClientCertificateVerify(&out, suite);
            }
        }

        var vd_buf: [max_hash_len]u8 = undefined;
        const vd_len = self.finishedVerifyData(&self.client_hs_secret, &vd_buf);
        const verify_data = vd_buf[0..vd_len];
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .finished, verify_data);
        try self.appendTranscript(hs.items);
        try self.deriveResumptionMasterSecret();
        const record = try sealRecordAlloc(self.allocator, suite, &self.client_hs_keys, self.hs_write_seq, .handshake, hs.items);
        defer self.allocator.free(record);
        self.hs_write_seq += 1;
        try out.appendSlice(self.allocator, record);
        return out.toOwnedSlice(self.allocator);
    }

    /// Test-only: append an encrypted client Certificate handshake record. When
    /// no client cert is configured the CertificateEntry list is empty (a
    /// well-formed decline per RFC 8446 §4.4.2).
    fn appendClientCertificate(self: *Client, out: *std.ArrayList(u8), suite: CipherSuite) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.append(self.allocator, 0); // certificate_request_context: empty
        if (self.client_cert_der) |der| {
            const entry_len = 3 + der.len + 2;
            try appendU24(self.allocator, &body, entry_len);
            try appendU24(self.allocator, &body, der.len);
            try body.appendSlice(self.allocator, der);
            try appendU16(self.allocator, &body, 0); // no certificate extensions
        } else {
            try appendU24(self.allocator, &body, 0); // empty entry list
        }
        try self.appendClientHandshakeRecord(out, suite, .certificate, body.items);
    }

    /// Test-only: append an encrypted client CertificateVerify signed with the
    /// configured key over the "client CertificateVerify" context, using the
    /// scheme matching the key type.
    fn appendClientCertificateVerify(self: *Client, out: *std.ArrayList(u8), suite: CipherSuite) Error!void {
        const key_pair = self.client_key_pair orelse return error.BadState;
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, client_certificate_verify_context, th[0..th_len]);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        switch (key_pair) {
            .ed25519 => |kp| {
                const sig = kp.sign(input) catch return error.BadSignature;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ed25519));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, &sig);
            },
            .ecdsa_p256 => |kp| {
                const sig = ecdsa_p256.sign(input, kp) catch return error.BadSignature;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = ecdsa_p256.signatureToDer(sig, &der_buf) catch return error.BadSignature;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256));
                try appendU16(self.allocator, &body, @intCast(der.len));
                try body.appendSlice(self.allocator, der);
            },
            .rsa => |key| {
                var mhash: [Sha256.hash_len]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(input, &mhash, .{});
                var salt: [Sha256.hash_len]u8 = undefined;
                try osEntropy(&salt);
                defer secureZero(&salt);
                var sig_buf: [rsa_verify.max_bytes]u8 = undefined;
                const sig = rsa_sign.signPss(key, .sha256, &mhash, &salt, &sig_buf) catch return error.BadSignature;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.rsa_pss_rsae_sha256));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, sig);
            },
        }
        try self.appendClientHandshakeRecord(out, suite, .certificate_verify, body.items);
    }

    fn appendClientHandshakeRecord(
        self: *Client,
        out: *std.ArrayList(u8),
        suite: CipherSuite,
        typ: HandshakeType,
        body: []const u8,
    ) Error!void {
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, typ, body);
        try self.appendTranscript(hs.items);
        const record = try sealRecordAlloc(self.allocator, suite, &self.client_hs_keys, self.hs_write_seq, .handshake, hs.items);
        defer self.allocator.free(record);
        self.hs_write_seq += 1;
        try out.appendSlice(self.allocator, record);
    }

    /// Negotiated transcript-hash algorithm (defaults to SHA-256 before the
    /// ServerHello selects a suite).
    fn hashAlg(self: *const Client) HashAlg {
        const suite = self.selected_suite orelse return .sha256;
        return suite.hashAlg();
    }

    fn hashLen(self: *const Client) usize {
        return switch (self.hashAlg()) {
            .sha256 => Sha256.hash_len,
            .sha384 => Sha384.hash_len,
        };
    }

    /// Transcript-Hash of the handshake so far, written into `out`; returns the
    /// digest length (32 for SHA-256, 48 for SHA-384).
    fn transcriptHash(self: *const Client, out: *[max_hash_len]u8) usize {
        switch (self.hashAlg()) {
            .sha256 => {
                const d = Sha256.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                return d.len;
            },
            .sha384 => {
                const d = Sha384.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                return d.len;
            },
        }
    }

    /// Constant-time Finished verify against the negotiated hash.
    fn finishedVerify(self: *const Client, base_key: *const [max_hash_len]u8, received: []const u8) bool {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        return switch (self.hashAlg()) {
            .sha256 => tls_finished.Sha256F.verify(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*, received),
            .sha384 => tls_finished.Sha384F.verify(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*, received),
        };
    }

    /// Finished verify_data for our own Finished, written into `out`; returns len.
    fn finishedVerifyData(self: *const Client, base_key: *const [max_hash_len]u8, out: *[max_hash_len]u8) usize {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        switch (self.hashAlg()) {
            .sha256 => {
                const v = tls_finished.Sha256F.verifyData(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
            .sha384 => {
                const v = tls_finished.Sha384F.verifyData(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
        }
    }

    fn deriveHandshakeKeys(self: *Client, shared_secret: []const u8) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveHandshakeKeysT(Sha256, shared_secret),
            .sha384 => try self.deriveHandshakeKeysT(Sha384, shared_secret),
        }
    }

    fn deriveClientEarlyTrafficKeys(self: *Client) Error!void {
        const offer = self.resume_offer orelse return error.BadState;
        switch (offer.suite.hashAlg()) {
            .sha256 => try self.deriveClientEarlyTrafficKeysT(Sha256, offer),
            .sha384 => try self.deriveClientEarlyTrafficKeysT(Sha384, offer),
        }
    }

    fn deriveClientEarlyTrafficKeysT(self: *Client, comptime KS: type, offer: ResumeOffer) Error!void {
        if (offer.psk_len != KS.hash_len) return error.BadHandshake;
        var early = KS.earlySecret(offer.psk[0..offer.psk_len]);
        defer early.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.deriveSecret(&early, "c e traffic", &th);
        defer traffic.wipe();
        var traffic_bytes = traffic.declassify();
        defer secureZero(&traffic_bytes);
        try deriveTrafficKeys(offer.suite, &traffic_bytes, &self.client_early_keys);
        self.early_write_seq = 0;
    }

    fn deriveHandshakeKeysT(self: *Client, comptime KS: type, shared_secret: []const u8) Error!void {
        const psk = if (self.psk_accepted) blk: {
            const offer = self.resume_offer orelse return error.BadHandshake;
            if (offer.psk_len != KS.hash_len) return error.BadHandshake;
            break :blk offer.psk[0..offer.psk_len];
        } else "";
        var early = KS.earlySecret(psk);
        defer early.wipe();
        self.early_secret[0..KS.hash_len].* = early.declassify();

        var handshake = try KS.handshakeSecret(&early, shared_secret);
        defer handshake.wipe();
        self.handshake_secret[0..KS.hash_len].* = handshake.declassify();

        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.handshakeTrafficSecrets(&handshake, &th);
        defer traffic.wipe();
        self.client_hs_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_hs_secret[0..KS.hash_len].* = traffic.server.declassify();

        var master = try KS.masterSecret(&handshake);
        defer master.wipe();
        self.master_secret[0..KS.hash_len].* = master.declassify();

        const suite = self.selected_suite orelse return error.BadState;
        try deriveTrafficKeys(suite, self.client_hs_secret[0..KS.hash_len], &self.client_hs_keys);
        try deriveTrafficKeys(suite, self.server_hs_secret[0..KS.hash_len], &self.server_hs_keys);
        self.hs_read_seq = 0;
        self.hs_write_seq = 0;
    }

    fn deriveApplicationKeys(self: *Client) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveApplicationKeysT(Sha256),
            .sha384 => try self.deriveApplicationKeysT(Sha384),
        }
    }

    fn deriveApplicationKeysT(self: *Client, comptime KS: type) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.master_secret[0..KS.hash_len]);
        var master = KS.SecretBytes.init(sk);
        defer master.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var exporter_master = try KS.exporterMasterSecret(&master, &th);
        defer exporter_master.wipe();
        self.exporter_master_secret[0..KS.hash_len].* = exporter_master.declassify();
        self.exporter_master_secret_ready = true;
        var traffic = try KS.applicationTrafficSecrets(&master, &th);
        defer traffic.wipe();
        self.client_app_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_app_secret[0..KS.hash_len].* = traffic.server.declassify();
        const suite = self.selected_suite orelse return error.BadState;
        try deriveTrafficKeys(suite, self.client_app_secret[0..KS.hash_len], &self.client_app_keys);
        try deriveTrafficKeys(suite, self.server_app_secret[0..KS.hash_len], &self.server_app_keys);
        self.app_read_seq = 0;
        self.app_write_seq = 0;
    }

    fn deriveResumptionMasterSecret(self: *Client) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveResumptionMasterSecretT(Sha256),
            .sha384 => try self.deriveResumptionMasterSecretT(Sha384),
        }
    }

    fn deriveResumptionMasterSecretT(self: *Client, comptime KS: type) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.master_secret[0..KS.hash_len]);
        var master = KS.SecretBytes.init(sk);
        defer master.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var rms = try KS.deriveSecret(&master, "res master", &th);
        defer rms.wipe();
        self.resumption_master_secret[0..KS.hash_len].* = rms.declassify();
    }

    fn exportKeyingMaterialT(self: *const Client, comptime KS: type, label: []const u8, context: []const u8, out: []u8) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.exporter_master_secret[0..KS.hash_len]);
        var exporter_master = KS.SecretBytes.init(sk);
        defer exporter_master.wipe();
        try KS.exportKeyingMaterial(&exporter_master, label, context, out);
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
const ext_status_request: u16 = 5;
const hello_retry_request_random = [_]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// A ServerHello whose random equals the magic value is a HelloRetryRequest
/// (RFC 8446 §4.1.3). `body` is the handshake message body (legacy_version then
/// the 32-byte random).
fn isHelloRetryRequest(body: []const u8) bool {
    if (body.len < 2 + 32) return false;
    return std.mem.eql(u8, body[2..34], &hello_retry_request_random);
}

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
        .tls_aes_256_gcm_sha384 => {
            const key = keys.key[0..Aes256Gcm.key_length].*;
            var tag: [Aes256Gcm.tag_length]u8 = undefined;
            Aes256Gcm.encrypt(out[5..][0..encoded.len], &tag, encoded, &aad, nonce, key);
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
        .tls_aes_256_gcm_sha384 => {
            const key = keys.key[0..Aes256Gcm.key_length].*;
            const tag = parsed.encrypted_record[clen..][0..Aes256Gcm.tag_length].*;
            Aes256Gcm.decrypt(inner, parsed.encrypted_record[0..clen], tag, &aad, nonce, key) catch return error.BadRecord;
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

fn deriveTrafficKeys(suite: CipherSuite, secret_bytes: []const u8, out: *TrafficKeys) Error!void {
    switch (suite.hashAlg()) {
        .sha256 => try deriveTrafficKeysT(Sha256, suite, secret_bytes, out),
        .sha384 => try deriveTrafficKeysT(Sha384, suite, secret_bytes, out),
    }
}

fn deriveTrafficKeysT(comptime KS: type, suite: CipherSuite, secret_bytes: []const u8, out: *TrafficKeys) Error!void {
    if (secret_bytes.len < KS.hash_len) return error.BadState;
    var sk: [KS.hash_len]u8 = undefined;
    @memcpy(&sk, secret_bytes[0..KS.hash_len]);
    var secret = KS.SecretBytes.init(sk);
    defer secret.wipe();
    out.wipe();
    try KS.hkdfExpandLabel(&secret, "key", "", out.key[0..suite.keyLen()]);
    try KS.hkdfExpandLabel(&secret, "iv", "", &out.iv);
}

/// In-place KeyUpdate of a traffic secret stored in a `[max_hash_len]u8` field;
/// only the schedule's digest-length prefix is live.
fn applyKeyUpdateT(comptime KS: type, suite: CipherSuite, secret: *[max_hash_len]u8, keys: *TrafficKeys) Error!void {
    var sk: [KS.hash_len]u8 = undefined;
    @memcpy(&sk, secret[0..KS.hash_len]);
    var cur = KS.SecretBytes.init(sk);
    defer cur.wipe();
    var next: [KS.hash_len]u8 = undefined;
    try KS.hkdfExpandLabel(&cur, "traffic upd", "", &next);
    @memcpy(secret[0..KS.hash_len], &next);
    secureZero(&next);
    try deriveTrafficKeys(suite, secret[0..KS.hash_len], keys);
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

fn parseTicketEarlyDataLimit(extensions: []const u8) Error!u32 {
    var it = tls_extension.Iterator.init(extensions);
    var limit: u32 = 0;
    while (try it.next()) |ext| {
        if (ext.typed() == .early_data) {
            if (ext.data.len != 4) return error.BadHandshake;
            limit = std.mem.readInt(u32, ext.data[0..4], .big);
        }
    }
    return limit;
}

/// Parse a TLS 1.3 CertificateEntry status_request extension body.
///
/// The extension_data is a CertificateStatus:
/// status_type(1) || ocsp_response_length(uint24) || OCSPResponse DER. Only
/// status_type=ocsp(1) is accepted here.
fn parseCertificateStatusOcsp(data: []const u8) Error![]const u8 {
    if (data.len < 4) return error.BadCertificate;
    if (data[0] != 1) return error.BadCertificate;
    const len = readU24Bytes(data[1..4]);
    if (data.len != 4 + len or len == 0) return error.BadCertificate;
    return data[4..];
}

/// Authenticate a stapled OCSP response and enforce the leaf's serial status.
///
/// Absence is handled by the caller. A signed `good`, signed `unknown`, or a
/// signed response with no matching SingleResponse soft-passes; a matching
/// `revoked` SingleResponse fails closed.
///
/// `now_unix` (the client's validity clock) enables delegated-responder
/// authorization (RFC 6960 §4.2.2.2 — most public CAs), which needs a clock to
/// check the responder cert's validity window. Without a clock we fall back to
/// direct-issuer signing only (fail-closed: a delegated staple is rejected rather
/// than trusted with an unverifiable responder-cert lifetime).
fn verifyOcspStapleForLeaf(staple_der: []const u8, issuer_spki_der: []const u8, leaf_serial: []const u8, now_unix: ?i64) Error!void {
    const parsed = try ocsp.parse(staple_der);
    const authenticated = if (now_unix) |now|
        ocsp.verifyResponseSignatureWithChain(parsed, issuer_spki_der, now)
    else
        ocsp.verifyResponseSignature(parsed, issuer_spki_der);
    if (!authenticated) return error.BadCertificate;
    try enforceOcspStatusForSerial(parsed, leaf_serial);
}

fn enforceOcspStatusForSerial(parsed: anytype, leaf_serial: []const u8) Error!void {
    const status = ocsp.statusForSerial(parsed, leaf_serial) orelse return;
    switch (status) {
        .revoked => return error.CertificateRevoked,
        .good, .unknown => return,
    }
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

const certificate_verify_context = "TLS 1.3, server CertificateVerify";
const client_certificate_verify_context = "TLS 1.3, client CertificateVerify";
/// 64 spaces + the longest context + 1 separator + the longest transcript hash.
const cert_verify_input_max = 64 + client_certificate_verify_context.len + 1 + max_hash_len;

/// Build the CertificateVerify signed content (RFC 8446 §4.4.3): 64 0x20 bytes,
/// the context string, a 0x00 separator, then the transcript hash. Written into
/// `out`; the returned slice is the used prefix. `context` is the server or
/// client context string and `transcript_hash` is 32 or 48 bytes.
fn buildCertVerifyInput(out: *[cert_verify_input_max]u8, context: []const u8, transcript_hash: []const u8) []const u8 {
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..context.len], context);
    out[64 + context.len] = 0;
    const tail = 64 + context.len + 1;
    @memcpy(out[tail..][0..transcript_hash.len], transcript_hash);
    return out[0 .. tail + transcript_hash.len];
}

/// Strictly validate a TLS 1.3 CertificateRequest body (RFC 8446 §4.3.2):
/// a 1-byte certificate_request_context (empty in the main handshake), then a
/// 2-byte length-prefixed extensions vector that parses cleanly, spans the
/// rest of the body exactly, and contains a well-formed, non-empty
/// signature_algorithms extension (the only mandatory one). Real clients
/// (gnutls/openssl) enforce all of this, so the loopback client must too —
/// otherwise server-side encoding bugs survive the round-trip tests.
fn validateCertificateRequest(body: []const u8) Error!void {
    if (body.len < 1) return error.BadHandshake;
    const ctx_len = body[0];
    if (ctx_len != 0) return error.BadHandshake; // MUST be empty outside post-handshake auth
    const block = body[1..];
    const ext_body = tls_extension.unwrap(block) catch return error.BadHandshake;
    if (2 + ext_body.len != block.len) return error.BadHandshake; // trailing garbage
    var saw_signature_algorithms = false;
    var it = tls_extension.Iterator.init(ext_body);
    while (it.next() catch return error.BadHandshake) |ext| {
        if (ext.typed() != .signature_algorithms) continue;
        // signature_algorithms data: 2-byte list length + even-sized,
        // non-empty list of u16 schemes spanning the data exactly.
        if (ext.data.len < 4) return error.BadHandshake;
        const list_len = std.mem.readInt(u16, ext.data[0..2], .big);
        if (list_len == 0 or list_len % 2 != 0) return error.BadHandshake;
        if (2 + @as(usize, list_len) != ext.data.len) return error.BadHandshake;
        saw_signature_algorithms = true;
    }
    if (!saw_signature_algorithms) return error.BadHandshake;
}

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
        .ecdsa_secp384r1_sha384 => {
            const pk = switch (key) {
                .ecdsa_p384 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            const decoded = EcdsaP384.Signature.fromDer(sig) catch return error.BadSignature;
            decoded.verify(msg, pk) catch return error.BadSignature;
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

fn verifyChainToTrustAnchors(chain: []const []const u8, anchors: []const []const u8, server_name: []const u8, now: ?i64) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    if (anchors.len == 0) return error.UnknownCa;
    const leaf = try x509.parse(chain[0]);
    if (!dnsNameMatchesCert(server_name, leaf)) return error.CertificateNameMismatch;
    // Reject expired / not-yet-valid leaf certificates when a clock is supplied.
    if (now) |t| try x509_verify.validateParsedAt(leaf, t);
    // The leaf must be usable for TLS server authentication: when an
    // ExtendedKeyUsage extension is present it has to list serverAuth (or
    // anyExtendedKeyUsage). Absent EKU is permitted (unrestricted).
    if (leaf.eku_present and !leaf.eku_server_auth) return error.BadCertificate;

    var i: usize = 0;
    while (i + 1 < chain.len) : (i += 1) {
        try verifyIssuedBy(chain[i], chain[i + 1]);
        const issuer = try x509.parse(chain[i + 1]);
        if (!issuer.basic_constraints_ca) return error.BadCertificate;
        // A CA in the path must be allowed to sign certificates and be valid now.
        if (issuer.key_usage_present and !issuer.key_usage_cert_sign) return error.BadCertificate;
        if (now) |t| try x509_verify.validateParsedAt(issuer, t);
        // RFC 5280 §4.2.1.10: a CA's NameConstraints bind the leaf's SAN dNSNames.
        try enforceNameConstraints(issuer, leaf);
    }

    // RFC 5280 §4.2.1.10 / §6.1.4(m): pathLenConstraint enforcement. Reduce the
    // chain to per-cert facts (path limit + self-issued) then check with the
    // pure `enforcePathLen` helper.
    var facts_buf: [16]CaPathFact = undefined;
    const fn_count = @min(chain.len, facts_buf.len);
    for (chain[0..fn_count], 0..) |der, idx| {
        const parsed_pl = if (x509.parse(der)) |p| p.basic_constraints_path_len else |_| null;
        const self_issued = if (extractCertParts(der)) |parts|
            std.mem.eql(u8, parts.subject_der, parts.issuer_der)
        else |_|
            false;
        facts_buf[idx] = .{ .path_len = parsed_pl, .self_issued = self_issued };
    }
    try enforcePathLen(facts_buf[0..fn_count]);

    const last = chain[chain.len - 1];
    const last_parts = try extractCertParts(last);
    for (anchors) |anchor_der| {
        const anchor_parts = extractCertParts(anchor_der) catch continue;
        // Match the chain tip to a trust anchor by DN: either the tip is issued by
        // the anchor (tip.issuer == anchor.subject), or the tip *is* the anchor
        // (self-included root). Then verify the tip's signature with the anchor.
        if (!std.mem.eql(u8, last_parts.issuer_der, anchor_parts.subject_der) and
            !std.mem.eql(u8, last_parts.subject_der, anchor_parts.subject_der))
        {
            continue;
        }
        verifyCertSignature(last_parts, anchor_der) catch |err| {
            dbg("trust-anchor DN matched but signature check failed: {s}", .{@errorName(err)});
            continue;
        };
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

/// One certificate's inputs to path-length checking. `path_len` is its
/// basicConstraints pathLenConstraint (null = absent); `self_issued` is
/// subject DN == issuer DN.
const CaPathFact = struct { path_len: ?u32, self_issued: bool };

/// RFC 5280 §4.2.1.10 / §6.1.4(m). `facts[0]` is the leaf; `facts[1..]` are the
/// CAs from the leaf toward the trust anchor. A CA's pathLenConstraint bounds
/// the number of NON-self-issued intermediate CAs strictly between it and the
/// leaf. This per-CA check is equivalent to the RFC's running-budget algorithm.
fn enforcePathLen(facts: []const CaPathFact) Error!void {
    var ci: usize = 1;
    while (ci < facts.len) : (ci += 1) {
        const limit = facts[ci].path_len orelse continue;
        var below: u32 = 0;
        var bi: usize = 1;
        while (bi < ci) : (bi += 1) {
            if (!facts[bi].self_issued) below += 1;
        }
        if (below > limit) return error.BadCertificate;
    }
}

test "enforcePathLen: pathLenConstraint bounds intermediates below a CA" {
    const F = CaPathFact;
    // Normal chain [leaf, R3(pathLen:0), root]: 0 intermediates below R3 — OK.
    try enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 0, .self_issued = false },
    });
    // [leaf, subCA, root(pathLen:0)]: subCA is a non-self-issued intermediate
    // below the pathLen:0 root — REJECT.
    try std.testing.expectError(error.BadCertificate, enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 0, .self_issued = false },
    }));
    // pathLen:1 permits exactly one intermediate below.
    try enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 1, .self_issued = false },
    });
    // Two intermediates below a pathLen:1 CA — REJECT.
    try std.testing.expectError(error.BadCertificate, enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = 1, .self_issued = false },
    }));
    // A self-issued (cross-signed) intermediate is exempt from the count.
    try enforcePathLen(&[_]F{
        .{ .path_len = null, .self_issued = false },
        .{ .path_len = null, .self_issued = true },
        .{ .path_len = 0, .self_issued = false },
    });
}

fn verifyCertSignature(cert: CertParts, issuer_der: []const u8) Error!void {
    const issuer = try extractCertParts(issuer_der);
    const key = try parsePublicKeyFromSpki(issuer.spki_der);
    if (oidEq(cert.signature_algorithm_oid, &oid_ecdsa_sha256)) {
        try verifySignatureScheme(key, .ecdsa_secp256r1_sha256, cert.tbs_der, cert.signature);
    } else if (oidEq(cert.signature_algorithm_oid, &oid_ecdsa_sha384)) {
        try verifySignatureScheme(key, .ecdsa_secp384r1_sha384, cert.tbs_der, cert.signature);
    } else if (oidEq(cert.signature_algorithm_oid, &oid_sha256_rsa)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(cert.tbs_der, &digest, .{});
        if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, cert.signature)) return error.BadSignature;
    } else if (oidEq(cert.signature_algorithm_oid, &oid_sha384_rsa)) {
        // sha384WithRSAEncryption — common on real CA intermediate/leaf certs.
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [48]u8 = undefined;
        std.crypto.hash.sha2.Sha384.hash(cert.tbs_der, &digest, .{});
        if (!rsa_verify.verifyPkcs1v15(pk, .sha384, &digest, cert.signature)) return error.BadSignature;
    } else if (oidEq(cert.signature_algorithm_oid, &oid_sha512_rsa)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        var digest: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(cert.tbs_der, &digest, .{});
        if (!rsa_verify.verifyPkcs1v15(pk, .sha512, &digest, cert.signature)) return error.BadSignature;
    } else if (oidEq(cert.signature_algorithm_oid, &oid_rsassa_pss)) {
        const pk = switch (key) {
            .rsa => |pk| pk,
            else => return error.UnsupportedPublicKey,
        };
        // id-RSASSA-PSS: the hash/MGF/salt are NOT in the OID — decode and
        // validate them (fail-closed) from the signatureAlgorithm parameters
        // instead of assuming SHA-256/salt-32.
        try verifyCertPss(pk, cert.signature_algorithm_params, cert.tbs_der, cert.signature);
    } else if (oidEq(cert.signature_algorithm_oid, &oid_ed25519)) {
        try verifySignatureScheme(key, .ed25519, cert.tbs_der, cert.signature);
    } else {
        return error.UnsupportedSignatureScheme;
    }
}

/// Verify an RSASSA-PSS certificate signature whose hash/MGF/salt are declared in
/// the `RSASSA-PSS-params` (raw parameters TLV). Delegates parameter validation
/// to `x509_verify.parsePssParams`, which fails closed on SHA-1 defaults, an
/// MGF/hash mismatch, an oversized salt, or malformed DER.
fn verifyCertPss(
    pk: rsa_verify.PublicKey,
    params_der: ?[]const u8,
    tbs: []const u8,
    sig: []const u8,
) Error!void {
    const params = x509_verify.parsePssParams(params_der orelse return error.BadSignature) catch
        return error.BadSignature;
    var digest: [64]u8 = undefined;
    const digest_slice = digest[0..params.hash.digestLen()];
    switch (params.hash) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(tbs, digest[0..32], .{}),
        .sha384 => std.crypto.hash.sha2.Sha384.hash(tbs, digest[0..48], .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(tbs, digest[0..64], .{}),
    }
    if (!rsa_verify.verifyPss(pk, params.hash, digest_slice, sig, params.salt_len)) {
        return error.BadSignature;
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

/// Enforce an issuing CA's NameConstraints (dNSName) against the leaf's SAN
/// dNSNames (RFC 5280 §4.2.1.10). Each leaf name must match no excluded subtree
/// and, when permitted dNSName subtrees exist, at least one permitted subtree.
fn enforceNameConstraints(issuer: x509.Certificate, leaf: x509.Certificate) Error!void {
    if (!issuer.name_constraints_present) return;
    var li: usize = 0;
    while (li < leaf.san_dns_count) : (li += 1) {
        const name = leaf.san_dns[li];
        var ei: usize = 0;
        while (ei < issuer.nc_excluded_dns_count) : (ei += 1) {
            if (dnsConstraintMatches(issuer.nc_excluded_dns[ei], name)) return error.BadCertificate;
        }
        if (issuer.nc_permitted_dns_count > 0) {
            var ok = false;
            var pi: usize = 0;
            while (pi < issuer.nc_permitted_dns_count) : (pi += 1) {
                if (dnsConstraintMatches(issuer.nc_permitted_dns[pi], name)) {
                    ok = true;
                    break;
                }
            }
            if (!ok) return error.BadCertificate;
        }
    }
}

/// dNSName name-constraint match (RFC 5280): the constraint matches the name and
/// any name with additional left-hand labels. An empty constraint matches all; a
/// leading-dot constraint matches strict subdomains only.
fn dnsConstraintMatches(constraint: []const u8, name: []const u8) bool {
    if (constraint.len == 0) return true;
    if (constraint[0] == '.') return asciiEndsWithIgnoreCase(name, constraint);
    if (asciiEqlIgnoreCase(name, constraint)) return true;
    // name == "<labels>." ++ constraint
    if (name.len > constraint.len + 1 and
        name[name.len - constraint.len - 1] == '.' and
        asciiEqlIgnoreCase(name[name.len - constraint.len ..], constraint))
    {
        return true;
    }
    return false;
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

    const sig_alg_parts = try algorithmOidParams(body, sig_alg);
    return .{
        .tbs_der = tbs.raw,
        .signature_algorithm_oid = sig_alg_parts.oid,
        .signature_algorithm_params = sig_alg_parts.params,
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
        const params = alg.params orelse return error.UnsupportedPublicKey;
        if (oidEq(params, &oid_prime256v1)) {
            return .{ .ecdsa_p256 = try ecdsa_p256.parsePublicKeySec1(key_bytes) };
        }
        if (oidEq(params, &oid_secp384r1)) {
            return .{ .ecdsa_p384 = EcdsaP384.PublicKey.fromSec1(key_bytes) catch return error.UnsupportedPublicKey };
        }
        return error.UnsupportedPublicKey;
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

/// Like `algorithmOid` but also returns the raw `parameters` TLV (if present) —
/// RSASSA-PSS carries its hash/MGF/salt there rather than in the OID.
fn algorithmOidParams(parent: x509.DerReader, seq_tlv: x509.Tlv) Error!struct {
    oid: []const u8,
    params: ?[]const u8,
} {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) params = (try r.readTlv()).raw;
    while (r.hasRemaining()) _ = try r.readTlv();
    return .{ .oid = oid.value, .params = params };
}

fn bitStringBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.BadCertificate;
    if (tlv.value[0] != 0) return error.BadCertificate;
    return tlv.value[1..];
}

fn positiveIntegerBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.tag != x509.Tag.integer or tlv.value.len == 0) return error.BadCertificate;
    // A DER INTEGER is two's-complement: a set high bit on the *first* byte means
    // negative. Positive values whose magnitude MSB is set carry a leading 0x00
    // sign byte, which we strip to get the unsigned magnitude. (The previous
    // check tested the high bit *after* stripping, wrongly rejecting every
    // RSA modulus, whose magnitude MSB is always set.)
    if (tlv.value[0] & 0x80 != 0) return error.BadCertificate; // negative
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..]; // drop the sign byte
    if (v.len == 0) return error.BadCertificate;
    return v;
}

fn oidEq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const oid_rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
const oid_sha256_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
const oid_sha384_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
const oid_sha512_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
const oid_rsassa_pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_secp384r1 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_ecdsa_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
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

test "ClientHello advertises OCSP status_request" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const ext_block = clientHelloExtensions(ch.body).?;
    var ext_it = tls_extension.Iterator.init(ext_block);
    var saw = false;
    while (try ext_it.next()) |ext| {
        if (ext.ext_type == ext_status_request) {
            saw = true;
            try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0, 0 }, ext.data);
        }
    }
    try std.testing.expect(saw);
}

test "OCSP staple status decision rejects revoked and soft-passes good or absent" {
    var parsed = ocsp.Parsed{
        .der = &.{},
        .response_status = .successful,
        .basic_response_der = null,
        .tbs_response_data_der = &.{},
        .signature_algorithm_oid = &.{},
        .signature_value = &.{},
        .responses = undefined,
        .response_count = 1,
    };
    parsed.responses[0] = .{
        .hash_algorithm_oid = &.{},
        .issuer_name_hash = &.{},
        .issuer_key_hash = &.{},
        .serial = &[_]u8{0x10},
        .cert_status = .revoked,
        .this_update = "20260102030405Z",
        .next_update = null,
    };
    try std.testing.expectError(error.CertificateRevoked, enforceOcspStatusForSerial(parsed, &[_]u8{0x10}));

    parsed.responses[0].cert_status = .good;
    try enforceOcspStatusForSerial(parsed, &[_]u8{0x10});
    try enforceOcspStatusForSerial(parsed, &[_]u8{0x11});
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

    // A syntactically valid, zero-lifetime NewSessionTicket arrives first
    // (seq 0), then real application data (seq 1). Zero lifetime means it is
    // consumed as control but not persisted for resumption.
    var ticket_body_buf: [32]u8 = undefined;
    const ticket_body = try tls_session_ticket.encode(&ticket_body_buf, .{
        .ticket_lifetime = 0,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = &.{0xaa},
        .extensions = "",
    });
    var ticket_hs: std.ArrayList(u8) = .empty;
    defer ticket_hs.deinit(allocator);
    try writeHandshake(allocator, &ticket_hs, .new_session_ticket, ticket_body);
    const ticket = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 0, .handshake, ticket_hs.items);
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

test "applyToml toggles the tls debug_log flag and restores cleanly" {
    const saved = debug_log;
    defer debug_log = saved; // never leak the override into other tests
    const allocator = std.testing.allocator;

    var on = try toml.parse(allocator, "[tls]\ndebug_log = true\n");
    defer on.deinit(allocator);
    applyToml(&on);
    try std.testing.expectEqual(true, debug_log);

    var off = try toml.parse(allocator, "[tls]\ndebug_log = false\n");
    defer off.deinit(allocator);
    applyToml(&off);
    try std.testing.expectEqual(false, debug_log);

    // Absent key leaves the current value unchanged.
    debug_log = true;
    var none = try toml.parse(allocator, "[server]\nname = \"mz\"\n");
    defer none.deinit(allocator);
    applyToml(&none);
    try std.testing.expectEqual(true, debug_log);
}

/// Build a HelloRetryRequest plaintext record carrying a cookie, for the given
/// client session_id. Used only by the HRR test below.
fn buildTestHrr(allocator: Allocator, session_id: []const u8, cookie: []const u8) ![]u8 {
    var ext: std.ArrayList(u8) = .empty;
    defer ext.deinit(allocator);
    // supported_versions (server form): selected_version = TLS 1.3.
    try appendU16(allocator, &ext, @intFromEnum(tls_extension.ExtensionType.supported_versions));
    try appendU16(allocator, &ext, 2);
    try appendU16(allocator, &ext, tls_supported_versions.tls13);
    // cookie: opaque cookie<1..2^16-1> (u16 length + bytes).
    try appendU16(allocator, &ext, @intFromEnum(tls_extension.ExtensionType.cookie));
    try appendU16(allocator, &ext, @intCast(2 + cookie.len));
    try appendU16(allocator, &ext, @intCast(cookie.len));
    try ext.appendSlice(allocator, cookie);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, tls_record.legacy_record_version);
    try body.appendSlice(allocator, &hello_retry_request_random);
    try body.append(allocator, @intCast(session_id.len));
    try body.appendSlice(allocator, session_id);
    try appendU16(allocator, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
    try body.append(allocator, 0); // null compression
    try appendU16(allocator, &body, @intCast(ext.items.len));
    try body.appendSlice(allocator, ext.items);

    var hs: std.ArrayList(u8) = .empty;
    defer hs.deinit(allocator);
    try writeHandshake(allocator, &hs, .server_hello, body.items);
    return writePlainRecord(allocator, .handshake, hs.items);
}

test "HelloRetryRequest: client echoes the cookie, reuses its random, rejects a second HRR" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "irc.test", .trust_anchors = &.{} });
    defer client.deinit();

    const ch1 = try client.start();
    defer allocator.free(ch1);
    // ClientHello random sits at record(5) + handshake header(4) + legacy_version(2).
    const ch1_random = ch1[11..43];

    const cookie = "retry-cookie-1234";
    const hrr = try buildTestHrr(allocator, &client.legacy_session_id, cookie);
    defer allocator.free(hrr);

    const ch2 = switch (try client.feed(hrr)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer allocator.free(ch2);

    // ClientHello2 must carry the cookie and reuse ClientHello1's random.
    try std.testing.expect(std.mem.indexOf(u8, ch2, cookie) != null);
    try std.testing.expectEqualSlices(u8, ch1_random, ch2[11..43]);
    try std.testing.expect(client.hrr_seen);

    // A second HelloRetryRequest is fatal (RFC 8446 §4.1.4).
    const hrr2 = try buildTestHrr(allocator, &client.legacy_session_id, cookie);
    defer allocator.free(hrr2);
    try std.testing.expectError(error.BadHandshake, client.feed(hrr2));
}

test "dnsConstraintMatches follows RFC 5280 subtree rules" {
    try std.testing.expect(dnsConstraintMatches("example.com", "example.com"));
    try std.testing.expect(dnsConstraintMatches("example.com", "host.example.com"));
    try std.testing.expect(dnsConstraintMatches("example.com", "a.b.example.com"));
    try std.testing.expect(!dnsConstraintMatches("example.com", "notexample.com"));
    try std.testing.expect(!dnsConstraintMatches("example.com", "example.com.evil.com"));
    try std.testing.expect(!dnsConstraintMatches("example.com", "other.com"));
    // Empty constraint matches everything; leading-dot matches subdomains only.
    try std.testing.expect(dnsConstraintMatches("", "anything.test"));
    try std.testing.expect(dnsConstraintMatches(".example.com", "host.example.com"));
    try std.testing.expect(!dnsConstraintMatches(".example.com", "example.com"));
}

test "enforceNameConstraints applies permitted + excluded dNSName subtrees" {
    var issuer = std.mem.zeroes(x509.Certificate);
    issuer.name_constraints_present = true;
    issuer.nc_permitted_dns[0] = "example.com";
    issuer.nc_permitted_dns_count = 1;
    issuer.nc_excluded_dns[0] = "bad.example.com";
    issuer.nc_excluded_dns_count = 1;

    var leaf = std.mem.zeroes(x509.Certificate);
    leaf.san_dns_count = 1;

    leaf.san_dns[0] = "host.example.com"; // permitted, not excluded
    try enforceNameConstraints(issuer, leaf);

    leaf.san_dns[0] = "host.other.com"; // outside the permitted subtree
    try std.testing.expectError(error.BadCertificate, enforceNameConstraints(issuer, leaf));

    leaf.san_dns[0] = "bad.example.com"; // excluded wins over permitted
    try std.testing.expectError(error.BadCertificate, enforceNameConstraints(issuer, leaf));

    // A CA without NameConstraints imposes nothing.
    const plain = std.mem.zeroes(x509.Certificate);
    leaf.san_dns[0] = "anything.test";
    try enforceNameConstraints(plain, leaf);
}

test {
    std.testing.refAllDecls(@This());
}

test "validateCertificateRequest enforces RFC 8446 §4.3.2 framing" {
    // Well-formed: empty context, exact extensions vector, one
    // signature_algorithms extension listing ed25519 + ecdsa_secp256r1_sha256.
    const good = [_]u8{
        0x00, // empty certificate_request_context
        0x00, 0x0a, // extensions total length (10)
        0x00, 0x0d, 0x00, 0x06, // signature_algorithms, data length 6
        0x00, 0x04, 0x08, 0x07, 0x04, 0x03, // list length 4: ed25519, ecdsa_p256
    };
    try validateCertificateRequest(&good);

    // The historical server bug: a second (doubled) extensions-length prefix.
    // Real clients reject this with "Invalid TLS extensions length field".
    const doubled = [_]u8{
        0x00,
        0x00, 0x0c, // outer (spurious) extensions length
        0x00, 0x0a, // inner extensions length — parsed as an extension type
        0x00, 0x0d,
        0x00, 0x06,
        0x00, 0x04,
        0x08, 0x07,
        0x04, 0x03,
    };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&doubled));

    // A non-empty context is illegal in the main handshake.
    const nonempty_ctx = [_]u8{ 0x01, 0xaa, 0x00, 0x0a, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x08, 0x07, 0x04, 0x03 };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&nonempty_ctx));

    // Missing the mandatory signature_algorithms extension.
    const no_sigalgs = [_]u8{ 0x00, 0x00, 0x04, 0x00, 0x2b, 0x00, 0x00 };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&no_sigalgs));

    // Extensions vector shorter than the remaining body (trailing garbage).
    const trailing = good ++ [_]u8{0x00};
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&trailing));

    // signature_algorithms list length disagreeing with the extension data.
    const bad_list = [_]u8{
        0x00,
        0x00,
        0x0a,
        0x00,
        0x0d,
        0x00,
        0x06,
        0x00, 0x06, 0x08, 0x07, 0x04, 0x03, // claims 6 list bytes, has 4
    };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&bad_list));
}

test "leaf RSA key survives the hs_plain consume (regression: copied, not borrowed)" {
    // A Certificate handshake whose RSA leaf-key bytes get clobbered after parse
    // (simulating the post-message consume of hs_plain). Pre-fix the key borrowed
    // those bytes and read garbage at CertificateVerify time; it must now be owned.
    const cert_der = [_]u8{ 0x30, 0x82, 0x03, 0x07, 0x30, 0x82, 0x01, 0xef, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x53, 0xd9, 0xd0, 0x2f, 0x30, 0xba, 0xc3, 0x6e, 0xa1, 0xb7, 0x63, 0xe4, 0x7b, 0xfe, 0x9c, 0x90, 0xdd, 0x91, 0xb3, 0xad, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x72, 0x73, 0x61, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36, 0x31, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36, 0x31, 0x33, 0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x72, 0x73, 0x61, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xef, 0x05, 0x77, 0x1d, 0xde, 0x6a, 0x66, 0xdf, 0xf9, 0x2c, 0x29, 0xbf, 0x5a, 0xb6, 0x97, 0x86, 0xa2, 0xd1, 0x8b, 0x6c, 0xfa, 0x28, 0x6b, 0x30, 0x1f, 0x00, 0x11, 0x2e, 0x11, 0x0d, 0x84, 0x57, 0x73, 0x9e, 0x0f, 0xb2, 0xd5, 0x50, 0x1a, 0x1c, 0xc4, 0x24, 0xdb, 0x95, 0x70, 0xba, 0x05, 0x6d, 0xa7, 0x85, 0x1f, 0x71, 0xc2, 0x6c, 0x42, 0x74, 0xd1, 0x3a, 0x35, 0x58, 0x9d, 0x70, 0x13, 0x07, 0xc0, 0x30, 0x1e, 0xf6, 0x9c, 0xfc, 0xe8, 0xb7, 0xf1, 0xa6, 0x4b, 0xa3, 0xbe, 0x52, 0x37, 0x5f, 0x4b, 0x73, 0x1f, 0x76, 0x11, 0xd3, 0xf4, 0x9d, 0x01, 0x34, 0xa0, 0x59, 0x09, 0x3d, 0x90, 0x9c, 0x2b, 0xb5, 0x5c, 0x24, 0x47, 0xec, 0x77, 0x08, 0x98, 0x56, 0x59, 0x6a, 0xda, 0x64, 0xf0, 0x27, 0x4a, 0x41, 0xcf, 0xba, 0x6c, 0x22, 0xc2, 0x51, 0x98, 0xe0, 0xc2, 0xb6, 0x12, 0xc7, 0xbc, 0x8f, 0xcb, 0x2b, 0x06, 0x7d, 0xac, 0xb3, 0x25, 0x4c, 0x82, 0x4d, 0x86, 0xb4, 0xb8, 0xac, 0x7d, 0xfc, 0xbf, 0xdf, 0xc2, 0x73, 0xa5, 0x73, 0x5b, 0x6e, 0x26, 0x4a, 0x44, 0x5b, 0xe5, 0xaa, 0xa6, 0xa3, 0x68, 0x88, 0x0e, 0x95, 0xbf, 0x82, 0x53, 0xf0, 0xd3, 0xe6, 0x34, 0xc1, 0x41, 0xd4, 0x48, 0x34, 0x3b, 0x63, 0xb8, 0x4b, 0xdd, 0xfb, 0x7f, 0x8e, 0xcf, 0xfd, 0x95, 0x96, 0x41, 0xe3, 0x7b, 0xf9, 0x4e, 0xc5, 0x46, 0xa4, 0x7b, 0xde, 0x42, 0x37, 0x2b, 0x54, 0xb0, 0x5f, 0x12, 0x77, 0x01, 0x23, 0x5c, 0xb7, 0x6c, 0x77, 0xc0, 0xe2, 0x4d, 0x87, 0x07, 0x9e, 0xed, 0x45, 0x34, 0x1b, 0x44, 0x4e, 0x02, 0x22, 0xfa, 0x47, 0x81, 0x12, 0xf2, 0xc9, 0xc6, 0x2c, 0xa8, 0x46, 0x2b, 0x0d, 0xf1, 0x4d, 0x94, 0x14, 0x3f, 0x88, 0x81, 0x84, 0xe2, 0x10, 0x8d, 0xd1, 0x99, 0x37, 0xfa, 0x15, 0x61, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x1a, 0xec, 0x86, 0x56, 0xd0, 0x23, 0x92, 0x61, 0x5e, 0x10, 0x5b, 0xb5, 0xc0, 0x0f, 0xa8, 0xef, 0xfe, 0xdd, 0x3e, 0xce, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x1a, 0xec, 0x86, 0x56, 0xd0, 0x23, 0x92, 0x61, 0x5e, 0x10, 0x5b, 0xb5, 0xc0, 0x0f, 0xa8, 0xef, 0xfe, 0xdd, 0x3e, 0xce, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x47, 0xe6, 0x09, 0x03, 0xef, 0x69, 0x19, 0x42, 0x65, 0xfd, 0x25, 0xb4, 0xe2, 0xb4, 0xf7, 0xea, 0x57, 0x60, 0x83, 0x89, 0x1e, 0x5e, 0x0a, 0x55, 0x90, 0xf9, 0xee, 0x92, 0x21, 0x5c, 0x2d, 0x0e, 0x2b, 0xc7, 0x8e, 0x89, 0xdb, 0x23, 0xfe, 0x53, 0x9b, 0xd2, 0x22, 0x68, 0x85, 0xe3, 0xd3, 0x52, 0xfd, 0x11, 0x43, 0xc2, 0xf2, 0x70, 0x3d, 0x9b, 0x77, 0x44, 0x5e, 0xe3, 0xcc, 0x64, 0x8b, 0xaa, 0x5d, 0x82, 0x26, 0xa5, 0xd0, 0x3b, 0x06, 0xc4, 0xf0, 0xa4, 0x18, 0x64, 0xe2, 0x13, 0xf6, 0x66, 0xe4, 0xda, 0xbb, 0x97, 0xce, 0x10, 0xcd, 0x0a, 0xa9, 0xd6, 0x71, 0x90, 0x16, 0x5e, 0x2d, 0xda, 0x53, 0xf2, 0xc6, 0xce, 0x8a, 0x51, 0xac, 0x17, 0x29, 0x63, 0xc2, 0x9b, 0x41, 0xda, 0xb7, 0x75, 0x18, 0x0a, 0xc9, 0xe3, 0x0c, 0xa8, 0x9f, 0x52, 0x5e, 0xe6, 0x3f, 0xef, 0x3d, 0x73, 0x3a, 0xe3, 0x60, 0x30, 0xed, 0x98, 0x88, 0x44, 0x52, 0x28, 0x30, 0x92, 0xf3, 0xb5, 0xe7, 0x29, 0x13, 0x3d, 0x2e, 0x2f, 0x82, 0xe1, 0x55, 0x1e, 0x53, 0x12, 0x38, 0xb4, 0x9f, 0xc4, 0x2a, 0xca, 0xc6, 0xaf, 0xcf, 0xe2, 0xb6, 0x20, 0x7b, 0xe1, 0xee, 0x6b, 0x7d, 0x02, 0x83, 0xdb, 0x64, 0x37, 0x5a, 0x84, 0x8c, 0xe2, 0xa9, 0xec, 0x9e, 0xc0, 0x6f, 0x04, 0x44, 0x6a, 0xa4, 0xc1, 0xfe, 0x75, 0x81, 0xbb, 0x4f, 0x37, 0x20, 0x97, 0x64, 0xdd, 0x0e, 0xcc, 0x85, 0x71, 0x2a, 0x45, 0x61, 0x7d, 0x08, 0x1a, 0x5c, 0xa8, 0xc3, 0x35, 0x6a, 0xa5, 0x7e, 0x69, 0x14, 0x9b, 0x2b, 0x1c, 0xf2, 0x13, 0x66, 0x5d, 0xaf, 0xf2, 0x14, 0xc3, 0xad, 0xa2, 0x55, 0x1d, 0xe3, 0x7d, 0x52, 0x4b, 0xf1, 0x2b, 0xf1, 0xa2, 0x81, 0xf7, 0xcf, 0x92, 0x40, 0xf5, 0x1f, 0x0a, 0xdb, 0x22, 0x5a, 0xa7, 0x91, 0x3f, 0x0c, 0xb7 };
    const a = std.testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try body.append(a, 0); // certificate_request_context length = 0
    const entry_len: usize = 3 + cert_der.len + 2; // certLen(3) + cert + extLen(2)
    try body.append(a, @intCast((entry_len >> 16) & 0xff));
    try body.append(a, @intCast((entry_len >> 8) & 0xff));
    try body.append(a, @intCast(entry_len & 0xff));
    try body.append(a, @intCast((cert_der.len >> 16) & 0xff));
    try body.append(a, @intCast((cert_der.len >> 8) & 0xff));
    try body.append(a, @intCast(cert_der.len & 0xff));
    try body.appendSlice(a, &cert_der);
    try body.append(a, 0);
    try body.append(a, 0); // extensions length = 0

    var client = try Client.init(a, .{ .server_name = "rsa.test", .trust_anchors = &.{} });
    defer client.deinit();
    client.skipServerCertVerifyForTest();
    try client.parseAndVerifyCertificate(body.items);

    const lk = client.leaf_key.?;
    try std.testing.expect(lk == .rsa);
    var n_snapshot: [rsa_verify.max_bytes]u8 = undefined;
    const n_len = lk.rsa.n.len;
    @memcpy(n_snapshot[0..n_len], lk.rsa.n);

    // Clobber the source buffer; an owned key is unaffected, a borrowed one reads 0xAA.
    @memset(body.items, 0xAA);
    try std.testing.expectEqualSlices(u8, n_snapshot[0..n_len], client.leaf_key.?.rsa.n);
    try std.testing.expect(client.leaf_key.?.rsa.n[0] != 0xAA);
    try std.testing.expect(client.leaf_key.?.rsa.e.len >= 1 and client.leaf_key.?.rsa.e[client.leaf_key.?.rsa.e.len - 1] == 0x01);
}
