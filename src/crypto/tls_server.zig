// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socketless TLS 1.3 server handshake state machine for the inbound IRC-over-TLS
//! listener. The daemon feeds raw bytes from the socket via `feed()` and writes
//! back the returned flight; once `handshakeDone()` is true it streams
//! application data through `encrypt()` / `decrypt()`.
//!
//! Scope (slice B of the TLS arc): TLS 1.3 only, X25519 key exchange, an
//! Ed25519, ECDSA-P256, or RSA leaf certificate (CertificateVerify signed with
//! the matching TLS 1.3 scheme), and the AES-128-GCM / ChaCha20-Poly1305 suites.
//! Interop is pinned by loopback tests against the in-repo standards client
//! `tls_client.Client`. HelloRetryRequest (RFC 8446 §4.1.4) is supported: when a
//! ClientHello offers no key_share the server can use but does advertise a group
//! it supports, the server sends a single HRR requesting that group and folds the
//! `message_hash` synthetic (§4.4.1) into the transcript before the retry.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const kx = @import("kx.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const hkdf = @import("hkdf_tls13.zig");
const tls_resumption = @import("tls_resumption.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_sign = @import("rsa_sign.zig");
const rsa_verify = @import("rsa_verify.zig");
const Sha256 = hkdf.Sha256;
const Sha384 = hkdf.Sha384;
/// Largest transcript-hash / traffic-secret length handled (SHA-384).
const max_hash_len = Sha384.hash_len;

const HashAlg = enum { sha256, sha384 };
const tls_record = @import("tls_record.zig");
const tls_keyshare = @import("../proto/tls_keyshare.zig");
const supported_groups = @import("../proto/supported_groups.zig");
const cert_compression = @import("../proto/cert_compression.zig");
const sni = @import("../proto/sni.zig");
const tls_extension = @import("../proto/tls_extension.zig");
const tls_supported_versions = @import("../proto/tls_supported_versions.zig");
const tls_signature_scheme = @import("../proto/tls_signature_scheme.zig");
const tls_finished = @import("../proto/tls_finished.zig");
const tls_alpn = @import("../proto/tls_alpn.zig");
const tls_psk = @import("../proto/tls_psk.zig");
const tls_session_ticket = @import("../proto/tls_session_ticket.zig");
const x509 = @import("x509.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const MlKem768 = std.crypto.kem.ml_kem.MLKem768;

// ── X25519MLKEM768 (TLS named group 0x11ec) wire sizes ──────────────────────
// Per the spec the ML-KEM-768 part comes first, then X25519, in the client share,
// the server share, and the combined shared secret.
const mlkem_ek_len = MlKem768.PublicKey.encoded_length; // 1184 — client encapsulation key
const mlkem_ct_len = MlKem768.ciphertext_length; // 1088 — server ciphertext
const x25519_pub_len = kx.X25519Kx.public_len; // 32
const hybrid_client_share_len = mlkem_ek_len + x25519_pub_len; // 1216
const hybrid_server_share_len = mlkem_ct_len + x25519_pub_len; // 1120

/// Result of the TLS 1.3 (EC)DHE / hybrid key exchange: 32 bytes for a classical
/// group (x25519 / secp256r1) or 64 bytes for X25519MLKEM768 (mlkem_ss || x25519_ss).
const KexShared = struct { buf: [64]u8 = undefined, len: usize = 0 };

/// Outcome of parsing a ClientHello: either we hold a usable (EC)DHE secret and
/// build the server flight, or the client offered no key_share we can use and we
/// must send a HelloRetryRequest asking it to retry with `retry` (RFC 8446 §4.1.4).
const ClientHelloOutcome = union(enum) {
    proceed: KexShared,
    retry: tls_keyshare.NamedGroup,
};

/// RFC 8446 §4.1.3: the special ServerHello.random marking a message as a
/// HelloRetryRequest — SHA-256 of the ASCII string "HelloRetryRequest".
const hello_retry_request_random = [_]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

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
    NoSigningKey,
    LeafKeyMismatch,
} || Allocator.Error || tls_record.Error || hkdf.Error ||
    tls_extension.Error || tls_alpn.Error || tls_keyshare.Error || tls_supported_versions.Error ||
    tls_signature_scheme.Error || tls_psk.Error || tls_session_ticket.EncodeError ||
    tls_resumption.Error || cert_compression.Error;

pub const Config = struct {
    /// DER certificates, leaf first. The leaf SPKI must match the configured
    /// signing key used for CertificateVerify.
    cert_chain: []const []const u8,
    /// Ed25519 key pair whose public key is the leaf certificate's SPKI; signs
    /// CertificateVerify with the `ed25519` scheme. This remains optional only
    /// so ECDSA-only configs can omit it; existing `.signing_key = kp` callers
    /// still coerce to `?Ed25519.KeyPair`.
    signing_key: ?Ed25519.KeyPair = null,
    /// ECDSA-P256 key pair whose public key is the leaf certificate's SPKI;
    /// signs CertificateVerify with `ecdsa_secp256r1_sha256`. When set, this
    /// takes precedence over `signing_key`.
    ecdsa_p256_signing_key: ?ecdsa_p256.KeyPair = null,
    /// RSA private key whose public key is the leaf certificate's SPKI; signs
    /// CertificateVerify with `rsa_pss_rsae_sha256`. When set, this takes
    /// precedence over the Ed25519 and ECDSA signing keys.
    rsa_signing_key: ?rsa_sign.PrivateKey = null,
    /// ALPN protocols the server is willing to select, in preference order.
    /// Empty disables ALPN negotiation.
    alpn_protocols: []const []const u8 = &.{},
    /// Mutual TLS: when true the server sends a CertificateRequest and verifies
    /// the client's Certificate + CertificateVerify (Ed25519). CertFP pins by
    /// fingerprint, so any presented leaf is accepted once its possession proof
    /// verifies — there is no CA-chain requirement. A client that declines (empty
    /// Certificate) still completes; `clientCertDer()` stays null. Default false
    /// is fully backward-compatible (no CertificateRequest).
    request_client_cert: bool = false,
    /// Enable one post-handshake NewSessionTicket after the client Finished.
    /// The default is false so existing full handshakes remain byte-for-byte
    /// unchanged unless the caller opts into resumption.
    enable_session_tickets: bool = false,
    /// RFC 8879: when true, and a client offers `compress_certificate` with an
    /// algorithm we can produce (zlib), the Certificate message is sent as a
    /// zlib-compressed `CompressedCertificate` — but only when that actually
    /// shrinks it. Default false ⇒ the handshake stays byte-for-byte identical
    /// until opted in, and even then only clients that advertised support (and
    /// therefore can decode it) ever receive the compressed form.
    enable_cert_compression: bool = false,
    /// Optional reusable ticket key. When omitted, `Server.init` generates a
    /// fresh per-server key; callers can retrieve it with `ticketKey()`.
    ticket_key: ?tls_resumption.TicketKey = null,
    /// Optional PREVIOUS ticket key retained across a rotation. New tickets are
    /// always sealed with `ticket_key`; on open, a ticket that fails under the
    /// current key is retried under this one, so rotating the key (set
    /// `previous_ticket_key` = the old `ticket_key`, install a new `ticket_key`)
    /// does not drop tickets still in flight. Mirrors cloak `previous_secret`.
    previous_ticket_key: ?tls_resumption.TicketKey = null,
    /// A DER-encoded OCSPResponse to staple in the leaf CertificateEntry when the
    /// client offers status_request (RFC 6066 / RFC 8446 §4.4.2.1). Empty = no
    /// staple (the CertificateEntry stays byte-identical to the unstapled wire).
    ocsp_staple: []const u8 = &.{},
    /// Lifetime advertised in NewSessionTicket.
    ticket_lifetime_seconds: u32 = 86_400,
    /// Maximum TLS 1.3 early data bytes advertised in NewSessionTicket and
    /// sealed into the local ticket. Zero disables 0-RTT acceptance.
    max_early_data_size: u32 = 0,
    /// Current wall-clock time (Unix seconds), supplied by the caller (this pure
    /// engine takes no clock). When set, it stamps issued NewSessionTickets and
    /// enforces the ticket lifetime on resumption (expired/future tickets are
    /// rejected, falling back to a full handshake). When null, lifetime is not
    /// enforced (back-compatible).
    now_unix_seconds: ?i64 = null,
    /// Shared 0-RTT anti-replay guard. When set, accepted-early-data is gated on
    /// the guard (a replayed PSK binder still resumes via 1-RTT but its early
    /// data is not accepted). The caller owns it and must serialize access if it
    /// is shared across threads. Null keeps the prior no-anti-replay behavior.
    replay_guard: ?*tls_resumption.ReplayGuard = null,
    /// SNI-based additional certificates (RFC 6066). When a ClientHello's
    /// `server_name` matches an entry, the server presents that entry's chain and
    /// signs CertificateVerify with its key (and staples its OCSP response)
    /// instead of the default top-level cert. First match wins; an absent or
    /// unmatched SNI falls back to the default cert. Empty ⇒ SNI is not consulted
    /// and the handshake is byte-identical to before.
    sni_certs: []const SniCert = &.{},
};

/// One SNI-selectable certificate (see `Config.sni_certs`). The signing-key
/// precedence mirrors the top-level Config: rsa › ecdsa_p256 › ed25519.
pub const SniCert = struct {
    /// Host names this entry answers to, matched case-insensitively. A leading
    /// `*.` wildcard matches exactly one left-most label (RFC 6125 §6.4.3).
    /// An empty list never matches.
    server_names: []const []const u8,
    /// DER certificates, leaf first (same shape as `Config.cert_chain`).
    cert_chain: []const []const u8,
    signing_key: ?Ed25519.KeyPair = null,
    ecdsa_p256_signing_key: ?ecdsa_p256.KeyPair = null,
    rsa_signing_key: ?rsa_sign.PrivateKey = null,
    /// Optional DER OCSPResponse to staple for this cert (like `Config.ocsp_staple`).
    ocsp_staple: []const u8 = &.{},
};

pub const SigningKey = union(enum) {
    ed25519: Ed25519.KeyPair,
    ecdsa_p256: ecdsa_p256.KeyPair,
    rsa: rsa_sign.PrivateKey,
};

pub const FeedResult = union(enum) {
    need_more,
    bytes_to_send: []u8,
};

/// TLS Alert level (RFC 8446 §6). TLS 1.3 treats every alert this daemon sends as
/// fatal (a `warning` alert other than close_notify is not used).
pub const AlertLevel = enum(u8) { warning = 1, fatal = 2 };

/// The subset of RFC 8446 §6 AlertDescription codes this server maps handshake
/// errors to. Non-exhaustive: only the codes we actually emit are named.
pub const AlertDescription = enum(u8) {
    handshake_failure = 40,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    internal_error = 80,
    missing_extension = 109,
    _,
};

/// Map a handshake-processing error to the fatal alert a peer should receive
/// (RFC 8446 §6), or null when no alert should be sent (`OutOfMemory` — we can't
/// allocate a record anyway). Accepts `anyerror` so the daemon can pass the
/// merged `TlsConn` error set without coupling to it.
pub fn alertDescriptionForError(err: anyerror) ?AlertDescription {
    return switch (err) {
        error.OutOfMemory => null,
        error.ProtocolVersion => .protocol_version,
        error.MissingExtension => .missing_extension,
        error.UnsupportedGroup, error.UnsupportedCipherSuite => .handshake_failure,
        error.FinishedMismatch => .decrypt_error, // (post-ServerHello ⇒ sent encrypted, see takeAlert)
        error.NoCertificate, error.NoSigningKey, error.LeafKeyMismatch => .internal_error,
        // Malformed handshake bytes or a wrong first-record content type: the peer
        // sent something we couldn't decode.
        error.BadHandshake, error.BadRecord => .decode_error,
        // Any other parse/negotiation failure: a generic fatal handshake_failure.
        else => .handshake_failure,
    };
}

/// Encode a fatal-alert PLAINTEXT record (content_type 21) for `err`, or null
/// when no alert should be sent. Plaintext is correct only before the ServerHello
/// (no handshake keys yet); post-ServerHello alerts must be encrypted (see
/// `Server.takeAlert`). Caller owns the returned buffer.
pub fn alertRecordForError(allocator: Allocator, err: anyerror) ?[]u8 {
    const desc = alertDescriptionForError(err) orelse return null;
    const body = [_]u8{ @intFromEnum(AlertLevel.fatal), @intFromEnum(desc) };
    return writePlainRecord(allocator, .alert, &body) catch null;
}

/// Encode a fatal-alert ENCRYPTED record for `err` (RFC 8446 §6), or null when
/// no alert should be sent. The alert travels as a TLSInnerPlaintext with inner
/// content_type `alert` (21) sealed under `keys`/`seq`, so the record's OUTER
/// content_type on the wire is application_data (23). Correct only AFTER the
/// ServerHello, when handshake/application keys exist. The caller MUST pass the
/// connection's currently-active server write keys + the next-unused write seq
/// for its state and must not reuse `seq` afterward (see `Server.takeAlert`).
/// Caller owns the returned buffer.
fn alertRecordEncrypted(
    allocator: Allocator,
    err: anyerror,
    suite: CipherSuite,
    keys: *const TrafficKeys,
    seq: u64,
) ?[]u8 {
    const desc = alertDescriptionForError(err) orelse return null;
    const body = [_]u8{ @intFromEnum(AlertLevel.fatal), @intFromEnum(desc) };
    return sealRecordAlloc(allocator, suite, keys, seq, .alert, &body) catch null;
}

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

    /// IANA registry name of the suite (static string, e.g.
    /// "TLS_AES_128_GCM_SHA256") — surfaced to users in WHOIS 671.
    fn name(self: CipherSuite) []const u8 {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => "TLS_AES_128_GCM_SHA256",
            .tls_aes_256_gcm_sha384 => "TLS_AES_256_GCM_SHA384",
            .tls_chacha20_poly1305_sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        };
    }
};

const State = enum {
    idle,
    wait_client_hello,
    // After a HelloRetryRequest: await the client's second ClientHello, which
    // must carry a key_share for the group we requested (RFC 8446 §4.1.4).
    wait_second_client_hello,
    // mTLS: the client's final flight is Certificate -> CertificateVerify ->
    // Finished. Without mTLS the server jumps straight to wait_client_finished.
    wait_client_cert,
    wait_client_cert_verify,
    wait_client_finished,
    connected,
};

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
    ticket_key: tls_resumption.TicketKey,

    x25519_pair: kx.X25519Kx.KeyPair,
    p256_pair: ecdh_p256.KeyPair,
    /// Group selected from the client's key_share. The server prefers X25519, then
    /// secp256r1, and falls back to the X25519MLKEM768 hybrid when the client
    /// offered only that (Chrome's post-quantum default).
    selected_group: tls_keyshare.NamedGroup = .x25519,
    /// The server's X25519MLKEM768 key_share to emit (ml-kem ciphertext || x25519
    /// public key). Valid only when `selected_group == .x25519mlkem768`.
    hybrid_keyshare: [hybrid_server_share_len]u8 = undefined,
    /// HelloRetryRequest state (RFC 8446 §4.1.4). `hrr_sent` guards against
    /// issuing more than one HRR and selects the `message_hash` transcript path;
    /// `hrr_group` is the group we asked the client to retry with — the second
    /// ClientHello's key_share must supply exactly that group; `hrr_suite` is the
    /// suite committed in the HRR, which ClientHello2 must not change.
    hrr_sent: bool = false,
    hrr_group: tls_keyshare.NamedGroup = .x25519,
    hrr_suite: ?CipherSuite = null,
    selected_suite: ?CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    resumed: bool = false,
    early_data_offered: bool = false,
    early_data_accepted: bool = false,
    early_data_done: bool = false,
    accepted_early_data_limit: u32 = 0,
    /// PSK binder of the accepted resumption (for the 0-RTT anti-replay check).
    accepted_binder: [tls_resumption.max_binder_len]u8 = undefined,
    accepted_binder_len: usize = 0,
    legacy_session_id: [32]u8 = [_]u8{0} ** 32,
    session_id_len: usize = 0,

    transcript: std.ArrayList(u8) = .empty,
    recv_buf: std.ArrayList(u8) = .empty,

    /// Post-handshake records the server must send back (a KeyUpdate reply when
    /// the client requested one). Drained by the caller via `takePendingSend`.
    post_handshake_send: std.ArrayList(u8) = .empty,
    /// Decrypted accepted 0-RTT application bytes. Ownership transfers through
    /// `takeEarlyData`; bytes are accumulated before the handshake completes.
    early_data_buf: std.ArrayList(u8) = .empty,

    /// mTLS: whether a CertificateRequest is sent + the client flight verified.
    request_client_cert: bool = false,
    /// Decrypted client-flight handshake bytes accumulated across records, so a
    /// Certificate/CertificateVerify/Finished split over records reassembles.
    client_flight: std.ArrayList(u8) = .empty,
    /// Verified client leaf DER (owned), or null when no cert was presented /
    /// the possession proof failed. SHA-256 of this is the SASL EXTERNAL CertFP.
    client_cert_der: ?[]u8 = null,
    /// Public key parsed from the presented leaf (for CertificateVerify).
    client_leaf_key: ?ClientLeafKey = null,

    // Stored at the maximum hash length (SHA-384); only the first
    // `selected_suite.hashAlg()` digest bytes are live for a given connection.
    early_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    accepted_psk: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
    accepted_psk_len: usize = 0,
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
    early_read_seq: u64 = 0,
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,
    /// RFC 8449 record_size_limit advertised by the peer: the max TLSInnerPlaintext
    /// length it will accept. Default 2^14+1 = "no restriction beyond the protocol
    /// max". Outbound application records are fragmented to honor it.
    peer_record_size_limit: usize = tls_record.max_plaintext_len + 1,
    /// The client offered the status_request extension (wants an OCSP staple).
    /// When true AND `config.ocsp_staple` is non-empty, the leaf CertificateEntry
    /// carries the staple.
    client_requested_ocsp: bool = false,
    /// RFC 8879: the compression algorithm negotiated from the client's
    /// `compress_certificate` extension (only ever `.zlib`, and only when
    /// `config.enable_cert_compression`). Null ⇒ send a plain Certificate.
    /// Re-derived per ClientHello (so a HelloRetryRequest re-reads it).
    cert_compression: ?cert_compression.Algorithm = null,
    /// Index into `config.sni_certs` selected by the ClientHello's server_name,
    /// or null for the default top-level cert. Pinned on ClientHello1 and NOT
    /// re-derived on ClientHello2 (a HelloRetryRequest must not change the cert).
    sni_cert: ?usize = null,
    /// SHA-256 of the SNI host_name advertised in ClientHello1 (null ⇒ no
    /// server_name was present). RFC 8446 §4.1.2 excludes SNI from the fields a
    /// client may change across a HelloRetryRequest, so ClientHello2 must carry
    /// the identical host_name; a mismatch is rejected (it would otherwise swap
    /// the presented cert out from under the pinned `sni_cert`).
    ch1_sni_digest: ?[32]u8 = null,

    pub fn init(allocator: Allocator, config: Config) Error!Server {
        if (config.cert_chain.len == 0) return error.NoCertificate;
        const default_key = activeSigningKey(config) orelse return error.NoSigningKey;
        // Fail fast when the configured signing key's type can't match the leaf it
        // must sign for — otherwise every handshake produces a CertificateVerify
        // the client rejects (mismatched key vs presented leaf). A boot-time error
        // is far clearer than a silent per-handshake failure.
        if (!leafKeyKindMatches(config.cert_chain[0], default_key)) return error.LeafKeyMismatch;
        // Every SNI cert must be independently presentable (chain + a signing key
        // whose type matches its leaf's public key).
        for (config.sni_certs) |entry| {
            if (entry.cert_chain.len == 0) return error.NoCertificate;
            const entry_key = sniEntrySigningKey(entry) orelse return error.NoSigningKey;
            if (!leafKeyKindMatches(entry.cert_chain[0], entry_key)) return error.LeafKeyMismatch;
        }
        var seed: [kx.X25519Kx.seed_len]u8 = undefined;
        try osEntropy(&seed);
        defer secureZero(&seed);
        var ticket_key: tls_resumption.TicketKey = undefined;
        if (config.ticket_key) |key| {
            ticket_key = key;
        } else {
            try osEntropy(&ticket_key);
        }
        return .{
            .allocator = allocator,
            .config = config,
            .ticket_key = ticket_key,
            .state = .wait_client_hello,
            .request_client_cert = config.request_client_cert,
            .x25519_pair = kx.X25519Kx.generateDeterministic(seed) catch return error.BadState,
            .p256_pair = ecdh_p256.generate() catch return error.BadState,
        };
    }

    pub fn deinit(self: *Server) void {
        self.x25519_pair.wipe();
        secureZero(&self.p256_pair.secret);
        secureZero(&self.ticket_key);
        secureZero(&self.early_secret);
        secureZero(&self.accepted_psk);
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
        self.early_data_buf.deinit(self.allocator);
        self.client_flight.deinit(self.allocator);
        self.post_handshake_send.deinit(self.allocator);
        if (self.client_cert_der) |der| self.allocator.free(der);
        self.* = undefined;
    }

    pub fn handshakeDone(self: *const Server) bool {
        return self.state == .connected;
    }

    /// A fatal TLS alert (RFC 8446 §6) to send for the handshake error `err`
    /// BEFORE closing, so the peer learns why instead of seeing a bare reset.
    ///
    /// The record encoding depends on where the state machine is:
    ///   * `wait_client_hello` / `wait_second_client_hello` — before any
    ///     ServerHello, so no keys exist ⇒ a PLAINTEXT alert (content_type 21).
    ///   * `wait_client_cert` / `wait_client_cert_verify` / `wait_client_finished`
    ///     — the server has already sent its Finished under the handshake keys and
    ///     switched its write to the APPLICATION traffic keys (0.5-RTT semantics,
    ///     RFC 8446 §A.1). An alert here MUST be sealed under
    ///     `server_app_keys`/`app_write_seq` (outer content_type 23); a FinishedMismatch
    ///     (wait_client_finished) or a bad client Certificate/CertificateVerify
    ///     (wait_client_cert/_verify) surface in exactly these states. The write
    ///     seq is bumped so the nonce is never reused.
    ///   * `idle` (never fed) / `connected` (post-handshake; a record-layer fault
    ///     there is out of this path's scope) ⇒ null, caller closes bare.
    ///
    /// Caller owns the returned buffer.
    pub fn takeAlert(self: *Server, err: anyerror) ?[]u8 {
        switch (self.state) {
            .wait_client_hello, .wait_second_client_hello => return alertRecordForError(self.allocator, err),
            .wait_client_cert, .wait_client_cert_verify, .wait_client_finished => {
                const suite = self.selected_suite orelse return null;
                const rec = alertRecordEncrypted(self.allocator, err, suite, &self.server_app_keys, self.app_write_seq) orelse return null;
                self.app_write_seq += 1;
                return rec;
            },
            .idle, .connected => return null,
        }
    }

    /// RFC 8446 section 7.5 TLS exporter. Valid only after the handshake
    /// reaches connected state.
    pub fn exportKeyingMaterial(self: *const Server, label: []const u8, context: []const u8, out: []u8) Error!void {
        if (self.state != .connected) return error.BadState;
        if (!self.exporter_master_secret_ready) return error.BadState;
        switch (self.hashAlg()) {
            .sha256 => try self.exportKeyingMaterialT(Sha256, label, context, out),
            .sha384 => try self.exportKeyingMaterialT(Sha384, label, context, out),
        }
    }

    /// RFC 9266 tls-exporter channel binding for SCRAM-SHA-*-PLUS.
    pub fn channelBindingTlsExporter(self: *const Server, out: *[32]u8) Error!void {
        try self.exportKeyingMaterial("EXPORTER-Channel-Binding", "", out[0..]);
    }

    /// The verified client leaf DER (mTLS), or null. SHA-256 of this is the
    /// SASL EXTERNAL CertFP.
    pub fn clientCertDer(self: *const Server) ?[]const u8 {
        return self.client_cert_der;
    }

    pub fn selectedAlpn(self: *const Server) ?[]const u8 {
        return self.selected_alpn;
    }

    /// IANA name of the negotiated cipher suite ("TLS_AES_128_GCM_SHA256"),
    /// or null before the ServerHello selects one. The returned string is
    /// static — safe to retain for the connection's lifetime.
    pub fn cipherName(self: *const Server) ?[]const u8 {
        const suite = self.selected_suite orelse return null;
        return suite.name();
    }

    /// Return the per-server ticket key so a replacement `Server` can accept
    /// tickets issued by this instance.
    pub fn ticketKey(self: *const Server) tls_resumption.TicketKey {
        return self.ticket_key;
    }

    /// Cipher identity for Linux kTLS offload, deliberately decoupled from the
    /// daemon's `ktls` module (crypto must not depend on the daemon). The daemon
    /// maps this to the kernel `TLS_CIPHER_*` code points.
    pub const KtlsCipher = enum { aes_128_gcm, aes_256_gcm, chacha20_poly1305 };

    /// The server→client (TX) crypto material a completed TLS 1.3 AEAD session
    /// hands to the kernel for `setsockopt(TLS_TX)`: the negotiated cipher, the
    /// application write key, the 12-byte static write IV, and the current write
    /// sequence number. `key` aliases the live traffic key (valid only while this
    /// `Server`'s keys are unrotated) and is exposed ONLY for the kernel-offload
    /// path — treat it as sensitive.
    pub const KtlsTxParams = struct {
        cipher: KtlsCipher,
        key: []const u8,
        iv: [12]u8,
        seq: u64,
    };

    /// TX offload parameters for a connected TLS 1.3 session, or null before the
    /// handshake completes (kTLS can only be attached post-handshake).
    pub fn ktlsTxParams(self: *const Server) ?KtlsTxParams {
        if (self.state != .connected) return null;
        const suite = self.selected_suite orelse return null;
        const cipher: KtlsCipher = switch (suite) {
            .tls_aes_128_gcm_sha256 => .aes_128_gcm,
            .tls_aes_256_gcm_sha384 => .aes_256_gcm,
            .tls_chacha20_poly1305_sha256 => .chacha20_poly1305,
        };
        return .{
            .cipher = cipher,
            .key = self.server_app_keys.key[0..suite.keyLen()],
            .iv = self.server_app_keys.iv,
            .seq = self.app_write_seq,
        };
    }

    /// RX offload parameters for a connected TLS 1.3 session: the client→server
    /// (decrypt) direction — the client application key, the client's 12-byte
    /// static IV, and the current read sequence. Same `KtlsTxParams` shape (the
    /// kernel `crypto_info` is direction-agnostic). Null before the handshake.
    /// `key` aliases the live traffic key — exposed only for the offload path.
    pub fn ktlsRxParams(self: *const Server) ?KtlsTxParams {
        if (self.state != .connected) return null;
        const suite = self.selected_suite orelse return null;
        const cipher: KtlsCipher = switch (suite) {
            .tls_aes_128_gcm_sha256 => .aes_128_gcm,
            .tls_aes_256_gcm_sha384 => .aes_256_gcm,
            .tls_chacha20_poly1305_sha256 => .chacha20_poly1305,
        };
        return .{
            .cipher = cipher,
            .key = self.client_app_keys.key[0..suite.keyLen()],
            .iv = self.client_app_keys.iv,
            .seq = self.app_read_seq,
        };
    }

    /// True when the current handshake accepted a PSK ticket and used the
    /// abbreviated TLS 1.3 resumption flight.
    pub fn acceptedSessionTicket(self: *const Server) bool {
        return self.resumed;
    }

    /// True when this handshake accepted the client's TLS 1.3 0-RTT offer.
    pub fn earlyDataAccepted(self: *const Server) bool {
        return self.early_data_accepted;
    }

    /// Take ownership of accepted 0-RTT application bytes accumulated before
    /// EndOfEarlyData. Returns null when no accepted early data is buffered.
    pub fn takeEarlyData(self: *Server) Error!?[]u8 {
        if (self.early_data_buf.items.len == 0) return null;
        return try self.early_data_buf.toOwnedSlice(self.allocator);
    }

    pub fn feed(self: *Server, received: []const u8) Error!FeedResult {
        if (self.state == .idle or self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);

        if (self.state == .wait_client_hello) {
            while (true) {
                const rec = completePlainRecord(self.recv_buf.items) orelse return .need_more;
                if (rec.content_type != .change_cipher_spec) break;
                consumePrefix(&self.recv_buf, rec.wire_len);
            }
            const rec = completePlainRecord(self.recv_buf.items) orelse return .need_more;
            if (rec.content_type != .handshake) return error.BadRecord;
            var off: usize = 0;
            const msg = try parseHandshake(rec.fragment, &off);
            if (off != rec.fragment.len or msg.typ != .client_hello) return error.BadHandshake;
            try self.appendTranscript(msg.raw);
            const reply = try self.buildServerFlight(msg.body, msg.raw);
            consumePrefix(&self.recv_buf, rec.wire_len);
            if (self.hrr_sent) {
                // We emitted a HelloRetryRequest; await ClientHello2. 0-RTT is
                // impossible after HRR, so no early-data handling here.
                self.state = .wait_second_client_hello;
                return .{ .bytes_to_send = reply };
            }
            if (self.early_data_accepted) {
                try self.processAcceptedEarlyRecords();
            } else if (self.early_data_offered) {
                self.skipRejectedEarlyRecords();
            }
            // mTLS expects Certificate -> CertificateVerify -> Finished; otherwise
            // just the client Finished.
            self.state = if (self.request_client_cert and !self.resumed) .wait_client_cert else .wait_client_finished;
            return .{ .bytes_to_send = reply };
        }

        if (self.state == .wait_second_client_hello) {
            while (true) {
                const rec = completePlainRecord(self.recv_buf.items) orelse return .need_more;
                if (rec.content_type != .change_cipher_spec) break;
                consumePrefix(&self.recv_buf, rec.wire_len);
            }
            const rec = completePlainRecord(self.recv_buf.items) orelse return .need_more;
            if (rec.content_type != .handshake) return error.BadRecord;
            var off: usize = 0;
            const msg = try parseHandshake(rec.fragment, &off);
            if (off != rec.fragment.len or msg.typ != .client_hello) return error.BadHandshake;
            // ClientHello2 folds in after the message_hash synthetic + HRR that
            // buildHelloRetryRequest already wrote to the transcript.
            try self.appendTranscript(msg.raw);
            const reply = try self.buildServerFlight(msg.body, msg.raw);
            consumePrefix(&self.recv_buf, rec.wire_len);
            self.state = if (self.request_client_cert and !self.resumed) .wait_client_cert else .wait_client_finished;
            return .{ .bytes_to_send = reply };
        }

        // Post-flight: drain every complete record currently buffered — the
        // client's closing flight (Certificate/CertificateVerify/Finished under
        // mTLS, or just Finished) may arrive across one or several records.
        // Decrypt each, accumulate the inner handshake bytes, and drive the
        // message sub-state machine until Finished completes the handshake.
        const suite = self.selected_suite orelse return error.BadState;
        while (self.state != .connected) {
            if (self.early_data_accepted and !self.early_data_done) {
                const before = self.recv_buf.items.len;
                try self.processAcceptedEarlyRecords();
                if (!self.early_data_done) {
                    if (self.recv_buf.items.len == before) break;
                    continue;
                }
            }
            const rec = completePlainRecord(self.recv_buf.items) orelse break;
            if (rec.content_type == .change_cipher_spec) {
                consumePrefix(&self.recv_buf, rec.wire_len);
                continue;
            }
            if (rec.content_type != .application_data) return error.BadRecord;
            const opened = openRecordAlloc(self.allocator, suite, &self.client_hs_keys, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]) catch |err| {
                if (self.early_data_offered and !self.early_data_accepted and err == error.BadRecord) {
                    consumePrefix(&self.recv_buf, rec.wire_len);
                    continue;
                }
                return err;
            };
            self.hs_read_seq += 1;
            defer self.allocator.free(opened.content);
            consumePrefix(&self.recv_buf, rec.wire_len);
            if (opened.content_type != .handshake) return error.BadRecord;
            try self.client_flight.appendSlice(self.allocator, opened.content);
            while (try self.processClientFlightMessage()) {}
        }
        return .need_more;
    }

    /// Parse and consume one complete handshake message from the accumulated
    /// client flight, advancing the sub-state. Returns false when no complete
    /// message remains (await more bytes).
    fn processClientFlightMessage(self: *Server) Error!bool {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(self.client_flight.items, &off) orelse return false;
        switch (self.state) {
            .wait_client_cert => {
                if (msg.typ != .certificate) return error.BadHandshake;
                try self.parseClientCertificate(msg.body);
                try self.appendTranscript(msg.raw);
                // A presented leaf must prove possession via CertificateVerify; an
                // empty Certificate (declined) goes straight to Finished.
                self.state = if (self.client_leaf_key != null) .wait_client_cert_verify else .wait_client_finished;
            },
            .wait_client_cert_verify => {
                if (msg.typ != .certificate_verify) return error.BadHandshake;
                try self.verifyClientCertificateVerify(msg.body);
                try self.appendTranscript(msg.raw);
                self.state = .wait_client_finished;
            },
            .wait_client_finished => {
                if (msg.typ != .finished) return error.BadHandshake;
                if (!self.finishedVerify(&self.client_hs_secret, msg.body)) return error.FinishedMismatch;
                try self.appendTranscript(msg.raw);
                try self.deriveResumptionMasterSecret();
                self.state = .connected;
                if (self.config.enable_session_tickets) try self.queueNewSessionTicket();
            },
            else => return error.BadState,
        }
        consumePrefix(&self.client_flight, off);
        return self.state != .connected;
    }

    /// Capture the presented client leaf DER (CertFP pins by fingerprint, so only
    /// the leaf matters; an empty list = a client that declined).
    fn parseClientCertificate(self: *Server, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const request_context = try c.take(try c.readU8());
        if (request_context.len != 0) return error.BadHandshake;
        const list = try c.take(try c.readU24());
        var certs = Cursor.init(list);
        if (certs.remaining() == 0) return; // declined
        const der = try certs.take(try certs.readU24());
        _ = try certs.take(try certs.readU16()); // per-cert extensions (ignored)
        const leaf = try self.allocator.dupe(u8, der);
        errdefer self.allocator.free(leaf);
        self.client_leaf_key = try clientKeyFromCert(leaf);
        self.client_cert_der = leaf;
    }

    /// Verify the client's CertificateVerify over the transcript with the client
    /// context, using the scheme matching the presented leaf key (Ed25519,
    /// ECDSA P-256, or RSA-PSS — the schemes the CertificateRequest advertised).
    /// A failed possession proof clears the captured cert so no untrusted
    /// fingerprint is exposed.
    fn verifyClientCertificateVerify(self: *Server, body: []const u8) Error!void {
        if (body.len < 4) return error.BadHandshake;
        const scheme = std.mem.readInt(u16, body[0..2], .big);
        const sig_len = std.mem.readInt(u16, body[2..4], .big);
        if (body.len != 4 + @as(usize, sig_len)) return error.BadHandshake;
        const sig = body[4..];
        const key = self.client_leaf_key orelse return error.BadHandshake;
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, client_certificate_verify_context, th[0..th_len]);
        switch (key) {
            .ed25519 => |pk| {
                if (scheme != @intFromEnum(tls_signature_scheme.SignatureScheme.ed25519)) return self.failClientCert();
                if (sig.len != Ed25519.Signature.encoded_length) return self.failClientCert();
                var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
                @memcpy(&sig_bytes, sig[0..Ed25519.Signature.encoded_length]);
                Ed25519.Signature.fromBytes(sig_bytes).verify(input, pk) catch return self.failClientCert();
            },
            .ecdsa_p256 => |pk| {
                if (scheme != @intFromEnum(tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256)) return self.failClientCert();
                const decoded = ecdsa_p256.signatureFromDer(sig) catch return self.failClientCert();
                if (!ecdsa_p256.verify(decoded, input, pk)) return self.failClientCert();
            },
            .rsa => |pk| {
                // TLS 1.3 client CertificateVerify with an RSA key is always
                // RSASSA-PSS (rsae); salt length equals the hash length.
                if (scheme != @intFromEnum(tls_signature_scheme.SignatureScheme.rsa_pss_rsae_sha256)) return self.failClientCert();
                var msg_hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(input, &msg_hash, .{});
                if (!rsa_verify.verifyPss(pk, .sha256, &msg_hash, sig, msg_hash.len)) return self.failClientCert();
            },
        }
    }

    fn failClientCert(self: *Server) Error {
        if (self.client_cert_der) |der| self.allocator.free(der);
        self.client_cert_der = null;
        self.client_leaf_key = null;
        return error.BadHandshake;
    }

    pub fn encrypt(self: *Server, appdata: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const limit = tls_record.recordContentLimit(self.peer_record_size_limit);
        if (appdata.len <= limit) {
            const out = try sealRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_write_seq, .application_data, appdata);
            self.app_write_seq += 1;
            return out;
        }
        // RFC 8449: the peer advertised a smaller record_size_limit — fragment the
        // application data into multiple records, each within its limit, and
        // return them concatenated (one record per fragment, seq bumped per record).
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        var off: usize = 0;
        while (off < appdata.len) {
            const n = @min(limit, appdata.len - off);
            const rec = try sealRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_write_seq, .application_data, appdata[off .. off + n]);
            defer self.allocator.free(rec);
            try buf.appendSlice(self.allocator, rec);
            self.app_write_seq += 1;
            off += n;
        }
        return buf.toOwnedSlice(self.allocator);
    }

    pub fn decrypt(self: *Server, record: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try openRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_read_seq, record);
        self.app_read_seq += 1;
        errdefer self.allocator.free(opened.content);
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

    /// Take ownership of any queued post-handshake bytes the caller must write to
    /// the socket (a KeyUpdate reply). Returns null when nothing is queued.
    pub fn takePendingSend(self: *Server) Error!?[]u8 {
        if (self.post_handshake_send.items.len == 0) return null;
        return try self.post_handshake_send.toOwnedSlice(self.allocator);
    }

    /// Initiate a KeyUpdate towards the client: returns the record to send (caller
    /// owns) and rotates the server→client application keys. When `request_peer`
    /// is true the client is asked to update its keys in return.
    pub fn initiateKeyUpdate(self: *Server, request_peer: bool) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const request: KeyUpdateRequest = if (request_peer) .requested else .not_requested;
        return self.buildKeyUpdateRecord(request);
    }

    /// Everything a successor process needs to keep decrypting/encrypting an
    /// ESTABLISHED TLS 1.3 connection: the negotiated suite, both application
    /// traffic secrets (so post-resume KeyUpdates still derive correctly), and
    /// the live record sequence numbers. Handshake-phase state (transcript,
    /// ephemeral key shares, handshake secrets) is deliberately NOT carried —
    /// it is dead once the handshake completes.
    pub const ResumeState = struct {
        suite: u16,
        client_app_secret: [max_hash_len]u8,
        server_app_secret: [max_hash_len]u8,
        exporter_master_secret: [max_hash_len]u8 = [_]u8{0} ** max_hash_len,
        exporter_master_secret_ready: bool = false,
        app_read_seq: u64,
        app_write_seq: u64,
    };

    /// Capture the connected-state snapshot for a Helix live upgrade. Only valid
    /// once the handshake completed; the secrets in the returned struct are key
    /// material — the caller must treat the bytes as sensitive.
    pub fn exportResume(self: *const Server) Error!ResumeState {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        return .{
            .suite = @intFromEnum(suite),
            .client_app_secret = self.client_app_secret,
            .server_app_secret = self.server_app_secret,
            .exporter_master_secret = self.exporter_master_secret,
            .exporter_master_secret_ready = self.exporter_master_secret_ready,
            .app_read_seq = self.app_read_seq,
            .app_write_seq = self.app_write_seq,
        };
    }

    /// Successor side of a Helix live upgrade: rebuild a CONNECTED server from an
    /// exported `ResumeState`. Traffic keys are re-derived from the carried
    /// application secrets, so the record stream continues seamlessly (including
    /// later KeyUpdates). The handshake machinery is never re-entered.
    pub fn resumeConnected(allocator: Allocator, config: Config, st: ResumeState) Error!Server {
        var self = try Server.init(allocator, config);
        errdefer self.deinit();
        const suite = try CipherSuite.fromWire(st.suite);
        self.selected_suite = suite;
        self.client_app_secret = st.client_app_secret;
        self.server_app_secret = st.server_app_secret;
        self.exporter_master_secret = st.exporter_master_secret;
        self.exporter_master_secret_ready = st.exporter_master_secret_ready;
        try deriveTrafficKeys(suite, self.client_app_secret[0..suite.hashLen()], &self.client_app_keys);
        try deriveTrafficKeys(suite, self.server_app_secret[0..suite.hashLen()], &self.server_app_keys);
        self.app_read_seq = st.app_read_seq;
        self.app_write_seq = st.app_write_seq;
        self.state = .connected;
        return self;
    }

    /// Process a decrypted post-handshake handshake fragment. A KeyUpdate rotates
    /// the client→server application keys and, when update_requested, queues our
    /// own KeyUpdate(update_not_requested) reply and rotates the server→client
    /// keys (RFC 8446 §4.6.3). Other messages are ignored.
    fn handlePostHandshake(self: *Server, fragment: []const u8) Error!void {
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
                try self.applyKeyUpdate(&self.client_app_secret, &self.client_app_keys);
                self.app_read_seq = 0;
                if (request == @intFromEnum(KeyUpdateRequest.requested)) {
                    const reply = try self.buildKeyUpdateRecord(.not_requested);
                    defer self.allocator.free(reply);
                    try self.post_handshake_send.appendSlice(self.allocator, reply);
                }
            }
        }
    }

    /// Build one KeyUpdate record sealed under the *current* server send keys,
    /// then rotate the server→client application keys so subsequent records use
    /// the new keys.
    fn buildKeyUpdateRecord(self: *Server, request: KeyUpdateRequest) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .key_update, &[_]u8{@intFromEnum(request)});
        const record = try sealRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_write_seq, .handshake, hs.items);
        errdefer self.allocator.free(record);
        self.app_write_seq += 1;
        try self.applyKeyUpdate(&self.server_app_secret, &self.server_app_keys);
        self.app_write_seq = 0;
        return record;
    }

    /// In-place KeyUpdate of one traffic secret and its derived keys.
    fn applyKeyUpdate(self: *Server, secret: *[max_hash_len]u8, keys: *TrafficKeys) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        switch (self.hashAlg()) {
            .sha256 => try applyKeyUpdateT(Sha256, suite, secret, keys),
            .sha384 => try applyKeyUpdateT(Sha384, suite, secret, keys),
        }
    }

    fn buildServerFlight(self: *Server, client_hello_body: []const u8, client_hello_raw: []const u8) Error![]u8 {
        const shared = switch (try self.processClientHello(client_hello_body, client_hello_raw)) {
            .retry => |group| return try self.buildHelloRetryRequest(group),
            .proceed => |s| s,
        };

        // ServerHello (plaintext handshake record).
        var sh_hs: std.ArrayList(u8) = .empty;
        defer sh_hs.deinit(self.allocator);
        try self.writeServerHello(&sh_hs);
        try self.appendTranscript(sh_hs.items);

        // Handshake keys are derived over CH + SH. The (EC)DHE secret is 32 bytes
        // for a classical group or 64 for the X25519MLKEM768 hybrid.
        try self.deriveHandshakeKeys(shared.buf[0..shared.len]);

        // Encrypted flight: EncryptedExtensions, Certificate, CertificateVerify,
        // Finished — concatenated into one handshake payload, sealed once.
        var flight: std.ArrayList(u8) = .empty;
        defer flight.deinit(self.allocator);
        try self.writeEncryptedExtensions(&flight);
        if (!self.resumed) {
            if (self.request_client_cert) try self.writeCertificateRequest(&flight);
            try self.writeCertificate(&flight);
            try self.writeCertificateVerify(&flight);
        }
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

    /// Build a HelloRetryRequest flight (RFC 8446 §4.1.4): a ServerHello carrying
    /// the magic random and a key_share naming the group the client must retry
    /// with. Per §4.4.1 the transcript's ClientHello1 is first replaced by the
    /// synthetic `message_hash` (handshake type 254), then the HRR is folded in.
    /// Returns the plaintext HRR record followed by a compatibility
    /// ChangeCipherSpec (caller owns).
    fn buildHelloRetryRequest(self: *Server, group: tls_keyshare.NamedGroup) Error![]u8 {
        self.selected_group = group;
        self.hrr_group = group;
        self.hrr_suite = self.selected_suite;
        self.hrr_sent = true;

        // At this point the transcript holds exactly ClientHello1, so
        // transcriptHash() yields Hash(CH1). Replace it with the message_hash:
        // 0xFE || uint24(Hash.length) || Hash(ClientHello1).
        var ch1_hash: [max_hash_len]u8 = undefined;
        const hlen = self.transcriptHash(&ch1_hash);
        self.transcript.clearRetainingCapacity();
        try self.transcript.append(self.allocator, 0xFE);
        try appendU24(self.allocator, &self.transcript, hlen);
        try self.transcript.appendSlice(self.allocator, ch1_hash[0..hlen]);

        var hrr_hs: std.ArrayList(u8) = .empty;
        defer hrr_hs.deinit(self.allocator);
        try self.writeHelloRetryRequest(&hrr_hs, group);
        try self.appendTranscript(hrr_hs.items);

        const hrr_record = try writePlainRecord(self.allocator, .handshake, hrr_hs.items);
        defer self.allocator.free(hrr_record);
        const ccs = [_]u8{ @intFromEnum(tls_record.ContentType.change_cipher_spec), 0x03, 0x03, 0x00, 0x01, 0x01 };
        var out = try self.allocator.alloc(u8, hrr_record.len + ccs.len);
        @memcpy(out[0..hrr_record.len], hrr_record);
        @memcpy(out[hrr_record.len..], &ccs);
        return out;
    }

    /// Encode the HelloRetryRequest handshake message: a ServerHello whose random
    /// is the magic HRR value, echoing the legacy_session_id, with only the
    /// supported_versions (TLS 1.3) and a HRR key_share (the bare 2-byte group,
    /// RFC 8446 §4.2.8) extensions.
    fn writeHelloRetryRequest(self: *Server, out: *std.ArrayList(u8), group: tls_keyshare.NamedGroup) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);

        try appendU16(self.allocator, &body, tls_record.legacy_record_version);
        try body.appendSlice(self.allocator, &hello_retry_request_random);
        try body.append(self.allocator, @intCast(self.session_id_len));
        try body.appendSlice(self.allocator, self.legacy_session_id[0..self.session_id_len]);
        try appendU16(self.allocator, &body, @intFromEnum(self.selected_suite.?));
        try body.append(self.allocator, 0); // null compression

        var ext_storage: [64]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        var ver_buf: [2]u8 = undefined;
        try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildServer(&ver_buf, tls_supported_versions.tls13));
        var ks_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &ks_buf, group.toInt(), .big);
        try ext_builder.addTyped(.key_share, &ks_buf);
        try body.appendSlice(self.allocator, try ext_builder.finish());

        try writeHandshake(self.allocator, out, .server_hello, body.items);
    }

    fn processClientHello(self: *Server, body: []const u8, raw: []const u8) Error!ClientHelloOutcome {
        var c = Cursor.init(body);
        if (try c.readU16() != tls_record.legacy_record_version) return error.ProtocolVersion;
        _ = try c.take(32); // client random (unused by the server key schedule)
        const sid = try c.take(try c.readU8());
        if (sid.len > self.legacy_session_id.len) return error.BadHandshake;
        @memcpy(self.legacy_session_id[0..sid.len], sid);
        self.session_id_len = sid.len;

        const suites_block = try c.take(try c.readU16());
        const full_suite = pickSuite(suites_block) orelse return error.UnsupportedCipherSuite;

        const comp = try c.take(try c.readU8());
        var null_comp = false;
        for (comp) |m| if (m == 0) {
            null_comp = true;
        };
        if (!null_comp) return error.BadHandshake;

        const ext_block = try c.take(try c.readU16());

        var offered_tls13 = false;
        var x25519_share: ?[]const u8 = null;
        var p256_share: ?[]const u8 = null;
        var hybrid_share: ?[]const u8 = null; // X25519MLKEM768 (post-quantum)
        var offered_groups: ?[]const u8 = null; // supported_groups body (for HRR)
        var offered_cert_compression: ?cert_compression.Algorithm = null; // RFC 8879
        var psk_modes_ok = false;
        var psk_ext: ?[]const u8 = null;
        var offered_early_data = false;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            switch (ext.typed()) {
                .supported_versions => {
                    if (tls_supported_versions.clientOffers(ext.data, tls_supported_versions.tls13)) offered_tls13 = true;
                },
                .supported_groups => offered_groups = ext.data,
                .key_share => {
                    var shares = tls_keyshare.parseClientShares(ext.data) catch continue;
                    while (shares.next() catch null) |entry| {
                        if (entry.group == .x25519 and entry.key_exchange.len == kx.X25519Kx.public_len) {
                            if (x25519_share == null) x25519_share = entry.key_exchange;
                        } else if (entry.group == .secp256r1 and entry.key_exchange.len == ecdh_p256.public_length) {
                            if (p256_share == null) p256_share = entry.key_exchange;
                        } else if (entry.group == .x25519mlkem768 and entry.key_exchange.len == hybrid_client_share_len) {
                            if (hybrid_share == null) hybrid_share = entry.key_exchange;
                        }
                    }
                },
                .alpn => self.maybeSelectAlpn(ext.data),
                .status_request => self.client_requested_ocsp = true,
                .compress_certificate => if (self.config.enable_cert_compression) {
                    // RFC 8879: remember the first algorithm we can produce (zlib).
                    offered_cert_compression = cert_compression.pickSupported(ext.data);
                },
                .record_size_limit => {
                    // RFC 8449: 2-byte value in [64, 2^14+1]; else illegal_parameter.
                    if (ext.data.len != 2) return error.BadHandshake;
                    const limit = std.mem.readInt(u16, ext.data[0..2], .big);
                    if (limit < tls_record.record_size_limit_min or limit > tls_record.record_size_limit_max) return error.BadHandshake;
                    self.peer_record_size_limit = limit;
                },
                .psk_key_exchange_modes => psk_modes_ok = pskModesAllowDhe(ext.data),
                .early_data => {
                    if (ext.data.len != 0) return error.BadHandshake;
                    offered_early_data = true;
                },
                .pre_shared_key => {
                    if (it.remaining() != 0) return error.BadHandshake;
                    psk_ext = ext.data;
                },
                else => {},
            }
        }

        if (!offered_tls13) return error.ProtocolVersion;
        self.selected_suite = full_suite;
        self.cert_compression = offered_cert_compression;
        // SNI (RFC 6066): pin the cert on ClientHello1. On ClientHello2 the SNI
        // MUST be unchanged (RFC 8446 §4.1.2 — it is not among the fields a client
        // may alter across a HelloRetryRequest), so verify CH2's host_name digest
        // matches CH1's and keep the pinned `sni_cert`; a mismatch is a protocol
        // violation (and a would-be cert-selection swap) and is fatal.
        const sni_name = sni.extractOptional(raw);
        if (self.hrr_sent) {
            if (!sniDigestEql(self.ch1_sni_digest, sniDigest(sni_name))) return error.BadHandshake;
        } else {
            self.ch1_sni_digest = sniDigest(sni_name);
            self.sni_cert = self.selectSniCert(sni_name);
        }
        self.resumed = false;
        self.early_data_offered = offered_early_data;
        self.early_data_accepted = false;
        self.early_data_done = !offered_early_data;
        self.accepted_early_data_limit = 0;
        self.accepted_psk_len = 0;

        // HelloRetryRequest (RFC 8446 §4.1.4): if the client offered no key_share
        // we can use but DID advertise a group we support, ask it to retry with
        // that group rather than failing. Decided BEFORE PSK/0-RTT so we never
        // accept early data on a hello we are about to bounce, and only once per
        // connection — a second hello still lacking a usable share is fatal below.
        const have_usable_share = x25519_share != null or p256_share != null or hybrid_share != null;
        if (!have_usable_share and !self.hrr_sent) {
            if (offered_groups) |groups| {
                const server_prefs = [_]supported_groups.NamedGroup{ .x25519, .secp256r1, .x25519mlkem768 };
                if (supported_groups.selectPreferred(groups, &server_prefs)) |g| {
                    return ClientHelloOutcome{ .retry = tls_keyshare.NamedGroup.fromInt(g.toInt()) };
                }
            }
        }

        // On the second ClientHello the client MUST retry with exactly the group
        // we requested (RFC 8446 §4.1.2). Ignore any share for a different group
        // so the key exchange binds to `hrr_group`; if none remains, abort.
        if (self.hrr_sent) {
            // §4.1.2: the client MUST remove early_data in ClientHello2 — 0-RTT is
            // not permitted after a HelloRetryRequest. Reject a peer that kept it.
            if (offered_early_data) return error.BadHandshake;
            // §4.1.4: ClientHello2 must keep the cipher suite the HRR committed to;
            // a changed suite could switch the transcript hash out from under the
            // message_hash synthetic. `hrr_suite` was stamped when the HRR was sent.
            if (self.hrr_suite) |committed| {
                if (committed != full_suite) return error.BadHandshake;
            }
            switch (self.hrr_group) {
                .x25519 => {
                    p256_share = null;
                    hybrid_share = null;
                },
                .secp256r1 => {
                    x25519_share = null;
                    hybrid_share = null;
                },
                .x25519mlkem768 => {
                    x25519_share = null;
                    p256_share = null;
                },
                else => return error.BadHandshake,
            }
            if (x25519_share == null and p256_share == null and hybrid_share == null) return error.BadHandshake;
        }

        if (psk_ext) |ext| {
            if (psk_modes_ok) {
                if (try self.tryAcceptPsk(suites_block, raw, ext)) |suite| {
                    self.selected_suite = suite;
                    self.resumed = true;
                    // Accept 0-RTT only when the limit is non-zero AND this PSK
                    // binder has not been seen before (anti-replay). A replay
                    // still resumes via 1-RTT; only its early data is refused.
                    const replay_ok = if (self.config.replay_guard) |g|
                        g.checkAndRecord(self.accepted_binder[0..self.accepted_binder_len])
                    else
                        true;
                    if (offered_early_data and self.accepted_early_data_limit > 0 and replay_ok) {
                        self.early_data_accepted = true;
                        self.early_data_done = false;
                        try self.deriveClientEarlyTrafficKeys();
                    }
                }
            }
        }
        if (!self.early_data_accepted) self.early_data_done = true;

        // Prefer classical X25519, then secp256r1, then the X25519MLKEM768 hybrid
        // (used when the client — e.g. modern Chrome — offered only the PQ share).
        if (x25519_share) |peer| {
            self.selected_group = .x25519;
            var peer_pub: kx.PublicKey = undefined;
            @memcpy(&peer_pub, peer);
            var secret = kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer_pub) catch return error.BadHandshake;
            defer secret.wipe();
            var out = KexShared{ .len = 32 };
            const ss = secret.declassify();
            @memcpy(out.buf[0..32], &ss);
            return ClientHelloOutcome{ .proceed = out };
        }
        if (p256_share) |peer| {
            self.selected_group = .secp256r1;
            const ss = ecdh_p256.sharedSecret(self.p256_pair.secret, peer[0..ecdh_p256.public_length].*) catch return error.BadHandshake;
            var out = KexShared{ .len = 32 };
            @memcpy(out.buf[0..32], &ss);
            return ClientHelloOutcome{ .proceed = out };
        }
        if (hybrid_share) |peer| {
            // X25519MLKEM768 (0x11ec): client share = ml-kem_ek(1184) || x25519_pk(32).
            self.selected_group = .x25519mlkem768;

            // X25519 ECDH against the classical half of the client share.
            var x_peer: kx.PublicKey = undefined;
            @memcpy(&x_peer, peer[mlkem_ek_len .. mlkem_ek_len + x25519_pub_len]);
            var x_secret = kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, x_peer) catch return error.BadHandshake;
            defer x_secret.wipe();

            // ML-KEM-768 encapsulate against the PQ half, with fresh entropy.
            var ek: [mlkem_ek_len]u8 = undefined;
            @memcpy(&ek, peer[0..mlkem_ek_len]);
            const mlkem_pk = MlKem768.PublicKey.fromBytes(&ek) catch return error.BadHandshake;
            var seed: [MlKem768.encaps_seed_length]u8 = undefined;
            try osEntropy(&seed);
            var enc = mlkem_pk.encapsDeterministic(&seed);
            secureZero(&seed);
            defer secureZero(&enc.shared_secret);

            // Server share (emitted in ServerHello): ml-kem_ct(1088) || x25519_pk(32).
            @memcpy(self.hybrid_keyshare[0..mlkem_ct_len], &enc.ciphertext);
            @memcpy(self.hybrid_keyshare[mlkem_ct_len..], &self.x25519_pair.public_key);

            // Combined (EC)DHE secret fed to the key schedule: ml-kem_ss || x25519_ss.
            var out = KexShared{ .len = 64 };
            @memcpy(out.buf[0..32], &enc.shared_secret);
            const x_ss = x_secret.declassify();
            @memcpy(out.buf[32..64], &x_ss);
            return ClientHelloOutcome{ .proceed = out };
        }
        return error.UnsupportedGroup;
    }

    fn tryAcceptPsk(self: *Server, suites_block: []const u8, client_hello_raw: []const u8, psk_ext: []const u8) Error!?CipherSuite {
        var parsed = tls_psk.parseClientPsk(psk_ext) catch return null;
        const identity = (parsed.identities.next() catch return null) orelse return null;
        const binder = (parsed.binders.next() catch return null) orelse return null;
        if ((parsed.identities.next() catch return null) != null) return null;
        if ((parsed.binders.next() catch return null) != null) return null;

        const opened = tls_resumption.openTicketWithRotation(self.allocator, self.ticket_key, self.config.previous_ticket_key, identity.identity) catch return null;
        defer self.allocator.free(opened.plain);
        const suite = CipherSuite.fromWire(opened.opened.suite) catch return null;
        if (!clientOfferedSuite(suites_block, suite)) return null;
        if (opened.opened.psk.len != suite.hashLen()) return null;
        if (binder.len != suite.hashLen()) return null;

        // Ticket-lifetime enforcement (when the caller supplies a clock and the
        // ticket carries a real issue time): reject expired or future tickets,
        // falling back to a full handshake.
        if (self.config.now_unix_seconds) |now_s| {
            const issued_s = @divTrunc(opened.opened.issued_unix_ms, 1000);
            if (issued_s != 0) {
                if (now_s < issued_s) return null;
                if (now_s - issued_s > @as(i64, self.config.ticket_lifetime_seconds)) return null;
            }
        }

        const binder_list_offset = tls_psk.binderListOffset(psk_ext) catch return null;
        const psk_body_offset = findPskExtensionBodyOffset(client_hello_raw) catch return null;
        const truncated_len = psk_body_offset + binder_list_offset;
        if (truncated_len > client_hello_raw.len) return null;
        if (!self.verifyPskBinder(suite, opened.opened.psk, client_hello_raw[0..truncated_len], binder)) return null;

        @memcpy(self.accepted_psk[0..opened.opened.psk.len], opened.opened.psk);
        self.accepted_psk_len = opened.opened.psk.len;
        self.accepted_early_data_limit = opened.opened.max_early_data_size;
        @memcpy(self.accepted_binder[0..binder.len], binder);
        self.accepted_binder_len = binder.len;
        return suite;
    }

    fn verifyPskBinder(self: *Server, suite: CipherSuite, psk: []const u8, truncated_client_hello: []const u8, binder: []const u8) bool {
        _ = self;
        return switch (suite.hashAlg()) {
            .sha256 => verifyPskBinderT(Sha256, psk, truncated_client_hello, binder),
            .sha384 => verifyPskBinderT(Sha384, psk, truncated_client_hello, binder),
        };
    }

    fn verifyPskBinderT(comptime KS: type, psk: []const u8, truncated_client_hello: []const u8, binder: []const u8) bool {
        if (psk.len != KS.hash_len or binder.len != KS.hash_len) return false;
        var early = KS.earlySecret(psk);
        defer early.wipe();
        var binder_key = KS.deriveSecret(&early, "res binder", &KS.emptyTranscriptHash()) catch return false;
        defer binder_key.wipe();
        const th = KS.transcriptHash(truncated_client_hello);
        const expected = tls_finished.For(KS).verifyData(binder_key.declassify(), th);
        return switch (KS.hash_len) {
            Sha256.hash_len => std.crypto.timing_safe.eql([Sha256.hash_len]u8, expected, binder[0..Sha256.hash_len].*),
            Sha384.hash_len => std.crypto.timing_safe.eql([Sha384.hash_len]u8, expected, binder[0..Sha384.hash_len].*),
            else => false,
        };
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

        // Sized to hold the X25519MLKEM768 server key_share (1120 bytes) plus the
        // supported_versions and (on resumption) pre_shared_key extensions.
        var ext_storage: [hybrid_server_share_len + 256]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        var ver_buf: [2]u8 = undefined;
        try ext_builder.addTyped(.supported_versions, try tls_supported_versions.buildServer(&ver_buf, tls_supported_versions.tls13));
        var ks_buf: [hybrid_server_share_len + 8]u8 = undefined;
        const ks = switch (self.selected_group) {
            .secp256r1 => try tls_keyshare.buildServerShare(&ks_buf, .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 }),
            .x25519mlkem768 => try tls_keyshare.buildServerShare(&ks_buf, .{ .group = .x25519mlkem768, .key_exchange = &self.hybrid_keyshare }),
            else => try tls_keyshare.buildServerShare(&ks_buf, .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key }),
        };
        try ext_builder.addTyped(.key_share, ks);
        if (self.resumed) {
            var psk_buf: [2]u8 = undefined;
            try ext_builder.addTyped(.pre_shared_key, try tls_psk.buildServerPsk(&psk_buf, 0));
        }
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
        if (self.early_data_accepted) try ext_builder.addTyped(.early_data, "");
        // RFC 8449: advertise the max TLSInnerPlaintext we accept (full-size
        // records — our recv path handles them). Enforcement of the PEER's limit
        // happens on our send path (see `encrypt`).
        var rsl_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &rsl_buf, tls_record.record_size_limit_max, .big);
        try ext_builder.addTyped(.record_size_limit, &rsl_buf);
        try self.emit(out, .encrypted_extensions, try ext_builder.finish());
    }

    /// Signature schemes the server can actually verify on a client
    /// CertificateVerify — exactly what the CertificateRequest advertises.
    const client_cert_schemes = [_]tls_signature_scheme.SignatureScheme{
        .ed25519,
        .ecdsa_secp256r1_sha256,
        // RSA-PSS (rsae) — TLS 1.3 forbids PKCS#1 v1.5 for CertificateVerify, so
        // only the PSS variant is offered. Lets RSA-2048 client certs (e.g. an
        // ACME-issued leaf reused as a certfp client cert) bind via CERTADD.
        .rsa_pss_rsae_sha256,
    };

    /// CertificateRequest (mTLS, RFC 8446 §4.3.2): empty request context + a
    /// signature_algorithms extension (the only mandatory one in TLS 1.3)
    /// listing the schemes we verify client certs with.
    ///
    /// NOTE: `tls_extension.Builder.finish()` already returns the extensions
    /// vector *including* its leading 2-byte total-length prefix (it is appended
    /// as-is in ServerHello/EncryptedExtensions too). Do not prepend another
    /// u16 length here — doing so doubled the prefix and made real clients
    /// reject the handshake with "Invalid TLS extensions length field".
    fn writeCertificateRequest(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.append(self.allocator, 0); // certificate_request_context: empty

        var sigs_buf: [2 + 2 * client_cert_schemes.len]u8 = undefined;
        const sigs = try tls_signature_scheme.build(&sigs_buf, &client_cert_schemes);
        var ext_storage: [32]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);
        try ext_builder.addTyped(.signature_algorithms, sigs);
        try body.appendSlice(self.allocator, try ext_builder.finish());
        try self.emit(out, .certificate_request, body.items);
    }

    /// Append a handshake message to the encrypted flight AND to the running
    /// transcript (every message after ServerHello must be folded in before the
    /// CertificateVerify signature and Finished MAC are computed).
    fn emit(self: *Server, out: *std.ArrayList(u8), typ: HandshakeType, body: []const u8) Error!void {
        const start = out.items.len;
        try writeHandshake(self.allocator, out, typ, body);
        try self.appendTranscript(out.items[start..]);
    }

    /// Choose the `config.sni_certs` index whose `server_names` matches the
    /// advertised SNI host_name (RFC 6066), or null for the default cert. `name`
    /// is the extracted host_name (null when the ClientHello carried no SNI).
    fn selectSniCert(self: *const Server, name: ?[]const u8) ?usize {
        if (self.config.sni_certs.len == 0) return null;
        const host = name orelse return null;
        for (self.config.sni_certs, 0..) |entry, i| {
            if (serverNameMatches(entry.server_names, host)) return i;
        }
        return null;
    }

    /// The cert chain to present for this handshake (SNI-selected or default).
    fn activeCertChain(self: *const Server) []const []const u8 {
        if (self.sni_cert) |i| return self.config.sni_certs[i].cert_chain;
        return self.config.cert_chain;
    }

    /// The OCSP staple to attach for this handshake (SNI-selected or default).
    fn activeOcspStaple(self: *const Server) []const u8 {
        if (self.sni_cert) |i| return self.config.sni_certs[i].ocsp_staple;
        return self.config.ocsp_staple;
    }

    /// The signing key matching the presented leaf (SNI-selected or default),
    /// with the same rsa › ecdsa › ed25519 precedence as `activeSigningKey`.
    fn activeSigningKeyResolved(self: *const Server) ?SigningKey {
        const i = self.sni_cert orelse return activeSigningKey(self.config);
        const entry = self.config.sni_certs[i];
        if (entry.rsa_signing_key) |key| return .{ .rsa = key };
        if (entry.ecdsa_p256_signing_key) |key| return .{ .ecdsa_p256 = key };
        if (entry.signing_key) |key| return .{ .ed25519 = key };
        return null;
    }

    fn writeCertificate(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.append(self.allocator, 0); // certificate_request_context = empty

        const staple = self.activeOcspStaple();
        const do_staple = self.client_requested_ocsp and staple.len != 0;
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.allocator);
        for (self.activeCertChain(), 0..) |der, i| {
            try appendU24(self.allocator, &list, der.len);
            try list.appendSlice(self.allocator, der);
            if (i == 0 and do_staple) {
                // Leaf CertificateEntry status_request extension (RFC 8446
                // §4.4.2.1): ext_type(5) ‖ ext_len ‖ CertificateStatus, where
                // CertificateStatus = status_type(1=ocsp) ‖ u24 len ‖ OCSPResponse.
                var ext: std.ArrayList(u8) = .empty;
                defer ext.deinit(self.allocator);
                try appendU16(self.allocator, &ext, @intFromEnum(tls_extension.ExtensionType.status_request));
                try appendU16(self.allocator, &ext, @intCast(1 + 3 + staple.len));
                try ext.append(self.allocator, 1); // status_type = ocsp
                try appendU24(self.allocator, &ext, staple.len);
                try ext.appendSlice(self.allocator, staple);
                try appendU16(self.allocator, &list, @intCast(ext.items.len));
                try list.appendSlice(self.allocator, ext.items);
            } else {
                try appendU16(self.allocator, &list, 0); // per-cert extensions = empty
            }
        }
        try appendU24(self.allocator, &body, list.items.len);
        try body.appendSlice(self.allocator, list.items);

        // RFC 8879: when the client negotiated zlib compression, send the
        // Certificate body as a CompressedCertificate — but only if it actually
        // shrinks (a tiny Ed25519/ECDSA chain can deflate larger). `emit` folds
        // whichever message we send into the transcript, so the peer hashes the
        // exact type-25 (or type-11) bytes it receives (RFC 8879 §5).
        if (self.cert_compression == cert_compression.Algorithm.zlib) {
            const compressed = try cert_compression.deflateZlib(self.allocator, body.items);
            defer self.allocator.free(compressed);
            if (compressed.len < body.items.len) {
                var cc: std.ArrayList(u8) = .empty;
                defer cc.deinit(self.allocator);
                try appendU16(self.allocator, &cc, cert_compression.Algorithm.zlib.toInt());
                try appendU24(self.allocator, &cc, body.items.len); // uncompressed_length
                try appendU24(self.allocator, &cc, compressed.len); // compressed vector length
                try cc.appendSlice(self.allocator, compressed);
                try self.emit(out, .compressed_certificate, cc.items);
                return;
            }
        }
        try self.emit(out, .certificate, body.items);
    }

    fn writeCertificateVerify(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, certificate_verify_context, th[0..th_len]);

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        switch (self.activeSigningKeyResolved() orelse return error.NoSigningKey) {
            .ed25519 => |key| {
                const sig = (key.sign(input, null) catch return error.BadHandshake).toBytes();
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ed25519));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, &sig);
            },
            .ecdsa_p256 => |key| {
                const sig = ecdsa_p256.sign(input, key) catch return error.BadHandshake;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = ecdsa_p256.signatureToDer(sig, &der_buf) catch return error.BadHandshake;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256));
                try appendU16(self.allocator, &body, @intCast(der.len));
                try body.appendSlice(self.allocator, der);
            },
            .rsa => |key| {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
                var salt: [32]u8 = undefined;
                try osEntropy(&salt);
                defer secureZero(&salt);
                var sig_buf: [512]u8 = undefined;
                const sig = rsa_sign.signPss(key, .sha256, &digest, &salt, &sig_buf) catch return error.BadHandshake;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.rsa_pss_rsae_sha256));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, sig);
            },
        }
        try self.emit(out, .certificate_verify, body.items);
    }

    fn writeServerFinished(self: *Server, out: *std.ArrayList(u8)) Error!void {
        var vd_buf: [max_hash_len]u8 = undefined;
        const vd_len = self.finishedVerifyData(&self.server_hs_secret, &vd_buf);
        try self.emit(out, .finished, vd_buf[0..vd_len]);
    }

    fn hashAlg(self: *const Server) HashAlg {
        const suite = self.selected_suite orelse return .sha256;
        return suite.hashAlg();
    }

    /// Transcript-Hash of the handshake so far into `out`; returns its length.
    fn transcriptHash(self: *const Server, out: *[max_hash_len]u8) usize {
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

    fn finishedVerify(self: *const Server, base_key: *const [max_hash_len]u8, received: []const u8) bool {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        return switch (self.hashAlg()) {
            .sha256 => tls_finished.Sha256F.verify(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*, received),
            .sha384 => tls_finished.Sha384F.verify(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*, received),
        };
    }

    fn finishedVerifyData(self: *const Server, base_key: *const [max_hash_len]u8, out: *[max_hash_len]u8) usize {
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

    fn deriveHandshakeKeys(self: *Server, shared_secret: []const u8) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveHandshakeKeysT(Sha256, shared_secret),
            .sha384 => try self.deriveHandshakeKeysT(Sha384, shared_secret),
        }
    }

    fn deriveClientEarlyTrafficKeys(self: *Server) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveClientEarlyTrafficKeysT(Sha256),
            .sha384 => try self.deriveClientEarlyTrafficKeysT(Sha384),
        }
    }

    fn deriveClientEarlyTrafficKeysT(self: *Server, comptime KS: type) Error!void {
        if (self.accepted_psk_len != KS.hash_len) return error.BadHandshake;
        var early = KS.earlySecret(self.accepted_psk[0..self.accepted_psk_len]);
        defer early.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.deriveSecret(&early, "c e traffic", &th);
        defer traffic.wipe();
        var traffic_bytes = traffic.declassify();
        defer secureZero(&traffic_bytes);
        try deriveTrafficKeys(self.selected_suite.?, &traffic_bytes, &self.client_early_keys);
        self.early_read_seq = 0;
    }

    fn deriveHandshakeKeysT(self: *Server, comptime KS: type, shared_secret: []const u8) Error!void {
        const psk = if (self.resumed) blk: {
            if (self.accepted_psk_len != KS.hash_len) return error.BadHandshake;
            break :blk self.accepted_psk[0..self.accepted_psk_len];
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

        const suite = self.selected_suite.?;
        try deriveTrafficKeys(suite, self.client_hs_secret[0..KS.hash_len], &self.client_hs_keys);
        try deriveTrafficKeys(suite, self.server_hs_secret[0..KS.hash_len], &self.server_hs_keys);
        self.hs_read_seq = 0;
        self.hs_write_seq = 0;
    }

    fn deriveApplicationKeys(self: *Server) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveApplicationKeysT(Sha256),
            .sha384 => try self.deriveApplicationKeysT(Sha384),
        }
    }

    fn deriveApplicationKeysT(self: *Server, comptime KS: type) Error!void {
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
        const suite = self.selected_suite.?;
        try deriveTrafficKeys(suite, self.client_app_secret[0..KS.hash_len], &self.client_app_keys);
        try deriveTrafficKeys(suite, self.server_app_secret[0..KS.hash_len], &self.server_app_keys);
        self.app_read_seq = 0;
        self.app_write_seq = 0;
    }

    fn deriveResumptionMasterSecret(self: *Server) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveResumptionMasterSecretT(Sha256),
            .sha384 => try self.deriveResumptionMasterSecretT(Sha384),
        }
    }

    fn deriveResumptionMasterSecretT(self: *Server, comptime KS: type) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.master_secret[0..KS.hash_len]);
        var master = KS.SecretBytes.init(sk);
        defer master.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var rms = try KS.deriveSecret(&master, "res master", &th);
        defer rms.wipe();
        self.resumption_master_secret[0..KS.hash_len].* = rms.declassify();
    }

    fn exportKeyingMaterialT(self: *const Server, comptime KS: type, label: []const u8, context: []const u8, out: []u8) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.exporter_master_secret[0..KS.hash_len]);
        var exporter_master = KS.SecretBytes.init(sk);
        defer exporter_master.wipe();
        try KS.exportKeyingMaterial(&exporter_master, label, context, out);
    }

    fn queueNewSessionTicket(self: *Server) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        var ticket_nonce: [tls_resumption.ticket_nonce_len]u8 = undefined;
        try osEntropy(&ticket_nonce);
        var age_add_bytes: [4]u8 = undefined;
        try osEntropy(&age_add_bytes);
        const ticket_age_add = std.mem.readInt(u32, &age_add_bytes, .big);
        var aead_nonce: [ChaCha20Poly1305.nonce_length]u8 = undefined;
        try osEntropy(&aead_nonce);

        var psk: [max_hash_len]u8 = undefined;
        const psk_len = switch (self.hashAlg()) {
            .sha256 => try self.deriveTicketPskT(Sha256, &ticket_nonce, &psk),
            .sha384 => try self.deriveTicketPskT(Sha384, &ticket_nonce, &psk),
        };
        defer secureZero(psk[0..psk_len]);

        const sealed = try tls_resumption.sealTicket(
            self.allocator,
            self.ticket_key,
            aead_nonce,
            @intFromEnum(suite),
            psk[0..psk_len],
            &ticket_nonce,
            if (self.config.now_unix_seconds) |s| s * 1000 else 0,
            self.config.max_early_data_size,
        );
        defer self.allocator.free(sealed);

        var ticket_ext_storage: [16]u8 = undefined;
        var ticket_ext_builder = try tls_extension.Builder.begin(&ticket_ext_storage);
        var early_ext: [4]u8 = undefined;
        std.mem.writeInt(u32, &early_ext, self.config.max_early_data_size, .big);
        try ticket_ext_builder.addTyped(.early_data, &early_ext);
        const ticket_extensions = try ticket_ext_builder.finish();

        var ticket_body_buf: [512]u8 = undefined;
        const ticket_body = try tls_session_ticket.encode(&ticket_body_buf, .{
            .ticket_lifetime = self.config.ticket_lifetime_seconds,
            .ticket_age_add = ticket_age_add,
            .ticket_nonce = &ticket_nonce,
            .ticket = sealed,
            .extensions = ticket_extensions[2..],
        });

        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .new_session_ticket, ticket_body);
        const record = try sealRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_write_seq, .handshake, hs.items);
        defer self.allocator.free(record);
        self.app_write_seq += 1;
        try self.post_handshake_send.appendSlice(self.allocator, record);
    }

    fn deriveTicketPskT(self: *Server, comptime KS: type, ticket_nonce: []const u8, out: *[max_hash_len]u8) Error!usize {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.resumption_master_secret[0..KS.hash_len]);
        var rms = KS.SecretBytes.init(sk);
        defer rms.wipe();
        try KS.hkdfExpandLabel(&rms, "resumption", ticket_nonce, out[0..KS.hash_len]);
        return KS.hash_len;
    }

    fn appendTranscript(self: *Server, bytes: []const u8) Error!void {
        try self.transcript.appendSlice(self.allocator, bytes);
    }

    fn processAcceptedEarlyRecords(self: *Server) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        while (!self.early_data_done) {
            const rec = completePlainRecord(self.recv_buf.items) orelse return;
            if (rec.content_type == .change_cipher_spec) {
                consumePrefix(&self.recv_buf, rec.wire_len);
                continue;
            }
            if (rec.content_type != .application_data) return error.BadRecord;
            const opened = try openRecordAlloc(self.allocator, suite, &self.client_early_keys, self.early_read_seq, self.recv_buf.items[0..rec.wire_len]);
            self.early_read_seq += 1;
            defer self.allocator.free(opened.content);
            consumePrefix(&self.recv_buf, rec.wire_len);
            switch (opened.content_type) {
                .application_data => {
                    if (opened.content.len > self.accepted_early_data_limit or
                        self.early_data_buf.items.len > self.accepted_early_data_limit - opened.content.len)
                    {
                        return error.BadRecord;
                    }
                    try self.early_data_buf.appendSlice(self.allocator, opened.content);
                },
                .handshake => {
                    var off: usize = 0;
                    const msg = try parseHandshake(opened.content, &off);
                    if (off != opened.content.len or msg.typ != .end_of_early_data or msg.body.len != 0) {
                        return error.BadHandshake;
                    }
                    self.early_data_done = true;
                },
                else => return error.BadRecord,
            }
        }
    }

    fn skipRejectedEarlyRecords(self: *Server) void {
        while (completePlainRecord(self.recv_buf.items)) |rec| {
            if (rec.content_type == .change_cipher_spec) {
                consumePrefix(&self.recv_buf, rec.wire_len);
                continue;
            }
            if (rec.content_type != .application_data) return;
            consumePrefix(&self.recv_buf, rec.wire_len);
        }
    }
};

fn activeSigningKey(config: Config) ?SigningKey {
    if (config.rsa_signing_key) |key| return .{ .rsa = key };
    if (config.ecdsa_p256_signing_key) |key| return .{ .ecdsa_p256 = key };
    if (config.signing_key) |key| return .{ .ed25519 = key };
    return null;
}

/// The signing key an `SniCert` entry would present, with the same
/// rsa › ecdsa › ed25519 precedence as `activeSigningKeyResolved`.
fn sniEntrySigningKey(entry: SniCert) ?SigningKey {
    if (entry.rsa_signing_key) |key| return .{ .rsa = key };
    if (entry.ecdsa_p256_signing_key) |key| return .{ .ecdsa_p256 = key };
    if (entry.signing_key) |key| return .{ .ed25519 = key };
    return null;
}

/// Whether `leaf_der`'s subjectPublicKey algorithm matches the type of `key`
/// (the key that will produce this leaf's CertificateVerify). Conservative: if
/// the leaf can't be parsed or its key type isn't recognized, returns true so a
/// parser gap never blocks boot on an otherwise-valid cert — the point is only to
/// catch a DEFINITE rsa/ecdsa/ed25519 mismatch early.
fn leafKeyKindMatches(leaf_der: []const u8, key: SigningKey) bool {
    const cert = x509.Certificate.parse(leaf_der) catch return true;
    const pk = x509.extractPublicKey(cert.spki_der) catch return true;
    const want: std.meta.Tag(x509.SubjectPublicKey) = switch (key) {
        .rsa => .rsa,
        .ecdsa_p256 => .ecdsa_p256,
        .ed25519 => .ed25519,
    };
    return std.meta.activeTag(pk) == want;
}

/// True when `sni` matches any of `patterns` (case-insensitive). A `*.` prefix
/// wildcard-matches exactly one left-most label (RFC 6125 §6.4.3): `*.a.com`
/// matches `x.a.com` but neither `a.com` nor `x.y.a.com`.
fn serverNameMatches(patterns: []const []const u8, host: []const u8) bool {
    for (patterns) |pat| {
        if (pat.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(pat, host)) return true;
        if (pat.len > 2 and pat[0] == '*' and pat[1] == '.') {
            const suffix = pat[1..]; // ".a.com"
            if (host.len <= suffix.len) continue;
            const host_suffix = host[host.len - suffix.len ..];
            const label = host[0 .. host.len - suffix.len];
            if (std.ascii.eqlIgnoreCase(host_suffix, suffix) and
                label.len != 0 and std.mem.indexOfScalar(u8, label, '.') == null)
            {
                return true;
            }
        }
    }
    return false;
}

/// SHA-256 of an advertised SNI host_name, or null when no server_name was
/// present. Used to pin ClientHello1's SNI so a HelloRetryRequest's second
/// ClientHello can be checked byte-exact (RFC 8446 §4.1.2) without retaining the
/// variable-length name. The digest is over non-secret data (no timing concern).
fn sniDigest(name: ?[]const u8) ?[32]u8 {
    const host = name orelse return null;
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(host, &out, .{});
    return out;
}

/// Whether two optional SNI digests match: both absent, or both present and
/// byte-equal. RFC 8446 §4.1.2 requires ClientHello2's SNI to be identical to
/// ClientHello1's (case included), so an exact compare is the intended check.
fn sniDigestEql(a: ?[32]u8, b: ?[32]u8) bool {
    const da = a orelse return b == null;
    const db = b orelse return false;
    return std.mem.eql(u8, &da, &db);
}

// --- record + handshake helpers (mirror tls_client.zig; kept local so the
//     proven client stays untouched) -------------------------------------

const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate_request = 13,
    certificate = 11,
    compressed_certificate = 25, // RFC 8879
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    _,
};

const KeyUpdateRequest = enum(u8) {
    not_requested = 0,
    requested = 1,
};

const HandshakeMsg = struct { typ: HandshakeType, body: []const u8, raw: []const u8 };

const PlainRecord = struct { content_type: tls_record.ContentType, fragment: []const u8, wire_len: usize };
const OpenedRecord = struct { content_type: tls_record.ContentType, content: []u8 };

const certificate_verify_context = "TLS 1.3, server CertificateVerify";
const client_certificate_verify_context = "TLS 1.3, client CertificateVerify";
const cert_verify_input_max = 64 + client_certificate_verify_context.len + 1 + max_hash_len;

/// CertificateVerify signed content (RFC 8446 §4.4.3): 64 0x20 bytes, the
/// context string, a 0x00 separator, then the transcript hash (32 or 48 bytes).
/// Written into `out`; returns the used prefix.
fn buildCertVerifyInput(out: *[cert_verify_input_max]u8, context: []const u8, transcript_hash: []const u8) []const u8 {
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..context.len], context);
    out[64 + context.len] = 0;
    const tail = 64 + context.len + 1;
    @memcpy(out[tail..][0..transcript_hash.len], transcript_hash);
    return out[0 .. tail + transcript_hash.len];
}

/// Client leaf public key kinds we can verify a client CertificateVerify with
/// (must stay in sync with `Server.client_cert_schemes`).
const ClientLeafKey = union(enum) {
    ed25519: Ed25519.PublicKey,
    ecdsa_p256: ecdsa_p256.PublicKey,
    // `n`/`e` borrow the leaf DER, which the caller keeps owned in
    // `client_cert_der` for the connection's lifetime — valid through the
    // CertificateVerify check that immediately follows.
    rsa: rsa_verify.PublicKey,
};

const oid_ed25519_spki = [_]u8{ 0x2B, 0x65, 0x70 }; // 1.3.101.112
const oid_ec_public_key_spki = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 }; // 1.2.840.10045.2.1
const oid_prime256v1_spki = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
const oid_rsa_encryption_spki = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }; // 1.2.840.113549.1.1.1

/// Extract the public key from a leaf certificate's DER SPKI. CertFP/EXTERNAL
/// target Ed25519 and ECDSA P-256 client certs; any other SPKI yields an error
/// so the caller fails the possession proof rather than trusting an
/// unverifiable cert.
fn clientKeyFromCert(der: []const u8) Error!ClientLeafKey {
    const cert = x509.parse(der) catch return error.BadHandshake;
    // SPKI value = SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00 ++ key } }.
    var spki = x509.DerReader.init(cert.spki_value);
    const alg_seq = spki.readExpected(x509.Tag.sequence) catch return error.BadHandshake;
    const key_bits = spki.readExpected(x509.Tag.bit_string) catch return error.BadHandshake;
    spki.expectEmpty() catch return error.BadHandshake;
    if (key_bits.value.len == 0 or key_bits.value[0] != 0) return error.BadHandshake;
    const key_bytes = key_bits.value[1..];

    var alg = spki.child(alg_seq) catch return error.BadHandshake;
    const alg_oid = alg.readExpected(x509.Tag.oid) catch return error.BadHandshake;
    if (std.mem.eql(u8, alg_oid.value, &oid_ed25519_spki)) {
        if (key_bytes.len != Ed25519.PublicKey.encoded_length) return error.BadHandshake;
        var raw: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        @memcpy(&raw, key_bytes);
        const pk = Ed25519.PublicKey.fromBytes(raw) catch return error.BadHandshake;
        return .{ .ed25519 = pk };
    }
    if (std.mem.eql(u8, alg_oid.value, &oid_ec_public_key_spki)) {
        const curve = alg.readExpected(x509.Tag.oid) catch return error.BadHandshake;
        if (!std.mem.eql(u8, curve.value, &oid_prime256v1_spki)) return error.BadHandshake;
        const pk = ecdsa_p256.parsePublicKeySec1(key_bytes) catch return error.BadHandshake;
        return .{ .ecdsa_p256 = pk };
    }
    if (std.mem.eql(u8, alg_oid.value, &oid_rsa_encryption_spki)) {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
        var r = x509.DerReader.init(key_bytes);
        const rsa_seq = r.readExpected(x509.Tag.sequence) catch return error.BadHandshake;
        r.expectEmpty() catch return error.BadHandshake;
        var body = r.child(rsa_seq) catch return error.BadHandshake;
        const n_tlv = body.readExpected(x509.Tag.integer) catch return error.BadHandshake;
        const e_tlv = body.readExpected(x509.Tag.integer) catch return error.BadHandshake;
        body.expectEmpty() catch return error.BadHandshake;
        const n = rsaUnsignedInt(n_tlv) orelse return error.BadHandshake;
        const e = rsaUnsignedInt(e_tlv) orelse return error.BadHandshake;
        if (n.len > rsa_verify.max_bytes) return error.BadHandshake;
        return .{ .rsa = .{ .n = n, .e = e } };
    }
    return error.BadHandshake;
}

/// A DER INTEGER's content as an unsigned big-endian magnitude: rejects a set
/// sign bit and strips the single leading 0x00 byte DER requires when the
/// magnitude's MSB is set. Returns null on a malformed/empty/negative integer.
fn rsaUnsignedInt(tlv: x509.Tlv) ?[]const u8 {
    if (tlv.value.len == 0) return null;
    if ((tlv.value[0] & 0x80) != 0) return null; // negative
    // Reject non-canonical DER: a leading 0x00 is only legal when the next byte's
    // MSB is set (otherwise the padding is redundant). Matches x509.unsignedInteger.
    if (tlv.value.len > 1 and tlv.value[0] == 0 and (tlv.value[1] & 0x80) == 0) return null;
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..];
    if (v.len == 0) return null;
    return v;
}

fn pickSuite(block: []const u8) ?CipherSuite {
    if (block.len % 2 != 0) return null;
    // Prefer AES-128-GCM, then AES-256-GCM, then ChaCha20-Poly1305.
    var has_aes256 = false;
    var has_chacha = false;
    var i: usize = 0;
    while (i + 1 < block.len) : (i += 2) {
        const v = std.mem.readInt(u16, block[i..][0..2], .big);
        if (v == @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256)) return .tls_aes_128_gcm_sha256;
        if (v == @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384)) has_aes256 = true;
        if (v == @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256)) has_chacha = true;
    }
    if (has_aes256) return .tls_aes_256_gcm_sha384;
    if (has_chacha) return .tls_chacha20_poly1305_sha256;
    return null;
}

fn clientOfferedSuite(block: []const u8, suite: CipherSuite) bool {
    if (block.len % 2 != 0) return false;
    var i: usize = 0;
    const wire: u16 = @intFromEnum(suite);
    while (i + 1 < block.len) : (i += 2) {
        if (std.mem.readInt(u16, block[i..][0..2], .big) == wire) return true;
    }
    return false;
}

fn pskModesAllowDhe(data: []const u8) bool {
    if (data.len < 1) return false;
    const len = data[0];
    if (data.len != 1 + @as(usize, len)) return false;
    for (data[1..]) |mode| {
        if (mode == 1) return true; // psk_dhe_ke
    }
    return false;
}

fn findPskExtensionBodyOffset(client_hello_raw: []const u8) Error!usize {
    if (client_hello_raw.len < 4 or client_hello_raw[0] != @intFromEnum(HandshakeType.client_hello)) {
        return error.BadHandshake;
    }
    const body_len = (@as(usize, client_hello_raw[1]) << 16) |
        (@as(usize, client_hello_raw[2]) << 8) |
        client_hello_raw[3];
    if (client_hello_raw.len != 4 + body_len) return error.BadHandshake;

    var c = Cursor.init(client_hello_raw[4..]);
    _ = try c.take(2);
    _ = try c.take(32);
    _ = try c.take(try c.readU8());
    _ = try c.take(try c.readU16());
    _ = try c.take(try c.readU8());
    const ext_len = try c.readU16();
    const ext_body_start = 4 + c.pos;
    const ext_body = try c.take(ext_len);
    if (c.remaining() != 0) return error.BadHandshake;

    var pos: usize = 0;
    while (pos < ext_body.len) {
        if (ext_body.len - pos < tls_extension.header_len) return error.BadHandshake;
        const typ = std.mem.readInt(u16, ext_body[pos..][0..2], .big);
        const len = std.mem.readInt(u16, ext_body[pos + 2 ..][0..2], .big);
        const data_start = pos + tls_extension.header_len;
        if (ext_body.len - data_start < len) return error.BadHandshake;
        if (typ == @intFromEnum(tls_extension.ExtensionType.pre_shared_key)) {
            return ext_body_start + data_start;
        }
        pos = data_start + len;
    }
    return error.MissingExtension;
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

/// In-place KeyUpdate of a traffic secret stored in a `[max_hash_len]u8` field.
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

    fn readU24(self: *Cursor) Error!usize {
        const b = try self.take(3);
        return (@as(usize, b[0]) << 16) | (@as(usize, b[1]) << 8) | b[2];
    }
};

/// Like parseHandshake but returns null (instead of erroring) when fewer than a
/// full handshake message is buffered yet — used to drain the client flight.
fn parseHandshakeMaybe(input: []const u8, offset: *usize) ?HandshakeMsg {
    if (input.len < 4) return null;
    const len = (@as(usize, input[1]) << 16) | (@as(usize, input[2]) << 8) | input[3];
    if (input.len < 4 + len) return null;
    return parseHandshake(input, offset) catch null;
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

    var premature_binding: [32]u8 = undefined;
    try std.testing.expectError(error.BadState, server.channelBindingTlsExporter(&premature_binding));
    try std.testing.expectError(error.BadState, client.channelBindingTlsExporter(&premature_binding));

    // No suite negotiated before the ClientHello is processed.
    try std.testing.expectEqual(@as(?[]const u8, null), server.cipherName());
    // kTLS TX params are unavailable until the handshake completes.
    try std.testing.expect(server.ktlsTxParams() == null);

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

    // kTLS TX offload params: available once connected, matching the live server
    // app write keys and the negotiated (default AES-128-GCM) suite. Checked
    // before any encrypt() so app_write_seq is still 0.
    {
        const p = server.ktlsTxParams() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(Server.KtlsCipher.aes_128_gcm, p.cipher);
        try std.testing.expectEqual(@as(usize, 16), p.key.len);
        try std.testing.expectEqualSlices(u8, server.server_app_keys.key[0..16], p.key);
        try std.testing.expectEqualSlices(u8, &server.server_app_keys.iv, &p.iv);
        try std.testing.expectEqual(server.app_write_seq, p.seq);
    }

    // The negotiated suite renders as its IANA name for WHOIS 671. The server
    // prefers AES-128-GCM whenever the client offers it (pickSuite).
    const negotiated = server.cipherName() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", negotiated);

    var client_binding: [32]u8 = undefined;
    var server_binding: [32]u8 = undefined;
    try client.channelBindingTlsExporter(&client_binding);
    try server.channelBindingTlsExporter(&server_binding);
    try std.testing.expectEqualSlices(u8, &client_binding, &server_binding);

    var different_label: [32]u8 = undefined;
    try client.exportKeyingMaterial("orochi-test-exporter", "", different_label[0..]);
    try std.testing.expect(!std.mem.eql(u8, &client_binding, &different_label));

    var different_context: [32]u8 = undefined;
    try client.exportKeyingMaterial("EXPORTER-Channel-Binding", "context", different_context[0..]);
    try std.testing.expect(!std.mem.eql(u8, &client_binding, &different_context));

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

test "loopback: record_size_limit negotiated + fragments outbound records (RFC 8449)" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x5d} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x5d, 0x01 },
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
    _ = try server.feed(cfin);
    try std.testing.expect(client.handshakeDone() and server.handshakeDone());

    // Both advertised the maximum, so each stored the "no restriction" default.
    try std.testing.expectEqual(@as(usize, tls_record.max_plaintext_len + 1), server.peer_record_size_limit);
    try std.testing.expectEqual(@as(usize, tls_record.max_plaintext_len + 1), client.peer_record_size_limit);

    // Simulate a peer that advertised a small limit (100) → content limit 99.
    // A 250-byte payload must fragment into ceil(250/99) = 3 records, and the
    // client must decrypt each and reassemble the original bytes exactly.
    server.peer_record_size_limit = 100;
    var payload: [250]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    const wire = try server.encrypt(&payload);
    defer alloc.free(wire);

    var reassembled: std.ArrayList(u8) = .empty;
    defer reassembled.deinit(alloc);
    var records: usize = 0;
    var off: usize = 0;
    while (off < wire.len) {
        try std.testing.expect(wire.len - off >= 5);
        const rec_len = std.mem.readInt(u16, wire[off + 3 ..][0..2], .big);
        // TLSInnerPlaintext = content + 1 content-type byte; ciphertext adds the
        // AEAD tag. So each record's inner plaintext stays within the 100 limit.
        const rec = wire[off .. off + 5 + rec_len];
        const pt = try client.decrypt(rec);
        defer alloc.free(pt);
        try reassembled.appendSlice(alloc, pt);
        records += 1;
        off += 5 + rec_len;
    }
    try std.testing.expectEqual(off, wire.len);
    try std.testing.expectEqual(@as(usize, 3), records);
    try std.testing.expectEqualSlices(u8, &payload, reassembled.items);
}

test "loopback: X25519MLKEM768 post-quantum hybrid handshake (client offer + server encaps)" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x6a} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x6a, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    client.offerOnlyHybridForTest(); // force the server to select x25519mlkem768

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

    // The server negotiated the PQ hybrid group (0x11ec).
    try std.testing.expectEqual(@as(u16, 0x11ec), @intFromEnum(server.selected_group));

    // A completed Finished + a data round-trip proves both sides derived the SAME
    // 64-byte combined secret (ml-kem_ss || x25519_ss, the raw IETF concat) — if
    // the client had used the wrong combiner the transcript MACs would not match.
    const s2c = try server.encrypt("pq hello client");
    defer alloc.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("pq hello client", got_c);

    const c2s = try client.encrypt("pq hello server");
    defer alloc.free(c2s);
    const got_s = try server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("pq hello server", got_s);
}

test "OCSP staple: leaf CertificateEntry carries status_request when client asked + staple set" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x7b} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x7b, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
    // The staple bytes are opaque here — this test checks the WIRE FRAMING the
    // server produces (the client's parse + OCSP verification are tested
    // separately). Real deployments configure a validly-signed OCSPResponse.
    const staple = "\x30\x05\x0a\x01\x00\x02\x00"; // arbitrary DER-ish blob

    const helper = struct {
        fn leafExtLen(server: *Server, a: std.mem.Allocator) !struct { ext_len: usize, msg: []u8 } {
            var out: std.ArrayList(u8) = .empty;
            try server.writeCertificate(&out);
            const m = try out.toOwnedSlice(a);
            // handshake: type(1)+len(3); body: ctx_len(1)+ctx; cert_list_len(3);
            // first entry: cert_len(3)+der + ext_len(2).
            var p: usize = 4;
            p += 1 + m[p]; // certificate_request_context
            p += 3; // certificate_list length
            const der_len = (@as(usize, m[p]) << 16) | (@as(usize, m[p + 1]) << 8) | m[p + 2];
            p += 3 + der_len;
            const ext_len = (@as(usize, m[p]) << 8) | m[p + 1];
            return .{ .ext_len = ext_len, .msg = m };
        }
    };

    // Configured staple + client asked → the leaf carries a status_request ext.
    {
        var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp, .ocsp_staple = staple });
        defer server.deinit();
        server.client_requested_ocsp = true;
        const r = try helper.leafExtLen(&server, alloc);
        defer alloc.free(r.msg);
        try std.testing.expect(r.ext_len > 0);
        // Locate the extension: type(5), len, then CertificateStatus.
        var p: usize = 4;
        p += 1 + r.msg[p];
        p += 3;
        const der_len = (@as(usize, r.msg[p]) << 16) | (@as(usize, r.msg[p + 1]) << 8) | r.msg[p + 2];
        p += 3 + der_len + 2; // skip cert + ext_len field
        const ext_type = (@as(u16, r.msg[p]) << 8) | r.msg[p + 1];
        try std.testing.expectEqual(@as(u16, 5), ext_type); // status_request
        const data = r.msg[p + 4 ..][0 .. (@as(usize, r.msg[p + 2]) << 8) | r.msg[p + 3]];
        try std.testing.expectEqual(@as(u8, 1), data[0]); // status_type = ocsp
        const resp_len = (@as(usize, data[1]) << 16) | (@as(usize, data[2]) << 8) | data[3];
        try std.testing.expectEqualSlices(u8, staple, data[4 .. 4 + resp_len]);
    }

    // No staple configured → the leaf extensions stay empty (byte-identical wire).
    {
        var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
        defer server.deinit();
        server.client_requested_ocsp = true; // asked, but nothing to staple
        const r = try helper.leafExtLen(&server, alloc);
        defer alloc.free(r.msg);
        try std.testing.expectEqual(@as(usize, 0), r.ext_len);
    }

    // Staple set but client did NOT ask → no staple (gated).
    {
        var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp, .ocsp_staple = staple });
        defer server.deinit();
        const r = try helper.leafExtLen(&server, alloc);
        defer alloc.free(r.msg);
        try std.testing.expectEqual(@as(usize, 0), r.ext_len);
    }
}

test "loopback: exportResume/resumeConnected carries a live session across Server instances" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x44} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x44, 0x01 },
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
    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    var client_binding: [32]u8 = undefined;
    var server_binding: [32]u8 = undefined;
    try client.channelBindingTlsExporter(&client_binding);
    try server.channelBindingTlsExporter(&server_binding);
    try std.testing.expectEqualSlices(u8, &client_binding, &server_binding);

    // Advance both sequence directions before the export so the carried seqs
    // are non-zero (the interesting case for a mid-life upgrade).
    const pre_s2c = try server.encrypt("pre-upgrade s2c");
    defer alloc.free(pre_s2c);
    const pre_got = try client.decrypt(pre_s2c);
    defer alloc.free(pre_got);
    const pre_c2s = try client.encrypt("pre-upgrade c2s");
    defer alloc.free(pre_c2s);
    const pre_got_s = try server.decrypt(pre_c2s);
    defer alloc.free(pre_got_s);

    // Export is rejected before connect (fresh server) and works when live.
    var fresh = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer fresh.deinit();
    try std.testing.expectError(error.BadState, fresh.exportResume());
    const st = try server.exportResume();
    try std.testing.expectEqual(@as(u64, 1), st.app_read_seq);
    try std.testing.expectEqual(@as(u64, 1), st.app_write_seq);

    // The successor instance continues the SAME record stream both ways.
    var successor = try Server.resumeConnected(alloc, .{ .cert_chain = &.{der}, .signing_key = kp }, st);
    defer successor.deinit();
    try std.testing.expect(successor.handshakeDone());
    var successor_binding: [32]u8 = undefined;
    try successor.channelBindingTlsExporter(&successor_binding);
    try std.testing.expectEqualSlices(u8, &client_binding, &successor_binding);

    const c2s = try client.encrypt("post-upgrade c2s");
    defer alloc.free(c2s);
    const got_s = try successor.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("post-upgrade c2s", got_s);

    const s2c = try successor.encrypt("post-upgrade s2c");
    defer alloc.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("post-upgrade s2c", got_c);

    // A KeyUpdate initiated by the resumed successor still works: the carried
    // application secrets (not just the derived keys) survived the handoff.
    const ku = try successor.initiateKeyUpdate(false);
    defer alloc.free(ku);
    try std.testing.expectEqual(tls_client.AppRead.control, try client.decryptApp(ku));
    const rotated = try successor.encrypt("after keyupdate");
    defer alloc.free(rotated);
    const got_rot = try client.decrypt(rotated);
    defer alloc.free(got_rot);
    try std.testing.expectEqualStrings("after keyupdate", got_rot);
}

test "loopback: TLS 1.3 PSK-DHE session resumption and binder tamper fallback" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x91} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x91, 0x13 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
    });
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

    const ticket_key = server.ticketKey();
    const ticket_record = (try server.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(ticket_record);
    try std.testing.expectEqual(tls_client.AppRead.control, try client.decryptApp(ticket_record));
    const stored = client.takeSessionTicket() orelse return error.TestUnexpectedResult;
    defer alloc.free(stored);

    var resumed_server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
    });
    defer resumed_server.deinit();
    var resumed_client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer resumed_client.deinit();
    try resumed_client.setSessionTicket(stored, 0);

    const rch = try resumed_client.start();
    defer alloc.free(rch);
    const rsflight = switch (try resumed_server.feed(rch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(rsflight);
    try std.testing.expect(resumed_server.acceptedSessionTicket());
    const rcfin = switch (try resumed_client.feed(rsflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(rcfin);
    try std.testing.expect(resumed_client.handshakeDone());
    try std.testing.expect(resumed_client.leaf_key == null);
    _ = try resumed_server.feed(rcfin);
    try std.testing.expect(resumed_server.handshakeDone());

    const s2c = try resumed_server.encrypt("resumed down");
    defer alloc.free(s2c);
    const got_c = try resumed_client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("resumed down", got_c);
    const c2s = try resumed_client.encrypt("resumed up");
    defer alloc.free(c2s);
    const got_s = try resumed_server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("resumed up", got_s);

    var tamper_server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
    });
    defer tamper_server.deinit();
    var tamper_client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer tamper_client.deinit();
    try tamper_client.setSessionTicket(stored, 0);

    const tch_orig = try tamper_client.start();
    defer alloc.free(tch_orig);
    const tch = try alloc.dupe(u8, tch_orig);
    defer alloc.free(tch);
    tch[tch.len - 1] ^= 0x01; // pre_shared_key is last; this flips a binder byte.
    tamper_client.transcript.items[tamper_client.transcript.items.len - 1] ^= 0x01;
    const tsflight = switch (try tamper_server.feed(tch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(tsflight);
    try std.testing.expect(!tamper_server.acceptedSessionTicket());
    const tcfin = switch (try tamper_client.feed(tsflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(tcfin);
    _ = try tamper_server.feed(tcfin);
    try std.testing.expect(tamper_server.handshakeDone());
    try std.testing.expect(!tamper_server.acceptedSessionTicket());
}

test "loopback: TLS 1.3 PSK-DHE resumption accepts 0-RTT early data" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0xA0} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0xA0, 0x13 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .max_early_data_size = 4096,
    });
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
    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    const ticket_key = server.ticketKey();
    const ticket_record = (try server.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(ticket_record);
    try std.testing.expectEqual(tls_client.AppRead.control, try client.decryptApp(ticket_record));
    const stored = client.takeSessionTicket() orelse return error.TestUnexpectedResult;
    defer alloc.free(stored);

    var resumed_server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
    });
    defer resumed_server.deinit();
    var resumed_client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer resumed_client.deinit();
    try resumed_client.setSessionTicket(stored, 0);
    try resumed_client.setEarlyData("GET /early");

    const rch = try resumed_client.start();
    defer alloc.free(rch);
    const rsflight = switch (try resumed_server.feed(rch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(rsflight);
    try std.testing.expect(resumed_server.acceptedSessionTicket());
    try std.testing.expect(resumed_server.earlyDataAccepted());
    const early = (try resumed_server.takeEarlyData()) orelse return error.TestUnexpectedResult;
    defer alloc.free(early);
    try std.testing.expectEqualStrings("GET /early", early);

    const rcfin = switch (try resumed_client.feed(rsflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(rcfin);
    try std.testing.expectEqual(@as(?bool, true), resumed_client.earlyDataAccepted());
    try std.testing.expect(resumed_client.handshakeDone());
    _ = try resumed_server.feed(rcfin);
    try std.testing.expect(resumed_server.handshakeDone());

    const s2c = try resumed_server.encrypt("early down");
    defer alloc.free(s2c);
    const got_c = try resumed_client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("early down", got_c);
    const c2s = try resumed_client.encrypt("early up");
    defer alloc.free(c2s);
    const got_s = try resumed_server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("early up", got_s);
}

test "loopback: an expired resumption ticket is rejected (lifetime enforced)" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0xB1} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0xB1, 0x13 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
    const t0: i64 = 1_700_000_000;

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .ticket_lifetime_seconds = 100,
        .now_unix_seconds = t0, // stamps the ticket's issue time
    });
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
    _ = try server.feed(cfin);
    const ticket_key = server.ticketKey();
    const ticket_record = (try server.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(ticket_record);
    _ = try client.decryptApp(ticket_record);
    const stored = client.takeSessionTicket() orelse return error.TestUnexpectedResult;
    defer alloc.free(stored);

    // Resume past the 100s lifetime: the server must refuse the PSK and run a
    // full handshake (no resumption).
    var resumed_server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
        .ticket_lifetime_seconds = 100,
        .now_unix_seconds = t0 + 101,
    });
    defer resumed_server.deinit();
    var resumed_client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer resumed_client.deinit();
    try resumed_client.setSessionTicket(stored, 0);

    const rch = try resumed_client.start();
    defer alloc.free(rch);
    const rsflight = switch (try resumed_server.feed(rch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(rsflight);
    try std.testing.expect(!resumed_server.acceptedSessionTicket());
}

test "loopback: a replayed 0-RTT ClientHello is resumed but its early data refused" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0xC2} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0xC2, 0x13 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .max_early_data_size = 4096,
    });
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
    _ = try server.feed(cfin);
    const ticket_key = server.ticketKey();
    const ticket_record = (try server.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(ticket_record);
    _ = try client.decryptApp(ticket_record);
    const stored = client.takeSessionTicket() orelse return error.TestUnexpectedResult;
    defer alloc.free(stored);

    var resumed_client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer resumed_client.deinit();
    try resumed_client.setSessionTicket(stored, 0);
    try resumed_client.setEarlyData("REPLAY ME");
    const rch = try resumed_client.start(); // the exact bytes an attacker would replay
    defer alloc.free(rch);

    var guard = tls_resumption.ReplayGuard{};

    // First delivery: 0-RTT accepted.
    var server_a = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
        .max_early_data_size = 4096,
        .replay_guard = &guard,
    });
    defer server_a.deinit();
    const a_flight = switch (try server_a.feed(rch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(a_flight);
    try std.testing.expect(server_a.acceptedSessionTicket());
    try std.testing.expect(server_a.earlyDataAccepted());

    // Replay of the identical ClientHello to a second server sharing the guard:
    // still resumes (1-RTT) but the early data is refused.
    var server_b = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
        .max_early_data_size = 4096,
        .replay_guard = &guard,
    });
    defer server_b.deinit();
    const b_flight = switch (try server_b.feed(rch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(b_flight);
    try std.testing.expect(server_b.acceptedSessionTicket());
    try std.testing.expect(!server_b.earlyDataAccepted());
}

test "loopback: TLS 1.3 PSK-DHE resumption rejects 0-RTT when sealed ticket limit is zero" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0xA1} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0xA1, 0x13 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .enable_session_tickets = true,
        .max_early_data_size = 0,
    });
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
    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    const ticket_key = server.ticketKey();
    const ticket_record = (try server.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(ticket_record);
    try std.testing.expectEqual(tls_client.AppRead.control, try client.decryptApp(ticket_record));
    const stored = client.takeSessionTicket() orelse return error.TestUnexpectedResult;
    defer alloc.free(stored);

    const decoded = try tls_resumption.decodeStoredSession(stored);
    const forged = try tls_resumption.encodeStoredSession(alloc, .{
        .suite = decoded.suite,
        .ticket_lifetime = decoded.ticket_lifetime,
        .ticket_age_add = decoded.ticket_age_add,
        .ticket = decoded.ticket,
        .psk = decoded.psk,
        .max_early_data_size = 4096,
    });
    defer alloc.free(forged);

    var resumed_server = try Server.init(alloc, .{
        .cert_chain = &.{der},
        .signing_key = kp,
        .ticket_key = ticket_key,
    });
    defer resumed_server.deinit();
    var resumed_client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer resumed_client.deinit();
    try resumed_client.setSessionTicket(forged, 0);
    try resumed_client.setEarlyData("GET /early");

    const rch = try resumed_client.start();
    defer alloc.free(rch);
    const rsflight = switch (try resumed_server.feed(rch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(rsflight);
    try std.testing.expect(resumed_server.acceptedSessionTicket());
    try std.testing.expect(!resumed_server.earlyDataAccepted());
    try std.testing.expect((try resumed_server.takeEarlyData()) == null);

    const rcfin = switch (try resumed_client.feed(rsflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(rcfin);
    try std.testing.expectEqual(@as(?bool, false), resumed_client.earlyDataAccepted());
    try std.testing.expect(resumed_client.handshakeDone());
    _ = try resumed_server.feed(rcfin);
    try std.testing.expect(resumed_server.handshakeDone());
}

test "loopback: tls_client completes a handshake against tls_server with ECDSA-P256 leaf" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x26, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .ecdsa_p256_signing_key = kp });
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

    const s2c = try server.encrypt("ecdsa hello client");
    defer alloc.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("ecdsa hello client", got_c);

    const c2s = try client.encrypt("ecdsa hello server");
    defer alloc.free(c2s);
    const got_s = try server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("ecdsa hello server", got_s);
}

test "loopback: tls_client completes a handshake against tls_server with RSA leaf" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const rsa_key = rsaTestPrivateKey();
    var cert_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedRsa(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x52, 0x13 },
        .public_modulus = rsa_key.n,
        .public_exponent = rsa_key.e,
        .private_key = rsa_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .rsa_signing_key = rsa_key });
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

    const s2c = try server.encrypt("rsa hello client");
    defer alloc.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("rsa hello client", got_c);

    const c2s = try client.encrypt("rsa hello server");
    defer alloc.free(c2s);
    const got_s = try server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("rsa hello server", got_s);
}

test "loopback: handshake completes over TLS_AES_256_GCM_SHA384 (SHA-384 schedule)" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x84} ** Ed25519.KeyPair.seed_length);
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
    client.offerOnlyAes256ForTest();

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

    var client_binding: [32]u8 = undefined;
    var server_binding: [32]u8 = undefined;
    try client.channelBindingTlsExporter(&client_binding);
    try server.channelBindingTlsExporter(&server_binding);
    try std.testing.expectEqualSlices(u8, &client_binding, &server_binding);

    // App data both ways under AES-256-GCM with the SHA-384 transcript/MAC.
    const s2c = try server.encrypt("aes256 down");
    defer alloc.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("aes256 down", got_c);
    const c2s = try client.encrypt("aes256 up");
    defer alloc.free(c2s);
    const got_s = try server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("aes256 up", got_s);

    // A KeyUpdate must rekey correctly under the SHA-384 schedule too.
    const ku = try server.initiateKeyUpdate(false);
    defer alloc.free(ku);
    const consumed = try client.decrypt(ku);
    defer alloc.free(consumed);
    const s2c2 = try server.encrypt("aes256 rekeyed");
    defer alloc.free(s2c2);
    const got_c2 = try client.decrypt(s2c2);
    defer alloc.free(got_c2);
    try std.testing.expectEqualStrings("aes256 rekeyed", got_c2);
}

test "loopback: handshake completes over secp256r1 key exchange" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x63} ** Ed25519.KeyPair.seed_length);
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
    client.offerOnlyP256ForTest();

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    try std.testing.expectEqual(tls_keyshare.NamedGroup.secp256r1, server.selected_group);

    const cfin = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());
    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    const s2c = try server.encrypt("p256 ok");
    defer alloc.free(s2c);
    const got = try client.decrypt(s2c);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("p256 ok", got);
}

/// True when `flight` begins with a plaintext handshake record carrying a
/// ServerHello whose random is the HelloRetryRequest magic value (RFC 8446).
fn firstHandshakeIsHelloRetryRequest(flight: []const u8) bool {
    const rec = completePlainRecord(flight) orelse return false;
    if (rec.content_type != .handshake) return false;
    var off: usize = 0;
    const msg = parseHandshake(rec.fragment, &off) catch return false;
    if (msg.typ != .server_hello or msg.body.len < 34) return false;
    return std.mem.eql(u8, msg.body[2..34], &hello_retry_request_random);
}

test "loopback: server HelloRetryRequest recovers a client that withheld key_shares" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x71} ** Ed25519.KeyPair.seed_length);
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
    // Advertise all groups but send an empty key_share, so the server must HRR.
    client.offerNoSharesForTest();

    // ClientHello1 (no shares) → server answers with a HelloRetryRequest.
    const ch1 = try client.start();
    defer alloc.free(ch1);
    const hrr = switch (try server.feed(ch1)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(hrr);
    try std.testing.expect(firstHandshakeIsHelloRetryRequest(hrr));
    try std.testing.expect(server.hrr_sent);
    try std.testing.expectEqual(tls_keyshare.NamedGroup.x25519, server.hrr_group);
    try std.testing.expectEqual(State.wait_second_client_hello, server.state);

    // Client consumes the HRR and emits ClientHello2 with the x25519 share.
    const ch2 = switch (try client.feed(hrr)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(ch2);

    // ClientHello2 → the real server flight; the exchange binds to x25519.
    const sflight = switch (try server.feed(ch2)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    try std.testing.expectEqual(tls_keyshare.NamedGroup.x25519, server.selected_group);

    const cfin = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());
    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    // Application data flows both ways over the post-HRR keys.
    const s2c = try server.encrypt("hrr ok");
    defer alloc.free(s2c);
    const got = try client.decrypt(s2c);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("hrr ok", got);

    const c2s = try client.encrypt("client after retry");
    defer alloc.free(c2s);
    const got2 = try server.decrypt(c2s);
    defer alloc.free(got2);
    try std.testing.expectEqualStrings("client after retry", got2);
}

test "server rejects a ClientHello2 whose SNI differs from ClientHello1 (RFC 8446 §4.1.2)" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x73} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x35 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    client.offerNoSharesForTest(); // force a HelloRetryRequest so CH2 exists

    const ch1 = try client.start();
    defer alloc.free(ch1);
    const hrr = switch (try server.feed(ch1)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(hrr);
    try std.testing.expect(server.hrr_sent);
    try std.testing.expect(server.ch1_sni_digest != null); // CH1's SNI was pinned.

    const ch2 = switch (try client.feed(hrr)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(ch2);

    // Tamper: rewrite the (plaintext) SNI host_name in ClientHello2 so it no
    // longer matches ClientHello1's. A conformant client sends a byte-identical
    // SNI; a confusion attacker might swap it to coax a different cert. The server
    // must reject at CH2 parse — "irc.test" appears only in the SNI here.
    const at = std.mem.indexOf(u8, ch2, "irc.test") orelse return error.TestUnexpectedResult;
    const tampered = try alloc.dupe(u8, ch2);
    defer alloc.free(tampered);
    tampered[at] = 'X'; // "Xrc.test" ⇒ different digest ⇒ rejection

    try std.testing.expectError(error.BadHandshake, server.feed(tampered));
}

test "sniDigest / sniDigestEql: presence and byte-exact equality" {
    try std.testing.expect(sniDigestEql(null, null));
    try std.testing.expect(!sniDigestEql(sniDigest("a.test"), null));
    try std.testing.expect(!sniDigestEql(null, sniDigest("a.test")));
    try std.testing.expect(sniDigestEql(sniDigest("a.test"), sniDigest("a.test")));
    try std.testing.expect(!sniDigestEql(sniDigest("a.test"), sniDigest("b.test")));
    // Case-sensitive on purpose: §4.1.2 requires a byte-identical ClientHello2,
    // so a case-flipped SNI is a (rejected) change, not a match.
    try std.testing.expect(!sniDigestEql(sniDigest("A.test"), sniDigest("a.test")));
}

test "init rejects a signing key whose type mismatches the leaf public key" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    // An Ed25519 leaf paired (wrongly) with an ECDSA-P256 signing key: every
    // CertificateVerify would be produced by a key that doesn't match the
    // presented leaf, so the server must refuse the config at init.
    const ed_kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x51} ** Ed25519.KeyPair.seed_length);
    var buf: [1024]u8 = undefined;
    const ed_leaf = try x509_selfsign.buildSelfSigned(&buf, .{
        .common_name = "leaf.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x01},
        .key_pair = ed_kp,
        .dns_names = &.{"leaf.test"},
    });
    const ecdsa_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    try std.testing.expectError(error.LeafKeyMismatch, Server.init(alloc, .{
        .cert_chain = &.{ed_leaf},
        .ecdsa_p256_signing_key = ecdsa_kp,
    }));

    // The matching pairing (Ed25519 leaf + Ed25519 key) initializes fine.
    var ok = try Server.init(alloc, .{ .cert_chain = &.{ed_leaf}, .signing_key = ed_kp });
    ok.deinit();
}

test "alertDescriptionForError maps handshake errors to RFC 8446 §6 codes" {
    try std.testing.expectEqual(AlertDescription.protocol_version, alertDescriptionForError(error.ProtocolVersion).?);
    try std.testing.expectEqual(AlertDescription.missing_extension, alertDescriptionForError(error.MissingExtension).?);
    try std.testing.expectEqual(AlertDescription.handshake_failure, alertDescriptionForError(error.UnsupportedCipherSuite).?);
    try std.testing.expectEqual(AlertDescription.decode_error, alertDescriptionForError(error.BadHandshake).?);
    try std.testing.expectEqual(AlertDescription.internal_error, alertDescriptionForError(error.NoCertificate).?);
    // OutOfMemory ⇒ no alert (can't allocate a record anyway).
    try std.testing.expect(alertDescriptionForError(error.OutOfMemory) == null);
    // Any unmapped error ⇒ a generic fatal handshake_failure.
    try std.testing.expectEqual(AlertDescription.handshake_failure, alertDescriptionForError(error.SomethingUnmapped).?);
}

test "takeAlert emits a fatal plaintext alert only before the ServerHello" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x61} ** Ed25519.KeyPair.seed_length);
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&buf, .{
        .common_name = "alert.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x01},
        .key_pair = kp,
        .dns_names = &.{"alert.test"},
    });
    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer server.deinit();

    // Fresh server (state = wait_client_hello): a well-formed plaintext alert.
    const rec = server.takeAlert(error.ProtocolVersion) orelse return error.TestUnexpectedResult;
    defer alloc.free(rec);
    // [content_type=21][0x03 0x03][len=0x0002][level=fatal(2)][desc=protocol_version(70)]
    try std.testing.expectEqual(@as(usize, 7), rec.len);
    try std.testing.expectEqual(@as(u8, 21), rec[0]); // ContentType.alert
    try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, rec[3..5], .big)); // fragment length
    try std.testing.expectEqual(@as(u8, @intFromEnum(AlertLevel.fatal)), rec[5]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(AlertDescription.protocol_version)), rec[6]);

    // OutOfMemory ⇒ no alert even before ServerHello.
    try std.testing.expect(server.takeAlert(error.OutOfMemory) == null);

    // A plaintext alert would be wrong past the ClientHello wait (keys exist).
    // `connected` is a completed handshake (a record-layer fault there is out of
    // this path's scope) ⇒ null (bare close). The post-ServerHello *handshake*
    // states emit an ENCRYPTED alert instead — see the next test.
    server.state = .connected;
    try std.testing.expect(server.takeAlert(error.BadHandshake) == null);
}

test "takeAlert seals an ENCRYPTED fatal alert for post-ServerHello handshake errors" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x53} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x07},
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    // ── Case 1: FinishedMismatch while awaiting the client Finished ──────────
    // Drive a real handshake up to (not through) the client Finished: after the
    // server emits its flight it is in `wait_client_finished` with the server
    // application write keys derived and `app_write_seq == 0`.
    {
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
        alloc.free(sflight);
        // The server has sent its Finished and switched its write to the app keys.
        try std.testing.expectEqual(State.wait_client_finished, server.state);
        try std.testing.expectEqual(@as(u64, 0), server.app_write_seq);

        const suite = server.selected_suite orelse return error.TestUnexpectedResult;
        const rec = server.takeAlert(error.FinishedMismatch) orelse return error.TestUnexpectedResult;
        defer alloc.free(rec);
        // The nonce/seq is consumed so it can never be reused.
        try std.testing.expectEqual(@as(u64, 1), server.app_write_seq);
        // On the wire a TLS 1.3 encrypted record has outer content_type 23.
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls_record.ContentType.application_data)), rec[0]);
        // It decrypts under the server application write keys at the seq used (0),
        // to an inner alert(21) carrying [fatal(2)][decrypt_error(51)].
        const opened = try openRecordAlloc(alloc, suite, &server.server_app_keys, 0, rec);
        defer alloc.free(opened.content);
        try std.testing.expectEqual(tls_record.ContentType.alert, opened.content_type);
        try std.testing.expectEqualSlices(u8, &.{
            @intFromEnum(AlertLevel.fatal),
            @intFromEnum(AlertDescription.decrypt_error),
        }, opened.content);
    }

    // ── Case 2: bad client Certificate while awaiting it (mTLS) ──────────────
    // With request_client_cert the server jumps to `wait_client_cert` right after
    // its flight; the write keys are the same application keys (seq 0).
    {
        var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp, .request_client_cert = true });
        defer server.deinit();
        var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
        defer client.deinit();

        const ch = try client.start();
        defer alloc.free(ch);
        const sflight = switch (try server.feed(ch)) {
            .bytes_to_send => |b| b,
            .need_more => return error.TestUnexpectedResult,
        };
        alloc.free(sflight);
        try std.testing.expectEqual(State.wait_client_cert, server.state);

        const suite = server.selected_suite orelse return error.TestUnexpectedResult;
        const rec = server.takeAlert(error.BadHandshake) orelse return error.TestUnexpectedResult;
        defer alloc.free(rec);
        try std.testing.expectEqual(@as(u8, @intFromEnum(tls_record.ContentType.application_data)), rec[0]);
        const opened = try openRecordAlloc(alloc, suite, &server.server_app_keys, 0, rec);
        defer alloc.free(opened.content);
        try std.testing.expectEqual(tls_record.ContentType.alert, opened.content_type);
        try std.testing.expectEqualSlices(u8, &.{
            @intFromEnum(AlertLevel.fatal),
            @intFromEnum(AlertDescription.decode_error),
        }, opened.content);
    }
}

test "loopback: RFC 8879 cert compression — server sends CompressedCertificate, client inflates" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x88} ** Ed25519.KeyPair.seed_length);
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

    // Duplicate certs make the Certificate body highly compressible (the repeats
    // deflate to back-references), so the server's "only compress if it shrinks"
    // guard reliably takes the compressed path.
    var server = try Server.init(alloc, .{
        .cert_chain = &.{ der, der, der },
        .signing_key = kp,
        .enable_cert_compression = true,
    });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    // Opt into RFC 8879 compression and skip chain-to-anchor validation so the
    // duplicated self-signed chain passes.
    client.offerCertCompression();
    client.skipServerCertVerifyForTest();

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    try std.testing.expect(server.cert_compression == cert_compression.Algorithm.zlib);

    const cfin = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cfin);
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(client.received_compressed_cert);
    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    const s2c = try server.encrypt("compressed cert ok");
    defer alloc.free(s2c);
    const got = try client.decrypt(s2c);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("compressed cert ok", got);
}

test "serverNameMatches: exact, case-insensitive, and single-label wildcard" {
    try std.testing.expect(serverNameMatches(&.{"a.test"}, "a.test"));
    try std.testing.expect(serverNameMatches(&.{"A.TEST"}, "a.test")); // case-insensitive
    try std.testing.expect(serverNameMatches(&.{ "x.test", "a.test" }, "a.test")); // later entry
    try std.testing.expect(!serverNameMatches(&.{"a.test"}, "b.test"));
    try std.testing.expect(!serverNameMatches(&.{}, "a.test")); // empty list never matches
    try std.testing.expect(!serverNameMatches(&.{""}, "a.test")); // empty pattern skipped
    // "*." matches exactly one left-most label.
    try std.testing.expect(serverNameMatches(&.{"*.a.com"}, "x.a.com"));
    try std.testing.expect(!serverNameMatches(&.{"*.a.com"}, "a.com")); // no label
    try std.testing.expect(!serverNameMatches(&.{"*.a.com"}, "x.y.a.com")); // two labels
    try std.testing.expect(!serverNameMatches(&.{"*.a.com"}, "xa.com")); // suffix boundary
}

/// Drive a full loopback handshake with the SNI-capable `cfg`, verify the leaf
/// against `server_name`/`trust`, round-trip app data, and return which
/// `sni_certs` index the server selected (null = default cert).
fn runSniHandshakeSelectedIndex(
    alloc: std.mem.Allocator,
    cfg: Config,
    server_name: []const u8,
    trust: []const []const u8,
) !?usize {
    const tls_client = @import("tls_client.zig");
    var server = try Server.init(alloc, cfg);
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = server_name, .trust_anchors = trust });
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
    if (!client.handshakeDone()) return error.TestUnexpectedResult;
    _ = try server.feed(cfin);
    if (!server.handshakeDone()) return error.TestUnexpectedResult;

    const s2c = try server.encrypt("sni ok");
    defer alloc.free(s2c);
    const got = try client.decrypt(s2c);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("sni ok", got);
    return server.sni_cert;
}

test "loopback: SNI selects the matching certificate among multiple" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp0 = try Ed25519.KeyPair.generateDeterministic([_]u8{0x90} ** Ed25519.KeyPair.seed_length);
    const kpA = try Ed25519.KeyPair.generateDeterministic([_]u8{0x91} ** Ed25519.KeyPair.seed_length);
    const kpB = try Ed25519.KeyPair.generateDeterministic([_]u8{0x92} ** Ed25519.KeyPair.seed_length);

    var buf0: [1024]u8 = undefined;
    var bufA: [1024]u8 = undefined;
    var bufB: [1024]u8 = undefined;
    const der0 = try x509_selfsign.buildSelfSigned(&buf0, .{ .common_name = "irc.test", .not_before = 1_704_067_200, .not_after = 4_102_444_800, .serial = &.{0x01}, .key_pair = kp0, .dns_names = &.{"irc.test"}, .is_ca = true });
    const derA = try x509_selfsign.buildSelfSigned(&bufA, .{ .common_name = "a.test", .not_before = 1_704_067_200, .not_after = 4_102_444_800, .serial = &.{0x02}, .key_pair = kpA, .dns_names = &.{"a.test"}, .is_ca = true });
    const derB = try x509_selfsign.buildSelfSigned(&bufB, .{ .common_name = "b.test", .not_before = 1_704_067_200, .not_after = 4_102_444_800, .serial = &.{0x03}, .key_pair = kpB, .dns_names = &.{"b.test"}, .is_ca = true });

    const sni_certs = [_]SniCert{
        .{ .server_names = &.{"a.test"}, .cert_chain = &.{derA}, .signing_key = kpA },
        .{ .server_names = &.{"b.test"}, .cert_chain = &.{derB}, .signing_key = kpB },
    };
    const cfg = Config{ .cert_chain = &.{der0}, .signing_key = kp0, .sni_certs = &sni_certs };

    // Each handshake only completes if the server presented the cert valid for the
    // client's server_name (SAN + trust anchor), so a green handshake *is* the
    // proof of correct selection; the returned index corroborates it.
    try std.testing.expectEqual(@as(?usize, 0), try runSniHandshakeSelectedIndex(alloc, cfg, "a.test", &.{derA}));
    try std.testing.expectEqual(@as(?usize, 1), try runSniHandshakeSelectedIndex(alloc, cfg, "b.test", &.{derB}));
    // Unmatched SNI falls back to the default cert.
    try std.testing.expectEqual(@as(?usize, null), try runSniHandshakeSelectedIndex(alloc, cfg, "irc.test", &.{der0}));
}

test "loopback: client rejects an expired server certificate when a clock is supplied" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x44} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    // Validity window entirely in 2024.
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200, // 2024-01-01
        .not_after = 1_706_745_600, // 2024-02-01
        .serial = &.{ 0x12, 0x34 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp });
    defer server.deinit();
    // Client clock is in 2033 — well past not_after.
    var client = try tls_client.Client.init(alloc, .{
        .server_name = "irc.test",
        .trust_anchors = &.{der},
        .now_unix_seconds = 2_000_000_000,
    });
    defer client.deinit();

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    try std.testing.expectError(error.Expired, client.feed(sflight));
}

test "loopback: post-handshake KeyUpdate rotates keys both directions" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x51} ** Ed25519.KeyPair.seed_length);
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
    _ = try server.feed(cfin);
    try std.testing.expect(server.handshakeDone());

    // Server initiates a KeyUpdate and asks the client to update in return.
    const ku = try server.initiateKeyUpdate(true);
    defer alloc.free(ku);
    const consumed = try client.decrypt(ku); // rotates server->client recv keys
    defer alloc.free(consumed);
    try std.testing.expectEqual(@as(usize, 0), consumed.len);

    // Server->client data now flows under the rotated server send keys.
    const s2c = try server.encrypt("after server rekey");
    defer alloc.free(s2c);
    const got_c = try client.decrypt(s2c);
    defer alloc.free(got_c);
    try std.testing.expectEqualStrings("after server rekey", got_c);

    // The client queued its own KeyUpdate reply (because update was requested).
    const reply = (try client.takePendingSend()) orelse return error.TestUnexpectedResult;
    defer alloc.free(reply);
    const consumed_s = try server.decrypt(reply); // rotates client->server recv keys
    defer alloc.free(consumed_s);
    try std.testing.expectEqual(@as(usize, 0), consumed_s.len);

    // Client->server data now flows under the rotated client send keys.
    const c2s = try client.encrypt("after client rekey");
    defer alloc.free(c2s);
    const got_s = try server.decrypt(c2s);
    defer alloc.free(got_s);
    try std.testing.expectEqualStrings("after client rekey", got_s);
}

test "mTLS: server requests + verifies a client cert and exposes its leaf DER" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const sign = @import("sign.zig");
    const alloc = std.testing.allocator;

    // One seed yields both the std-Ed25519 cert key and the sign.KeyPair the
    // client signs CertificateVerify with — same public key, so the server's
    // SPKI-extracted key verifies the possession proof.
    const s_seed = [_]u8{0x33} ** Ed25519.KeyPair.seed_length;
    const c_seed = [_]u8{0x44} ** Ed25519.KeyPair.seed_length;
    const server_kp = try Ed25519.KeyPair.generateDeterministic(s_seed);
    const client_kp = try Ed25519.KeyPair.generateDeterministic(c_seed);
    const client_sign = try sign.KeyPair.fromSeed(c_seed);

    var server_cert_buf: [1024]u8 = undefined;
    const server_der = try x509_selfsign.buildSelfSigned(&server_cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x33, 0x01 },
        .key_pair = server_kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
    var client_cert_buf: [1024]u8 = undefined;
    const client_der = try x509_selfsign.buildSelfSigned(&client_cert_buf, .{
        .common_name = "client.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x44, 0x01 },
        .key_pair = client_kp,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{server_der}, .signing_key = server_kp, .request_client_cert = true });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{server_der} });
    defer client.deinit();
    client.setClientCertForTest(client_der, client_sign);

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    const cflight = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cflight);
    try std.testing.expect(client.handshakeDone());

    _ = try server.feed(cflight);
    try std.testing.expect(server.handshakeDone());

    // The verified client leaf is exactly what was presented (CertFP source).
    const presented = server.clientCertDer() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, client_der, presented);
}

test "mTLS: a declining client still completes with no client cert" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x55} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x55, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp, .request_client_cert = true });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{der} });
    defer client.deinit();
    client.declineClientCertForTest(); // responds to CertificateRequest with an empty Certificate

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    const cflight = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cflight);
    _ = try server.feed(cflight);
    try std.testing.expect(server.handshakeDone());
    try std.testing.expect(server.clientCertDer() == null);
}

test "mTLS: CertificateRequest wire encoding is exact (RFC 8446 §4.3.2)" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const alloc = std.testing.allocator;

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x66} ** Ed25519.KeyPair.seed_length);
    var cert_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x66, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .signing_key = kp, .request_client_cert = true });
    defer server.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    try server.writeCertificateRequest(&out);

    // certificate_request(13), u24 body length 15, then:
    //   0x00                empty certificate_request_context
    //   0x00 0x0c           extensions vector total length (12)
    //   0x00 0x0d 0x00 0x08 signature_algorithms(13), extension_data length 8
    //   0x00 0x06           supported_signature_algorithms list length (6)
    //   0x08 0x07           ed25519
    //   0x04 0x03           ecdsa_secp256r1_sha256
    //   0x08 0x04           rsa_pss_rsae_sha256
    // Every length prefix must be internally consistent — a doubled extensions
    // length here is exactly what broke gnutls/openssl mTLS clients.
    const expected = [_]u8{
        0x0d, 0x00, 0x00, 0x0f,
        0x00, 0x00, 0x0c, 0x00,
        0x0d, 0x00, 0x08, 0x00,
        0x06, 0x08, 0x07, 0x04,
        0x03, 0x08, 0x04,
    };
    try std.testing.expectEqualSlices(u8, &expected, out.items);
}

test "clientKeyFromCert parses an RSA-2048 leaf SPKI into modulus/exponent" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const rsa_key = rsaTestPrivateKey();
    var cert_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedRsa(&cert_buf, .{
        .common_name = "client.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x10, 0x01 },
        .public_modulus = rsa_key.n,
        .public_exponent = rsa_key.e,
        .private_key = rsa_key,
        .dns_names = &.{"client.test"},
        .is_ca = false,
    });
    const key = try clientKeyFromCert(der);
    try std.testing.expect(key == .rsa);
    // n/e must round-trip the DER INTEGER encoding exactly (the leading 0x00 DER
    // adds for a set MSB is stripped back off by rsaUnsignedInt).
    try std.testing.expectEqualSlices(u8, rsa_key.n, key.rsa.n);
    try std.testing.expectEqualSlices(u8, rsa_key.e, key.rsa.e);
}

test "mTLS: ECDSA P-256 client cert completes and exposes leaf + CertFP" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const certfp = @import("../proto/certfp.zig");
    const alloc = std.testing.allocator;

    const server_kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x77} ** Ed25519.KeyPair.seed_length);
    const client_kp = ecdsa_p256.KeyPair.generate(std.testing.io);

    var server_cert_buf: [1024]u8 = undefined;
    const server_der = try x509_selfsign.buildSelfSigned(&server_cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x77, 0x01 },
        .key_pair = server_kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
    var client_cert_buf: [1024]u8 = undefined;
    const client_der = try x509_selfsign.buildSelfSignedEcdsaP256(&client_cert_buf, .{
        .common_name = "client.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x77, 0x02 },
        .key_pair = client_kp,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{server_der}, .signing_key = server_kp, .request_client_cert = true });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{server_der} });
    defer client.deinit();
    client.setClientCertEcdsaP256ForTest(client_der, client_kp);

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    const cflight = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cflight);
    try std.testing.expect(client.handshakeDone());

    _ = try server.feed(cflight);
    try std.testing.expect(server.handshakeDone());

    // The verified client leaf is exactly what was presented, and its CertFP
    // (lowercase-hex SHA-256 of the DER leaf) is what SASL EXTERNAL matches.
    const presented = server.clientCertDer() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, client_der, presented);
    var fp: certfp.Fingerprint = undefined;
    certfp.computeHex(presented, &fp);
    var expected_fp: certfp.Fingerprint = undefined;
    certfp.computeHex(client_der, &expected_fp);
    try std.testing.expectEqualSlices(u8, &expected_fp, &fp);

    // Application data flows both ways on the mutually-authenticated channel.
    const c2s = try client.encrypt("AUTHENTICATE EXTERNAL\r\n");
    defer alloc.free(c2s);
    const got = try server.decrypt(c2s);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("AUTHENTICATE EXTERNAL\r\n", got);
}

test "mTLS: RSA client cert completes and exposes leaf + CertFP" {
    const tls_client = @import("tls_client.zig");
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const certfp = @import("../proto/certfp.zig");
    const alloc = std.testing.allocator;

    const server_kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x78} ** Ed25519.KeyPair.seed_length);
    const client_rsa = rsaTestPrivateKey();

    var server_cert_buf: [1024]u8 = undefined;
    const server_der = try x509_selfsign.buildSelfSigned(&server_cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x78, 0x01 },
        .key_pair = server_kp,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });
    var client_cert_buf: [2048]u8 = undefined;
    const client_der = try x509_selfsign.buildSelfSignedRsa(&client_cert_buf, .{
        .common_name = "client.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x78, 0x02 },
        .public_modulus = client_rsa.n,
        .public_exponent = client_rsa.e,
        .private_key = client_rsa,
        .dns_names = &.{"client.test"},
        .is_ca = false,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{server_der}, .signing_key = server_kp, .request_client_cert = true });
    defer server.deinit();
    var client = try tls_client.Client.init(alloc, .{ .server_name = "irc.test", .trust_anchors = &.{server_der} });
    defer client.deinit();
    client.setClientCertRsaForTest(client_der, client_rsa);

    const ch = try client.start();
    defer alloc.free(ch);
    const sflight = switch (try server.feed(ch)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(sflight);
    const cflight = switch (try client.feed(sflight)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer alloc.free(cflight);
    try std.testing.expect(client.handshakeDone());

    _ = try server.feed(cflight);
    try std.testing.expect(server.handshakeDone());

    const presented = server.clientCertDer() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, client_der, presented);
    var fp: certfp.Fingerprint = undefined;
    certfp.computeHex(presented, &fp);
    var expected_fp: certfp.Fingerprint = undefined;
    certfp.computeHex(client_der, &expected_fp);
    try std.testing.expectEqualSlices(u8, &expected_fp, &fp);

    const c2s = try client.encrypt("AUTHENTICATE EXTERNAL\r\n");
    defer alloc.free(c2s);
    const got = try server.decrypt(c2s);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("AUTHENTICATE EXTERNAL\r\n", got);
}

test {
    std.testing.refAllDecls(@This());
}

// Real-client interop: drive a gnutls-cli TLS 1.3 handshake against the
// in-repo server with an RSA-2048 leaf over a loopback socket.
//
// gnutls is the strictest mainstream verifier of the RSA-PSS
// CertificateVerify (nettle enforces salt_len == hash_len and the exact EM
// layout; openssl's verify is lenient about salt length). This is exactly the
// client class that exposed the production ReleaseFast mulAddWord
// inline-asm earlyclobber bug (see rsa_verify.zig): optimized builds emitted
// garbage RSA signatures and gnutls failed the handshake with
// "Public key signature verification has failed" while Debug tests stayed
// green. Run the suite with `-Doptimize=ReleaseFast` to exercise that
// historical failure mode end to end.
//
// Returns true when the handshake completed on both ends; errors with
// SkipZigTest when gnutls-cli (or socket plumbing) is unavailable so the
// suite stays green in minimal environments.
fn gnutlsRsaLeafHandshake(priority: ?[]const u8, verbose: bool) !bool {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const linux = std.os.linux;
    const posix = std.posix;
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    const rsa_key = rsaTestPrivateKey();
    var cert_buf: [2048]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedRsa(&cert_buf, .{
        .common_name = "irc.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x52, 0x13 },
        .public_modulus = rsa_key.n,
        .public_exponent = rsa_key.e,
        .private_key = rsa_key,
        .dns_names = &.{"irc.test"},
        .is_ca = true,
    });

    var server = try Server.init(alloc, .{ .cert_chain = &.{der}, .rsa_signing_key = rsa_key });
    defer server.deinit();

    // Listening socket on 127.0.0.1:ephemeral.
    const lfd_rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(lfd_rc) != .SUCCESS) return error.SkipZigTest;
    const lfd: linux.fd_t = @intCast(lfd_rc);
    defer _ = linux.close(lfd);
    var addr = posix.sockaddr.in{
        .port = 0,
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
    };
    if (posix.errno(linux.bind(lfd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(lfd, 1)) != .SUCCESS) return error.SkipZigTest;
    var got_addr: posix.sockaddr.in = undefined;
    var got_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    if (posix.errno(linux.getsockname(lfd, @ptrCast(&got_addr), &got_len)) != .SUCCESS) return error.SkipZigTest;
    const port = std.mem.bigToNative(u16, got_addr.port);

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;

    var argv_buf: [8][]const u8 = undefined;
    var argc: usize = 0;
    argv_buf[argc] = "gnutls-cli";
    argc += 1;
    argv_buf[argc] = "--insecure";
    argc += 1;
    if (priority) |p| {
        argv_buf[argc] = "--priority";
        argc += 1;
        argv_buf[argc] = p;
        argc += 1;
    }
    argv_buf[argc] = "-p";
    argc += 1;
    argv_buf[argc] = port_str;
    argc += 1;
    argv_buf[argc] = "127.0.0.1";
    argc += 1;

    var child = std.process.spawn(io, .{
        .argv = argv_buf[0..argc],
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch {
        // gnutls-cli not installed (CI/sandbox): skip silently. A stray stderr
        // line here would make `zig build test` print a spurious "failed command"
        // (see daemon/dlog.zig); the skip is already surfaced by the test runner.
        return error.SkipZigTest;
    };

    // Hang-proofing: every blocking socket/pipe operation below is gated on a
    // poll() with a deadline so a wedged client can never hang the suite.
    if (!pollReadable(lfd, 15_000)) {
        child.kill(io);
        return error.SkipZigTest;
    }
    const cfd_rc = linux.accept4(lfd, null, null, 0);
    if (posix.errno(cfd_rc) != .SUCCESS) {
        child.kill(io);
        return error.SkipZigTest;
    }
    const cfd: linux.fd_t = @intCast(cfd_rc);
    defer _ = linux.close(cfd);

    var buf: [16384]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        if (!pollReadable(cfd, 10_000)) break;
        const n_rc = linux.read(cfd, &buf, buf.len);
        if (posix.errno(n_rc) != .SUCCESS) break;
        const n: usize = @intCast(n_rc);
        if (n == 0) break;
        const res = server.feed(buf[0..n]) catch |err| {
            if (verbose) std.debug.print("gnutls interop: server.feed error {t}\n", .{err});
            break;
        };
        switch (res) {
            .bytes_to_send => |out| {
                defer alloc.free(out);
                var off: usize = 0;
                while (off < out.len) {
                    const w_rc = linux.write(cfd, out.ptr + off, out.len - off);
                    if (posix.errno(w_rc) != .SUCCESS) break;
                    off += @intCast(w_rc);
                }
            },
            .need_more => {},
        }
        if (server.handshakeDone()) break;
    }
    const done = server.handshakeDone();
    _ = linux.shutdown(cfd, linux.SHUT.RDWR);

    // Read child output BEFORE wait (wait closes the pipe files).
    var out_buf: [16384]u8 = undefined;
    const out_len = drainFd(if (child.stdout) |f| f.handle else null, &out_buf);
    var err_buf: [16384]u8 = undefined;
    const err_len = drainFd(if (child.stderr) |f| f.handle else null, &err_buf);
    const term = child.wait(io) catch return error.SkipZigTest;

    // Success = both sides finished the handshake. gnutls-cli's exit code is
    // deliberately not part of the criterion: tearing the TCP stream down
    // without a close_notify makes it exit 1 ("non-properly terminated") even
    // after a fully successful handshake.
    const ok = done and std.mem.indexOf(u8, out_buf[0..out_len], "Handshake was completed") != null;
    if (verbose or !ok) {
        std.debug.print(
            "gnutls interop: handshakeDone={} term={any}\n--- gnutls stdout ---\n{s}\n--- gnutls stderr ---\n{s}\n",
            .{ done, term, out_buf[0..out_len], err_buf[0..err_len] },
        );
    }
    return ok;
}

/// poll() `fd` for readability with a millisecond deadline; false on timeout
/// or poll error. Keeps the gnutls interop test free of unbounded blocking.
fn pollReadable(fd: std.os.linux.fd_t, timeout_ms: i32) bool {
    const linux = std.os.linux;
    var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    const rc = linux.poll(&fds, 1, timeout_ms);
    if (std.posix.errno(rc) != .SUCCESS) return false;
    return rc == 1 and (fds[0].revents & (linux.POLL.IN | linux.POLL.HUP)) != 0;
}

/// Read everything currently available from `fd` (bounded by `buf` and a poll
/// deadline per read); returns the number of bytes captured.
fn drainFd(fd_opt: ?std.os.linux.fd_t, buf: []u8) usize {
    const linux = std.os.linux;
    const fd = fd_opt orelse return 0;
    var len: usize = 0;
    while (len < buf.len) {
        if (!pollReadable(fd, 10_000)) break;
        const rc = linux.read(fd, buf[len..].ptr, buf.len - len);
        if (std.posix.errno(rc) != .SUCCESS) break;
        const n: usize = @intCast(rc);
        if (n == 0) break;
        len += n;
    }
    return len;
}

test "gnutls-cli interop: RSA-2048 leaf TLS 1.3 handshake (CertificateVerify accepted)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Default priority covers the common path; the PSS-only signature policy
    // forces gnutls to require rsa_pss_rsae_sha256 for the CertificateVerify.
    try std.testing.expect(try gnutlsRsaLeafHandshake(null, false));
    try std.testing.expect(try gnutlsRsaLeafHandshake("NORMAL:-SIGN-ALL:+SIGN-RSA-PSS-RSAE-SHA256", false));
}
