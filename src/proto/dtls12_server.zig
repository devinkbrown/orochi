// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.2 server-side handshake flight state machine (RFC 6347) for the
//! WebRTC DTLS-SRTP media leg (RFC 5764 / RFC 8827). Orochi is always the DTLS
//! *server* (`setup:passive`); the browser/mobile peer is the client and
//! initiates.
//!
//! This drives the ECDHE-ECDSA-AES128-GCM handshake on top of the record and
//! message codecs in `dtls12_record.zig` / `dtls12_messages.zig`:
//!
//!   client → ClientHello (no cookie)
//!   server → HelloVerifyRequest(cookie)              [stateless, no state kept]
//!   client → ClientHello (cookie)
//!   server → ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
//!   client → ClientKeyExchange, ChangeCipherSpec, Finished
//!   server → ChangeCipherSpec, Finished              [handshake established]
//!
//! DoS resistance: the stateless HelloVerifyRequest cookie (RFC 6347 §4.2.1) is
//! a keyed MAC over the peer's transport address and the ClientHello.random. No
//! per-peer state is allocated until a returned cookie proves return-routability
//! — so half-open handshakes are bounded and fail-closed.
//!
//! On completion both directions of SRTP keying material are derived via
//! `dtls_srtp.exportSrtpKeys` and stored on the session for the SFU leg
//! (Increment 2 consumes them; this layer only derives + stores).
//!
//! Every parse is fail-closed and constant-time where secret (cookie and
//! Finished verify_data comparisons); hostile UDP input never traps.
const std = @import("std");

const record = @import("dtls12_record.zig");
const msg = @import("dtls12_messages.zig");
const dhs = @import("dtls_handshake.zig");
const kx = @import("dtls_keyexchange.zig");
const dtls_srtp = @import("dtls_srtp.zig");
const fingerprint = @import("dtls_fingerprint.zig");
const peer_verify = @import("dtls_peer_verify.zig");
const x509_selfsign = @import("x509_selfsign.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const x509 = @import("../crypto/x509.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const TransportAddress = @import("ice.zig").TransportAddress;

pub const cookie_len: usize = 16;
pub const verify_data_len: usize = kx.verify_data_length;
pub const cert_der_cap: usize = 1024;
/// Flight 4 = ServerHello + Certificate(cert) + ServerKeyExchange +
/// ServerHelloDone. Sized to always fit (and thus always cache) the largest
/// cert, so a retransmitted ClientHello never re-derives a fresh handshake.
pub const flight4_cap: usize = cert_der_cap + 600;
pub const flight6_cap: usize = 64;
comptime {
    // Guard the flight-4 retransmit cache against silently not-caching (which
    // would break an in-flight handshake on a retransmitted ClientHello).
    std.debug.assert(flight4_cap >= cert_der_cap + 512);
}
/// Message_seq the server assigns to its handshake-proper flight (HVR is 0).
const server_hello_seq: u16 = 1;

/// Default bound on concurrent (post-cookie) handshakes. A flood beyond this
/// recycles the stalest slot rather than growing memory.
pub const default_max_sessions: usize = 256;

pub const Error = error{
    EntropyUnavailable,
    CertBuildFailed,
} || record.EncodeError;

const State = enum {
    /// Cookie validated, flight 4 sent, awaiting ClientKeyExchange/CCS/Finished.
    expect_client_finish,
    established,
};

pub const Session = struct {
    active: bool = false,
    addr: TransportAddress = .{},
    state: State = .expect_client_finish,
    last_activity_ms: i64 = 0,

    client_random: [32]u8 = @splat(0),
    server_random: [32]u8 = @splat(0),
    ecdhe: kx.KeyPair = undefined,
    srtp_profile: u16 = 0,

    transcript: Sha256 = undefined,
    master_secret: [kx.master_secret_length]u8 = @splat(0),
    key_block: msg.KeyBlock = undefined,
    have_keys: bool = false,
    got_cke: bool = false,
    got_ccs: bool = false,

    srtp_keys: dtls_srtp.ExportedKeys = undefined,

    /// RFC 8122 peer verification. `fp_verified` is set true only once a
    /// presented peer certificate has matched the expected fingerprint bound for
    /// this address AND possession of its private key was proven (the client
    /// CertificateVerify signature validated). Whether an expectation EXISTS is
    /// evaluated live off `Terminator.verify_bindings` at the accessor, so a
    /// binding registered any time before key export still gates.
    fp_verified: bool = false,

    /// Mutual-auth (client-certificate capture, #64). Set at flight-4 emission
    /// when the terminator requests client certs AND a fingerprint is bound for
    /// this peer. Once set, `peerVerifiedSession` requires `fp_verified` for THIS
    /// session regardless of the (possibly later-evicted) binding — so an evicted
    /// binding can never re-open the gate.
    mutual_auth: bool = false,
    /// The peer sent a client Certificate message (even an empty/invalid one).
    /// Also a processed-once latch: a retransmitted Certificate is ignored so the
    /// transcript is never double-fed.
    got_client_cert: bool = false,
    /// Processed-once latch for the client CertificateVerify (retransmit-safe).
    got_client_cv: bool = false,
    /// The client CertificateVerify signature validated against the presented
    /// certificate's public key (possession proven).
    client_cert_verified: bool = false,
    /// Parsed public key of the presented client leaf certificate.
    client_pubkey: ecdsa_p256.PublicKey = undefined,
    have_client_pubkey: bool = false,
    /// SHA-256 of the presented client leaf certificate DER (RFC 8122 match).
    client_cert_digest: [peer_verify.digest_len]u8 = @splat(0),

    /// Cached server flights for retransmit (respond to a retransmitted client
    /// flight with the identical bytes rather than re-deriving).
    flight4: [flight4_cap]u8 = undefined,
    flight4_len: usize = 0,
    flight6: [flight6_cap]u8 = undefined,
    flight6_len: usize = 0,
    /// Per-session epoch-0 record sequence for the server's flights. Starts at 1
    /// so it never collides with a seq-0 HelloVerifyRequest.
    epoch0_write_seq: u48 = 1,

    fn reset(self: *Session) void {
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_block));
        std.crypto.secureZero(u8, &self.ecdhe.secret);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.srtp_keys));
        self.* = .{};
    }
};

/// Per-address DTLS server terminator. Owns the self-signed cert, the cookie
/// secret, and the bounded session table. Pump-thread-owned: NOT internally
/// synchronised.
pub const Terminator = struct {
    cert_der: [cert_der_cap]u8 = undefined,
    cert_len: usize = 0,
    cert_key: ecdsa_p256.KeyPair = undefined,
    cookie_secret: [32]u8 = @splat(0),
    csprng: std.Random.DefaultCsprng = undefined,
    sessions: []Session,
    /// RFC 8122 expected peer fingerprints, keyed by remote transport address.
    /// Bound by the signaling layer (per MEDIA OFFER) before the ClientHello
    /// arrives; consulted at handshake completion. Fixed-capacity, no alloc.
    verify_bindings: peer_verify.Bindings(default_max_sessions) = .{},
    /// Client-certificate capture (#64). When true, a session with a bound
    /// expected fingerprint requests + possession-verifies the peer's client
    /// certificate (mutual DTLS). Default OFF ⇒ server-authenticated only, wire
    /// byte-identical (no CertificateRequest is ever sent). The media plane sets
    /// this the moment DTLS-SRTP is enabled.
    request_client_cert: bool = false,

    /// Initialise from a 32-byte entropy seed: mints the self-signed
    /// ECDSA-P256 cert, the cookie secret, and seeds the per-handshake CSPRNG.
    /// `sessions` is a caller-owned, caller-freed backing array.
    pub fn init(seed: [32]u8, sessions: []Session, not_before: i64, not_after: i64) Error!Terminator {
        var self: Terminator = .{ .sessions = sessions };
        self.csprng = std.Random.DefaultCsprng.init(seed);
        const rng = self.csprng.random();
        rng.bytes(&self.cookie_secret);

        var key_seed: [ecdsa_p256.KeyPair.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &key_seed);
        rng.bytes(&key_seed);
        self.cert_key = ecdsa_p256.KeyPair.generateDeterministic(key_seed) catch
            return error.CertBuildFailed;

        var serial: [8]u8 = undefined;
        rng.bytes(&serial);
        serial[0] |= 0x01; // keep it non-zero after leading-zero trim
        const der = x509_selfsign.buildSelfSignedEcdsaP256(&self.cert_der, .{
            .common_name = "orochi-dtls",
            .not_before = not_before,
            .not_after = not_after,
            .serial = &serial,
            .key_pair = self.cert_key,
        }) catch return error.CertBuildFailed;
        self.cert_len = der.len;

        for (self.sessions) |*s| s.* = .{};
        return self;
    }

    /// Secure-zero all key material on teardown: the cookie secret, the cert
    /// private key (signs every ServerKeyExchange), the CSPRNG state (seeds the
    /// cert key + every per-session ECDHE key), and each session's secrets.
    pub fn deinit(self: *Terminator) void {
        std.crypto.secureZero(u8, &self.cookie_secret);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.cert_key));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.csprng));
        for (self.sessions) |*s| s.reset();
    }

    pub fn certDer(self: *const Terminator) []const u8 {
        return self.cert_der[0..self.cert_len];
    }

    /// The daemon's DTLS cert public key (for tests / SKE-signature checks).
    pub fn certPublicKey(self: *const Terminator) ecdsa_p256.PublicKey {
        return self.cert_key.public_key;
    }

    /// The DTLS certificate key pair. Shared with the DTLS 1.3 terminator so both
    /// version engines sign with — and advertise the fingerprint of — ONE cert.
    /// Daemon-internal (the signing identity); never leaves the process.
    pub fn certKeyPair(self: *const Terminator) ecdsa_p256.KeyPair {
        return self.cert_key;
    }

    /// Format the SHA-256 `a=fingerprint` line (RFC 8122) into `out`.
    pub fn fingerprintLine(self: *const Terminator, out: []u8) fingerprint.Error![]const u8 {
        return fingerprint.format(.sha256, self.certDer(), out);
    }

    /// Whether the handshake with `addr` has completed (SRTP keys ready).
    pub fn established(self: *const Terminator, addr: TransportAddress) bool {
        const s = self.find(addr) orelse return false;
        return s.state == .established;
    }

    /// Exported SRTP keying material for `addr` once established (Increment 2
    /// drives the SFU SRTP contexts from this), else null. FAILS CLOSED: when
    /// the signaling layer bound an expected peer fingerprint (RFC 8122) that
    /// has not been verified against a presented certificate, no keys are handed
    /// out — an unverifiable peer gets no media.
    pub fn exportedKeys(self: *const Terminator, addr: TransportAddress) ?dtls_srtp.ExportedKeys {
        const s = self.find(addr) orelse return null;
        if (s.state != .established) return null;
        if (!self.peerVerifiedSession(addr, s)) return null;
        return s.srtp_keys;
    }

    /// The negotiated SRTP profile for `addr` once established, else null. Fails
    /// closed on an unverified expected fingerprint, mirroring `exportedKeys`.
    pub fn srtpProfile(self: *const Terminator, addr: TransportAddress) ?u16 {
        const s = self.find(addr) orelse return null;
        if (s.state != .established) return null;
        if (!self.peerVerifiedSession(addr, s)) return null;
        return s.srtp_profile;
    }

    /// RFC 8122 verdict for a resolved session: true when the presented cert was
    /// verified, or when verification was never engaged for this session. Once a
    /// session commits to mutual auth (`mutual_auth`, set at flight-4 emission
    /// when a fingerprint was bound), it REQUIRES `fp_verified` — independent of
    /// the live binding table — so an evicted binding can never re-open the gate.
    /// Otherwise it is live-evaluated off the binding table (a binding set any
    /// time before key export still gates).
    fn peerVerifiedSession(self: *const Terminator, addr: TransportAddress, s: *const Session) bool {
        if (s.mutual_auth) return s.fp_verified;
        return self.verify_bindings.expectedFor(addr) == null or s.fp_verified;
    }

    /// Bind the RFC 8122 fingerprint the peer signaled for `addr` (SHA-256 of
    /// the certificate the peer will present). Idempotent; safe to call on every
    /// inbound datagram before the handshake completes.
    pub fn bindExpectedFingerprint(self: *Terminator, addr: TransportAddress, digest: [peer_verify.digest_len]u8) void {
        _ = self.verify_bindings.bind(addr, digest);
    }

    /// Record the certificate the peer presented in the DTLS handshake and
    /// verify it against the bound expected fingerprint. This is the seam the
    /// handshake calls the moment client-certificate capture lands; it is a
    /// no-op when no session exists for `addr`.
    pub fn recordPeerCertificate(self: *Terminator, addr: TransportAddress, cert_der: []const u8) void {
        const s = self.find(addr) orelse return;
        if (self.verify_bindings.expectedFor(addr)) |exp| {
            s.fp_verified = peer_verify.digestEql(exp, peer_verify.certDigest(cert_der));
        } else {
            s.fp_verified = false;
        }
    }

    /// Whether the peer at `addr` is RFC 8122 verified: true when no expected
    /// fingerprint was bound (verification not requested) or the presented
    /// certificate matched it. False for a bound-but-unverified peer.
    pub fn peerVerified(self: *const Terminator, addr: TransportAddress) bool {
        const s = self.find(addr) orelse return false;
        return self.peerVerifiedSession(addr, s);
    }

    // -- session table -----------------------------------------------------

    fn find(self: *const Terminator, addr: TransportAddress) ?*Session {
        for (self.sessions) |*s| {
            if (s.active and s.addr.eql(addr)) return @constCast(s);
        }
        return null;
    }

    /// Find-or-allocate a session slot for `addr`. On a full table, evicts the
    /// stalest slot (bounds half-open handshakes).
    fn acquire(self: *Terminator, addr: TransportAddress, now_ms: i64) *Session {
        if (self.find(addr)) |s| return s;
        var free: ?*Session = null;
        var stalest: *Session = &self.sessions[0];
        for (self.sessions) |*s| {
            if (!s.active) {
                free = s;
                break;
            }
            if (s.last_activity_ms < stalest.last_activity_ms) stalest = s;
        }
        const slot = free orelse stalest;
        // Evicting a live slot for a different peer: drop that peer's stale
        // fingerprint binding so a reused address never inherits it.
        if (slot.active and !slot.addr.eql(addr)) self.verify_bindings.clear(slot.addr);
        slot.reset();
        slot.active = true;
        slot.addr = addr;
        slot.last_activity_ms = now_ms;
        return slot;
    }

    // -- cookie ------------------------------------------------------------

    fn computeCookie(self: *const Terminator, addr: TransportAddress, client_random: [32]u8) [cookie_len]u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        var h = HmacSha256.init(&self.cookie_secret);
        // Length-delimit the IP bytes (ip_len ∈ {4,16}) so the address and port
        // cannot alias across a v4/v6 boundary.
        h.update(&[_]u8{addr.ip_len});
        h.update(addr.bytes());
        var port_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &port_be, addr.port, .big);
        h.update(&port_be);
        h.update(&client_random);
        h.final(&mac);
        return mac[0..cookie_len].*;
    }

    // -- main entry --------------------------------------------------------

    /// Process one inbound DTLS datagram from `addr`. Returns a response
    /// datagram written into `out` (borrows `out`), or null when nothing is to
    /// be sent. Never traps on malformed input.
    pub fn handleDatagram(
        self: *Terminator,
        addr: TransportAddress,
        datagram: []const u8,
        now_ms: i64,
        out: []u8,
    ) ?[]const u8 {
        var resp_len: usize = 0;
        var off: usize = 0;
        while (off < datagram.len) {
            const dec = record.RecordHeader.decode(datagram[off..]) catch break;
            off += dec.consumed;
            switch (dec.hdr.content_type) {
                .handshake => {
                    if (self.handleHandshakeRecord(addr, dec.hdr, dec.fragment, now_ms, out)) |n| {
                        // At most one record per client flight elicits a server
                        // flight; stop so a later record can't overwrite `out`
                        // and orphan the response bytes behind a stale length.
                        resp_len = n;
                        break;
                    }
                },
                .change_cipher_spec => {
                    if (self.find(addr)) |s| {
                        s.got_ccs = true;
                        s.last_activity_ms = now_ms;
                    }
                },
                else => {}, // alerts / app-data: ignore in this layer
            }
        }
        if (resp_len == 0) return null;
        return out[0..resp_len];
    }

    /// Handle one handshake record. Returns the length written to `out` if a
    /// response flight was produced, else null.
    fn handleHandshakeRecord(
        self: *Terminator,
        addr: TransportAddress,
        hdr: record.RecordHeader,
        fragment: []const u8,
        now_ms: i64,
        out: []u8,
    ) ?usize {
        // Epoch-1 handshake records (client Finished) are GCM-protected.
        var plaintext_buf: [512]u8 = undefined;
        const hs_bytes: []const u8 = if (hdr.epoch == 0)
            fragment
        else blk: {
            const s = self.find(addr) orelse return null;
            if (!s.have_keys or !s.got_ccs) return null;
            break :blk record.openGcm(
                s.key_block.client_write_key,
                s.key_block.client_write_iv,
                .handshake,
                hdr.seqNum(),
                fragment,
                &plaintext_buf,
            ) catch return null;
        };

        const dh = dhs.Header.decode(hs_bytes) catch return null;
        // Single-fragment messages only (our peers send these small messages
        // unfragmented); reassembly of fragmented flights is a follow-up.
        if (dh.hdr.fragment_offset != 0 or dh.hdr.fragment_length != dh.hdr.length) return null;
        const body_len: usize = dh.hdr.length;
        if (hs_bytes.len < dhs.handshake_header_len + body_len) return null;
        const body = hs_bytes[dhs.handshake_header_len..][0..body_len];

        return switch (dh.hdr.msg_type) {
            .client_hello => self.onClientHello(addr, dh.hdr.message_seq, body, now_ms, out),
            .certificate => self.onClientCertificate(addr, dh.hdr.message_seq, body, now_ms),
            .client_key_exchange => self.onClientKeyExchange(addr, dh.hdr.message_seq, body, now_ms),
            .certificate_verify => self.onClientCertificateVerify(addr, dh.hdr.message_seq, body, now_ms),
            .finished => self.onFinished(addr, dh.hdr.message_seq, body, now_ms, out),
            else => null,
        };
    }

    fn onClientHello(
        self: *Terminator,
        addr: TransportAddress,
        message_seq: u16,
        body: []const u8,
        now_ms: i64,
        out: []u8,
    ) ?usize {
        const ch = msg.parseClientHello(body) catch return null;
        if (!ch.offers_target_cipher) return null;
        // Version-dispatch seam (1.2 side): this engine only serves peers that
        // can speak DTLS 1.2. A 1.3-only peer would be routed to a 1.3 engine by
        // a facade upstream (a later increment); here it is simply not ours.
        if (!ch.offers_dtls12) return null;

        const expected = self.computeCookie(addr, ch.random);
        const cookie_ok = ch.cookie.len == cookie_len and
            std.crypto.timing_safe.eql([cookie_len]u8, expected, ch.cookie[0..cookie_len].*);
        if (!cookie_ok) {
            // Flight 2: HelloVerifyRequest with the fresh cookie. Stateless —
            // echo the client's record sequence (RFC 6347 §4.2.1) by using 0
            // here; a new ClientHello with the cookie will begin the session.
            return self.emitHelloVerifyRequest(&expected, out);
        }

        // Cookie good. Select an SRTP profile we support.
        const profile = selectSrtpProfile(ch.use_srtp_body) orelse return null;

        // Retransmitted second ClientHello for an in-flight session: resend the
        // cached flight 4 without re-deriving (keeps the transcript stable).
        if (self.find(addr)) |existing| {
            if (existing.flight4_len != 0 and std.mem.eql(u8, &existing.client_random, &ch.random)) {
                existing.last_activity_ms = now_ms;
                if (out.len < existing.flight4_len) return null;
                @memcpy(out[0..existing.flight4_len], existing.flight4[0..existing.flight4_len]);
                return existing.flight4_len;
            }
        }

        const s = self.acquire(addr, now_ms);
        s.reset();
        s.active = true;
        s.addr = addr;
        s.last_activity_ms = now_ms;
        s.state = .expect_client_finish;
        s.client_random = ch.random;
        s.srtp_profile = profile;
        s.epoch0_write_seq = 1;
        // Mutual auth (#64): request + possession-verify the peer's client cert
        // when this terminator is configured to AND a fingerprint is bound for
        // the peer. Committed here so an evicted binding can't relax the gate.
        s.mutual_auth = self.request_client_cert and self.verify_bindings.expectedFor(addr) != null;

        // Server Random — 32 fully random bytes (RFC 8446 §4.1.3 style; the
        // legacy gmt_unix_time field carries no meaning here).
        const rng = self.csprng.random();
        rng.bytes(&s.server_random);

        // Ephemeral server ECDHE key pair.
        var ecdhe_seed: [32]u8 = undefined;
        rng.bytes(&ecdhe_seed);
        s.ecdhe = kx.generateKeyPair(ecdhe_seed);

        s.transcript = Sha256.init(.{});
        // Transcript begins with the second ClientHello (cookie exchange excluded).
        feedTranscript(&s.transcript, .client_hello, message_seq, body);

        return self.emitFlight4(s, out);
    }

    fn onClientKeyExchange(
        self: *Terminator,
        addr: TransportAddress,
        message_seq: u16,
        body: []const u8,
        now_ms: i64,
    ) ?usize {
        const s = self.find(addr) orelse return null;
        if (s.state != .expect_client_finish) return null;
        const client_point = msg.parseClientKeyExchange(body) catch return null;

        const pre_master = kx.computeSharedSecret(s.ecdhe.secret, client_point) catch return null;
        s.master_secret = kx.masterSecret(&pre_master, s.client_random, s.server_random);
        s.key_block = msg.deriveKeyBlock(&s.master_secret, s.client_random, s.server_random);
        s.have_keys = true;
        s.got_cke = true;
        s.last_activity_ms = now_ms;

        feedTranscript(&s.transcript, .client_key_exchange, message_seq, body);
        return null; // no response until Finished
    }

    /// Handle the client Certificate (mutual auth). Parses + captures the leaf
    /// cert's public key + fingerprint for the later CertificateVerify possession
    /// check. Feeds the raw message into the transcript FIRST (so the transcript
    /// stays consistent even for an unparseable/empty cert, which then simply
    /// fails closed at CertificateVerify). No response.
    fn onClientCertificate(
        self: *Terminator,
        addr: TransportAddress,
        message_seq: u16,
        body: []const u8,
        now_ms: i64,
    ) ?usize {
        const s = self.find(addr) orelse return null;
        if (s.state != .expect_client_finish or !s.mutual_auth) return null;
        // Processed-once: a retransmitted Certificate must not double-feed the
        // transcript (which would break the handshake — fail-closed but a legit
        // reconnect could fail).
        if (s.got_client_cert) return null;
        s.last_activity_ms = now_ms;
        s.got_client_cert = true;
        feedTranscript(&s.transcript, .certificate, message_seq, body);

        // Capture the leaf public key + fingerprint (fail-closed on any issue: a
        // missing pubkey makes the CertificateVerify unverifiable ⇒ no media).
        const leaf = msg.parseCertificate(body) catch return null;
        if (leaf.len == 0) return null;
        s.client_cert_digest = peer_verify.certDigest(leaf);
        const parsed = x509.parse(leaf) catch return null;
        const spk = x509.extractPublicKey(parsed.spki_der) catch return null;
        const point = switch (spk) {
            .ecdsa_p256 => |pt| pt,
            else => return null, // wrong key family ⇒ fail closed
        };
        s.client_pubkey = ecdsa_p256.parsePublicKeySec1(point) catch return null;
        s.have_client_pubkey = true;
        return null;
    }

    /// Handle the client CertificateVerify (mutual auth). Verifies possession —
    /// the ECDSA signature over the handshake transcript up to (and including) the
    /// ClientKeyExchange — under the presented cert's public key, then binds
    /// RFC 8122 identity (fingerprint match). Fail-closed on any deviation. No
    /// response. Must run BEFORE the transcript is advanced past CKE.
    fn onClientCertificateVerify(
        self: *Terminator,
        addr: TransportAddress,
        message_seq: u16,
        body: []const u8,
        now_ms: i64,
    ) ?usize {
        const s = self.find(addr) orelse return null;
        if (s.state != .expect_client_finish or !s.mutual_auth) return null;
        if (s.got_client_cv) return null; // processed-once (retransmit-safe)
        s.got_client_cv = true;
        s.last_activity_ms = now_ms;

        // The CertificateVerify signature covers SHA-256(handshake_messages) from
        // ClientHello through ClientKeyExchange — exactly the current transcript
        // (CertificateVerify itself is not yet fed).
        const transcript_through_cke = s.transcript.peek();
        self.verifyClientPossession(s, addr, body, transcript_through_cke);

        // CertificateVerify is part of the transcript the Finished messages cover.
        feedTranscript(&s.transcript, .certificate_verify, message_seq, body);
        return null;
    }

    /// Possession verify + RFC 8122 fingerprint bind for the presented client
    /// cert. Sets `client_cert_verified`/`fp_verified` only on full success;
    /// silent on any failure (the session then stays fail-closed).
    fn verifyClientPossession(
        self: *Terminator,
        s: *Session,
        addr: TransportAddress,
        cv_body: []const u8,
        transcript_hash: [Sha256.digest_length]u8,
    ) void {
        if (!s.have_client_pubkey) return;
        const view = msg.parseCertificateVerify(cv_body) catch return;
        if (view.scheme != msg.sig_scheme_ecdsa_secp256r1_sha256) return;
        const sig = ecdsa_p256.signatureFromDer(view.sig_der) catch return;
        if (!ecdsa_p256.verifyPrehashed(sig, transcript_hash, s.client_pubkey)) return;
        // Possession proven. Now bind RFC 8122 identity: the presented cert's
        // fingerprint must match the one the peer signaled (if any expectation).
        s.client_cert_verified = true;
        if (self.verify_bindings.expectedFor(addr)) |exp| {
            s.fp_verified = peer_verify.digestEql(exp, s.client_cert_digest);
        } else {
            s.fp_verified = false;
        }
    }

    fn onFinished(
        self: *Terminator,
        addr: TransportAddress,
        message_seq: u16,
        body: []const u8,
        now_ms: i64,
        out: []u8,
    ) ?usize {
        const s = self.find(addr) orelse return null;

        // Established retransmit: resend cached flight 6.
        if (s.state == .established) {
            if (s.flight6_len != 0 and out.len >= s.flight6_len) {
                @memcpy(out[0..s.flight6_len], s.flight6[0..s.flight6_len]);
                return s.flight6_len;
            }
            return null;
        }
        if (!s.have_keys or !s.got_cke or !s.got_ccs) return null;
        // Mutual auth (#64): the peer's client certificate MUST have been
        // presented and possession-verified, else fail closed — no server
        // Finished, no keys, no media (even though the DTLS transcript matches).
        if (s.mutual_auth and !s.client_cert_verified) return null;
        if (body.len != verify_data_len) return null;

        // Verify the client's Finished against the transcript up to CKE.
        const client_hash = s.transcript.peek();
        const expected = kx.verifyData(&s.master_secret, "client finished", client_hash);
        if (!std.crypto.timing_safe.eql([verify_data_len]u8, expected, body[0..verify_data_len].*)) return null;

        // Include the client Finished in the transcript for the server Finished.
        feedTranscript(&s.transcript, .finished, message_seq, body);
        const server_hash = s.transcript.peek();
        const server_vd = kx.verifyData(&s.master_secret, "server finished", server_hash);

        const resp = self.emitFlight6(s, &server_vd, out) orelse return null;

        // Derive + store the SRTP keying material (RFC 5764 §4.2).
        s.srtp_keys = dtls_srtp.exportSrtpKeys(&s.master_secret, s.client_random, s.server_random);
        s.state = .established;
        s.last_activity_ms = now_ms;
        return resp;
    }

    // -- flight builders ---------------------------------------------------

    fn emitHelloVerifyRequest(self: *Terminator, cookie: []const u8, out: []u8) ?usize {
        _ = self;
        var hvr_buf: [3 + cookie_len]u8 = undefined;
        const hvr = dhs.encodeHelloVerifyRequest(cookie, &hvr_buf) catch return null;
        // HVR is message_seq 0, epoch 0, record seq 0 (stateless).
        const n = framePlaintextHandshake(out, .hello_verify_request, 0, 0, 0, hvr) catch return null;
        return n;
    }

    fn emitFlight4(self: *Terminator, s: *Session, out: []u8) ?usize {
        var body_buf: [cert_der_cap + 32]u8 = undefined;
        var total: usize = 0;

        // ServerHello (msg_seq 1)
        {
            const sh = msg.buildServerHello(&body_buf, s.server_random, msg.cipher_ecdhe_ecdsa_aes128_gcm_sha256, s.srtp_profile) catch return null;
            feedTranscript(&s.transcript, .server_hello, server_hello_seq, sh);
            total += framePlaintextHandshake(out[total..], .server_hello, server_hello_seq, 0, s.epoch0_write_seq, sh) catch return null;
            s.epoch0_write_seq += 1;
        }
        // Certificate (msg_seq 2)
        {
            const cert = msg.buildCertificate(&body_buf, self.certDer()) catch return null;
            feedTranscript(&s.transcript, .certificate, server_hello_seq + 1, cert);
            total += framePlaintextHandshake(out[total..], .certificate, server_hello_seq + 1, 0, s.epoch0_write_seq, cert) catch return null;
            s.epoch0_write_seq += 1;
        }
        // ServerKeyExchange (msg_seq 3)
        {
            var signed_buf: [160]u8 = undefined;
            const signed = msg.serverKeyExchangeSignedData(&signed_buf, s.client_random, s.server_random, s.ecdhe.public) catch return null;
            const sig = ecdsa_p256.sign(signed, self.cert_key) catch return null;
            var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
            const sig_der = ecdsa_p256.signatureToDer(sig, &sig_der_buf) catch return null;
            const ske = msg.buildServerKeyExchange(&body_buf, s.ecdhe.public, sig_der) catch return null;
            feedTranscript(&s.transcript, .server_key_exchange, server_hello_seq + 2, ske);
            total += framePlaintextHandshake(out[total..], .server_key_exchange, server_hello_seq + 2, 0, s.epoch0_write_seq, ske) catch return null;
            s.epoch0_write_seq += 1;
        }
        // CertificateRequest (msg_seq 4) — mutual auth only (#64). Off ⇒ this
        // message is never emitted, so the server-auth-only flight is byte-
        // identical. When present, ServerHelloDone shifts to msg_seq 5.
        var done_seq: u16 = server_hello_seq + 3;
        if (s.mutual_auth) {
            var cr_buf: [64]u8 = undefined;
            const cr = msg.buildCertificateRequest(&cr_buf) catch return null;
            feedTranscript(&s.transcript, .certificate_request, server_hello_seq + 3, cr);
            total += framePlaintextHandshake(out[total..], .certificate_request, server_hello_seq + 3, 0, s.epoch0_write_seq, cr) catch return null;
            s.epoch0_write_seq += 1;
            done_seq = server_hello_seq + 4;
        }
        // ServerHelloDone (empty)
        {
            feedTranscript(&s.transcript, .server_hello_done, done_seq, &.{});
            total += framePlaintextHandshake(out[total..], .server_hello_done, done_seq, 0, s.epoch0_write_seq, &.{}) catch return null;
            s.epoch0_write_seq += 1;
        }

        if (total <= s.flight4.len) {
            @memcpy(s.flight4[0..total], out[0..total]);
            s.flight4_len = total;
        }
        return total;
    }

    fn emitFlight6(self: *Terminator, s: *Session, server_vd: *const [verify_data_len]u8, out: []u8) ?usize {
        _ = self;
        var total: usize = 0;
        // ChangeCipherSpec (epoch 0, one byte 0x01).
        total += (record.writePlaintext(.change_cipher_spec, 0, s.epoch0_write_seq, &.{0x01}, out) catch return null).len;
        s.epoch0_write_seq += 1;

        // Finished (epoch 1, GCM-protected, msg_seq 5, server write keys, seq 0).
        const n = frameEncryptedHandshake(
            out[total..],
            s.key_block.server_write_key,
            s.key_block.server_write_iv,
            1,
            0,
            .finished,
            server_hello_seq + 4,
            server_vd,
        ) catch return null;
        total += n;

        if (total <= s.flight6.len) {
            @memcpy(s.flight6[0..total], out[0..total]);
            s.flight6_len = total;
        }
        return total;
    }
};

/// Choose the best SRTP profile we support from a use_srtp extension body.
/// Prefers AES-128-CM-HMAC-SHA1-80 (the WebRTC-mandatory profile `srtp.zig`
/// implements). Returns null if none offered / body absent.
pub fn selectSrtpProfile(use_srtp_body: []const u8) ?u16 {
    if (use_srtp_body.len == 0) return null;
    if (dtls_srtp.offersProfile(use_srtp_body, dtls_srtp.profile_aes128_cm_sha1_80))
        return dtls_srtp.profile_aes128_cm_sha1_80;
    return null;
}

/// Feed one handshake message into a transcript hash using its canonical
/// single-fragment header (fragment_offset=0, fragment_length=length),
/// preserving message_seq (RFC 6347 §4.2.6).
pub fn feedTranscript(t: *Sha256, msg_type: dhs.HandshakeType, message_seq: u16, body: []const u8) void {
    var hdr_buf: [dhs.handshake_header_len]u8 = undefined;
    const hdr = dhs.Header{
        .msg_type = msg_type,
        .length = @intCast(body.len),
        .message_seq = message_seq,
        .fragment_offset = 0,
        .fragment_length = @intCast(body.len),
    };
    const enc = hdr.encode(&hdr_buf) catch return; // 12-byte buf always fits
    t.update(enc);
    t.update(body);
}

/// Frame a plaintext (epoch-0) handshake message: record header + handshake
/// header + body. Returns bytes written to `out`.
pub fn framePlaintextHandshake(
    out: []u8,
    msg_type: dhs.HandshakeType,
    message_seq: u16,
    epoch: u16,
    rec_seq: u48,
    body: []const u8,
) record.EncodeError!usize {
    const frag_len = dhs.handshake_header_len + body.len;
    const total = record.record_header_len + frag_len;
    if (out.len < total) return error.BufferTooSmall;
    if (frag_len > std.math.maxInt(u16)) return error.BufferTooSmall;

    const rh = record.RecordHeader{ .content_type = .handshake, .epoch = epoch, .seq = rec_seq, .length = @intCast(frag_len) };
    _ = try rh.encode(out[0..record.record_header_len]);
    const hh = dhs.Header{
        .msg_type = msg_type,
        .length = @intCast(body.len),
        .message_seq = message_seq,
        .fragment_offset = 0,
        .fragment_length = @intCast(body.len),
    };
    _ = hh.encode(out[record.record_header_len..][0..dhs.handshake_header_len]) catch return error.BufferTooSmall;
    @memcpy(out[record.record_header_len + dhs.handshake_header_len ..][0..body.len], body);
    return total;
}

/// Frame a GCM-protected (epoch ≥ 1) handshake message. The plaintext is the
/// handshake header + body; the record fragment is the sealed ciphertext.
pub fn frameEncryptedHandshake(
    out: []u8,
    key: [record.gcm_key_len]u8,
    salt: [record.gcm_salt_len]u8,
    epoch: u16,
    rec_seq: u48,
    msg_type: dhs.HandshakeType,
    message_seq: u16,
    body: []const u8,
) record.EncodeError!usize {
    var pt: [dhs.handshake_header_len + verify_data_len]u8 = undefined;
    if (body.len > verify_data_len) return error.BufferTooSmall;
    const hh = dhs.Header{
        .msg_type = msg_type,
        .length = @intCast(body.len),
        .message_seq = message_seq,
        .fragment_offset = 0,
        .fragment_length = @intCast(body.len),
    };
    _ = hh.encode(pt[0..dhs.handshake_header_len]) catch return error.BufferTooSmall;
    @memcpy(pt[dhs.handshake_header_len..][0..body.len], body);
    const pt_len = dhs.handshake_header_len + body.len;

    var sealed_buf: [dhs.handshake_header_len + verify_data_len + record.gcm_overhead]u8 = undefined;
    const sealed = try record.sealGcm(key, salt, .handshake, epoch, rec_seq, pt[0..pt_len], &sealed_buf);
    return (try record.writePlaintext(.handshake, epoch, rec_seq, sealed, out)).len;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testAddr(last_octet: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last_octet }, port) catch unreachable;
}

fn makeTerminator(seed_byte: u8) !struct { term: Terminator, sessions: []Session } {
    const sessions = try testing.allocator.alloc(Session, 8);
    errdefer testing.allocator.free(sessions);
    const term = try Terminator.init(@splat(seed_byte), sessions, 1_700_000_000, 1_900_000_000);
    return .{ .term = term, .sessions = sessions };
}

test "fingerprint is deterministic for a fixed cert and well-formed" {
    var setup = try makeTerminator(0x11);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();

    var buf1: [128]u8 = undefined;
    var buf2: [128]u8 = undefined;
    const fp1 = try setup.term.fingerprintLine(&buf1);
    const fp2 = try setup.term.fingerprintLine(&buf2);
    try testing.expectEqualStrings(fp1, fp2);
    try testing.expect(std.mem.startsWith(u8, fp1, "sha-256 "));
    // sha-256 <95 hex/colon chars>
    try testing.expectEqual(@as(usize, "sha-256 ".len + 95), fp1.len);

    // Independent terminator (different seed) → different cert → different fp.
    var other = try makeTerminator(0x22);
    defer testing.allocator.free(other.sessions);
    defer other.term.deinit();
    var buf3: [128]u8 = undefined;
    const fp3 = try other.term.fingerprintLine(&buf3);
    try testing.expect(!std.mem.eql(u8, fp1, fp3));
}

test "HelloVerifyRequest cookie round-trip: bare ClientHello elicits a cookie, wrong cookie re-elicits, no session kept" {
    var setup = try makeTerminator(0x33);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    const addr = testAddr(2, 5000);

    var client_random: [32]u8 = undefined;
    for (&client_random, 0..) |*b, i| b.* = @intCast(i +% 3);

    // Bare ClientHello (no cookie).
    var ch_body: [512]u8 = undefined;
    const chb = try msg.buildClientHello(&ch_body, .{ .random = client_random, .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80} });
    var dgram: [600]u8 = undefined;
    const dlen = try framePlaintextHandshake(&dgram, .client_hello, 0, 0, 0, chb);

    var out: [2048]u8 = undefined;
    const resp = setup.term.handleDatagram(addr, dgram[0..dlen], 1000, &out) orelse return error.TestUnexpectedResult;

    // Response is a single HelloVerifyRequest handshake record.
    const rdec = try record.RecordHeader.decode(resp);
    try testing.expectEqual(record.ContentType.handshake, rdec.hdr.content_type);
    const hh = try dhs.Header.decode(rdec.fragment);
    try testing.expectEqual(dhs.HandshakeType.hello_verify_request, hh.hdr.msg_type);
    const hvr_body = rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length];
    const cookie = try dhs.parseHelloVerifyRequest(hvr_body);
    try testing.expect(cookie.len == cookie_len);

    // No session state was allocated (stateless cookie).
    try testing.expect(setup.term.find(addr) == null);

    // A ClientHello with a WRONG cookie is re-challenged (still no session).
    const bad_cookie: [cookie_len]u8 = @splat(0xAA);
    var ch2_body: [512]u8 = undefined;
    const ch2b = try msg.buildClientHello(&ch2_body, .{ .random = client_random, .cookie = &bad_cookie, .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80} });
    var dgram2: [600]u8 = undefined;
    const dlen2 = try framePlaintextHandshake(&dgram2, .client_hello, 1, 0, 1, ch2b);
    const resp2 = setup.term.handleDatagram(addr, dgram2[0..dlen2], 1001, &out) orelse return error.TestUnexpectedResult;
    const rdec2 = try record.RecordHeader.decode(resp2);
    const hh2 = try dhs.Header.decode(rdec2.fragment);
    try testing.expectEqual(dhs.HandshakeType.hello_verify_request, hh2.hdr.msg_type);
    try testing.expect(setup.term.find(addr) == null);
}

test "malformed DTLS records are dropped without a trap and never allocate a session" {
    var setup = try makeTerminator(0x44);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    const addr = testAddr(9, 6000);
    var out: [2048]u8 = undefined;

    // Fuzz-ish: a spread of random/garbage datagrams.
    var prng = std.Random.DefaultPrng.init(0xDEAD_BEEF);
    const rng = prng.random();
    for (0..2000) |_| {
        var junk: [256]u8 = undefined;
        const n = 1 + rng.uintLessThan(usize, junk.len);
        rng.bytes(junk[0..n]);
        // Force the record content-type byte across the DTLS range sometimes.
        if (rng.boolean()) junk[0] = 20 + rng.uintLessThan(u8, 4);
        _ = setup.term.handleDatagram(addr, junk[0..n], 1, &out);
    }
    // Hostile bytes wrapped in a WELL-FORMED record + handshake header, so the
    // deep message parsers (onClientHello / onFinished / parse*) get exercised.
    for (0..2000) |_| {
        var body: [200]u8 = undefined;
        const blen = rng.uintLessThan(usize, body.len);
        rng.bytes(body[0..blen]);
        const mtypes = [_]dhs.HandshakeType{ .client_hello, .client_key_exchange, .finished, .certificate };
        const mtype = mtypes[rng.uintLessThan(usize, mtypes.len)];
        var dgram: [256]u8 = undefined;
        // random epoch (0 or 1) to hit both plaintext and GCM-open reject paths.
        const epoch: u16 = rng.uintLessThan(u16, 2);
        const framed = framePlaintextHandshake(&dgram, mtype, rng.int(u16), epoch, rng.int(u16), body[0..blen]) catch continue;
        _ = setup.term.handleDatagram(addr, dgram[0..framed], 1, &out);
    }
    // A handshake record whose declared length overruns the datagram.
    const overrun = [_]u8{ 22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    try testing.expect(setup.term.handleDatagram(addr, &overrun, 1, &out) == null);
    // No session was ever created by garbage.
    try testing.expect(setup.term.find(addr) == null);
}

// -- Full loopback handshake: a DTLS client driver built from the same lib
//    completes the handshake and both sides derive identical SRTP keys. -----

/// Client-authentication material for the mutual-auth loopback (a self-signed
/// ECDSA-P256 cert + its key, mirroring a WebRTC browser peer).
const ClientAuth = struct {
    key_pair: ecdsa_p256.KeyPair,
    cert_der: []const u8,
};

const ClientDriver = struct {
    client_random: [32]u8,
    server_random: [32]u8 = @splat(0),
    cookie: [64]u8 = @splat(0),
    cookie_len: usize = 0,
    ecdhe: kx.KeyPair,
    server_point: [msg.p256_point_len]u8 = @splat(0),
    master_secret: [kx.master_secret_length]u8 = @splat(0),
    key_block: msg.KeyBlock = undefined,
    transcript: Sha256 = undefined,
    srtp_profile: u16 = 0,
    /// Mutual auth: when set, present this client cert + sign a CertificateVerify.
    auth: ?ClientAuth = null,
    /// Raw handshake_messages accumulator (only when `auth` is set) — the exact
    /// bytes the DTLS 1.2 CertificateVerify signature covers.
    raw: [4096]u8 = undefined,
    raw_len: usize = 0,
    saw_certificate_request: bool = false,

    fn init() ClientDriver {
        var cr: [32]u8 = undefined;
        for (&cr, 0..) |*b, i| b.* = @intCast((i *% 7) +% 1);
        return .{ .client_random = cr, .ecdhe = kx.generateKeyPair(@splat(0x5c)) };
    }

    /// Feed one handshake message into the running transcript AND (for mutual
    /// auth) the raw handshake_messages accumulator.
    fn feed(self: *ClientDriver, msg_type: dhs.HandshakeType, message_seq: u16, body: []const u8) void {
        feedTranscript(&self.transcript, msg_type, message_seq, body);
        if (self.auth == null) return;
        var hb: [dhs.handshake_header_len]u8 = undefined;
        const hdr = dhs.Header{
            .msg_type = msg_type,
            .length = @intCast(body.len),
            .message_seq = message_seq,
            .fragment_offset = 0,
            .fragment_length = @intCast(body.len),
        };
        const enc = hdr.encode(&hb) catch unreachable;
        @memcpy(self.raw[self.raw_len..][0..enc.len], enc);
        self.raw_len += enc.len;
        @memcpy(self.raw[self.raw_len..][0..body.len], body);
        self.raw_len += body.len;
    }

    fn buildClientHello(self: *ClientDriver, message_seq: u16, rec_seq: u48, out: []u8) ![]const u8 {
        var body: [512]u8 = undefined;
        const b = try msg.buildClientHello(&body, .{
            .random = self.client_random,
            .cookie = self.cookie[0..self.cookie_len],
            .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        });
        const n = try framePlaintextHandshake(out, .client_hello, message_seq, 0, rec_seq, b);
        return out[0..n];
    }
};

/// Drive a complete DTLS-SRTP loopback handshake (client role, built from the
/// same lib) against `term` for `addr`, returning the client driver once the
/// session is established. Shared by the handshake and RFC 8122 verification
/// tests.
/// Flight-5 behaviour, for exercising the mutual-auth fail-closed paths.
const Flight5Mode = enum {
    /// A well-formed flight (server-auth, or mutual auth presenting a valid cert).
    normal,
    /// Mutual server, but the client omits Certificate + CertificateVerify.
    omit_cert,
    /// Mutual server, but the client's CertificateVerify signature is corrupted.
    tamper_cv,
};

fn driveLoopbackHandshake(term: *Terminator, addr: TransportAddress) !ClientDriver {
    return driveLoopbackHandshakeAuth(term, addr, null, .normal);
}

fn driveLoopbackHandshakeAuth(
    term: *Terminator,
    addr: TransportAddress,
    client_auth: ?ClientAuth,
    mode: Flight5Mode,
) !ClientDriver {
    var client = ClientDriver.init();
    client.auth = client_auth;
    var out: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;

    // 1) ClientHello (no cookie) → HelloVerifyRequest.
    const ch1 = try client.buildClientHello(0, 0, &scratch);
    const hvr_dg = term.handleDatagram(addr, ch1, 100, &out) orelse return error.TestUnexpectedResult;
    {
        const rdec = try record.RecordHeader.decode(hvr_dg);
        const hh = try dhs.Header.decode(rdec.fragment);
        try testing.expectEqual(dhs.HandshakeType.hello_verify_request, hh.hdr.msg_type);
        const cookie = try dhs.parseHelloVerifyRequest(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]);
        @memcpy(client.cookie[0..cookie.len], cookie);
        client.cookie_len = cookie.len;
    }

    // 2) ClientHello (cookie) → flight 4. Begin the client transcript with CH2.
    client.transcript = Sha256.init(.{});
    var ch2_scratch: [600]u8 = undefined;
    const ch2_body = try msg.buildClientHello(&ch2_scratch, .{
        .random = client.client_random,
        .cookie = client.cookie[0..client.cookie_len],
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    client.feed(.client_hello, 1, ch2_body);
    var ch2_dg: [700]u8 = undefined;
    const ch2_len = try framePlaintextHandshake(&ch2_dg, .client_hello, 1, 0, 1, ch2_body);
    const flight4 = term.handleDatagram(addr, ch2_dg[0..ch2_len], 101, &out) orelse return error.TestUnexpectedResult;

    // 3) Parse flight 4: ServerHello, Certificate, ServerKeyExchange,
    //    [CertificateRequest], ServerHelloDone.
    {
        var off: usize = 0;
        var cert_der: []const u8 = &.{};
        while (off < flight4.len) {
            const rdec = try record.RecordHeader.decode(flight4[off..]);
            off += rdec.consumed;
            const hh = try dhs.Header.decode(rdec.fragment);
            const mbody = rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length];
            switch (hh.hdr.msg_type) {
                .server_hello => {
                    const sh = try msg.parseServerHello(mbody);
                    client.server_random = sh.random;
                    client.srtp_profile = sh.srtp_profile orelse return error.TestUnexpectedResult;
                    try testing.expectEqual(msg.cipher_ecdhe_ecdsa_aes128_gcm_sha256, sh.cipher_suite);
                    client.feed(.server_hello, hh.hdr.message_seq, mbody);
                },
                .certificate => {
                    cert_der = try msg.parseCertificate(mbody);
                    client.feed(.certificate, hh.hdr.message_seq, mbody);
                },
                .server_key_exchange => {
                    const ske = try msg.parseServerKeyExchange(mbody);
                    client.server_point = ske.point;
                    // Verify the SKE signature with the daemon's cert key (proves the
                    // ECDHE point is authenticated by the DTLS cert).
                    var signed_buf: [160]u8 = undefined;
                    const signed = try msg.serverKeyExchangeSignedData(&signed_buf, client.client_random, client.server_random, ske.point);
                    const sig = try ecdsa_p256.signatureFromDer(ske.sig_der);
                    try testing.expect(ecdsa_p256.verify(sig, signed, term.certPublicKey()));
                    client.feed(.server_key_exchange, hh.hdr.message_seq, mbody);
                },
                .certificate_request => {
                    const cr = try msg.parseCertificateRequest(mbody);
                    try testing.expect(cr.wants_ecdsa_sign and cr.offers_ecdsa_secp256r1_sha256);
                    client.saw_certificate_request = true;
                    client.feed(.certificate_request, hh.hdr.message_seq, mbody);
                },
                .server_hello_done => {
                    client.feed(.server_hello_done, hh.hdr.message_seq, mbody);
                },
                else => return error.TestUnexpectedResult,
            }
        }
        try testing.expect(cert_der.len > 0);
        try testing.expectEqualSlices(u8, term.certDer(), cert_der);
        // The server requests a client cert iff we are doing mutual auth.
        try testing.expectEqual(client.auth != null, client.saw_certificate_request);
    }

    // 4) Client derives the shared secret, master secret, and key block.
    const pre_master = try kx.computeSharedSecret(client.ecdhe.secret, client.server_point);
    client.master_secret = kx.masterSecret(&pre_master, client.client_random, client.server_random);
    client.key_block = msg.deriveKeyBlock(&client.master_secret, client.client_random, client.server_random);

    // 5) Build flight 5. Server-auth only: ClientKeyExchange, CCS, Finished
    //    (msg_seqs 2, 3). Mutual auth: Certificate, ClientKeyExchange,
    //    CertificateVerify, CCS, Finished (msg_seqs 2, 3, 4, 5).
    var flight5: [4096]u8 = undefined;
    var f5_len: usize = 0;
    {
        var epoch0_seq: u48 = 2;
        var finished_seq: u16 = 3;
        // `omit_cert` simulates a client that ignores the CertificateRequest and
        // sends a server-auth-style flight; the server must fail closed.
        const send_cert = client.auth != null and mode != .omit_cert;

        if (send_cert) {
            const auth = client.auth.?;
            // Certificate (msg_seq 2, epoch0 seq 2).
            var cert_buf: [cert_der_cap + 32]u8 = undefined;
            const cert = try msg.buildCertificate(&cert_buf, auth.cert_der);
            client.feed(.certificate, 2, cert);
            f5_len += try framePlaintextHandshake(flight5[f5_len..], .certificate, 2, 0, epoch0_seq, cert);
            epoch0_seq += 1;
        }

        // ClientKeyExchange (msg_seq 2 or 3).
        const cke_seq: u16 = if (send_cert) 3 else 2;
        var cke_body: [80]u8 = undefined;
        const cke = try msg.buildClientKeyExchange(&cke_body, client.ecdhe.public);
        client.feed(.client_key_exchange, cke_seq, cke);
        f5_len += try framePlaintextHandshake(flight5[f5_len..], .client_key_exchange, cke_seq, 0, epoch0_seq, cke);
        epoch0_seq += 1;

        if (send_cert) {
            const auth = client.auth.?;
            // CertificateVerify (msg_seq 4, epoch0 seq 4) — sign the raw
            // handshake_messages accumulated through ClientKeyExchange.
            const cv_sig = try ecdsa_p256.sign(client.raw[0..client.raw_len], auth.key_pair);
            var sig_der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
            const sig_der = try ecdsa_p256.signatureToDer(cv_sig, &sig_der_buf);
            var cv_buf: [128]u8 = undefined;
            const cv = try msg.buildCertificateVerify(&cv_buf, sig_der);
            if (mode == .tamper_cv) {
                // Flip a bit in the signature bytes: possession must NOT verify.
                cv_buf[cv.len - 1] ^= 0x40;
            }
            client.feed(.certificate_verify, 4, cv);
            f5_len += try framePlaintextHandshake(flight5[f5_len..], .certificate_verify, 4, 0, epoch0_seq, cv);
            epoch0_seq += 1;
            finished_seq = 5;
        }

        // ChangeCipherSpec (epoch0 seq).
        f5_len += (try record.writePlaintext(.change_cipher_spec, 0, epoch0_seq, &.{0x01}, flight5[f5_len..])).len;

        // Finished (encrypted, epoch1 seq0). verify_data over the transcript
        // through the last handshake message before Finished.
        const client_hash = client.transcript.peek();
        const client_vd = kx.verifyData(&client.master_secret, "client finished", client_hash);
        f5_len += try frameEncryptedHandshake(
            flight5[f5_len..],
            client.key_block.client_write_key,
            client.key_block.client_write_iv,
            1,
            0,
            .finished,
            finished_seq,
            &client_vd,
        );
        // The client's transcript for verifying the server's Finished includes
        // its own Finished message.
        feedTranscript(&client.transcript, .finished, finished_seq, &client_vd);
    }

    const flight6_opt = term.handleDatagram(addr, flight5[0..f5_len], 102, &out);
    if (mode != .normal) {
        // Fail-closed mutual auth: the server must NOT complete (no flight 6).
        if (flight6_opt != null) return error.TestUnexpectedResult;
        return client;
    }
    const flight6 = flight6_opt orelse return error.TestUnexpectedResult;

    // 6) Parse flight 6: ChangeCipherSpec + encrypted server Finished; verify it.
    {
        var off: usize = 0;
        var verified = false;
        while (off < flight6.len) {
            const rdec = try record.RecordHeader.decode(flight6[off..]);
            off += rdec.consumed;
            switch (rdec.hdr.content_type) {
                .change_cipher_spec => {},
                .handshake => {
                    try testing.expectEqual(@as(u16, 1), rdec.hdr.epoch);
                    var pt: [64]u8 = undefined;
                    const hs = try record.openGcm(
                        client.key_block.server_write_key,
                        client.key_block.server_write_iv,
                        .handshake,
                        rdec.hdr.seqNum(),
                        rdec.fragment,
                        &pt,
                    );
                    const hh = try dhs.Header.decode(hs);
                    try testing.expectEqual(dhs.HandshakeType.finished, hh.hdr.msg_type);
                    const server_vd = hs[dhs.handshake_header_len..][0..hh.hdr.length];
                    const server_hash = client.transcript.peek();
                    const expected = kx.verifyData(&client.master_secret, "server finished", server_hash);
                    try testing.expectEqualSlices(u8, &expected, server_vd);
                    verified = true;
                },
                else => return error.TestUnexpectedResult,
            }
        }
        try testing.expect(verified);
    }
    return client;
}

test "full DTLS-SRTP loopback handshake: both sides derive identical SRTP keys" {
    var setup = try makeTerminator(0x77);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    const addr = testAddr(5, 7000);
    var client = try driveLoopbackHandshake(term, addr);

    // 7) Both sides now export SRTP keys — assert byte-for-byte equality.
    try testing.expect(term.established(addr));
    const server_keys = term.exportedKeys(addr) orelse return error.TestUnexpectedResult;
    const client_keys = dtls_srtp.exportSrtpKeys(&client.master_secret, client.client_random, client.server_random);
    try testing.expectEqualSlices(u8, &client_keys.client, &server_keys.client);
    try testing.expectEqualSlices(u8, &client_keys.server, &server_keys.server);
    try testing.expectEqual(@as(?u16, dtls_srtp.profile_aes128_cm_sha1_80), term.srtpProfile(addr));

    // The exported material actually feeds an SRTP session (round-trip a frame).
    const srtp = @import("srtp.zig");
    const sk = srtp.deriveSessionKeys(client_keys.clientMaster(), client_keys.clientSalt());
    const rtp = [_]u8{ 0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0xCA, 0xFE, 0xBA, 0xBE } ++ "voice".*;
    var prot: [rtp.len + srtp.auth_tag_len]u8 = undefined;
    const wire = try srtp.protect(sk, 0, &rtp, &prot);
    var back: [rtp.len]u8 = undefined;
    try testing.expectEqualSlices(u8, &rtp, try srtp.unprotect(sk, 0, wire, &back));
}

test "RFC 8122: an established session with no bound fingerprint exports keys (byte-identical default)" {
    var setup = try makeTerminator(0x91);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    const addr = testAddr(5, 7300);

    // No bindExpectedFingerprint call: verification is not requested, so the
    // gate is inert and behavior matches the pre-Increment-3 terminator.
    var client = try driveLoopbackHandshake(term, addr);
    _ = &client;
    try testing.expect(term.established(addr));
    try testing.expect(term.peerVerified(addr)); // no expectation ⇒ verified
    try testing.expect(term.exportedKeys(addr) != null);
    try testing.expect(term.srtpProfile(addr) != null);
}

test "RFC 8122: a matching peer fingerprint verifies and unlocks the SRTP keys" {
    var setup = try makeTerminator(0x92);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    const addr = testAddr(5, 7400);

    // The signaling layer bound the fingerprint of the certificate the peer
    // will present (here a simulated browser client cert DER).
    const peer_cert = "simulated browser client certificate DER blob";
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(peer_cert));

    var client = try driveLoopbackHandshake(term, addr);
    _ = &client;

    // Handshake completed, but the expected fingerprint is not yet verified:
    // FAIL CLOSED — no keys, no profile, until a presented cert matches.
    try testing.expect(term.established(addr));
    try testing.expect(!term.peerVerified(addr));
    try testing.expect(term.exportedKeys(addr) == null);
    try testing.expect(term.srtpProfile(addr) == null);

    // The peer presents the matching certificate ⇒ verified ⇒ keys unlocked.
    term.recordPeerCertificate(addr, peer_cert);
    try testing.expect(term.peerVerified(addr));
    try testing.expect(term.exportedKeys(addr) != null);
    try testing.expect(term.srtpProfile(addr) != null);
}

test "RFC 8122: a mismatched peer fingerprint stays fail-closed (no keys, no profile)" {
    var setup = try makeTerminator(0x93);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    const addr = testAddr(5, 7500);

    term.bindExpectedFingerprint(addr, peer_verify.certDigest("the certificate the peer PROMISED"));

    var client = try driveLoopbackHandshake(term, addr);
    _ = &client;

    // The peer presents a DIFFERENT certificate than it signaled ⇒ mismatch ⇒
    // the session is rejected: no exported keys, no SRTP context handed out.
    term.recordPeerCertificate(addr, "an ENTIRELY different certificate DER");
    try testing.expect(term.established(addr)); // the DTLS layer completed...
    try testing.expect(!term.peerVerified(addr)); // ...but identity is unverified
    try testing.expect(term.exportedKeys(addr) == null);
    try testing.expect(term.srtpProfile(addr) == null);
}

// -- Mutual DTLS auth (#64): client-certificate capture + possession verify ---

/// Build a self-signed ECDSA-P256 client certificate (WebRTC peer) into
/// `cert_buf`, returning the auth material. The DER borrows `cert_buf`, which
/// must outlive the handshake.
fn makeClientAuth(seed_byte: u8, cert_buf: []u8) !ClientAuth {
    const key_seed: [ecdsa_p256.KeyPair.seed_length]u8 = @splat(seed_byte);
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(key_seed);
    const serial = [_]u8{ 0x0a, 0x0b, 0x0c, 0x0d, 0x01, 0x02, 0x03, 0x04 };
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(cert_buf, .{
        .common_name = "webrtc-client",
        .not_before = 1_700_000_000,
        .not_after = 1_900_000_000,
        .serial = &serial,
        .key_pair = kp,
    });
    return .{ .key_pair = kp, .cert_der = der };
}

test "mutual auth: a matching client cert completes the handshake and unlocks SRTP keys" {
    var setup = try makeTerminator(0xA1);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    term.request_client_cert = true; // DTLS-SRTP mutual auth engaged
    const addr = testAddr(5, 7700);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth(0x31, &cert_buf);
    // The signaling layer bound the SHA-256 of the cert the browser will present.
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(auth.cert_der));

    var client = try driveLoopbackHandshakeAuth(term, addr, auth, .normal);

    // The mutual handshake completed: the server requested + captured +
    // possession-verified the client cert, and the fingerprint matched.
    try testing.expect(client.saw_certificate_request);
    try testing.expect(term.established(addr));
    try testing.expect(term.peerVerified(addr));
    const server_keys = term.exportedKeys(addr) orelse return error.TestUnexpectedResult;
    try testing.expect(term.srtpProfile(addr) != null);

    // Both sides derive identical SRTP keys — media would flow.
    const client_keys = dtls_srtp.exportSrtpKeys(&client.master_secret, client.client_random, client.server_random);
    try testing.expectEqualSlices(u8, &client_keys.client, &server_keys.client);
    try testing.expectEqualSlices(u8, &client_keys.server, &server_keys.server);
}

test "mutual auth: a client cert whose fingerprint mismatches yields NO keys (fail closed)" {
    var setup = try makeTerminator(0xA2);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(5, 7701);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth(0x32, &cert_buf);
    // Bind a DIFFERENT fingerprint than the cert the client actually presents.
    term.bindExpectedFingerprint(addr, peer_verify.certDigest("a cert the peer will NOT present"));

    var client = try driveLoopbackHandshakeAuth(term, addr, auth, .normal);
    _ = &client;

    // Possession is proven (valid CertificateVerify) so the DTLS layer completes,
    // but the RFC 8122 identity does NOT match ⇒ no exported keys, no media.
    try testing.expect(term.established(addr));
    try testing.expect(!term.peerVerified(addr));
    try testing.expect(term.exportedKeys(addr) == null);
    try testing.expect(term.srtpProfile(addr) == null);
}

test "mutual auth: a client that omits its Certificate is rejected (no completion, no keys)" {
    var setup = try makeTerminator(0xA3);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(5, 7702);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth(0x33, &cert_buf);
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(auth.cert_der));

    // The client ignores the CertificateRequest and sends a server-auth flight.
    _ = try driveLoopbackHandshakeAuth(term, addr, auth, .omit_cert);
    try testing.expect(!term.established(addr));
    try testing.expect(term.exportedKeys(addr) == null);
    try testing.expect(term.srtpProfile(addr) == null);
}

test "mutual auth: a tampered CertificateVerify signature is rejected (no completion, no keys)" {
    var setup = try makeTerminator(0xA4);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    term.request_client_cert = true;
    const addr = testAddr(5, 7703);

    var cert_buf: [cert_der_cap]u8 = undefined;
    const auth = try makeClientAuth(0x34, &cert_buf);
    term.bindExpectedFingerprint(addr, peer_verify.certDigest(auth.cert_der));

    // The client presents a matching cert but a corrupted CertificateVerify ⇒
    // possession is NOT proven ⇒ fail closed.
    _ = try driveLoopbackHandshakeAuth(term, addr, auth, .tamper_cv);
    try testing.expect(!term.established(addr));
    try testing.expect(term.exportedKeys(addr) == null);
    try testing.expect(term.srtpProfile(addr) == null);
}

test "mutual auth off (server-auth only) is byte-identical to the pre-#64 flight 4" {
    // Two terminators from the same seed: one with mutual auth engaged but NO
    // fingerprint bound (⇒ mutual not activated for the peer), one untouched.
    var a = try makeTerminator(0xB7);
    defer testing.allocator.free(a.sessions);
    defer a.term.deinit();
    var b = try makeTerminator(0xB7);
    defer testing.allocator.free(b.sessions);
    defer b.term.deinit();
    a.term.request_client_cert = true; // engaged, but no fingerprint bound below

    const addr = testAddr(8, 7710);
    // Drive both through CH2→flight4 and compare the emitted flight 4 bytes.
    const f4a = try captureFlight4(&a.term, addr);
    const f4b = try captureFlight4(&b.term, addr);
    // No CertificateRequest was emitted (no fingerprint bound ⇒ server-auth only).
    try testing.expectEqualSlices(u8, f4a.bytes[0..f4a.len], f4b.bytes[0..f4b.len]);
}

const CapturedFlight = struct { bytes: [2048]u8, len: usize };

/// Drive CH1→HVR→CH2 and capture the server's flight 4 bytes (for byte-identity
/// assertions). Uses a fixed client random so two same-seed terminators emit the
/// same flight.
fn captureFlight4(term: *Terminator, addr: TransportAddress) !CapturedFlight {
    var client = ClientDriver.init();
    var out: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    const ch1 = try client.buildClientHello(0, 0, &scratch);
    const hvr = term.handleDatagram(addr, ch1, 100, &out) orelse return error.TestUnexpectedResult;
    const rdec = try record.RecordHeader.decode(hvr);
    const hh = try dhs.Header.decode(rdec.fragment);
    const cookie = try dhs.parseHelloVerifyRequest(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]);
    @memcpy(client.cookie[0..cookie.len], cookie);
    client.cookie_len = cookie.len;
    var ch2_dg: [700]u8 = undefined;
    const ch2 = try client.buildClientHello(1, 1, &ch2_dg);
    const f4 = term.handleDatagram(addr, ch2, 101, &out) orelse return error.TestUnexpectedResult;
    var cap: CapturedFlight = .{ .bytes = undefined, .len = f4.len };
    @memcpy(cap.bytes[0..f4.len], f4);
    return cap;
}

test "retransmitted second ClientHello resends the cached flight 4 verbatim" {
    var setup = try makeTerminator(0x88);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    const addr = testAddr(6, 7100);

    var client = ClientDriver.init();
    var out: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;

    const ch1 = try client.buildClientHello(0, 0, &scratch);
    const hvr = term.handleDatagram(addr, ch1, 100, &out) orelse return error.TestUnexpectedResult;
    const rdec = try record.RecordHeader.decode(hvr);
    const hh = try dhs.Header.decode(rdec.fragment);
    const cookie = try dhs.parseHelloVerifyRequest(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]);
    @memcpy(client.cookie[0..cookie.len], cookie);
    client.cookie_len = cookie.len;

    var ch2_dg: [700]u8 = undefined;
    const ch2 = try client.buildClientHello(1, 1, &ch2_dg);
    var first_out: [2048]u8 = undefined;
    const f4a = term.handleDatagram(addr, ch2, 101, &first_out) orelse return error.TestUnexpectedResult;
    var first_copy: [2048]u8 = undefined;
    @memcpy(first_copy[0..f4a.len], f4a);

    // Retransmit the identical CH2 → identical flight 4, no new session slot.
    const f4b = term.handleDatagram(addr, ch2, 102, &out) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, first_copy[0..f4a.len], f4b);
}
